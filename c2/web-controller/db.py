"""
Database layer — per-thread SQLite connections with WAL mode.
Sensitive columns are AES-GCM sealed at rest when C2_DB_KEY is set
(see _enc/_dec); unset key = plaintext mode.
"""
import collections
import json
import logging
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta

import crypto as _crypto

# ── At-rest field encryption (stealth gap #2) ────────────────────────────────
# Sensitive columns (command/response bodies, host identity, sysinfo, notes,
# audit details) are AES-GCM sealed with a key from C2_DB_KEY. Unset key =
# plaintext mode (identical behaviour). Decryption falls back to the original
# value so pre-encryption rows keep reading.
_DB_KEY = os.environ.get("C2_DB_KEY", "")


def _enc(value):
    if not _DB_KEY or not value:
        return value
    out = _crypto.encrypt(str(value), _DB_KEY)
    if not out:
        _db_logger.warning("db._enc 加密失败——该字段将以明文落库（检查 C2_DB_KEY/内存）")
        return value
    # Pre-warm the decrypt cache: the plaintext is in hand right now, so
    # future reads of this field never pay the PBKDF2 cost.
    with _DECRYPT_CACHE_LOCK:
        _DECRYPT_CACHE[out] = str(value)
        if len(_DECRYPT_CACHE) > _DECRYPT_CACHE_MAX:
            _DECRYPT_CACHE.popitem(last=False)
    return out


_DECRYPT_CACHE = collections.OrderedDict()   # ciphertext → plaintext LRU
_DECRYPT_CACHE_MAX = 8192
_DECRYPT_CACHE_LOCK = threading.Lock()

_db_logger = logging.getLogger("c2.db")
_db_logger.setLevel(logging.DEBUG)
_decrypt_failures = 0                        # C2_DB_KEY 错配/数据损坏的哨兵
_DECRYPT_FAIL_WARN_EVERY = 10


def _dec(value):
    """Decrypt a stored field with an LRU cache.

    Every V1 ciphertext carries its own random salt, so each FIRST decryption
    costs a full PBKDF2 run (~10 ms) — a terminal with a few hundred messages
    meant seconds of KDF work on every agent click, and the GIL made every
    other request (/api/files included) wait too. Cache ciphertext→plaintext:
    repeated selects become dict lookups; only genuinely new rows pay the KDF.
    """
    if not _DB_KEY or not value:
        return value
    with _DECRYPT_CACHE_LOCK:
        hit = _DECRYPT_CACHE.get(value)
    if hit is not None:
        return hit
    pt = _crypto.decrypt(value, _DB_KEY)
    if pt is None:
        # 密钥丢失/错配的静默损坏哨兵：不再无声当明文，计数 + 周期性大声告警
        global _decrypt_failures
        _decrypt_failures += 1
        if _decrypt_failures % _DECRYPT_FAIL_WARN_EVERY == 1:
            _db_logger.warning(
                f"db._dec 解密失败累计 {_decrypt_failures} 次——"
                f"C2_DB_KEY 可能丢失或不匹配（密文将按原样返回，仅作显示）")
        return value
    with _DECRYPT_CACHE_LOCK:
        _DECRYPT_CACHE[value] = pt
        if len(_DECRYPT_CACHE) > _DECRYPT_CACHE_MAX:
            _DECRYPT_CACHE.popitem(last=False)
    return pt


def _db_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    probe = os.path.join(script_dir, ".write_probe")
    try:
        open(probe, "w").close()
        os.remove(probe)
        return os.path.join(script_dir, "c2_web.db")
    except OSError:
        return os.path.join(os.path.expanduser("~"), "c2_web.db")


DB_PATH = _db_path()
_local  = threading.local()


def get_conn() -> sqlite3.Connection:
    if not getattr(_local, "conn", None):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")   # fsync only at WAL checkpoint, ~10x faster writes
        conn.execute("PRAGMA cache_size=-8192")     # 8 MB page cache per connection
        conn.execute("PRAGMA temp_store=MEMORY")    # temp tables in RAM
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        _local.conn = conn
        _create_tables(conn)
    return _local.conn


def init_at_startup():
    """Call once at Flask startup (main thread) to create tables + trim old data."""
    conn = get_conn()
    _trim(conn)


def _create_tables(conn: sqlite3.Connection):
    """Create tables and indexes. Fast — only DDL, no data scanning."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY, value TEXT NOT NULL);

        -- All content stored as plaintext (decrypted before saving)
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL, timestamp TEXT NOT NULL,
            content TEXT NOT NULL, is_command INTEGER NOT NULL,
            command_id TEXT, response_to TEXT, message_type TEXT);

        CREATE TABLE IF NOT EXISTS file_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL, path TEXT NOT NULL,
            name TEXT NOT NULL, is_dir INTEGER NOT NULL,
            size INTEGER, timestamp TEXT NOT NULL,
            UNIQUE(agent_id, path, name));

        CREATE TABLE IF NOT EXISTS processed_comments (
            agent_id TEXT NOT NULL, comment_id TEXT NOT NULL,
            PRIMARY KEY (agent_id, comment_id));

        CREATE TABLE IF NOT EXISTS last_comment_times (
            agent_id TEXT PRIMARY KEY, ts TEXT NOT NULL);

        CREATE TABLE IF NOT EXISTS command_history (
            command_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL, command TEXT NOT NULL, sent_at TEXT NOT NULL);

        -- Sysinfo & sensitive snapshots (plaintext, long-term archive)
        CREATE TABLE IF NOT EXISTS agent_sysinfo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL, collected_at TEXT NOT NULL, content TEXT NOT NULL);

        CREATE TABLE IF NOT EXISTS agent_sensitive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL, collected_at TEXT NOT NULL, content TEXT NOT NULL);

        -- Agent notes / remarks
        CREATE TABLE IF NOT EXISTS agent_notes (
            agent_id TEXT PRIMARY KEY, note TEXT NOT NULL DEFAULT '');

        -- Agent registry: persists discovered agents across restarts.
        -- Primary key is (id, repo, channel) because GitHub id = issue number
        -- (unique per repo) while Notion id = page UUID (globally unique).
        CREATE TABLE IF NOT EXISTS agents (
            id         TEXT NOT NULL,
            repo       TEXT NOT NULL DEFAULT '',
            channel    TEXT NOT NULL DEFAULT 'github',
            agent_uuid TEXT DEFAULT '',
            hostname   TEXT DEFAULT 'unknown',
            username   TEXT DEFAULT 'unknown',
            os         TEXT DEFAULT 'unknown',
            privilege  TEXT DEFAULT 'user',
            kernel     TEXT DEFAULT '',
            arch       TEXT DEFAULT '',
            version    TEXT DEFAULT '',
            release_id TEXT DEFAULT '',
            last_seen  TEXT DEFAULT '',
            PRIMARY KEY (id, repo, channel));

        -- Operator audit trail: who did what, when, to which agent.
        -- Research reproducibility + misoperation forensics.
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            operator TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            agent_id TEXT DEFAULT '',
            detail TEXT DEFAULT '');

        -- WS Shell recordings (also created by older app.py _ensure_pty_table).
        CREATE TABLE IF NOT EXISTS pty_sessions (
            session_id   TEXT PRIMARY KEY,
            agent_id     TEXT NOT NULL,
            started_at   TEXT NOT NULL,
            ended_at     TEXT,
            content_text TEXT);

        -- sendit.sh "download+dispatch" is not atomic: persist across restarts
        -- so the agent reply can still trigger the download after a crash.
        CREATE TABLE IF NOT EXISTS sendit_pending (
            cmd_id   TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            agent_json TEXT NOT NULL,
            ts       REAL NOT NULL);

        -- Incomplete [Part i/n] groups survive controller restart
        CREATE TABLE IF NOT EXISTS chunk_parts (
            agent_id TEXT NOT NULL,
            resp_id  TEXT NOT NULL,
            idx      INTEGER NOT NULL,
            total    INTEGER NOT NULL,
            resp_to  TEXT,
            msg_type TEXT,
            part     TEXT NOT NULL,
            ts       REAL NOT NULL,
            PRIMARY KEY (agent_id, resp_id, idx));

        -- Indexes for high-frequency queries
        CREATE INDEX IF NOT EXISTS idx_msg_agent  ON messages(agent_id);
        CREATE INDEX IF NOT EXISTS idx_proc_agent ON processed_comments(agent_id);
        CREATE INDEX IF NOT EXISTS idx_si_agent   ON agent_sysinfo(agent_id);
        CREATE INDEX IF NOT EXISTS idx_sen_agent   ON agent_sensitive(agent_id);
        CREATE INDEX IF NOT EXISTS idx_cmd_agent  ON command_history(agent_id);
        CREATE INDEX IF NOT EXISTS idx_fl_agent   ON file_list(agent_id);
        CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log(ts);
        CREATE INDEX IF NOT EXISTS idx_pty_agent  ON pty_sessions(agent_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_sendit_ts  ON sendit_pending(ts);
        CREATE INDEX IF NOT EXISTS idx_chunk_aid  ON chunk_parts(agent_id, resp_id);
    """)

    # Column migration for pre-version databases (项 9 版本自上报): no-op when
    # the columns already exist; never fail startup on an old schema.
    # 审计说明（N6）：列名经 f-string 插值——只允许下方白名单内的合法
    # SQLite 标识符，防止未来改动把外部输入接进来。
    import re as _re
    for _col in ("version", "release_id"):
        if not _re.fullmatch(r"[a-z_]+", _col):
            continue
        try:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {_col} TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # already present
    conn.commit()


def _trim(conn: sqlite3.Connection):
    """Trim old data. Called once at startup, not on every new thread."""
    # Auto-trim: keep latest 2000 messages and 50 snapshots per agent.
    # ROW_NUMBER window function (SQLite 3.25+) is faster than NOT IN correlated subquery.
    try:
        conn.executescript("""
            DELETE FROM messages
            WHERE id IN (
                SELECT id FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY id DESC) AS rn
                    FROM messages
                ) WHERE rn > 2000
            );
            DELETE FROM agent_sysinfo
            WHERE id IN (
                SELECT id FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY id DESC) AS rn
                    FROM agent_sysinfo
                ) WHERE rn > 50
            );
            DELETE FROM agent_sensitive
            WHERE id IN (
                SELECT id FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY id DESC) AS rn
                    FROM agent_sensitive
                ) WHERE rn > 50
            );
            DELETE FROM pty_sessions
            WHERE session_id IN (
                SELECT session_id FROM (
                    SELECT session_id,
                           ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY started_at DESC) AS rn
                    FROM pty_sessions
                ) WHERE rn > 20
            );
        """)
    except Exception:
        # SQLite < 3.25 fallback
        conn.executescript("""
            DELETE FROM messages WHERE id NOT IN (
                SELECT id FROM messages m2
                WHERE m2.agent_id = messages.agent_id
                ORDER BY id DESC LIMIT 2000);
            DELETE FROM agent_sysinfo WHERE id NOT IN (
                SELECT id FROM agent_sysinfo s2
                WHERE s2.agent_id = agent_sysinfo.agent_id
                ORDER BY id DESC LIMIT 50);
            DELETE FROM agent_sensitive WHERE id NOT IN (
                SELECT id FROM agent_sensitive s2
                WHERE s2.agent_id = agent_sensitive.agent_id
                ORDER BY id DESC LIMIT 50);
            DELETE FROM pty_sessions WHERE session_id NOT IN (
                SELECT session_id FROM pty_sessions p2
                WHERE p2.agent_id = pty_sessions.agent_id
                ORDER BY started_at DESC LIMIT 20);
        """)
    conn.commit()


# ── Config ────────────────────────────────────────────────────────────────────

def cfg_get(conn, key: str, default=None):
    r = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return r[0] if r else default


def cfg_set(conn, key: str, value: str):
    conn.execute("INSERT OR REPLACE INTO config(key,value) VALUES(?,?)", (key, value))
    conn.commit()


# ── Messages (stored as plaintext after decryption) ───────────────────────────

def msg_save(conn, agent_id, content, is_cmd, cmd_id=None, resp_to=None, msg_type=None):
    # Full ISO timestamp (with date): stats_snapshot's 24h cutoff compares
    # lexicographically — a time-only "%H:%M:%S" value can never match.
    ts = datetime.now().isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO messages(agent_id,timestamp,content,is_command,command_id,response_to,message_type)"
        " VALUES(?,?,?,?,?,?,?)",
        (agent_id, ts, _enc(content), 1 if is_cmd else 0, cmd_id, resp_to, msg_type),
    )
    conn.commit()


def msg_list(conn, agent_id, limit=None):
    """Newest-first message load for the terminal view.

    `limit` (int) returns only the most recent N rows — the terminal shows a
    small window and loads older history on demand (?all=1), so the default
    path avoids decrypting entire histories on every agent click.
    """
    if limit:
        rows = conn.execute(
            "SELECT timestamp,content,is_command,command_id,response_to,message_type"
            " FROM messages WHERE agent_id=? ORDER BY id DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
        rows.reverse()   # keep chronological order for the UI
    else:
        rows = conn.execute(
            "SELECT timestamp,content,is_command,command_id,response_to,message_type"
            " FROM messages WHERE agent_id=? ORDER BY id",
            (agent_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["content"] = _dec(d.get("content"))
        out.append(d)
    return out


def msg_list_many(conn, agent_ids, limit=None):
    """Union messages from several agent ids (dual-channel siblings), chronological."""
    ids = [str(i) for i in (agent_ids or []) if i]
    if not ids:
        return []
    if len(ids) == 1:
        return msg_list(conn, ids[0], limit)
    placeholders = ",".join("?" * len(ids))
    if limit:
        rows = conn.execute(
            "SELECT timestamp,content,is_command,command_id,response_to,message_type"
            f" FROM messages WHERE agent_id IN ({placeholders}) ORDER BY id DESC LIMIT ?",
            (*ids, limit),
        ).fetchall()
        rows.reverse()
    else:
        rows = conn.execute(
            "SELECT timestamp,content,is_command,command_id,response_to,message_type"
            f" FROM messages WHERE agent_id IN ({placeholders}) ORDER BY id",
            ids,
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["content"] = _dec(d.get("content"))
        out.append(d)
    return out


def msg_clear(conn, agent_id):
    # 审计说明（N6）：表名经 f-string 插值——只能来自下方固定白名单。
    # 加显式校验，防止未来有人把外部输入接进 tbl 而引入注入。
    _allowed_tables = {"messages", "processed_comments", "last_comment_times",
                       "command_history", "file_list"}
    for tbl in ("messages", "processed_comments", "last_comment_times",
                "command_history", "file_list"):
        assert tbl in _allowed_tables  # 白名单内常量，防御性断言
        conn.execute(f"DELETE FROM {tbl} WHERE agent_id=?", (agent_id,))
    conn.commit()


# ── Processed comments ────────────────────────────────────────────────────────

def comment_is_processed(conn, agent_id, comment_id) -> bool:
    r = conn.execute(
        "SELECT 1 FROM processed_comments WHERE agent_id=? AND comment_id=?",
        (agent_id, comment_id),
    ).fetchone()
    return bool(r)


def comment_mark(conn, agent_id, comment_id):
    conn.execute(
        "INSERT OR IGNORE INTO processed_comments(agent_id,comment_id) VALUES(?,?)",
        (agent_id, comment_id),
    )
    conn.commit()


# ── File list ─────────────────────────────────────────────────────────────────

def fl_save(conn, agent_id, path, name, is_dir, size):
    conn.execute(
        "INSERT OR REPLACE INTO file_list(agent_id,path,name,is_dir,size,timestamp)"
        " VALUES(?,?,?,?,?,?)",
        (agent_id, path, name, 1 if is_dir else 0, size, datetime.now().isoformat()),
    )
    conn.commit()


def fl_get(conn, agent_id, path):
    rows = conn.execute(
        "SELECT name,is_dir,size FROM file_list WHERE agent_id=? AND path=?",
        (agent_id, path),
    ).fetchall()
    return [dict(r) for r in rows]


def fl_clear(conn, agent_id, path):
    conn.execute("DELETE FROM file_list WHERE agent_id=? AND path=?", (agent_id, path))
    conn.commit()


# ── Last comment cursor ───────────────────────────────────────────────────────

def cursor_get(conn, agent_id) -> str | None:
    r = conn.execute(
        "SELECT ts FROM last_comment_times WHERE agent_id=?", (agent_id,)
    ).fetchone()
    return r[0] if r else None


def cursor_set(conn, agent_id, ts: str):
    conn.execute(
        "INSERT OR REPLACE INTO last_comment_times(agent_id,ts) VALUES(?,?)", (agent_id, ts)
    )
    conn.commit()


def cursor_all(conn) -> dict:
    """启动时灌回评论水位，避免重启后 since=None 全量拉评论。"""
    try:
        rows = conn.execute("SELECT agent_id, ts FROM last_comment_times").fetchall()
        return {r[0]: r[1] for r in rows if r[0] and r[1]}
    except Exception:
        return {}


# ── Command history ───────────────────────────────────────────────────────────

def cmd_save(conn, cmd_id, agent_id, command):
    conn.execute(
        "INSERT OR REPLACE INTO command_history(command_id,agent_id,command,sent_at)"
        " VALUES(?,?,?,?)",
        (cmd_id, agent_id, _enc(command), datetime.now().isoformat()),
    )
    conn.commit()


def cmd_get(conn, cmd_id) -> str | None:
    r = conn.execute(
        "SELECT command FROM command_history WHERE command_id=?", (cmd_id,)
    ).fetchone()
    return _dec(r[0]) if r else None


def cmd_list(conn, agent_id):
    rows = conn.execute(
        "SELECT command_id,command FROM command_history WHERE agent_id=? ORDER BY rowid",
        (agent_id,),
    ).fetchall()
    return {r[0]: _dec(r[1]) for r in rows}


# ── Sysinfo snapshots ─────────────────────────────────────────────────────────

def si_save(conn, agent_id, content):
    conn.execute(
        "INSERT INTO agent_sysinfo(agent_id,collected_at,content) VALUES(?,?,?)",
        (agent_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _enc(content)),
    )
    conn.commit()


def si_latest(conn, agent_id):
    r = conn.execute(
        "SELECT id,collected_at,content FROM agent_sysinfo"
        " WHERE agent_id=? ORDER BY id DESC LIMIT 1",
        (agent_id,),
    ).fetchone()
    d = dict(r) if r else None
    if d:
        d["content"] = _dec(d.get("content"))
    return d


def si_history(conn, agent_id):
    rows = conn.execute(
        "SELECT id,collected_at FROM agent_sysinfo WHERE agent_id=? ORDER BY id DESC LIMIT 50",
        (agent_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def si_by_id(conn, agent_id: str, sid: int):
    r = conn.execute(
        "SELECT content FROM agent_sysinfo WHERE id=? AND agent_id=?", (sid, agent_id)
    ).fetchone()
    return _dec(r[0]) if r else None


# ── Sensitive snapshots ───────────────────────────────────────────────────────

def sen_save(conn, agent_id, content):
    conn.execute(
        "INSERT INTO agent_sensitive(agent_id,collected_at,content) VALUES(?,?,?)",
        (agent_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _enc(content)),
    )
    conn.commit()


def sen_latest(conn, agent_id):
    r = conn.execute(
        "SELECT id,collected_at,content FROM agent_sensitive"
        " WHERE agent_id=? ORDER BY id DESC LIMIT 1",
        (agent_id,),
    ).fetchone()
    d = dict(r) if r else None
    if d:
        d["content"] = _dec(d.get("content"))
    return d


def sen_history(conn, agent_id):
    rows = conn.execute(
        "SELECT id,collected_at FROM agent_sensitive WHERE agent_id=? ORDER BY id DESC LIMIT 50",
        (agent_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def sen_by_id(conn, agent_id: str, sid: int):
    r = conn.execute(
        "SELECT content FROM agent_sensitive WHERE id=? AND agent_id=?", (sid, agent_id)
    ).fetchone()
    return _dec(r[0]) if r else None


# ── Agent notes ───────────────────────────────────────────────────────────────

def note_get(conn, agent_id) -> str:
    r = conn.execute(
        "SELECT note FROM agent_notes WHERE agent_id=?", (agent_id,)
    ).fetchone()
    return _dec(r[0]) if r else ""


def note_set(conn, agent_id, note: str):
    conn.execute(
        "INSERT OR REPLACE INTO agent_notes(agent_id,note) VALUES(?,?)",
        (agent_id, _enc(note)),
    )
    conn.commit()


# ── Agent registry ────────────────────────────────────────────────────────────

def agent_upsert(conn, a: dict):
    """Insert or update an agent record. On conflict, update all mutable fields."""
    conn.execute("""
        INSERT INTO agents (id, repo, channel, agent_uuid, hostname, username,
                            os, privilege, kernel, arch, version, release_id, last_seen)
        VALUES (:id, :repo, :channel, :agent_uuid, :hostname, :username,
                :os, :privilege, :kernel, :arch, :version, :release_id, :last_seen)
        ON CONFLICT(id, repo, channel) DO UPDATE SET
            agent_uuid = excluded.agent_uuid,
            hostname   = excluded.hostname,
            username   = excluded.username,
            os         = excluded.os,
            privilege  = excluded.privilege,
            kernel     = excluded.kernel,
            arch       = excluded.arch,
            version    = excluded.version,
            release_id = excluded.release_id,
            last_seen  = excluded.last_seen
    """, {
        "id":         a.get("id", ""),
        "repo":       a.get("repo", ""),
        "channel":    a.get("channel", "github"),
        "agent_uuid": _enc(a.get("agent_uuid", "")),
        "hostname":   _enc(a.get("hostname", "unknown")),
        "username":   _enc(a.get("username", "unknown")),
        "os":         _enc(a.get("os", "unknown")),
        "privilege":  a.get("privilege", "user"),
        "kernel":     _enc(a.get("kernel", "")),
        "arch":       _enc(a.get("arch", "")),
        "version":    _enc(a.get("version", "")),
        "release_id": _enc(a.get("release_id", "")),
        "last_seen":  a.get("last_seen", ""),
    })
    conn.commit()


def agent_list(conn) -> list[dict]:
    """Return all agents ordered by last_seen descending."""
    rows = conn.execute("""
        SELECT id, repo, channel, agent_uuid, hostname, username,
               os, privilege, kernel, arch, version, release_id, last_seen
        FROM agents ORDER BY last_seen DESC
    """).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("agent_uuid", "hostname", "username", "os", "kernel", "arch",
                  "version", "release_id"):
            d[k] = _dec(d.get(k))
        out.append(d)
    return out


def agent_delete(conn, agent_id: str, repo: str, channel: str):
    """Remove an agent from the registry."""
    conn.execute(
        "DELETE FROM agents WHERE id=? AND repo=? AND channel=?",
        (agent_id, repo, channel),
    )
    conn.commit()


# ── Audit log ─────────────────────────────────────────────────────────────────

def audit_log(conn, operator: str, action: str, agent_id: str = "", detail: str = ""):
    """Append an audit entry. Never raises — auditing must not break operations."""
    try:
        from datetime import datetime as _dt
        conn.execute(
            "INSERT INTO audit_log (ts, operator, action, agent_id, detail) VALUES (?,?,?,?,?)",
            (_dt.now().isoformat(timespec="seconds"), operator, action,
             agent_id[:64], _enc(detail[:512]) if detail else ""),
        )
        conn.commit()
    except Exception:
        pass


def audit_list(conn, limit: int = 200) -> list[dict]:
    """Latest audit entries, newest first."""
    try:
        rows = conn.execute(
            "SELECT ts, operator, action, agent_id, detail "
            "FROM audit_log ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 2000)),),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = _dec(d.get("detail"))
            out.append(d)
        return out
    except Exception:
        return []


def agent_prune_duplicates(conn, repo: str, keep: dict):
    """Remove stale agent rows that duplicate a still-live agent.

    P1-6: decrypt-and-compare, not encrypt-and-match. AES-GCM random salt
    means re-encrypting the search uuid never equals the stored ciphertext.
    """
    for uuid, keep_id in keep.items():
        if not uuid:
            continue
        rows = conn.execute(
            "SELECT id, agent_uuid, repo, channel FROM agents WHERE repo=?",
            (repo,)).fetchall()
        for row_id, stored_uuid, row_repo, row_ch in rows:
            if not stored_uuid:
                continue
            decrypted = _dec(stored_uuid) if _DB_KEY else stored_uuid
            if decrypted == uuid and str(row_id) != str(keep_id):
                conn.execute(
                    "DELETE FROM agents WHERE id=? AND repo=? AND channel=?",
                    (row_id, row_repo or "", row_ch or "github"),
                )
    conn.commit()


def stats_snapshot(conn) -> dict:
    """Aggregated counters for the dashboard KPI row.

    Timestamps are local-time ISO strings, so the 24h cutoff is computed in
    Python and compared lexicographically (ISO strings sort chronologically).
    """
    cutoff = (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
    stats = {}
    try:
        stats["agents_total"] = conn.execute(
            "SELECT COUNT(*) FROM agents").fetchone()[0] or 0
        stats["messages_total"] = conn.execute(
            "SELECT COUNT(*) FROM messages").fetchone()[0] or 0
        stats["messages_24h"] = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE timestamp >= ?",
            (cutoff,)).fetchone()[0] or 0
        stats["commands_24h"] = conn.execute(
            "SELECT COUNT(*) FROM command_history WHERE sent_at >= ?",
            (cutoff,)).fetchone()[0] or 0
        stats["files_total"] = conn.execute(
            "SELECT COUNT(*) FROM file_list").fetchone()[0] or 0
        stats["sysinfo_total"] = conn.execute(
            "SELECT COUNT(*) FROM agent_sysinfo").fetchone()[0] or 0
    except Exception:
        stats = {k: 0 for k in (
            "agents_total", "messages_total", "messages_24h",
            "commands_24h", "files_total", "sysinfo_total")}
    return stats


# ── sendit pending (survives controller restart) ──────────────────────────────

def sendit_put(conn, cmd_id: str, filename: str, agent: dict, ts: float):
    conn.execute(
        "INSERT OR REPLACE INTO sendit_pending(cmd_id,filename,agent_id,agent_json,ts)"
        " VALUES(?,?,?,?,?)",
        (cmd_id, filename, (agent or {}).get("id", ""),
         json.dumps(agent or {}, ensure_ascii=False), float(ts)),
    )
    conn.commit()


def sendit_pop(conn, cmd_id: str):
    """Claim one pending row. Returns {filename, agent, ts} or None."""
    row = conn.execute(
        "SELECT filename, agent_json, ts FROM sendit_pending WHERE cmd_id=?",
        (cmd_id,),
    ).fetchone()
    if not row:
        return None
    conn.execute("DELETE FROM sendit_pending WHERE cmd_id=?", (cmd_id,))
    conn.commit()
    try:
        agent = json.loads(row[1] or "{}")
    except (TypeError, ValueError):
        agent = {"id": ""}
    return {"filename": row[0], "agent": agent, "ts": row[2]}


def sendit_load(conn) -> dict:
    """cmd_id → {filename, agent, ts} for in-memory hydrate on startup."""
    out = {}
    try:
        rows = conn.execute(
            "SELECT cmd_id, filename, agent_json, ts FROM sendit_pending"
        ).fetchall()
    except Exception:
        return out
    for cmd_id, filename, agent_json, ts in rows:
        try:
            agent = json.loads(agent_json or "{}")
        except (TypeError, ValueError):
            agent = {"id": ""}
        out[cmd_id] = {"filename": filename, "agent": agent, "ts": ts}
    return out


def sendit_purge(conn, older_than: float):
    conn.execute("DELETE FROM sendit_pending WHERE ts < ?", (older_than,))
    conn.commit()


def chunk_put(conn, agent_id, resp_id, idx, total, resp_to, msg_type, part, ts):
    conn.execute(
        "INSERT OR REPLACE INTO chunk_parts"
        "(agent_id,resp_id,idx,total,resp_to,msg_type,part,ts)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (agent_id, resp_id, idx, total, resp_to, msg_type, part, ts),
    )
    conn.commit()


def chunk_delete_group(conn, agent_id, resp_id):
    conn.execute(
        "DELETE FROM chunk_parts WHERE agent_id=? AND resp_id=?",
        (agent_id, resp_id),
    )
    conn.commit()


def chunk_purge_stale(conn, older_than: float):
    conn.execute("DELETE FROM chunk_parts WHERE ts < ?", (older_than,))
    conn.commit()


def chunk_load_all(conn, max_age: float = 1800) -> list:
    cutoff = time.time() - max_age
    try:
        chunk_purge_stale(conn, cutoff)
        rows = conn.execute(
            "SELECT agent_id,resp_id,idx,total,resp_to,msg_type,part,ts"
            " FROM chunk_parts"
        ).fetchall()
    except Exception:
        return []
    return [dict(r) for r in rows]


def pty_trim_agent(conn, agent_id: str, keep: int = 20):
    """Keep the newest `keep` recordings for one agent (called after each save)."""
    try:
        conn.execute("""
            DELETE FROM pty_sessions
            WHERE agent_id=? AND session_id NOT IN (
                SELECT session_id FROM pty_sessions
                WHERE agent_id=?
                ORDER BY started_at DESC LIMIT ?
            )
        """, (agent_id, agent_id, keep))
        conn.commit()
    except Exception:
        pass
