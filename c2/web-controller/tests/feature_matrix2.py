"""
feature_matrix2.py — interactive shell + traffic-forwarding proxy tests.

Drives the controller HTTP/WebSocket API against a live agent:
  A. WS Shell: start cliws → send wspty to agent → open the browser-side
     WebSocket → drive a real PTY (id / echo marker) → stop.
  B. Tunnel:   start stowaway admin → agent-side `tunnel ip:port secret` →
     curl THROUGH socks5://127.0.0.1:1080 at the controller → stop.

Usage (on the lab server, from web-controller/):
    venv/bin/python tests/feature_matrix2.py <ctrl_base> <web_user> <web_password>
Optional env: C2_AGENT_USERNAME (pick a specific agent), C2_WS_PORT (default 7337).
No credentials are stored in this file.
"""
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

import websocket  # websocket-client, in requirements.txt

CTRL   = sys.argv[1].rstrip("/")
USER   = sys.argv[2]
WEBPWD = sys.argv[3]
WS_PORT = os.environ.get("C2_WS_PORT", "7337")
WANT_USER = os.environ.get("C2_AGENT_USERNAME", "")

_results = []


def check(name, ok, detail=""):
    _results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""), flush=True)


def wait_for(fn, timeout, interval=3):
    deadline = time.time() + timeout
    v = None
    while time.time() < deadline:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(interval)
    return v


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, path, data=None, timeout=30):
        body = json.dumps(data).encode() if data is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        r = urllib.request.Request(CTRL + path, data=body, headers=headers, method=method)
        try:
            resp = self.op.open(r, timeout=timeout)
            return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode() or "{}")
            except Exception:
                return e.code, {}

    def post(self, path, data=None):
        return self.req("POST", path, data)

    def get(self, path):
        return self.req("GET", path)

    def cookie_header(self):
        return "; ".join(f"{c.name}={c.value}" for c in self.jar)


def agent_rows(body):
    if isinstance(body, list):
        return body
    return (body or {}).get("agents") or []


c = Client()

# ── login ───────────────────────────────────────────────────────────────────
body = urllib.parse.urlencode({"username": USER, "password": WEBPWD}).encode()
r = urllib.request.Request(CTRL + "/login", data=body,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
resp = c.op.open(r, timeout=20)
check("login", "/login" not in resp.url)

# ── pick agent ──────────────────────────────────────────────────────────────
agents = wait_for(lambda: agent_rows(c.get("/api/agents")[1]) or None, 60)
if WANT_USER:
    agents = [a for a in agents if a.get("username") == WANT_USER]
if os.environ.get("C2_CHANNEL"):
    agents = [a for a in agents if a.get("channel") == os.environ["C2_CHANNEL"]]
# freshest first — stale rows (recycled issues) must never win
agents = sorted(agents or [], key=lambda a: a.get("last_reply_ts") or 0, reverse=True)
check("agent available", bool(agents),
      f"{len(agents)} agent(s)" + (f", filtered to username={WANT_USER!r}" if WANT_USER else ""))
if not agents:
    sys.exit(1)
A   = agents[0]
AID = A["id"]
print(f"      agent: {A.get('username')}@{A.get('hostname')} privilege={A.get('privilege')}", flush=True)

# relay address the agent-side tunnel dials back to (same host in this lab)
st, d = c.req("POST", "/api/settings",
              {"tunnel_ip": "127.0.0.1", "tunnel_port": "9998"})
check("0 tunnel relay configured", st == 200 and d.get("ok"), json.dumps(d)[:100])

# ═ A. interactive WS Shell ══════════════════════════════════════════════════
st, d = c.post("/api/wsshell/start",
               {"controller_ip": "127.0.0.1", "controller_port": WS_PORT})
check("A1 cliws backend started", st == 200 and d.get("ok"), json.dumps(d)[:120])

st, d = c.post("/api/wsshell/connect", {"agent_id": AID})
check("A2 wspty command sent", st == 200 and d.get("ok"), json.dumps(d)[:120])

MARK = f"WSMARK-{random.randint(100000, 999999)}"
ws_out = []


def ws_drive():
    """Open browser-side WS, wait for the remote PTY, run two commands."""
    url = CTRL.replace("http://", "ws://") + f"/wsshell/ws/{AID}"
    ws = websocket.WebSocket()
    ws.settimeout(3)
    ws.connect(url, header=[f"Cookie: {c.cookie_header()}"], timeout=25)
    deadline = time.time() + 60
    saw_prompt = saw_id = saw_mark = False
    sent_id = sent_mark = False
    buf = ""
    while time.time() < deadline and not (saw_id and saw_mark):
        try:
            frame = ws.recv()
            if not frame:
                continue
            text = frame.decode("utf-8", "replace") if isinstance(frame, bytes) else str(frame)
            buf += text
            ws_out.append(text)
        except websocket.WebSocketTimeoutException:
            if saw_prompt and not sent_id:
                ws.send("id\n"); sent_id = True
            elif sent_id and saw_id and not sent_mark:
                ws.send(f"echo {MARK}\n"); sent_mark = True
            elif sent_mark and saw_mark:
                break
            continue
        if ("$" in buf or "#" in buf or "login" in buf or buf.strip()):
            saw_prompt = True
        if "uid=" in buf:
            saw_id = True
        if MARK in buf and sent_mark:
            saw_mark = True
    uid_line = next((l for l in buf.splitlines() if "uid=" in l), "")
    ws.close()
    return saw_id, saw_mark, uid_line.strip()

saw_id, saw_mark, uid_line = wait_for(ws_drive, 90, interval=1) or (False, False, "")
check("A3 PTY interactive (id)", saw_id, uid_line[:80])
check("A4 PTY echo marker", saw_mark, MARK)
try:
    print("      pty tail:", "".join(ws_out)[-160:].replace("\n", "⏎"), flush=True)
except Exception:
    pass

st, d = c.post("/api/wsshell/stop", {"agent_id": AID})
check("A5 wsshell stopped", st == 200 and d.get("ok"))

# ═ B. traffic forwarding (Stowaway SOCKS5) ══════════════════════════════════
st, d = c.post("/api/tunnel/admin/start")
check("B1 stowaway admin started", st == 200 and d.get("ok"), json.dumps(d)[:120])

st, d = c.post("/api/tunnel/start", {"agent_id": AID})
check("B2 agent tunnel command sent", st == 200 and "command_id" in d, json.dumps(d)[:120])


def socks_probe():
    """curl THROUGH the agent-side SOCKS5 to the controller's own /login."""
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "12",
             "--socks5-hostname", os.environ.get("C2_SOCKS_CREDS", "c2op:x@127.0.0.1:1080"),
             CTRL + "/login"],
            capture_output=True, text=True, timeout=20)
        return r.stdout.strip() if r.stdout.strip() == "200" else None
    except Exception:
        return None


code = wait_for(socks_probe, 90, interval=5)
check("B3 SOCKS5 proxy chain works (curl → socks5 → agent → controller)", code == "200",
      f"status={code}")

# teardown: agent side then admin side
st, d = c.post("/api/tunnel/stop", {"agent_id": AID})
time.sleep(3)
st, d = c.post("/api/tunnel/admin/stop")
check("B4 tunnel stopped", st == 200 and d.get("ok"))

# ── summary ────────────────────────────────────────────────────────────────
fails = [n for n, ok in _results if not ok]
print(f"\n===== matrix2 (shell+proxy): {len(_results) - len(fails)}/{len(_results)} passed =====", flush=True)
if fails:
    print("FAILED:", ", ".join(fails), flush=True)
    sys.exit(1)
