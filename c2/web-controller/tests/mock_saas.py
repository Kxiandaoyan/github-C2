"""
Mock SaaS server — an in-memory fake GitHub REST API for agent integration
tests (the Notion shape is not implemented; test the GitHub channel first).

Endpoints (GitHub-compatible, only what the agent uses):
  GET   /repos/{o}/{r}/issues                     → list issues (labels filter)
  POST  /repos/{o}/{r}/issues                     → create issue {number}
  GET   /repos/{o}/{r}/issues/{n}                 → 200 issue / 404
  PATCH /repos/{o}/{r}/issues/{n}                 → update body (heartbeat)
  GET   /repos/{o}/{r}/issues/{n}/comments        → list comments (?since=)
  POST  /repos/{o}/{r}/issues/{n}/comments        → create comment {id}

Test-control endpoints (NOT part of the agent contract):
  POST  /__admin/command   {issue, body}          → append a comment as "server"
  GET   /__admin/state                          → full state dump (JSON)
  POST  /__admin/reset                          → wipe state

Run:  python mock_saas.py [port]     (default 8480)
Used by run_integration_linux.sh — see header there.
"""
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.issues = {}      # number → {title, body, labels, state}
        self.comments = {}    # number → [ {id, body, created_at} ]
        self.next_number = 1
        self.next_comment_id = 1000

    def reset(self):
        with self.lock:
            self.__init__()


STATE = State()

GH_ISSUES_RE   = re.compile(r"^/repos/([^/]+)/([^/]+)/issues$")
GH_ISSUE_RE    = re.compile(r"^/repos/([^/]+)/([^/]+)/issues/(\d+)$")
GH_COMMENTS_RE = re.compile(r"^/repos/([^/]+)/([^/]+)/issues/(\d+)/comments$")


def iso_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet
        pass

    # ── helpers ────────────────────────────────────────────────────────────
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    # ── routing ────────────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0]
        query = self.path.split("?")[1] if "?" in self.path else ""

        if path == "/__admin/state":
            with STATE.lock:
                return self._json(200, {
                    "issues": {k: v for k, v in STATE.issues.items()},
                    "comments": {k: v for k, v in STATE.comments.items()},
                })

        m = GH_ISSUES_RE.match(path)
        if m:
            labels = "labels=agent" in query
            with STATE.lock:
                items = [
                    {"number": n, "title": i["title"], "body": i["body"],
                     "labels": [{"name": l} for l in i["labels"]],
                     "state": i["state"]}
                    for n, i in STATE.issues.items()
                    if not labels or "agent" in i["labels"]
                ]
            return self._json(200, items)

        m = GH_ISSUE_RE.match(path)
        if m:
            n = int(m.group(3))
            with STATE.lock:
                if n in STATE.issues:
                    i = STATE.issues[n]
                    return self._json(200, {"number": n, "state": i["state"],
                                            "body": i["body"], "title": i["title"]})
            return self._json(404, {"message": "Not Found"})

        m = GH_COMMENTS_RE.match(path)
        if m:
            n = int(m.group(3))
            since = ""
            if "since=" in query:
                since = query.split("since=")[1].split("&")[0]
            with STATE.lock:
                cs = STATE.comments.get(n, [])
                if since:
                    cs = [c for c in cs if c["created_at"] > since]
            return self._json(200, cs)

        return self._json(404, {"message": "Not Found"})

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/__admin/reset":
            STATE.reset()
            return self._json(200, {"ok": True})

        if path == "/__admin/command":
            b = self._body()
            n = int(b["issue"])
            with STATE.lock:
                cid = STATE.next_comment_id
                STATE.next_comment_id += 1
                STATE.comments.setdefault(n, []).append(
                    {"id": cid, "body": b["body"], "created_at": iso_now()})
            return self._json(200, {"id": cid})

        m = GH_ISSUES_RE.match(path)
        if m:
            b = self._body()
            with STATE.lock:
                n = STATE.next_number
                STATE.next_number += 1
                STATE.issues[n] = {
                    "title": b.get("title", ""),
                    "body": b.get("body", ""),
                    "labels": [l.get("name", "") for l in b.get("labels", [])],
                    "state": "open",
                }
            return self._json(201, {"number": n, "html_url": f"mock://{n}"})

        m = GH_COMMENTS_RE.match(path)
        if m:
            n = int(m.group(3))
            b = self._body()
            with STATE.lock:
                cid = STATE.next_comment_id
                STATE.next_comment_id += 1
                STATE.comments.setdefault(n, []).append(
                    {"id": cid, "body": b.get("body", ""), "created_at": iso_now()})
            return self._json(201, {"id": cid, "created_at": iso_now()})

        return self._json(404, {"message": "Not Found"})

    def do_PATCH(self):
        path = self.path.split("?")[0]
        m = GH_ISSUE_RE.match(path)
        if m:
            n = int(m.group(3))
            b = self._body()
            with STATE.lock:
                if n not in STATE.issues:
                    return self._json(404, {"message": "Not Found"})
                if "body" in b:
                    STATE.issues[n]["body"] = b["body"]
                if "state" in b:
                    STATE.issues[n]["state"] = b["state"]
            return self._json(200, {"ok": True})
        return self._json(404, {"message": "Not Found"})


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8480
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock-saas listening on http://127.0.0.1:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
