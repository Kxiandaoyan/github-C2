#!/usr/bin/env python3
"""
mock_notion.py — in-memory Notion REST mock for lab testing of the third channel.

Implements exactly the surface the agent + controller use:
  POST   /v1/databases/{id}/query     page listing (discovery)
  GET    /v1/pages/{id}               page fetch (archived check)
  PATCH  /v1/pages/{id}               property update / trash
  POST   /v1/pages                    create page (agent registration)
  GET    /v1/comments?block_id=       list comments (oldest-first, like Notion)
  POST   /v1/comments                 create comment (rich_text chunks)
  DELETE /v1/comments/{id}            delete comment

Auth: any Bearer token is accepted (lab). Pages carry an "Agent ID" title
property so the controller's discovery parser works unmodified.

Usage: python3 mock_notion.py [port]     (default 8481)
"""
import json
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOCK = threading.Lock()
PAGES = {}      # page_id -> {"props": {...}, "archived": bool, "created": iso}
COMMENTS = {}   # page_id -> [ {id, text, created} ]
SEQ = [0]


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _uid(prefix):
    return prefix + uuid.uuid4().hex[:12]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _props_in(self, payload):
        """Flatten Notion property format → {name: plain value}."""
        out = {}
        for name, spec in (payload.get("properties") or {}).items():
            t = spec.get("type", "")
            if t == "title":
                out[name] = "".join(x.get("plain_text", x.get("text", {}).get("content", ""))
                                    for x in spec.get("title", []))
            elif t == "rich_text":
                out[name] = "".join(x.get("plain_text", x.get("text", {}).get("content", ""))
                                    for x in spec.get("rich_text", []))
            elif t == "select":
                out[name] = (spec.get("select") or {}).get("name", "")
        return out

    def _page_obj(self, pid):
        p = PAGES[pid]
        props = {}
        for name, val in p["props"].items():
            if name == "Name" or name == "title":
                props[name] = {"id": "t", "type": "title",
                               "title": [{"plain_text": val, "text": {"content": val}}]}
            else:
                props[name] = {"id": "r", "type": "rich_text",
                               "rich_text": [{"plain_text": str(val), "text": {"content": str(val)}}]}
        return {"object": "page", "id": pid, "created_time": p["created"],
                "last_edited_time": _now(), "archived": p["archived"],
                "properties": props}

    # ── routing ─────────────────────────────────────────────────────────────
    def do_GET(self):
        u = urlparse(self.path)
        m = re.match(r"^/v1/pages/([0-9a-f-]+)$", u.path)
        if m and m.group(1) in PAGES:
            return self._send(200, self._page_obj(m.group(1)))
        if u.path == "/v1/comments":
            qs = parse_qs(u.query)
            pid = qs.get("block_id", [""])[0]
            with LOCK:
                items = COMMENTS.get(pid, [])
            results = [{
                "object": "comment", "id": c["id"], "created_time": c["created"],
                "rich_text": [{"plain_text": c["text"], "text": {"content": c["text"]}}],
            } for c in items]
            return self._send(200, {"object": "list", "results": results, "has_more": False})
        return self._send(404, {"object": "error", "message": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        body = self._body()
        m = re.match(r"^/v1/databases/([0-9a-f-]+)/query$", u.path)
        if m:
            with LOCK:
                pages = [self._page_obj(p) for p in PAGES if not PAGES[p]["archived"]]
            return self._send(200, {"object": "list", "results": pages, "has_more": False})
        if u.path == "/v1/pages":
            pid = _uid("pg-")
            props = self._props_in(body)
            props.setdefault("Name", "page")
            with LOCK:
                PAGES[pid] = {"props": props, "archived": False, "created": _now()}
                COMMENTS[pid] = []
            return self._send(200, self._page_obj(pid))
        if u.path == "/v1/comments":
            pid = (body.get("parent") or {}).get("page_id", "")
            if pid not in PAGES:
                return self._send(404, {"object": "error", "message": "page not found"})
            text = "".join(rt.get("text", {}).get("content", "")
                           for rt in body.get("rich_text", []))
            with LOCK:
                SEQ[0] += 1
                c = {"id": f"cm-{SEQ[0]:06d}", "text": text, "created": _now()}
                COMMENTS[pid].append(c)
            return self._send(200, {"object": "comment", "id": c["id"],
                                    "created_time": c["created"],
                                    "rich_text": [{"plain_text": text}]})
        return self._send(404, {"object": "error", "message": "not found"})

    def do_PATCH(self):
        u = urlparse(self.path)
        body = self._body()
        m = re.match(r"^/v1/pages/([0-9a-f-]+)$", u.path)
        if m and m.group(1) in PAGES:
            p = PAGES[m.group(1)]
            p["props"].update(self._props_in(body))
            if body.get("archived"):
                p["archived"] = True
            return self._send(200, self._page_obj(m.group(1)))
        return self._send(404, {"object": "error", "message": "not found"})

    def do_DELETE(self):
        u = urlparse(self.path)
        m = re.match(r"^/v1/comments/([0-9a-f-]+)$", u.path)
        if m:
            with LOCK:
                for pid in COMMENTS:
                    COMMENTS[pid] = [c for c in COMMENTS[pid] if c["id"] != m.group(1)]
            return self._send(200, {"object": "comment", "id": m.group(1)})
        return self._send(404, {"object": "error", "message": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8481
    print(f"mock-notion on :{port} (in-memory)", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
