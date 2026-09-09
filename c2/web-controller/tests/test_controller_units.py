"""
Controller unit tests — pure logic slices of app.py.

Importing app.py has side effects (creates c2_web.db, downloads/, stowaway/,
starts the background poller daemon — idle without tokens configured). Tests
use unique agent ids and clean their rows afterwards.

Run:  python -m unittest discover -s tests   (from web-controller/)
"""
import os
import sys
import tempfile
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "unit-test-secret")

import app  # noqa: E402


class TestChunkReassembly(unittest.TestCase):
    """_handle_chunk must reassemble [Part id/i/n] responses in order,
    regardless of arrival order, and dispatch exactly once when complete."""

    AID = "unittest-agent-chunk"

    def setUp(self):
        with app._lock:
            app._state["chunk_buf"].pop(self.AID, None)
            app._state["agents"] = [
                {"id": self.AID, "hostname": "unit", "repo": "t/t", "channel": "github"}
            ]

    def tearDown(self):
        conn = app._conn()
        conn.execute("DELETE FROM messages WHERE agent_id=?", (self.AID,))
        try:
            conn.execute("DELETE FROM chunk_parts WHERE agent_id=?", (self.AID,))
        except Exception:
            pass
        conn.commit()
        with app._lock:
            app._state["chunk_buf"].pop(self.AID, None)
            app._state["agents"] = []

    def _parts(self, resp_id, total, texts):
        for i, t in enumerate(texts, start=1):
            app._handle_chunk(
                self.AID,
                f"[Part {resp_id}/{i}/{total}]\n{t}",
                "cmd-x",
                "chunk",
            )

    def test_in_order(self):
        self._parts("r1", 3, ["aaa", "bbb", "ccc"])
        conn = app._conn()
        rows = conn.execute(
            "SELECT content FROM messages WHERE agent_id=? AND is_command=0",
            (self.AID,)).fetchall()
        self.assertEqual([r[0] for r in rows], ["aaabbbccc"])

    def test_out_of_order(self):
        self._parts("r2", 3, [])  # ensure buf exists
        texts = ["aaa", "bbb", "ccc"]
        for order in [2, 3, 1]:
            app._handle_chunk(
                self.AID, f"[Part r2/{order}/3]\n{texts[order - 1]}", "cmd-x", "chunk")
        conn = app._conn()
        rows = conn.execute(
            "SELECT content FROM messages WHERE agent_id=? AND is_command=0",
            (self.AID,)).fetchall()
        self.assertEqual([r[0] for r in rows], ["aaabbbccc"])

    def test_incomplete_not_dispatched(self):
        self._parts("r3", 3, ["aaa"])
        conn = app._conn()
        n = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE agent_id=? AND is_command=0",
            (self.AID,)).fetchone()[0]
        self.assertEqual(n, 0)

    def test_gap_in_parts_not_assembled(self):
        app._handle_chunk(self.AID, "[Part r4/1/3]\naaa", "cmd-x", "chunk")
        app._handle_chunk(self.AID, "[Part r4/3/3]\nccc", "cmd-x", "chunk")
        conn = app._conn()
        n = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE agent_id=? AND is_command=0",
            (self.AID,)).fetchone()[0]
        self.assertEqual(n, 0)

    def test_cmd_verb_strips_args(self):
        self.assertEqual(app._cmd_verb("whoami"), "whoami")
        self.assertEqual(app._cmd_verb("cat /etc/shadow"), "cat")
        self.assertEqual(app._cmd_verb(""), "?")

    def test_huge_total_is_rejected(self):
        ok = app._handle_chunk(
            self.AID, "[Part boom/1/999999999]\nx", "cmd-x", "chunk")
        self.assertFalse(ok)
        with app._lock:
            buf = app._state["chunk_buf"].get(self.AID, {})
            self.assertNotIn("boom", buf)


class TestSafePath(unittest.TestCase):
    def test_ok(self):
        # Use a REAL absolute temp dir: _safe_path mixes normpath/abspath,
        # which only agree when lib_dir is a fully-qualified native path
        # (drive letter on Windows) — as it always is in production.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = app._safe_path(td, "notes/1.md")
            self.assertTrue(os.path.normcase(p).startswith(os.path.normcase(td)))

    def test_traversal_rejected(self):
        for rel in ("../etc/passwd", "notes/../../x", ".."):
            with self.assertRaises(ValueError, msg=rel):
                app._safe_path("/tmp/lib", rel)


class TestIsFileCmd(unittest.TestCase):
    def test_classification(self):
        for cmd, want in [
            ("ls", True), ("ls /etc", True), ("dir C:\\", True),
            ("readfile /etc/passwd", True), ("upload /x", True),
            ("upload_chunk {...}", True),
            ("whoami", False), ("sysinfo", False), ("cat /etc/passwd", False),
        ]:
            self.assertEqual(app._is_file_cmd(cmd), want, cmd)


class TestLastReplyAnnotate(unittest.TestCase):
    AID = "unittest-agent-lastreply"

    def tearDown(self):
        conn = app._conn()
        conn.execute("DELETE FROM messages WHERE agent_id=?", (self.AID,))
        conn.commit()
        app._agent_last_reply.pop(self.AID, None)

    def test_db_fallback_when_memory_empty(self):
        conn = app._conn()
        import db as _db
        _db.msg_save(conn, self.AID, "pong", False, None, "cmd-1", "response")
        agents = [{"id": self.AID}]
        app._agent_last_reply.pop(self.AID, None)
        app._annotate_last_reply(agents, conn, now=time.time())
        self.assertIsNotNone(agents[0]["last_reply_ts"])
        self.assertIsNotNone(agents[0]["last_reply_ago"])

    def test_memory_wins_over_db(self):
        conn = app._conn()
        import db as _db
        _db.msg_save(conn, self.AID, "old", False, None, "cmd-1", "response")
        app._agent_last_reply[self.AID] = 1_700_000_000.0
        agents = [{"id": self.AID}]
        app._annotate_last_reply(agents, conn)
        self.assertEqual(agents[0]["last_reply_ts"], 1_700_000_000.0)


class TestSenditPersist(unittest.TestCase):
    CMD = "unittest-sendit-cmd"

    def tearDown(self):
        app._sendit_pending.pop(self.CMD, None)
        conn = app._conn()
        conn.execute("DELETE FROM sendit_pending WHERE cmd_id=?", (self.CMD,))
        conn.commit()

    def test_register_survives_memory_wipe(self):
        agent = {"id": "a1", "hostname": "box"}
        app._sendit_register(self.CMD, "secret.txt", agent)
        app._sendit_pending.clear()
        # hydrate like _load_config
        app._sendit_pending.update(__import__("db").sendit_load(app._conn()))
        self.assertIn(self.CMD, app._sendit_pending)
        claimed = app._sendit_claim(self.CMD)
        self.assertEqual(claimed["filename"], "secret.txt")
        self.assertEqual(claimed["agent"]["id"], "a1")
        self.assertIsNone(app._sendit_claim(self.CMD))


class TestBuildReportTunnel(unittest.TestCase):
    def test_latest_close_wins(self):
        md = app._build_report_md({
            "agent": {"hostname": "h", "id": "1", "channel": "github"},
            "messages": [
                {"is_command": 1, "content": "tunnel 1.2.3.4 9999", "timestamp": "t1"},
                {"is_command": 1, "content": "tunnel:close", "timestamp": "t2"},
            ],
            "downloaded_files": [],
            "library_dir": "/tmp",
            "generated_at": "now",
            "stowaway_socks": "1080",
            "tunnel_ip": "1.2.3.4",
            "sysinfo": None,
            "sensitive": None,
            "note": "",
            "operator_notes": [],
        })
        self.assertIn("SOCKS5 CLOSED", md)
        self.assertNotIn("pkill", md)


class TestVersionAndGuide(unittest.TestCase):
    def test_read_version_shape(self):
        v = app._read_version()
        self.assertEqual(v["name"], "github-c2")
        self.assertIn("rev", v)
        self.assertIn("always_poll", v)

    def test_mcp_guide_uses_handoff_not_persist(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("**handoff**（默认）", src)
        self.assertNotIn("**persist**（默认给 AI agent）", src)


class TestPtyTrim(unittest.TestCase):
    AID = "unittest-pty-trim"

    def tearDown(self):
        conn = app._conn()
        conn.execute("DELETE FROM pty_sessions WHERE agent_id=?", (self.AID,))
        conn.commit()

    def test_keeps_newest_n(self):
        import db as _db
        conn = app._conn()
        for i in range(25):
            conn.execute(
                "INSERT OR REPLACE INTO pty_sessions"
                "(session_id,agent_id,started_at,ended_at,content_text)"
                " VALUES(?,?,?,?,?)",
                (f"s{i}", self.AID, f"2026-01-01T00:{i:02d}:00", None, "x"),
            )
        conn.commit()
        _db.pty_trim_agent(conn, self.AID, keep=20)
        n = conn.execute(
            "SELECT COUNT(*) FROM pty_sessions WHERE agent_id=?",
            (self.AID,)).fetchone()[0]
        self.assertEqual(n, 20)


class TestD1SequenceReset(unittest.TestCase):
    def test_rebuild_when_probe_max_below_since(self):
        self.assertTrue(app._d1_sequence_reset("5000", [{"id": "1"}, {"id": "3"}]))
        self.assertFalse(app._d1_sequence_reset("5000", [{"id": "4900"}, {"id": "5000"}]))
        self.assertFalse(app._d1_sequence_reset("0", [{"id": "1"}]))
        self.assertFalse(app._d1_sequence_reset("5000", []))
        self.assertFalse(app._d1_sequence_reset("2024-01-01T00:00:00Z", [{"id": "1"}]))

    def test_probe_due_throttles(self):
        aid = "unittest-d1-probe"
        with app._lock:
            app._WORKER_EMPTY_STREAK.pop(aid, None)
        try:
            self.assertFalse(app._worker_d1_probe_due(aid, False))
            for i in range(11):
                self.assertFalse(app._worker_d1_probe_due(aid, True), i)
            self.assertTrue(app._worker_d1_probe_due(aid, True))
            self.assertFalse(app._worker_d1_probe_due(aid, False))
        finally:
            with app._lock:
                app._WORKER_EMPTY_STREAK.pop(aid, None)


class TestDualChannelMerge(unittest.TestCase):
    def test_same_machine_uuid_and_wid(self):
        gh = {"id": "42", "channel": "github", "agent_uuid": "abcdef1234567890"}
        wk = {"id": "w-abcdef12", "channel": "worker", "agent_uuid": "abcdef1234567890"}
        self.assertTrue(app._same_machine(gh, wk))
        other = {"id": "7", "channel": "github", "agent_uuid": "ffffffffffff0000"}
        self.assertFalse(app._same_machine(gh, other))

    def test_collapse_picks_newer_and_keeps_github_repo(self):
        gh = {"id": "42", "channel": "github", "agent_uuid": "aabbccdd11223344",
              "repo": "o/r", "last_reply_ts": 100, "note": "lab-box"}
        wk = {"id": "w-aabbccdd", "channel": "worker", "agent_uuid": "aabbccdd11223344",
              "repo": "", "last_reply_ts": 200}
        out = app._collapse_dual_channel_agents([gh, wk], now=300)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "w-aabbccdd")
        self.assertEqual(out[0]["repo"], "o/r")
        self.assertEqual(sorted(out[0]["sibling_ids"]), ["42", "w-aabbccdd"])
        self.assertEqual(out[0]["last_reply_ago"], 100)
        self.assertEqual(out[0]["note"], "lab-box")
        self.assertIn("github", out[0]["channels"])
        self.assertIn("worker", out[0]["channels"])

    def test_unrelated_stay_separate(self):
        a = {"id": "1", "channel": "github", "agent_uuid": "aaa"}
        b = {"id": "2", "channel": "github", "agent_uuid": "bbb"}
        out = app._collapse_dual_channel_agents([a, b], now=1)
        self.assertEqual(len(out), 2)


class TestInternalSendFailover(unittest.TestCase):
    UUID = "deadbeef00001111"

    def setUp(self):
        self._prev_agents = list(app._state.get("agents") or [])
        self._prev_pw = app._state.get("password")
        self._prev_reply = dict(app._agent_last_reply)
        app._agent_last_reply.clear()
        with app._lock:
            app._state["password"] = "unit-pw"
            app._state["agents"] = [
                {"id": "42", "channel": "github", "agent_uuid": self.UUID,
                 "repo": "o/r", "last_reply_ts": 1},
                {"id": "w-deadbeef", "channel": "worker", "agent_uuid": self.UUID,
                 "repo": "", "last_reply_ts": 9},
            ]
        self._orig_client = app._channel_client

    def tearDown(self):
        app._channel_client = self._orig_client
        app._agent_last_reply.clear()
        app._agent_last_reply.update(self._prev_reply)
        with app._lock:
            app._state["agents"] = self._prev_agents
            app._state["password"] = self._prev_pw
        conn = app._conn()
        for aid in ("42", "w-deadbeef"):
            conn.execute("DELETE FROM messages WHERE agent_id=?", (aid,))
            conn.execute("DELETE FROM command_history WHERE agent_id=?", (aid,))
        conn.commit()

    def test_prefers_fresher_channel(self):
        calls = []

        def fake_client(agent):
            class C:
                def post_comment(self, aid, body):
                    calls.append((agent.get("channel"), aid))
                    return True, ""
            return C(), ""

        app._channel_client = fake_client
        ok, cmd_id = app._internal_send("42", "whoami")
        self.assertTrue(ok, cmd_id)
        self.assertTrue(cmd_id.startswith("cmd-"))
        self.assertEqual(calls[0], ("worker", "w-deadbeef"))
        self.assertIn(("github", "42"), calls)

    def test_retries_next_channel_when_first_post_fails(self):
        calls = []

        def fake_client(agent):
            class C:
                def post_comment(self, aid, body):
                    calls.append(aid)
                    if aid == "w-deadbeef":
                        return False, "relay down"
                    return True, ""
            return C(), ""

        app._channel_client = fake_client
        ok, cmd_id = app._internal_send("42", "id")
        self.assertTrue(ok, cmd_id)
        self.assertEqual(calls, ["w-deadbeef", "42"])


class TestSettingsWorkerKeep(unittest.TestCase):
    def setUp(self):
        self._snap = {
            k: app._state.get(k)
            for k in ("worker_urls", "worker_secret", "worker_path",
                      "issue_limit", "poll_interval", "wspty_host", "wspty_port")
        }

    def tearDown(self):
        with app._lock:
            app._state.update(self._snap)
        app._save_config()

    def _post(self, payload):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        return client.post("/api/settings", json=payload)

    def test_empty_worker_fields_do_not_wipe(self):
        with app._lock:
            app._state["worker_urls"] = "https://keep.example"
            app._state["worker_secret"] = "keep-secret"
            app._state["worker_path"] = "keep-path"
        r = self._post({"worker_urls": "", "worker_secret": "", "worker_path": ""})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["worker_urls"], "https://keep.example")
        self.assertEqual(app._state["worker_secret"], "keep-secret")
        self.assertEqual(app._state["worker_path"], "keep-path")

    def test_issue_limit_zero_disables(self):
        r = self._post({"issue_limit": 0})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["issue_limit"], 0)

    def test_dash_clears_worker_field(self):
        with app._lock:
            app._state["worker_path"] = "old"
        r = self._post({"worker_path": "-"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["worker_path"], "")

    def test_empty_c2_password_does_not_wipe(self):
        with app._lock:
            app._state["password"] = "keep-c2"
        r = self._post({"password": ""})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["password"], "keep-c2")

    def test_empty_wspty_host_does_not_wipe(self):
        with app._lock:
            app._state["wspty_host"] = "10.0.0.8"
        r = self._post({"wspty_host": "", "wspty_port": ""})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["wspty_host"], "10.0.0.8")


class TestBuilderSecretKeep(unittest.TestCase):
    def setUp(self):
        conn = app._conn()
        self._prev_pw = __import__("db").cfg_get(conn, "builder_password")
        __import__("db").cfg_set(conn, "builder_password", "keep-bld")

    def tearDown(self):
        conn = app._conn()
        if self._prev_pw is None:
            conn.execute("DELETE FROM config WHERE key=?", ("builder_password",))
            conn.commit()
        else:
            __import__("db").cfg_set(conn, "builder_password", self._prev_pw)

    def _client(self):
        c = app.app.test_client()
        with c.session_transaction() as sess:
            sess["logged_in"] = True
        return c

    def test_empty_builder_password_keeps(self):
        r = self._client().post("/api/builder/config", json={"builder_password": ""})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(__import__("db").cfg_get(app._conn(), "builder_password"), "keep-bld")

    def test_get_masks_builder_secrets(self):
        r = self._client().get("/api/builder/config")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d.get("builder_password_set"))
        self.assertEqual(d.get("builder_password"), "")
        self.assertEqual(d.get("builder_token"), "")
        self.assertIn("builder_token_set", d)
        self.assertIn("builder_github_token_set", d)

    def test_empty_builder_repo_keeps(self):
        conn = app._conn()
        dbm = __import__("db")
        prev = dbm.cfg_get(conn, "builder_github_repo")
        dbm.cfg_set(conn, "builder_github_repo", "keep/repo")
        try:
            r = self._client().post("/api/builder/config", json={"builder_github_repo": ""})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(dbm.cfg_get(app._conn(), "builder_github_repo"), "keep/repo")
        finally:
            if prev is None:
                conn.execute("DELETE FROM config WHERE key=?", ("builder_github_repo",))
                conn.commit()
            else:
                dbm.cfg_set(conn, "builder_github_repo", prev)


class TestSettingsGetMasks(unittest.TestCase):
    def test_get_omits_plaintext_secrets(self):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        r = client.get("/api/settings")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertNotIn("password", d)
        self.assertNotIn("worker_secret", d)
        self.assertNotIn("tunnel_secret", d)
        self.assertNotIn("github_token", d)
        self.assertNotIn("notion_token", d)
        self.assertIn("password_set", d)
        self.assertIn("worker_secret_set", d)
        self.assertIn("tunnel_secret_set", d)
        self.assertIn("github_token_set", d)
        self.assertIn("github_token_hints", d)
        self.assertIn("notion_token_set", d)
        self.assertIn("worker_discovery_blocked", d)


class TestStatsThresholds(unittest.TestCase):
    def test_online_idle_match_sidebar(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("if ago < 300:", src)
        self.assertIn("elif ago < 1800:", src)


class TestSiblingNoteFilesSysinfo(unittest.TestCase):
    GH, WK = "unit-sib-42", "w-unitsib0"
    UUID = "unitsib00001111"

    def setUp(self):
        self._prev = list(app._state.get("agents") or [])
        with app._lock:
            app._state["agents"] = [
                {"id": self.GH, "channel": "github", "agent_uuid": self.UUID,
                 "repo": "o/r", "hostname": "box"},
                {"id": self.WK, "channel": "worker", "agent_uuid": self.UUID,
                 "repo": "", "hostname": "box"},
            ]
        conn = app._conn()
        import db as _db
        _db.note_set(conn, self.GH, "old-gh-note")
        _db.fl_save(conn, self.GH, "/", "etc", True, 0)
        _db.si_save(conn, self.GH, "from-gh")
        _db.si_save(conn, self.WK, "from-wk")

    def tearDown(self):
        conn = app._conn()
        for aid in (self.GH, self.WK):
            conn.execute("DELETE FROM agent_notes WHERE agent_id=?", (aid,))
            conn.execute("DELETE FROM file_list WHERE agent_id=?", (aid,))
            conn.execute("DELETE FROM agent_sysinfo WHERE agent_id=?", (aid,))
        conn.commit()
        with app._lock:
            app._state["agents"] = self._prev

    def test_note_get_from_sibling(self):
        conn = app._conn()
        self.assertEqual(app._note_get_any(conn, self.WK), "old-gh-note")

    def test_note_set_all_siblings(self):
        conn = app._conn()
        app._note_set_all(conn, self.WK, "synced")
        import db as _db
        self.assertEqual(_db.note_get(conn, self.GH), "synced")
        self.assertEqual(_db.note_get(conn, self.WK), "synced")

    def test_files_union(self):
        conn = app._conn()
        names = [e["name"] for e in app._fl_get_any(conn, self.WK, "/")]
        self.assertIn("etc", names)

    def test_sysinfo_picks_newer_sibling(self):
        conn = app._conn()
        latest = app._si_latest_any(conn, self.GH)
        self.assertEqual(latest["content"], "from-wk")


class TestSettingsTokenKeep(unittest.TestCase):
    def setUp(self):
        self._prev = app._state.get("github_token")
        self._prev_n = app._state.get("notion_token")

    def tearDown(self):
        with app._lock:
            app._state["github_token"] = self._prev
            app._state["notion_token"] = self._prev_n
        app._save_config()

    def _post(self, payload):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        return client.post("/api/settings", json=payload)

    def test_empty_github_token_does_not_wipe(self):
        with app._lock:
            app._state["github_token"] = "ghp_keepmeXXXX"
        r = self._post({"poll_interval": 30})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["github_token"], "ghp_keepmeXXXX")

    def test_keep_hints_and_add(self):
        with app._lock:
            app._state["github_token"] = "ghp_aaaaAAA1,ghp_bbbbBBB2"
        r = self._post({
            "github_token_keep_hints": ["AAA1"],
            "github_token_add": ["ghp_ccccCCC3"],
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["github_token"], "ghp_aaaaAAA1,ghp_ccccCCC3")

    def test_apply_token_keep_add_helper(self):
        out = app._apply_token_keep_add(
            "tokAAAA,tokBBBB", ["BBBB"], ["tokCCCC"])
        self.assertEqual(out, "tokBBBB,tokCCCC")

    def test_keep_indices_avoids_hint_collision(self):
        with app._lock:
            app._state["github_token"] = "ghp_aaaaXXXX,ghp_bbbbXXXX"
        r = self._post({
            "github_token_keep_indices": [1],
            "github_token_add": ["ghp_ccccYYYY"],
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["github_token"], "ghp_bbbbXXXX,ghp_ccccYYYY")


class TestChunkPersistAndAgentRow(unittest.TestCase):
    AID = "unittest-chunk-persist"
    GH, WK = "unit-row-gh", "w-unitrow0"
    UUID = "unitrow00001111"

    def tearDown(self):
        conn = app._conn()
        conn.execute("DELETE FROM messages WHERE agent_id=?", (self.AID,))
        try:
            conn.execute("DELETE FROM chunk_parts WHERE agent_id=?", (self.AID,))
        except Exception:
            pass
        conn.commit()
        with app._lock:
            app._state["chunk_buf"].pop(self.AID, None)

    def test_chunk_survives_memory_wipe(self):
        with app._lock:
            app._state["agents"] = [
                {"id": self.AID, "hostname": "unit", "repo": "t/t", "channel": "github"}
            ]
        self.assertTrue(app._handle_chunk(
            self.AID, "[Part persist/1/2]\naaa", "cmd-x", "chunk"))
        with app._lock:
            app._state["chunk_buf"].pop(self.AID, None)
        app._hydrate_chunk_buf()
        self.assertTrue(app._handle_chunk(
            self.AID, "[Part persist/2/2]\nbbb", "cmd-x", "chunk"))
        conn = app._conn()
        rows = conn.execute(
            "SELECT content FROM messages WHERE agent_id=? AND is_command=0",
            (self.AID,)).fetchall()
        self.assertEqual([r[0] for r in rows], ["aaabbb"])

    def test_agent_row_finds_sibling(self):
        prev = list(app._state.get("agents") or [])
        with app._lock:
            app._state["agents"] = [
                {"id": self.GH, "channel": "github", "agent_uuid": self.UUID,
                 "repo": "o/r", "hostname": "box"},
                {"id": self.WK, "channel": "worker", "agent_uuid": self.UUID,
                 "repo": "", "hostname": "box"},
            ]
        try:
            row = app._agent_row(self.WK)
            self.assertIsNotNone(row)
            self.assertEqual(row["id"], self.WK)
            self.assertIsNone(app._agent_row("no-such-agent"))
        finally:
            with app._lock:
                app._state["agents"] = prev


class TestMcpGetOutputSignature(unittest.TestCase):
    def test_wrapper_uses_keyword_tail(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "mcp_server.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("tail=tail", src)
        self.assertIn("wait_seconds=wait_seconds", src)
        self.assertIn("command_id=command_id", src)
        self.assertNotIn("_get_output(agent_id, tail, wait_seconds)", src)
        self.assertIn('"dest_path": dest_dir', src)


class TestTunnelAdminMasksSecret(unittest.TestCase):
    def test_get_omits_full_secret(self):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        r = client.get("/api/tunnel/admin/config")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertNotIn("secret", d)
        self.assertIn("secret_set", d)
        self.assertIn("socks_user", d)


class TestScanUrlKeep(unittest.TestCase):
    def setUp(self):
        self._prev = app._state.get("scan_url")

    def tearDown(self):
        with app._lock:
            app._state["scan_url"] = self._prev
        app._save_config()

    def _post(self, payload):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        return client.post("/api/scan/config", json=payload)

    def test_empty_scan_url_does_not_wipe(self):
        with app._lock:
            app._state["scan_url"] = "https://keep.example/fscan"
        r = self._post({"scan_url": ""})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["scan_url"], "https://keep.example/fscan")

    def test_dash_clears_scan_url(self):
        with app._lock:
            app._state["scan_url"] = "https://old.example/fscan"
        r = self._post({"scan_url": "-"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(app._state["scan_url"], "")


class TestChunkParseFailAndStowawayArgs(unittest.TestCase):
    def test_chunk_parse_fail_does_not_claim_success(self):
        self.assertFalse(app._handle_chunk("aid", "[Part broken", "cmd", "chunk"))

    def test_stowaway_args_match(self):
        path = app.STOWAWAY_ARGS
        prev = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                prev = fh.read()
        try:
            app._stowaway_write_args("9998", "1080", "sec")
            self.assertTrue(app._stowaway_args_match("9998", "1080", "sec"))
            self.assertFalse(app._stowaway_args_match("8888", "1080", "sec"))
        finally:
            if prev is None:
                try:
                    os.remove(path)
                except OSError:
                    pass
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(prev)


class TestUploadDestAlias(unittest.TestCase):
    def test_accepts_dest_dir_alias(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('request.form.get("dest_dir")', src)


class TestKillswitchMentionsNotion(unittest.TestCase):
    def test_error_lists_notion_when_no_channel(self):
        snap = {k: app._state.get(k) for k in
                ("github_token", "github_repos", "worker_urls",
                 "worker_secret", "notion_token")}
        with app._lock:
            app._state["github_token"] = ""
            app._state["github_repos"] = []
            app._state["worker_urls"] = ""
            app._state["worker_secret"] = ""
            app._state["notion_token"] = ""
        try:
            client = app.app.test_client()
            with client.session_transaction() as sess:
                sess["logged_in"] = True
            r = client.post("/api/killswitch/activate")
            self.assertEqual(r.status_code, 400)
            self.assertIn("Notion", r.get_json().get("error", ""))
        finally:
            with app._lock:
                app._state.update(snap)


class TestBuilderFourChannelsAndSecret(unittest.TestCase):
    def setUp(self):
        self.conn = app._conn()
        self.dbm = __import__("db")
        self._keys = (
            "password", "builder_channel", "builder_password",
            "builder_worker_urls", "builder_worker_secret", "builder_worker_path",
            "builder_dual_migrated",
            "builder_github_token", "builder_github_repo",
            "builder_notion_token", "builder_notion_repo",
            "builder_token", "builder_repo",
        )
        self._prev = {k: self.dbm.cfg_get(self.conn, k) for k in self._keys}
        self._prev_pw = app._state.get("password")

    def tearDown(self):
        for k, v in self._prev.items():
            if v is None:
                self.conn.execute("DELETE FROM config WHERE key=?", (k,))
            else:
                self.dbm.cfg_set(self.conn, k, v)
        self.conn.commit()
        with app._lock:
            app._state["password"] = self._prev_pw

    def _client(self):
        c = app.app.test_client()
        with c.session_transaction() as sess:
            sess["logged_in"] = True
        return c

    def test_settings_password_counts_as_builder_secret(self):
        self.conn.execute("DELETE FROM config WHERE key=?", ("builder_password",))
        self.conn.commit()
        with app._lock:
            app._state["password"] = "deploy-secret"
        r = self._client().get("/api/builder/config")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get("builder_password_set"))
        self.assertEqual(r.get_json().get("builder_password"), "")

    def test_github_plus_worker_migrates_once_to_dual(self):
        self.conn.execute("DELETE FROM config WHERE key=?", ("builder_dual_migrated",))
        self.conn.commit()
        self.dbm.cfg_set(self.conn, "builder_channel", "github")
        self.dbm.cfg_set(self.conn, "builder_worker_urls", "https://w.example")
        self.dbm.cfg_set(self.conn, "builder_worker_secret", "ws")
        self.dbm.cfg_set(self.conn, "builder_worker_path", "p")
        app._migrate_builder_dual(self.conn)
        self.assertEqual(self.dbm.cfg_get(self.conn, "builder_channel"), "dual")
        self.dbm.cfg_set(self.conn, "builder_channel", "github")
        app._migrate_builder_dual(self.conn)
        self.assertEqual(self.dbm.cfg_get(self.conn, "builder_channel"), "github")

    def test_settings_password_syncs_builder(self):
        r = self._client().post("/api/settings", json={"password": "synced-secret"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.dbm.cfg_get(self.conn, "builder_password"), "synced-secret")

    def test_resolve_falls_back_to_settings_password(self):
        self.conn.execute("DELETE FROM config WHERE key=?", ("builder_password",))
        self.conn.commit()
        self.dbm.cfg_set(self.conn, "builder_channel", "github")
        with app._lock:
            app._state["password"] = "from-settings"
        fields, err = app._resolve_builder_embed(self.conn)
        self.assertIsNone(err)
        self.assertEqual(fields["password"], "from-settings")
        self.assertEqual(fields["embed_channel"], "github")
        self.assertEqual(fields["w_urls"], "")

    def test_github_single_strips_leftover_worker(self):
        self.dbm.cfg_set(self.conn, "builder_channel", "github")
        self.dbm.cfg_set(self.conn, "builder_password", "pw")
        self.dbm.cfg_set(self.conn, "builder_worker_urls", "https://w.example")
        self.dbm.cfg_set(self.conn, "builder_worker_secret", "ws")
        self.dbm.cfg_set(self.conn, "builder_worker_path", "p")
        fields, err = app._resolve_builder_embed(self.conn)
        self.assertIsNone(err)
        self.assertEqual(fields["embed_channel"], "github")
        self.assertEqual(fields["w_urls"], "")
        self.assertEqual(fields["w_secret"], "")
        self.assertEqual(fields["w_path"], "")

    def test_dual_requires_worker_triple(self):
        self.dbm.cfg_set(self.conn, "builder_channel", "dual")
        self.dbm.cfg_set(self.conn, "builder_password", "pw")
        self.conn.execute("DELETE FROM config WHERE key=?", ("builder_worker_urls",))
        self.conn.commit()
        fields, err = app._resolve_builder_embed(self.conn)
        self.assertIsNone(fields)
        self.assertEqual(err[1], 400)
        self.assertIn("双通道", err[0])

    def test_dual_embeds_as_worker_with_github_backup(self):
        # 方向调整：双通道 = Worker 主 + GitHub 备（embed channel_type=worker，
        # GitHub token/repo 作为备用凭据一并编入）。
        self.dbm.cfg_set(self.conn, "builder_channel", "dual")
        self.dbm.cfg_set(self.conn, "builder_password", "pw")
        self.dbm.cfg_set(self.conn, "builder_worker_urls", "https://w.example")
        self.dbm.cfg_set(self.conn, "builder_worker_secret", "ws")
        self.dbm.cfg_set(self.conn, "builder_worker_path", "sec")
        self.dbm.cfg_set(self.conn, "builder_github_token", "ghp_backup")
        self.dbm.cfg_set(self.conn, "builder_github_repo", "own/bak")
        fields, err = app._resolve_builder_embed(self.conn)
        self.assertIsNone(err)
        self.assertEqual(fields["embed_channel"], "worker")
        self.assertEqual(fields["w_urls"], "https://w.example")
        self.assertEqual(fields["w_path"], "sec")
        self.assertEqual(fields["token"], "ghp_backup")
        self.assertEqual(fields["repo"], "own/bak")

    def test_dual_requires_github_backup_creds(self):
        # 双通道缺 GitHub 备用凭据 → 明确报错（不能静默降级成纯 worker）
        self.dbm.cfg_set(self.conn, "builder_channel", "dual")
        self.dbm.cfg_set(self.conn, "builder_password", "pw")
        self.dbm.cfg_set(self.conn, "builder_worker_urls", "https://w.example")
        self.dbm.cfg_set(self.conn, "builder_worker_secret", "ws")
        self.dbm.cfg_set(self.conn, "builder_worker_path", "sec")
        self.conn.execute(
            "DELETE FROM config WHERE key IN ('builder_github_token','builder_github_repo','builder_token','builder_repo')")
        self.conn.commit()
        prev_tok = app._state.get("github_token")
        prev_repos = list(app._state.get("github_repos") or [])
        try:
            with app._lock:
                app._state["github_token"] = ""
                app._state["github_repos"] = []
            fields, err = app._resolve_builder_embed(self.conn)
            self.assertIsNone(fields)
            self.assertIn("GitHub", err[0])
        finally:
            with app._lock:
                app._state["github_token"] = prev_tok
                app._state["github_repos"] = prev_repos

    def test_missing_secret_errors(self):
        self.conn.execute("DELETE FROM config WHERE key=?", ("builder_password",))
        self.conn.commit()
        self.dbm.cfg_set(self.conn, "builder_channel", "github")
        with app._lock:
            app._state["password"] = ""
        fields, err = app._resolve_builder_embed(self.conn)
        self.assertIsNone(fields)
        self.assertIn("通信加密", err[0])

    def test_seed_from_env_when_empty(self):
        self.conn.execute("DELETE FROM config WHERE key IN ('password','builder_password')")
        self.conn.commit()
        with app._lock:
            app._state["password"] = ""
        old = os.environ.get("C2_PASSWORD")
        os.environ["C2_PASSWORD"] = "env-seeded"
        try:
            app._maybe_seed_c2_password(self.conn)
            self.assertEqual(app._state.get("password"), "env-seeded")
            self.assertEqual(self.dbm.cfg_get(self.conn, "password"), "env-seeded")
            self.assertEqual(self.dbm.cfg_get(self.conn, "builder_password"), "env-seeded")
        finally:
            if old is None:
                os.environ.pop("C2_PASSWORD", None)
            else:
                os.environ["C2_PASSWORD"] = old

    def test_seed_does_not_overwrite_existing(self):
        self.dbm.cfg_set(self.conn, "password", "keep-db")
        self.dbm.cfg_set(self.conn, "builder_password", "keep-bld")
        with app._lock:
            app._state["password"] = "keep-db"
        old = os.environ.get("C2_PASSWORD")
        os.environ["C2_PASSWORD"] = "should-not-win"
        try:
            app._maybe_seed_c2_password(self.conn)
            self.assertEqual(app._state.get("password"), "keep-db")
            self.assertEqual(self.dbm.cfg_get(self.conn, "builder_password"), "keep-bld")
        finally:
            if old is None:
                os.environ.pop("C2_PASSWORD", None)
            else:
                os.environ["C2_PASSWORD"] = old


    def test_github_build_uses_github_token_not_notion(self):
        self.dbm.cfg_set(self.conn, "builder_channel", "github")
        self.dbm.cfg_set(self.conn, "builder_password", "pw")
        self.dbm.cfg_set(self.conn, "builder_token", "ntn_leftover")
        self.dbm.cfg_set(self.conn, "builder_repo", "notion-db")
        self.dbm.cfg_set(self.conn, "builder_github_token", "ghp_real")
        self.dbm.cfg_set(self.conn, "builder_github_repo", "o/r")
        self.dbm.cfg_set(self.conn, "builder_notion_token", "ntn_real")
        fields, err = app._resolve_builder_embed(self.conn)
        self.assertIsNone(err)
        self.assertEqual(fields["token"], "ghp_real")
        self.assertEqual(fields["repo"], "o/r")

    def test_dual_falls_back_to_settings_github(self):
        self.dbm.cfg_set(self.conn, "builder_channel", "dual")
        self.dbm.cfg_set(self.conn, "builder_password", "pw")
        self.dbm.cfg_set(self.conn, "builder_worker_urls", "https://w.example")
        self.dbm.cfg_set(self.conn, "builder_worker_secret", "ws")
        self.dbm.cfg_set(self.conn, "builder_worker_path", "sec")
        self.conn.execute("DELETE FROM config WHERE key IN ('builder_github_token','builder_github_repo')")
        self.conn.commit()
        prev_tok = app._state.get("github_token")
        prev_repos = list(app._state.get("github_repos") or [])
        try:
            with app._lock:
                app._state["github_token"] = "ghp_settings"
                app._state["github_repos"] = ["set/tings"]
            fields, err = app._resolve_builder_embed(self.conn)
            self.assertIsNone(err)
            self.assertEqual(fields["token"], "ghp_settings")
            self.assertEqual(fields["repo"], "set/tings")
        finally:
            with app._lock:
                app._state["github_token"] = prev_tok
                app._state["github_repos"] = prev_repos

    def test_pick_token_falls_back_to_builder(self):
        prev = app._state.get("github_token")
        try:
            with app._lock:
                app._state["github_token"] = ""
            self.dbm.cfg_set(self.conn, "builder_github_token", "ghp_from_builder")
            self.assertEqual(app._pick_token(), "ghp_from_builder")
        finally:
            with app._lock:
                app._state["github_token"] = prev

    def test_effective_repos_include_builder_backup(self):
        prev = list(app._state.get("github_repos") or [])
        try:
            with app._lock:
                app._state["github_repos"] = ["keep/me"]
            self.dbm.cfg_set(self.conn, "builder_github_repo", "own/bak")
            repos = app._github_repos_effective(self.conn)
            self.assertIn("keep/me", repos)
            self.assertIn("own/bak", repos)
        finally:
            with app._lock:
                app._state["github_repos"] = prev

    def test_merge_worker_urls_keeps_custom_domain(self):
        self.assertEqual(
            app._merge_worker_urls("https://old.workers.dev,https://cdn.example",
                                   "https://new.workers.dev"),
            "https://new.workers.dev,https://old.workers.dev,https://cdn.example")

    def test_sync_builder_repo_into_settings(self):
        prev = list(app._state.get("github_repos") or [])
        try:
            with app._lock:
                app._state["github_repos"] = []
            self.dbm.cfg_set(self.conn, "builder_channel", "dual")
            self.dbm.cfg_set(self.conn, "builder_github_repo", "lab/c2")
            self.assertTrue(app._sync_builder_github_into_settings(self.conn))
            self.assertIn("lab/c2", app._state["github_repos"])
            self.assertFalse(app._sync_builder_github_into_settings(self.conn))
        finally:
            with app._lock:
                app._state["github_repos"] = prev
            app._save_config()


class TestRound8Stability(unittest.TestCase):
    def _client(self):
        c = app.app.test_client()
        with c.session_transaction() as sess:
            sess["logged_in"] = True
        return c

    def test_agents_get_is_object_with_warnings(self):
        r = self._client().get("/api/agents")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIsInstance(d, dict)
        self.assertIn("agents", d)
        self.assertIn("warnings", d)
        self.assertIsInstance(d["agents"], list)

    def test_promote_github_to_dual(self):
        conn = app._conn()
        dbm = __import__("db")
        prev = dbm.cfg_get(conn, "builder_channel")
        prev_flag = dbm.cfg_get(conn, "builder_dual_promoted")
        try:
            conn.execute("DELETE FROM config WHERE key=?", ("builder_dual_promoted",))
            conn.commit()
            dbm.cfg_set(conn, "builder_channel", "github")
            self.assertTrue(app._promote_builder_to_dual(conn))
            self.assertEqual(dbm.cfg_get(conn, "builder_channel"), "dual")
            dbm.cfg_set(conn, "builder_channel", "github")
            self.assertFalse(app._promote_builder_to_dual(conn))
            self.assertEqual(dbm.cfg_get(conn, "builder_channel"), "github")
            dbm.cfg_set(conn, "builder_channel", "notion")
            self.assertFalse(app._promote_builder_to_dual(conn))
            self.assertEqual(dbm.cfg_get(conn, "builder_channel"), "notion")
        finally:
            if prev is None:
                conn.execute("DELETE FROM config WHERE key=?", ("builder_channel",))
            else:
                dbm.cfg_set(conn, "builder_channel", prev)
            if prev_flag is None:
                conn.execute("DELETE FROM config WHERE key=?", ("builder_dual_promoted",))
            else:
                dbm.cfg_set(conn, "builder_dual_promoted", prev_flag)
            conn.commit()

    def test_worker_channel_preserves_github_backup_creds(self):
        # unused 占位只针对 UI 的 worker 单通道；dual 的 embed_channel 也是
        # worker，但不能在编包时把 GitHub 备用凭据盖成 unused。
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('token = token.strip() or "unused"', src)
        self.assertIn('if (resolved.get("ui_channel") or "") == "worker":', src)
        self.assertNotIn('token, repo = "unused", "unused"', src)

    def test_embedded_placeholder_has_empty_secrets(self):
        ph = app._EMBEDDED_CONFIG_PLACEHOLDER
        self.assertIn('pub fn encryption_password() -> String { obfstr::obfstr!("").to_string() }', ph)
        self.assertIn('pub fn github_token() -> String { obfstr::obfstr!("").to_string() }', ph)
        self.assertIn('pub fn worker_secret() -> String { obfstr::obfstr!("").to_string() }', ph)

    def test_command_echo_decrypt_fail_not_marked_in_source(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("command-echo decrypt failed", src)


class TestRound10Stability(unittest.TestCase):
    def test_cursor_all_and_hydrate_helper(self):
        self.assertTrue(callable(__import__("db").cursor_all))

    def test_web_password_env_does_not_clobber_db(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('if env_web and not (db_web or "").strip():', src)
        self.assertIn("_sync_runtime_env_key", src)

    def test_download_route_on_named_handler(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("def api_builder_download():", src)
        self.assertIn('"/api/builder/download"', src)

    def test_mcp_sysinfo_waits_for_command_id(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "mcp_server.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('command_id=d.get("command_id")', src)

    def test_notion_cancel_marker(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("<!-- k -->CANCEL", src)


    def test_prefer_newer_issue_keeps_max(self):
        keep = {}
        app._prefer_newer_issue(keep, "u", "10")
        app._prefer_newer_issue(keep, "u", "3")
        app._prefer_newer_issue(keep, "u", "42")
        self.assertEqual(keep["u"], "42")

    def test_incomplete_chunk_returns_pending(self):
        aid = "unittest-agent-chunk-pend"
        with app._lock:
            app._state["chunk_buf"].pop(aid, None)
        st = app._handle_chunk(aid, "[Part rpend/1/3]\naaa", "cmd-x", "chunk")
        self.assertEqual(st, "pending")
        conn = app._conn()
        try:
            conn.execute("DELETE FROM chunk_parts WHERE agent_id=?", (aid,))
            conn.commit()
        except Exception:
            pass
        with app._lock:
            app._state["chunk_buf"].pop(aid, None)

    def test_kill_sweep_runs_when_idle(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("last_killsweep", src)
        self.assertIn("check_github_kill", open(
            os.path.join(os.path.dirname(path), "agent", "src", "main.rs"),
            encoding="utf-8").read())

    def test_stowaway_status_does_not_leak_secret(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        fn = src[src.find("def api_stowaway_status"):src.find("def api_stowaway_status") + 1800]
        self.assertIn("secret_set", fn)
        self.assertNotIn('"secret":       secret', fn)


class TestRound12Ops(unittest.TestCase):
    def test_wsshell_bound_rejects_other_agent(self):
        with app._cliws_lock:
            prev = dict(app._cliws_session)
            app._cliws_session.clear()
            app._cliws_session.update({
                "bound_agent_id": "42",
                "bound_sibling_ids": ["42", "w-aabbccdd"],
            })
        try:
            self.assertTrue(app._wsshell_agent_allowed("42"))
            self.assertTrue(app._wsshell_agent_allowed("w-aabbccdd"))
            self.assertFalse(app._wsshell_agent_allowed("99"))
        finally:
            with app._cliws_lock:
                app._cliws_session.clear()
                app._cliws_session.update(prev)

    def test_wsshell_unbound_allows(self):
        with app._cliws_lock:
            prev = dict(app._cliws_session)
            app._cliws_session.clear()
        try:
            self.assertTrue(app._wsshell_agent_allowed("42"))
        finally:
            with app._cliws_lock:
                app._cliws_session.clear()
                app._cliws_session.update(prev)

    def test_web_username_synced_to_runtime_env(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('_sync_runtime_env_key("WEB_USERNAME"', src)

    def test_stowaway_match_includes_socks_auth(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("socks_user", src[src.find("def _stowaway_args_match"):
                                        src.find("def _stowaway_args_match") + 600])

    def test_worker_purge_network_fail_not_supported(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "worker_api.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("return 0, False", src)
        self.assertNotIn("treat as attempted", src)


class TestConsoleBackup(unittest.TestCase):
    def test_unauthenticated_is_401(self):
        client = app.app.test_client()
        r = client.get("/api/backup")
        self.assertEqual(r.status_code, 401)

    def test_zip_contains_db_and_readme(self):
        fd, zpath = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            info = app.build_console_backup(zpath)
            self.assertIn("c2_web.db", info["files"])
            self.assertIn("README.txt", info["files"])
            with zipfile.ZipFile(zpath) as zf:
                names = zf.namelist()
                self.assertIn("c2_web.db", names)
                self.assertIn("README.txt", names)
                text = zf.read("README.txt").decode("utf-8")
                self.assertIn("SECRETS", text)
        finally:
            try:
                os.remove(zpath)
            except OSError:
                pass

    def test_authenticated_download(self):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        r = client.get("/api/backup")
        self.assertEqual(r.status_code, 200)
        self.assertIn("zip", (r.mimetype or "").lower())
        self.assertGreater(len(r.data), 32)
        self.assertIn("attachment", r.headers.get("Content-Disposition", "").lower())


class TestWsShellOneShot(unittest.TestCase):
    """cliws `-b` is one-shot: leftover wspty must be closed before the next pair."""

    def test_connect_recycles_bridge_then_sends_close_and_wspty(self):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        with app._cliws_lock:
            prev = dict(app._cliws_session)
            app._cliws_session.clear()
            app._cliws_session.update({
                "port": 7337,
                "ctrl_ip": "1.2.3.4",
                "bound_agent_id": "42",
                "bound_sibling_ids": ["42"],
            })
        orig_start = app._cliws_start
        orig_send = app._internal_send
        sent = []
        started = []
        try:
            def fake_start(ctrl_ip, port):
                started.append((ctrl_ip, port))
                app._cliws_session.update({
                    "port": port,
                    "ctrl_ip": ctrl_ip,
                    "bound_agent_id": None,
                    "bound_sibling_ids": [],
                })
                return True, {"ok": True, "port": port, "tmux_session": "c2-cliws-7337"}

            def fake_send(aid, cmd):
                sent.append((str(aid), cmd))
                return True, "cmd-x"

            app._cliws_start = fake_start
            app._internal_send = fake_send
            r = client.post("/api/wsshell/connect", json={
                "agent_id": "42",
                "controller_ip": "1.2.3.4",
                "controller_port": "7337",
            })
            self.assertEqual(r.status_code, 200)
            self.assertEqual(started, [("1.2.3.4", 7337)])
            self.assertGreaterEqual(len(sent), 2)
            self.assertEqual(sent[0], ("42", "wspty:close"))
            self.assertTrue(sent[-1][1].startswith("wspty ws://1.2.3.4:7337/"))
            body = r.get_json()
            self.assertTrue(body.get("recycled"))
        finally:
            app._cliws_start = orig_start
            app._internal_send = orig_send
            with app._cliws_lock:
                app._cliws_session.clear()
                app._cliws_session.update(prev)

    def test_proxy_end_always_sends_close(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        fn = src[src.find("def wsshell_ws_proxy"):src.find("def api_wspty_sessions")]
        self.assertIn('_internal_send(agent_id, "wspty:close")', fn)
        self.assertNotIn("browser closed but cliws still running", fn)

    def test_frontend_does_not_auto_open_on_stale_bound(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "static", "js", "app.js")
        with open(path, encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("expectOpen", js)
        self.assertIn("WSSHELL.expectOpen && !WSSHELL.connected", js)
        self.assertIn("已重建桥接并下发反弹", js)

    def test_ui_documents_oneshot_flow(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "templates", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("wsshell.oneshot_hint", html)

    def test_connect_rolls_back_cliws_if_wspty_send_fails(self):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["logged_in"] = True
        orig_start = app._cliws_start
        orig_send = app._internal_send
        orig_stop = app._cliws_stop
        stopped = []
        try:
            app._cliws_start = lambda ip, port: (True, {"ok": True, "port": port})

            def fake_send(aid, cmd):
                if str(cmd).startswith("wspty "):
                    return False, "channel down"
                return True, "cmd-x"

            app._internal_send = fake_send
            app._cliws_stop = lambda: stopped.append(True)
            r = client.post("/api/wsshell/connect", json={
                "agent_id": "42",
                "controller_ip": "1.2.3.4",
                "controller_port": "7337",
            })
            self.assertEqual(r.status_code, 500)
            self.assertTrue(stopped)
        finally:
            app._cliws_start = orig_start
            app._internal_send = orig_send
            app._cliws_stop = orig_stop

    def test_frontend_hydrates_ip_and_checks_sendraw(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "static", "js", "app.js")
        with open(path, encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("_wsshellHydrateConfig", js)
        self.assertIn("if (!r.ok || d.error)", js)

    def test_agent_does_not_reconnect_after_live_bridge(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "agent", "src", "ws_pty.rs")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("waiting for a new wspty command", src)
        self.assertNotIn("disconnected, will retry", src)


class TestDecryptWatermark(unittest.TestCase):
    AID = "unittest-wm-hold"

    def setUp(self):
        conn = app._conn()
        conn.execute("DELETE FROM processed_comments WHERE agent_id=?", (self.AID,))
        conn.execute("DELETE FROM last_comment_times WHERE agent_id=?", (self.AID,))
        conn.execute("DELETE FROM messages WHERE agent_id=?", (self.AID,))
        conn.commit()
        with app._lock:
            app._state["last_times"][self.AID] = "5"
            app._state.setdefault("decrypt_fails", {}).pop(self.AID, None)

    def tearDown(self):
        conn = app._conn()
        conn.execute("DELETE FROM processed_comments WHERE agent_id=?", (self.AID,))
        conn.execute("DELETE FROM last_comment_times WHERE agent_id=?", (self.AID,))
        conn.execute("DELETE FROM messages WHERE agent_id=?", (self.AID,))
        conn.commit()
        with app._lock:
            app._state["last_times"].pop(self.AID, None)
            app._state.setdefault("decrypt_fails", {}).pop(self.AID, None)

    def test_failed_decrypt_does_not_skip_over_later_success(self):
        import json
        import crypto
        pw = "unit-test-wm"
        good = crypto.encrypt(json.dumps({
            "content": "pong-wm",
            "response_to": "cmd-wm",
            "message_type": "output",
        }), pw)
        comments = [
            {"id": "10", "body": "<!-- r -->not-a-valid-blob", "updated_at": "10"},
            {"id": "20", "body": f"<!-- r -->{good}", "updated_at": "20"},
        ]
        agent = {"id": self.AID, "channel": "worker", "repo": "t/t"}
        app._process_comments(agent, comments, pw)
        self.assertEqual(app._state["last_times"].get(self.AID), "5")
        self.assertEqual(app.db.cursor_get(app._conn(), self.AID), None)


class TestScheduleUiPresent(unittest.TestCase):
    def test_schedule_tab_and_commands(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "templates", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn('data-tab="schedule"', html)
        self.assertIn("panel-schedule", html)
        with open(os.path.join(root, "static", "js", "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("schedule add", js)
        self.assertIn("downloadConsoleBackup", js)


if __name__ == "__main__":
    unittest.main()
