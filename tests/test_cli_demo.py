from __future__ import annotations

import io
import os
import contextlib
import tempfile
import unittest

from tests.helpers import Base

from pr_shepherd.cli.demo import run_demo
from pr_shepherd.cli.main import main


def run(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    old = dict(os.environ)
    os.environ.update(env or {})
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
    finally:
        os.environ.clear(); os.environ.update(old)
    return rc, out.getvalue(), err.getvalue()


class TestCLI(Base):
    def test_demo_is_deterministic_and_ends_settlement_pending(self):
        lines1, lines2 = [], []
        r1, r2 = run_demo(lines1.append), run_demo(lines2.append)
        self.assertEqual(lines1, lines2)
        self.assertEqual(r1["final_state"], "SETTLEMENT_PENDING")
        self.assertEqual(r1["settlement_stage"], "SUBMITTED_PAYOUT")
        self.assertEqual((r1["repair_round"], r1["review_round"], r1["pushes"]), (1, 2, 3))
        self.assertEqual({"demo-mission"}, {r1["mission_id"]})
        self.assertNotIn("PAYOUT_SIGNAL", r1["submission_events"])

    def test_cli_demo(self):
        rc, out, _ = run(["demo"])
        self.assertEqual(rc, 0)
        self.assertIn("SETTLEMENT_PENDING", out)

    def test_watch_status_events_offline(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "s.db")
            rc, out, _ = run(["--db", db, "watch", "https://github.com/example-org/example-repo/pull/7", "--mission-id", "m1",
                              "--task-id", "t1", "--head-sha", "abcdef1", "--head-branch", "feature/x"])
            self.assertEqual(rc, 0, out)
            rc, out, _ = run(["--db", db, "status"])
            self.assertIn("example-org/example-repo#7 WATCHING", out)
            rc, out, _ = run(["--db", db, "status", "--json"])
            self.assertIn('"watched_prs": 1', out)
            rc, out, _ = run(["--db", db, "events", "example-org/example-repo#7"])
            self.assertEqual(rc, 0)
            rc, _, err = run(["--db", db, "events", "example-org/example-repo#99"])
            self.assertEqual(rc, 2)
            rc, _, err = run(["--db", db, "watch", "https://evil.example/o/r/pull/1", "--mission-id", "m", "--task-id", "t",
                              "--head-sha", "abcdef1", "--head-branch", "b"])
            self.assertEqual(rc, 2)

    def test_demo_json(self):
        import json
        rc, out, _ = run(["demo", "--json"])
        self.assertEqual((rc, json.loads(out)["final_state"]), (0, "SETTLEMENT_PENDING"))

    def test_release_command_unblocks_human_hold_without_any_github_write(self):
        from pr_shepherd.core.models import State
        from pr_shepherd.storage.sqlite import Store
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "s.db")
            url = "https://github.com/example-org/example-repo/pull/7"
            run(["--db", db, "watch", url, "--mission-id", "m1", "--task-id", "t1", "--head-sha", "abcdef1", "--head-branch", "feature/x"])
            st = Store(db)
            pr = st.list_prs()[0]
            st.save_pr(pr.copy(state=State.HUMAN_ACTION_REQUIRED, blocker={"reason": "revision budget exhausted"}, review_round=3))
            st.close()
            # requires an explicit reason
            with self.assertRaises(SystemExit):
                run(["--db", db, "release", url])
            rc, out, _ = run(["--db", db, "release", url, "--reason", "operator reviewed", "--reset-budgets"])
            self.assertEqual(rc, 0, out)
            self.assertIn("no GitHub write", out)
            st = Store(db)
            pr = st.list_prs()[0]
            self.assertEqual((pr.state, pr.review_round, pr.blocker), (State.WATCHING, 0, {}))
            self.assertEqual(st.outbox(pr.shepherd_id, "github"), [])
            self.assertTrue(st.audit_log(pr.shepherd_id, "human_released"))
            st.close()
            rc, _, err = run(["--db", db, "release", url, "--reason", "again"])  # not on hold any more
            self.assertEqual(rc, 2)

    def test_doctor_reports_writes_disabled_and_never_prints_token(self):
        rc, out, _ = run(["doctor"], {"GITHUB_TOKEN": "ghp_" + "x" * 30, "PR_SHEPHERD_DB": ":memory:"})
        self.assertIn("GitHub writes: disabled", out)
        self.assertNotIn("ghp_", out)

    def test_ingest_requires_valid_signature(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "p.json")
            with open(f, "w") as fh:
                fh.write("{}")
            rc, _, err = run(["--db", os.path.join(d, "s.db"), "ingest", "--event", "issue_comment", "--file", f, "--signature", "sha256=00"],
                             {"PR_SHEPHERD_WEBHOOK_SECRET": "s"})
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
