from __future__ import annotations

import unittest

from tests.helpers import PATCH_LOG, REPO, Base, Harness, submission

from pr_shepherd.adapters.fakes import FakeVerifier, FakeWorker
from pr_shepherd.core.models import EventType, RawEvent, SettlementEvidence, SettlementStage, State
from pr_shepherd.core.policy import Policy


class TestWatchAndCI(Base):
    def test_submitted_pr_enters_watching(self):
        h = Harness()
        self.assertEqual(h.state(), "WATCHING")
        self.assertEqual(h.get().settlement_stage, SettlementStage.SUBMITTED_PAYOUT)
        self.assertIn("PR_WATCH_STARTED", h.submissions.types())
        self.assertEqual(h.sh.status()["watched_prs"], 1)

    def test_watch_is_idempotent_one_mission_per_pr(self):
        h = Harness()
        again = h.sh.watch(submission(mission_id="mission-OTHER"), head_sha=h.gh.head_sha, head_branch="feature/fix")
        self.assertEqual(again.mission_id, "mission-A")
        self.assertEqual(len(h.store.list_prs()), 1)

    def test_ci_pass_stays_watching(self):
        h = Harness()
        h.gh.add_check("build", "success")
        h.poll()
        self.assertEqual(h.state(), "WATCHING")
        self.assertEqual(h.get().ci_state.value, "PASSING")
        self.assertEqual(h.actions(), [])

    def test_ci_failure_routes_repair_same_mission_same_branch(self):
        h = Harness(with_worker=False)
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        self.assertEqual(h.state(), "REPAIR_QUEUED")
        (a,) = h.actions("CI_REPAIR")
        c = a["payload"]["contract"]
        self.assertEqual((c["mission_id"], c["task_id"], c["branch"], c["head_sha"], c["pr_number"]),
                         ("mission-A", "task-A", "feature/fix", h.gh.head_sha, 1))
        self.assertTrue(c["ci_evidence"]["failures"])
        self.assertEqual(c["previous_verification"]["receipt_id"], "rcpt-0")
        self.assertEqual(a["route"], "ROUTE_CODEX")
        self.assertIn("src/app.py", c["affected_files"])

    def test_flaky_and_upstream_ci_do_not_rewrite_code(self):
        for log, concl in (("ECONNRESET connection reset by peer", "failure"), ("502 Bad Gateway from registry", "failure"),
                           ("npm ERR! 404 not found", "failure"), ("", "timed_out")):
            h = Harness()
            h.gh.add_check("build", concl, log=log)
            h.poll()
            self.assertEqual(h.actions(), [], log)
            self.assertEqual(h.state(), "CI_FAILED")
            self.assertEqual(h.worker.contracts, [])

    def test_repeated_polling_does_not_duplicate_actions(self):
        h = Harness(with_worker=False)
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        for _ in range(4):
            h.poll()
        self.assertEqual(len(h.actions("CI_REPAIR")), 1)
        self.assertEqual(h.get().repair_round, 1)

    def test_repair_updates_same_pr_and_branch(self):
        h = Harness(live=True)
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        old = h.gh.head_sha
        h.poll()
        self.assertEqual(h.state(), "WATCHING")
        push = [w for w in h.gh.writes if w[0] == "push_update"]
        self.assertEqual(len(push), 1)
        self.assertEqual(push[0][1]["branch"], "feature/fix")
        self.assertEqual(push[0][1]["expected"], old)
        self.assertNotEqual(h.get().head_sha, old)
        self.assertEqual(h.get().pr_number, 1)
        self.assertEqual(len(h.store.list_prs()), 1)
        self.assertIn("REVISION_VERIFIED", h.submissions.types())
        self.assertEqual(h.get().verification_receipt_id, "rcpt-1")

    def test_dry_run_default_never_pushes(self):
        h = Harness(live=False)
        h.gh.allow_writes = True  # even a permissive adapter must not be called while the policy gate is closed
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        self.assertEqual(h.gh.writes, [])
        self.assertEqual(h.state(), "READY_TO_UPDATE")
        (row,) = [o for o in h.store.outbox(h.sid, "github") if o["op"] == "push_update"]
        self.assertEqual(row["status"], "DRY_RUN")

    def test_verification_failure_prevents_update(self):
        h = Harness(live=True, verifier=FakeVerifier(passed=False))
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        old = h.gh.head_sha
        h.poll()
        self.assertEqual(h.gh.writes, [])
        self.assertEqual(h.gh.head_sha, old)
        (a,) = h.actions("CI_REPAIR")
        self.assertEqual(a["status"], "VERIFY_FAILED")
        self.assertEqual(h.state(), "CI_FAILED")

    def test_stale_ci_event_for_old_sha_is_ignored(self):
        h = Harness()
        h.gh.add_check("build", "failure", log=PATCH_LOG, sha="0" * 12)
        h.poll()
        self.assertEqual(h.state(), "WATCHING")

    def test_one_passing_check_does_not_mask_a_failing_one(self):
        h = Harness(with_worker=False)
        h.gh.add_check("lint", "success")
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        self.assertEqual(h.get().ci_state.value, "FAILING")


class TestReview(Base):
    def test_requested_changes_create_same_mission_revision(self):
        h = Harness(with_worker=False)
        h.gh.add_review("CHANGES_REQUESTED", "please rename foo to bar")
        h.poll()
        (a,) = h.actions("REVIEW_REVISION")
        c = a["payload"]["contract"]
        self.assertEqual((c["mission_id"], c["task_id"]), ("mission-A", "task-A"))
        self.assertEqual(c["acceptance_contract"], {"summary": "fix the thing"})
        self.assertEqual(c["head_sha"], h.gh.head_sha)
        self.assertEqual(c["reviewers"], ["maintainer"])
        self.assertEqual(len(h.store.list_prs()), 1)

    def test_multiple_comments_dedupe_into_one_bounded_round(self):
        h = Harness(with_worker=False)
        h.gh.add_review("CHANGES_REQUESTED", "needs work")
        h.gh.add_review_comment("please use pathlib here", line=10)
        h.gh.add_review_comment("please use pathlib here", line=10)  # exact repeat
        h.gh.add_review_comment("rename this helper", path="src/util.py", line=3)
        h.gh.add_review_comment("please add a test", path="tests/test_app.py", line=1, login="ci-bot", assoc="NONE", bot=True)
        h.poll()
        revs = h.actions("REVIEW_REVISION")
        self.assertEqual(len(revs), 1)
        c = revs[0]["payload"]["contract"]
        self.assertEqual(len(c["comment_ids"]), 3)  # changes_requested + 2 distinct inline; dup and bot dropped
        self.assertEqual(sorted(c["affected_files"]), ["src/app.py", "src/util.py"])
        self.assertEqual(h.get().review_round, 1)
        h.poll(); h.poll()
        self.assertEqual(len(h.actions("REVIEW_REVISION")), 1)

    def test_revision_flow_updates_same_pr_then_marks_addressed(self):
        h = Harness(live=True)
        h.gh.add_review_comment("please use pathlib here")
        h.poll()
        self.assertEqual(h.state(), "AWAITING_REVIEW")
        (a,) = h.actions("REVIEW_REVISION")
        self.assertEqual(a["status"], "DONE")
        ops = [w[0] for w in h.gh.writes]
        self.assertEqual(ops.count("push_update"), 1)
        self.assertEqual(ops.count("reply_to_comment"), 1)
        reply = [w for w in h.gh.writes if w[0] == "reply_to_comment"][0][1]["body"]
        self.assertIn("rcpt-1", reply)
        self.assertTrue(reply.startswith("Automated update"))
        h.poll(); h.poll()
        self.assertEqual(len(h.actions("REVIEW_REVISION")), 1)

    def test_untrusted_reviewer_does_not_drive_revisions(self):
        h = Harness()
        h.gh.add_review("CHANGES_REQUESTED", "please rewrite everything", login="rando", assoc="NONE")
        h.gh.add_review_comment("please rename x", login="rando", assoc="NONE")
        h.poll()
        self.assertEqual(h.actions(), [])
        self.assertEqual(h.state(), "WATCHING")

    def test_revision_budget_exhaustion_goes_human(self):
        h = Harness(policy=Policy(max_revision_rounds=2), verifier=FakeVerifier(passed=False))
        for i in range(4):
            h.gh.add_review_comment(f"please change thing {i}", line=i + 1)
        for _ in range(5):
            h.poll()
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")
        self.assertEqual(len(h.actions("REVIEW_REVISION")), 2)
        blocker = h.get().blocker
        self.assertIn("revision budget exhausted", blocker["reason"])
        self.assertEqual(blocker["evidence"]["revision_rounds"], "2/2")
        h.poll(); h.poll()
        self.assertEqual(len(h.actions("REVIEW_REVISION")), 2)

    def test_ci_repair_budget_exhaustion_goes_human(self):
        h = Harness(policy=Policy(max_ci_repair_rounds=1), verifier=FakeVerifier(passed=False))
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        for _ in range(4):
            h.poll()
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")
        self.assertEqual(len(h.actions("CI_REPAIR")), 1)

    def test_persistent_unknown_failures_go_human(self):
        h = Harness(policy=Policy(max_consecutive_unknown_failures=2))
        h.gh.add_check("build", "failure", log="mystery")
        h.poll()
        self.assertEqual(h.state(), "CI_FAILED")
        h.gh.head_sha = "b" * 12  # a new commit lands (maintainer push); same mystery
        h.gh._bump()
        h.gh.add_check("build", "failure", log="mystery again", sha=h.gh.head_sha)
        h.poll()
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")
        self.assertEqual(h.get().blocker["evidence"]["nonactionable_streak"], "2/2")

    def test_worker_failure_counts_against_budget(self):
        h = Harness(policy=Policy(max_ci_repair_rounds=2), worker=FakeWorker(ok=False))
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        for _ in range(4):
            h.poll()
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")
        self.assertEqual({a["status"] for a in h.actions("CI_REPAIR")}, {"WORKER_FAILED"})

    def test_external_worker_flow_via_complete_task(self):
        h = Harness(with_worker=False)
        h.gh.add_review_comment("please use pathlib here")
        h.poll()
        (t,) = h.sh.pending_tasks()
        from pr_shepherd.core.models import VerificationResult, WorkerResult
        st = h.sh.complete_task(t["action_key"], WorkerResult(True, "c" * 12, "feature/fix", "used pathlib"),
                                VerificationResult(True, "rcpt-x", "sha256:x", ("t1",), "ok"))
        self.assertEqual(st, "VERIFIED")  # dry-run: verified, awaiting push gate
        self.assertEqual(h.state(), "READY_TO_UPDATE")
        # wrong-branch result is rejected
        h2 = Harness(with_worker=False)
        h2.gh.add_review_comment("please use pathlib here")
        h2.poll()
        (t2,) = h2.sh.pending_tasks()
        st2 = h2.sh.complete_task(t2["action_key"], WorkerResult(True, "d" * 12, "other-branch", "x"), VerificationResult(True, "r", "sha256:y"))
        self.assertEqual(st2, "WORKER_FAILED")


class TestRobustness(Base):
    def test_head_moving_during_external_task_makes_it_stale_not_pushed(self):
        from pr_shepherd.core.models import VerificationResult, WorkerResult
        h = Harness(with_worker=False, live=True)
        h.gh.add_review_comment("please use pathlib here")
        h.poll()
        (t,) = h.sh.pending_tasks()
        h.gh.head_sha = "9" * 12  # someone else pushed meanwhile
        h.gh._bump()
        h.poll()
        st = h.sh.complete_task(t["action_key"], WorkerResult(True, "c" * 12, "feature/fix", "x"), VerificationResult(True, "r", "sha256:z"))
        self.assertEqual(st, "STALE")
        self.assertEqual([w for w in h.gh.writes if w[0] == "push_update"], [])

    def test_human_release_returns_to_watching_and_can_reset_budgets(self):
        h = Harness(policy=Policy(max_revision_rounds=1), verifier=FakeVerifier(passed=False))
        h.gh.add_review_comment("please change a")
        for _ in range(3):
            h.poll()
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")
        pr = h.sh.release_human(h.sid, "maintainer agreed to another try", reset_budgets=True)
        self.assertEqual((pr.state, pr.review_round, pr.blocker), (State.WATCHING, 0, {}))

    def test_worker_exception_is_a_failed_attempt_not_a_crash(self):
        class Boom:
            def run(self, c):
                raise RuntimeError("secret internal detail")
        h = Harness(worker=Boom())
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        self.assertEqual(h.actions("CI_REPAIR")[0]["status"], "WORKER_FAILED")
        self.assertNotIn("secret internal detail", str(h.actions("CI_REPAIR")[0]["result"]))


class TestForksAndFreeze(Base):
    FORK = "contributor/example-repo"

    def test_fork_pr_external_push_is_tracked_and_ci_seen(self):
        h = Harness(head_repo=self.FORK, with_worker=False)
        h.gh.head_sha = "e" * 12
        h.gh._bump()
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        self.assertEqual(h.get().head_sha, "e" * 12)
        self.assertEqual(h.state(), "REPAIR_QUEUED")
        self.assertEqual(len(h.actions("CI_REPAIR")), 1)

    def test_fork_push_targets_head_repository(self):
        h = Harness(head_repo=self.FORK, live=True)
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        self.assertEqual([o["payload"]["repository"] for o in h.store.outbox(h.sid, "github") if o["op"] == "push_update"], [self.FORK])

    def test_head_from_third_repo_still_rejected(self):
        h = Harness(head_repo=self.FORK)
        r = h.sh.ingest(h.sid, [RawEvent("head", "head:" + "d" * 12, REPO, 1, "x", {"sha": "d" * 12, "head_repository": "attacker/fork"})])
        self.assertEqual(r.rejected, 1)
        self.assertEqual(h.get().head_sha, h.gh.head_sha)

    def test_human_escalation_freezes_in_flight_task_no_push(self):
        from pr_shepherd.core.models import VerificationResult, WorkerResult
        h = Harness(with_worker=False, live=True)
        h.gh.add_review_comment("please use pathlib here")
        h.poll()
        (t,) = h.sh.pending_tasks()
        h.gh.add_issue_comment("Why did you choose this approach?")
        h.poll()
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")
        st = h.sh.complete_task(t["action_key"], WorkerResult(True, "c" * 12, "feature/fix", "x"), VerificationResult(True, "r", "sha256:z"))
        self.assertEqual(st, "STALE")
        self.assertEqual(h.gh.writes, [])
        self.assertFalse(h.store.audit_log(h.sid, "illegal_transition"))


class TestApprovalSettlement(Base):
    def test_settlement_watch_starts_at_approval_but_needs_platform_evidence(self):
        h = Harness()
        h.gh.add_review("APPROVED", "LGTM")
        h.poll()
        self.assertEqual(h.state(), "APPROVED")
        h.poll()
        self.assertEqual(h.get().settlement_stage, SettlementStage.SUBMITTED_PAYOUT)
        h.submissions.evidence = [SettlementEvidence(SettlementStage.ACCEPTED_PAYOUT, "platform-x", "acc-1", 1.0)]
        h.poll()
        self.assertEqual(h.state(), "APPROVED")  # approval + acceptance evidence is still not merged
        self.assertEqual(h.get().settlement_stage, SettlementStage.ACCEPTED_PAYOUT)
        self.assertNotIn("PAYOUT_SIGNAL", h.submissions.types())
        h.gh.merge()
        h.poll()
        self.assertEqual(h.state(), "ACCEPTED_PAYOUT")  # not REALIZED_REVENUE
        self.assertEqual(h.submissions.types().count("BOUNTY_ACCEPTED_SIGNAL"), 1)

    def test_no_approval_time_probe_without_expected_payout(self):
        h = Harness()
        h.store.save_pr(h.get().copy(expected_payout=None))
        h.gh.add_review("APPROVED", "LGTM")
        h.submissions.evidence = [SettlementEvidence(SettlementStage.ACCEPTED_PAYOUT, "p", "a", 1.0)]
        h.poll(); h.poll()
        self.assertNotEqual(h.get().settlement_stage, SettlementStage.ACCEPTED_PAYOUT)


class TestQuestionsAndReplies(Base):
    def test_factual_response_grounded_in_evidence(self):
        h = Harness(live=True)
        h.gh.add_issue_comment("Do the tests pass on this change?")
        h.poll()
        posts = [w for w in h.gh.writes if w[0] == "post_pr_comment"]
        self.assertEqual(len(posts), 1)
        self.assertIn("rcpt-0", posts[0][1]["body"])
        self.assertIn("tests/test_app.py::test_ok", posts[0][1]["body"])
        self.assertEqual(h.state(), "AWAITING_REVIEW")

    def test_factual_response_requires_evidence(self):
        h = Harness(live=True)
        h.store.save_pr(h.get().copy(last_verification={}, verification_receipt_id=""))
        h.gh.add_issue_comment("Do the tests pass on this change?")
        h.poll()
        self.assertEqual([w for w in h.gh.writes if w[0] == "post_pr_comment"], [])
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")

    def test_factual_reply_disabled_by_policy_escalates(self):
        h = Harness(policy=Policy(allow_factual_replies=False))
        h.gh.add_issue_comment("Why did you change this?")
        h.poll()
        self.assertEqual(h.state(), "HUMAN_ACTION_REQUIRED")


class TestTerminalAndSettlement(Base):
    def _merge_flow(self, h):
        h.gh.add_review("APPROVED", "LGTM")
        h.poll()
        self.assertEqual(h.state(), "APPROVED")
        h.gh.merge()
        h.poll()

    def test_merge_does_not_equal_payment(self):
        h = Harness()
        self._merge_flow(h)
        pr = h.get()
        self.assertEqual(pr.state, State.SETTLEMENT_PENDING)
        self.assertEqual(pr.settlement_stage, SettlementStage.SUBMITTED_PAYOUT)
        self.assertNotIn(pr.state, (State.ACCEPTED_PAYOUT, State.REALIZED_REVENUE))
        self.assertIn("PR_MERGED", h.submissions.types())
        self.assertNotIn("PAYOUT_SIGNAL", h.submissions.types())
        self.assertNotIn("BOUNTY_ACCEPTED_SIGNAL", h.submissions.types())

    def test_approved_is_not_paid(self):
        h = Harness()
        h.gh.add_review("APPROVED", "LGTM")
        h.poll()
        self.assertEqual(h.state(), "APPROVED")
        self.assertEqual(h.get().settlement_stage, SettlementStage.SUBMITTED_PAYOUT)

    def test_github_text_payout_claims_do_not_move_settlement(self):
        h = Harness()
        self._merge_flow(h)
        h.gh.add_issue_comment("The bounty has been accepted and the payout has been sent!")
        h.gh.add_issue_comment("payment sent", login="rando", assoc="NONE")
        h.poll(); h.poll(3600)
        pr = h.get()
        self.assertEqual(pr.state, State.SETTLEMENT_PENDING)
        self.assertEqual(pr.settlement_stage, SettlementStage.SUBMITTED_PAYOUT)
        self.assertNotIn("PAYOUT_SIGNAL", h.submissions.types())

    def test_accepted_payout_is_not_realized_revenue(self):
        h = Harness()
        self._merge_flow(h)
        h.submissions.evidence = [SettlementEvidence(SettlementStage.ACCEPTED_PAYOUT, "platform-x", "acc-1", 1.0)]
        h.poll(3600)
        pr = h.get()
        self.assertEqual(pr.state, State.ACCEPTED_PAYOUT)
        self.assertEqual(pr.settlement_stage, SettlementStage.ACCEPTED_PAYOUT)
        self.assertIn("BOUNTY_ACCEPTED_SIGNAL", h.submissions.types())
        self.assertNotIn("PAYOUT_SIGNAL", h.submissions.types())
        h.submissions.evidence.append(SettlementEvidence(SettlementStage.REALIZED_REVENUE, "platform-x", "pay-1", 2.0, {"amount": "100"}))
        h.poll(3600)
        self.assertEqual(h.state(), "REALIZED_REVENUE")
        self.assertIsNone(h.get().next_check_at)

    def test_settlement_evidence_is_idempotent(self):
        h = Harness()
        self._merge_flow(h)
        ev = SettlementEvidence(SettlementStage.ACCEPTED_PAYOUT, "platform-x", "acc-1", 1.0)
        h.submissions.evidence = [ev]
        h.poll(3600); h.poll(3600)
        self.assertEqual(h.submissions.types().count("BOUNTY_ACCEPTED_SIGNAL"), 1)

    def test_submissions_signal_requires_evidence(self):
        from pr_shepherd.adapters.submission import SubmissionEvent, SubmissionEventType
        with self.assertRaises(ValueError):
            SubmissionEvent(SubmissionEventType.PAYOUT_SIGNAL, "m", "t", "s", "u", "k")

    def test_closed_pr_terminates_coding_loop(self):
        h = Harness(with_worker=False)
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        self.assertEqual(len(h.actions("CI_REPAIR")), 1)
        h.gh.close()
        h.poll()
        self.assertEqual(h.state(), "CLOSED")
        self.assertEqual(h.actions("CI_REPAIR")[0]["status"], "STALE")
        self.assertIsNone(h.get().next_check_at)
        n = len(h.actions())
        h.gh.add_review_comment("please change x")
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll(); h.poll()
        self.assertEqual(len(h.actions()), n)
        self.assertIn("PR_CLOSED", h.submissions.types())
        self.assertEqual(h.sh.tick(h.clock() + 10**6).polled, [])

    def test_same_mission_invariant_end_to_end(self):
        h = Harness(live=True)
        h.gh.add_check("build", "failure", log=PATCH_LOG)
        h.poll()
        h.gh.add_review_comment("please rename x")
        h.poll()
        h.gh.add_review_comment("please add docs", line=20)
        h.poll()
        missions = {a["payload"]["contract"]["mission_id"] for a in h.actions()}
        tasks = {a["payload"]["contract"]["task_id"] for a in h.actions()}
        self.assertEqual((missions, tasks), ({"mission-A"}, {"task-A"}))
        self.assertEqual({e.mission_id for e in h.submissions.events}, {"mission-A"})
        self.assertEqual(len(h.store.list_prs()), 1)
        self.assertGreaterEqual(len(h.actions()), 3)


if __name__ == "__main__":
    unittest.main()
