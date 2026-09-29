"""Deterministic, offline demo. Fake GitHub, fake worker, fake verifier. Nothing leaves the process."""
from __future__ import annotations

from typing import Callable

from ..adapters.fakes import FakeGitHub, FakeVerifier, FakeWorker
from ..adapters.submission import Submission, InMemorySubmissionAdapter
from ..core.engine import Shepherd
from ..core.policy import Policy
from ..storage.sqlite import Store

REPO = "example-org/example-repo"
LOG = "FAILED tests/test_app.py::test_ok - AssertionError: assert 1 == 2\nsrc/app.py:10: AssertionError"


def run_demo(say: Callable[[str], None] = print) -> dict:
    t = [1_800_000_000.0]
    clock = lambda: t[0]  # noqa: E731
    gh = FakeGitHub(REPO, 1, allow_writes=True)  # a FAKE remote; the policy write gate is opened for the fake only
    submissions, store = InMemorySubmissionAdapter(), Store(":memory:")
    sh = Shepherd(store, reader=gh, writer=gh, submissions=submissions, worker=FakeWorker(),
                  verifier=FakeVerifier(), policy=Policy(live_writes=True, allow_factual_replies=True), clock=clock)
    pr = sh.watch(Submission(
        mission_id="demo-mission", task_id="demo-task", submission_receipt_id="rcpt-0", artifact_digest="sha256:demo",
        pr_url=f"https://github.com/{REPO}/pull/1", expected_payout={"amount": "100", "currency": "USD"},
        acceptance_contract={"summary": "make test_ok pass"},
        verification_summary={"tests": ["tests/test_app.py::test_ok"], "evidence_digest": "sha256:ev0"}),
        head_sha=gh.head_sha, head_branch=gh.head_ref)
    sid = pr.shepherd_id
    step = [0]

    seen = [0]

    def poll(title: str) -> None:
        step[0] += 1
        t[0] += 120
        sh.poll_pr(sid, t[0])
        after = store.get_pr(sid)
        trans = store.transitions(sid)[seen[0]:]
        seen[0] += len(trans)
        path = " -> ".join([trans[0]["from_state"]] + [x["to_state"] for x in trans]) if trans else after.state.value
        say(f"[{step[0]}] {title}\n    {path}\n    head={after.head_sha[:7]} ci={after.ci_state.value} review={after.review_state.value} "
            f"rounds(ci/review)={after.repair_round}/{after.review_round}")

    say("Drex PR Shepherd demo (fake GitHub, fake worker; no network, no real writes)\n")
    say(f"[0] Submitted PR #1 is now watched: {store.get_pr(sid).state.value}   mission={pr.mission_id}")
    gh.add_check("build", "failure", log=LOG)
    poll("CI fails on our patch -> Drex classifies PATCH_CAUSED_FAILURE -> routes Codex repair -> verifier passes -> SAME branch pushed")
    gh.add_review("CHANGES_REQUESTED", "A couple of changes, please.")
    gh.add_review_comment("please use pathlib here", line=10)
    gh.add_review_comment("please add a docstring", line=20)
    poll("Reviewer requests changes (3 items) -> ONE bounded revision round -> verifier passes -> same PR updated -> factual reply")
    gh.add_review("CHANGES_REQUESTED", "One more thing: please handle empty input.")
    poll("Reviewer asks again -> second bounded revision, same mission, same PR")
    gh.add_review("APPROVED", "LGTM")
    poll("Reviewer approves (approved is not merged, not paid)")
    gh.merge()
    poll("Maintainer merges (merged is not paid) -> settlement watch begins")
    submissions.evidence = []
    poll("Settlement still pending: no platform evidence, so no accepted/realized claim")
    final = store.get_pr(sid)
    say("\nFacts kept separate:")
    say(f"    code state     : {final.state.value}")
    say(f"    settlement     : {final.settlement_stage.value} (not ACCEPTED, not REALIZED)")
    say(f"    mission/PR     : {final.mission_id} / #{final.pr_number} (one mission, one PR, {final.review_round} review + {final.repair_round} CI rounds)")
    say(f"    branch pushes  : {[w[1]['branch'] for w in gh.writes if w[0] == 'push_update']}")
    say(f"    fake replies   : {sum(1 for w in gh.writes if w[0] != 'push_update')}")
    say(f"    submission events: {', '.join(submissions.types())}")
    return {"final_state": final.state.value, "settlement_stage": final.settlement_stage.value,
            "pushes": sum(1 for w in gh.writes if w[0] == "push_update"), "mission_id": final.mission_id,
            "submission_events": submissions.types(), "review_round": final.review_round, "repair_round": final.repair_round}
