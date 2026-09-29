from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pr_shepherd.adapters.fakes import FakeGitHub, FakeVerifier, FakeWorker  # noqa: E402
from pr_shepherd.adapters.submission import Submission, InMemorySubmissionAdapter  # noqa: E402
from pr_shepherd.core.engine import Shepherd  # noqa: E402
from pr_shepherd.core.models import ResourceState  # noqa: E402
from pr_shepherd.core.policy import Policy  # noqa: E402
from pr_shepherd.storage.sqlite import Store  # noqa: E402

REPO = "example-org/example-repo"
PR_URL = f"https://github.com/{REPO}/pull/1"
PATCH_LOG = "FAILED tests/test_app.py::test_ok - AssertionError: assert 1 == 2\nsrc/app.py:10: AssertionError"


class Clock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def submission(**kw) -> Submission:
    base = dict(
        mission_id="mission-A", task_id="task-A", submission_receipt_id="rcpt-0", artifact_digest="sha256:art0",
        pr_url=PR_URL, expected_payout={"amount": "100", "currency": "USD"},
        acceptance_contract={"summary": "fix the thing"},
        verification_summary={"tests": ["tests/test_app.py::test_ok"], "summary": "initial", "evidence_digest": "sha256:ev0"},
    )
    base.update(kw)
    return Submission(**base)


class Harness:
    def __init__(self, *, policy: Policy | None = None, worker=None, verifier=None, live: bool = False, db: str = ":memory:",
                 with_worker: bool = True, head_repo: str | None = None):
        self.clock = Clock()
        self.gh = FakeGitHub(REPO, 1, allow_writes=live, head_repo=head_repo)
        self.submissions = InMemorySubmissionAdapter()
        self.policy = policy or Policy(live_writes=live, allow_factual_replies=True)
        self.store = Store(db)
        self.worker = worker or FakeWorker()
        self.verifier = verifier or FakeVerifier()
        self.make(with_worker)
        self.pr = self.sh.watch(submission(), head_sha=self.gh.head_sha, head_branch=self.gh.head_ref, base_branch="main",
                                 head_repository=head_repo or "")
        self.sid = self.pr.shepherd_id

    def make(self, with_worker: bool = True) -> None:
        self.sh = Shepherd(self.store, reader=self.gh, writer=self.gh, submissions=self.submissions, policy=self.policy,
                           worker=self.worker if with_worker else None, verifier=self.verifier if with_worker else None,
                           resources=ResourceState(), clock=self.clock)

    def poll(self, advance: float = 120.0):
        self.clock.advance(advance)
        return self.sh.poll_pr(self.sid, self.clock())

    def get(self):
        return self.store.get_pr(self.sid)

    def state(self) -> str:
        return self.get().state.value

    def actions(self, kind=None):
        return self.store.actions(self.sid, kind)


class Base(unittest.TestCase):
    pass
