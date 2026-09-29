"""In-memory GitHub fake used by tests and the safe demo. No network, no real writes."""
from __future__ import annotations

import copy
from typing import Any, Optional

from .github import (
    GitHubAdapter, MergeStatus, NotFound, Page, PRSnapshot, PushRequest, RateLimited, WriteDisabled,
)


class FakeGitHub(GitHubAdapter):
    def __init__(self, repo: str = "example-org/example-repo", number: int = 1, head_sha: str = "a1b2c3d4e5f6",
                 head_ref: str = "feature/fix", base_ref: str = "main", *, allow_writes: bool = False,
                 head_repo: Optional[str] = None):
        self.head_repo = head_repo or repo
        self.repo, self.number = repo, number
        self.head_sha, self.head_ref, self.base_ref = head_sha, head_ref, base_ref
        self.state, self.merged, self.mergeable = "open", False, True
        self.reviews: list[dict[str, Any]] = []
        self.review_comments: list[dict[str, Any]] = []
        self.issue_comments: list[dict[str, Any]] = []
        self.check_runs: dict[str, list[dict[str, Any]]] = {}
        self.changed_files: list[str] = ["src/app.py", "tests/test_app.py"]
        self.allow_writes = allow_writes
        self.writes: list[tuple[str, dict[str, Any]]] = []
        self.calls: list[str] = []
        self.raise_rate_limit: Optional[float] = None
        self._v = 1
        self._id = 1000

    # -- scripting helpers
    def _bump(self) -> None:
        self._v += 1

    def _next(self) -> int:
        self._id += 1
        return self._id

    def user(self, login: str, assoc: str = "MEMBER", bot: bool = False) -> dict[str, Any]:
        return {"user": {"login": login, "type": "Bot" if bot else "User"}, "author_association": assoc}

    def add_check(self, name: str, conclusion: Optional[str], *, status: str = "completed", log: str = "", sha: Optional[str] = None) -> int:
        i = self._next()
        self.check_runs.setdefault(sha or self.head_sha, []).append(
            {"id": i, "name": name, "status": status, "conclusion": conclusion, "head_sha": sha or self.head_sha,
             "started_at": "2026-01-01T00:00:00Z", "output": {"summary": log, "text": ""}})
        self._bump()
        return i

    def add_review(self, state: str, body: str = "", login: str = "maintainer", assoc: str = "MEMBER") -> int:
        i = self._next()
        self.reviews.append({"id": i, "state": state, "body": body, "submitted_at": "2026-01-01T01:00:00Z",
                             "commit_id": self.head_sha, **self.user(login, assoc)})
        self._bump()
        return i

    def add_review_comment(self, body: str, path: str = "src/app.py", line: int = 10, login: str = "maintainer",
                           assoc: str = "MEMBER", bot: bool = False) -> int:
        i = self._next()
        self.review_comments.append({"id": i, "body": body, "path": path, "line": line, "created_at": "2026-01-01T01:00:00Z",
                                     "commit_id": self.head_sha, **self.user(login, assoc, bot)})
        self._bump()
        return i

    def add_issue_comment(self, body: str, login: str = "maintainer", assoc: str = "MEMBER") -> int:
        i = self._next()
        self.issue_comments.append({"id": i, "body": body, "created_at": "2026-01-01T02:00:00Z", **self.user(login, assoc)})
        self._bump()
        return i

    def merge(self) -> None:
        self.state, self.merged = "closed", True
        self._bump()

    def close(self) -> None:
        self.state = "closed"
        self._bump()

    # -- reads
    def _guard(self) -> None:
        if self.raise_rate_limit is not None:
            raise RateLimited(self.raise_rate_limit)

    def _etag(self, key: str) -> str:
        return f'W/"{key}-{self._v}"'

    def _page(self, key: str, items: list, etag: Optional[str]) -> Page:
        self.calls.append(key)
        self._guard()
        tag = self._etag(key)
        if etag == tag:
            return Page([], tag, True)
        return Page(copy.deepcopy(items), tag, False)

    def get_pr(self, repo: str, number: int, etag: Optional[str] = None) -> PRSnapshot:
        self.calls.append("pr")
        self._guard()
        if (repo, number) != (self.repo, self.number):
            raise NotFound(f"{repo}#{number}")
        tag = self._etag("pr")
        if etag == tag:
            return PRSnapshot(number, "", False, "", "", "", "", None, "", tag, True)
        return PRSnapshot(number, self.state, self.merged, self.head_sha, self.head_ref, self.head_repo, self.base_ref,
                          self.mergeable, "deadbeef" if self.merged else "", tag)

    def get_reviews(self, repo, number, etag=None):
        return self._page("reviews", self.reviews, etag)

    def get_review_comments(self, repo, number, etag=None):
        return self._page("rc", self.review_comments, etag)

    def get_issue_comments(self, repo, number, etag=None):
        return self._page("ic", self.issue_comments, etag)

    def get_check_runs(self, repo, sha, etag=None):
        return self._page(f"checks:{sha}", self.check_runs.get(sha, []), etag)

    def get_commits(self, repo, number, etag=None):
        return self._page("commits", [{"sha": self.head_sha}], etag)

    def get_merge_status(self, repo, number):
        return MergeStatus(self.mergeable, "clean" if self.mergeable else "dirty")

    def get_changed_files(self, repo, number):
        return list(self.changed_files)

    # -- writes (recorded; only mutate when the fake itself allows writes)
    def _write(self, op: str, payload: dict[str, Any]) -> None:
        if not self.allow_writes:
            raise WriteDisabled("fake adapter has writes disabled")
        self.writes.append((op, payload))

    def push_update(self, req: PushRequest) -> None:
        self._write("push_update", {"repo": req.repository, "branch": req.branch, "expected": req.expected_head_sha, "new": req.new_head_sha})
        if req.expected_head_sha != self.head_sha or req.branch != self.head_ref:
            raise WriteDisabled("lease mismatch")  # models --force-with-lease rejection
        self.head_sha = req.new_head_sha
        self._bump()

    def reply_to_comment(self, repo, number, comment_id, body):
        self._write("reply_to_comment", {"comment_id": comment_id, "body": body})

    def post_pr_comment(self, repo, number, body):
        self._write("post_pr_comment", {"body": body})


class FakeWorker:
    """Deterministic worker: produces a new head sha derived from the contract."""

    def __init__(self, *, ok: bool = True, summary: str = "adjusted implementation") -> None:
        self.ok, self.summary = ok, summary
        self.contracts: list[Any] = []
        self.counter = 0

    def run(self, contract):
        from ..core.models import WorkerResult

        self.contracts.append(contract)
        self.counter += 1
        if not self.ok:
            return WorkerResult(ok=False, error="worker could not produce a patch")
        sha = f"{self.counter:02d}" + "ab" * 5 + contract.kind.value[:2].lower()
        sha = "".join(c if c in "0123456789abcdef" else "f" for c in sha)
        return WorkerResult(ok=True, new_head_sha=sha, branch=contract.branch, summary=self.summary, patch_digest=f"sha256:{sha}")


class FakeVerifier:
    def __init__(self, *, passed: bool = True, tests: tuple[str, ...] = ("tests/test_app.py::test_ok",)) -> None:
        self.passed, self.tests = passed, tests
        self.calls = 0

    def verify(self, contract, result):
        from ..core.models import VerificationResult

        self.calls += 1
        if not self.passed:
            return VerificationResult(passed=False, summary="1 test failed")
        return VerificationResult(passed=True, receipt_id=f"rcpt-{self.calls}", evidence_digest=f"sha256:ev{self.calls}",
                                  tests=self.tests, summary="all checks passed")
