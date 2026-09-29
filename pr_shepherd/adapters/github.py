"""GitHub adapter interface plus a transport-agnostic REST implementation.

READ and WRITE are separate ABCs. The core only depends on these interfaces, so either the
REST API (urllib) or the `gh` CLI can sit underneath. Writes raise WriteDisabled unless the
adapter was explicitly constructed with allow_writes=True.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..core import security
from ..core.models import RawEvent


class GitHubError(Exception):
    pass


class NotFound(GitHubError):
    pass


class WriteDisabled(GitHubError):
    pass


class RateLimited(GitHubError):
    def __init__(self, reset_at: float, message: str = "rate limited"):
        super().__init__(message)
        self.reset_at = reset_at


@dataclass
class Page:
    items: list[dict[str, Any]] = field(default_factory=list)
    etag: Optional[str] = None
    not_modified: bool = False


@dataclass
class PRSnapshot:
    number: int
    state: str  # open | closed
    merged: bool
    head_sha: str
    head_ref: str
    head_repo: str
    base_ref: str
    mergeable: Optional[bool] = None
    merge_commit_sha: str = ""
    etag: Optional[str] = None
    not_modified: bool = False


@dataclass
class MergeStatus:
    mergeable: Optional[bool]
    mergeable_state: str = ""


@dataclass(frozen=True)
class PushRequest:
    repository: str
    branch: str
    expected_head_sha: str
    new_head_sha: str


class GitHubReader(ABC):
    @abstractmethod
    def get_pr(self, repo: str, number: int, etag: Optional[str] = None) -> PRSnapshot: ...
    @abstractmethod
    def get_reviews(self, repo: str, number: int, etag: Optional[str] = None) -> Page: ...
    @abstractmethod
    def get_review_comments(self, repo: str, number: int, etag: Optional[str] = None) -> Page: ...
    @abstractmethod
    def get_issue_comments(self, repo: str, number: int, etag: Optional[str] = None) -> Page: ...
    @abstractmethod
    def get_check_runs(self, repo: str, sha: str, etag: Optional[str] = None) -> Page: ...
    @abstractmethod
    def get_commits(self, repo: str, number: int, etag: Optional[str] = None) -> Page: ...
    @abstractmethod
    def get_merge_status(self, repo: str, number: int) -> MergeStatus: ...
    @abstractmethod
    def get_changed_files(self, repo: str, number: int) -> list[str]: ...


class GitHubWriter(ABC):
    allow_writes: bool = False

    @abstractmethod
    def push_update(self, req: PushRequest) -> None: ...
    @abstractmethod
    def reply_to_comment(self, repo: str, number: int, comment_id: str, body: str) -> None: ...
    @abstractmethod
    def post_pr_comment(self, repo: str, number: int, body: str) -> None: ...


class GitHubAdapter(GitHubReader, GitHubWriter):
    pass


# --------------------------------------------------------------------------- URL parsing

_PR_URL = re.compile(r"^https://(?P<host>[A-Za-z0-9.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)/pull/(?P<num>\d+)/?(?:[?#].*)?$")


def parse_pr_url(url: str, allowed_hosts: frozenset[str] = frozenset({"github.com"})) -> tuple[str, int]:
    m = _PR_URL.match((url or "").strip())
    if not m or m.group("host").lower() not in allowed_hosts:
        raise ValueError("not a recognized pull request URL")
    repo = m.group("repo")
    if not security.is_safe_repo(repo):
        raise ValueError("unsafe repository name")
    return repo, int(m.group("num"))


# --------------------------------------------------------------------------- transports


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: Any = None


Transport = Callable[[str, str, Optional[dict], Any], Response]  # (method, path_with_query, headers, json_body)


class UrllibTransport:
    """Minimal HTTPS transport. Reads GITHUB_TOKEN from the environment; never logs it."""

    def __init__(self, api_url: str = "https://api.github.com", token: Optional[str] = None, timeout: float = 20.0):
        if not api_url.startswith("https://"):
            raise ValueError("api_url must be https")
        self.api_url, self.timeout = api_url.rstrip("/"), timeout
        self._token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")

    def __call__(self, method: str, path: str, headers: Optional[dict], body: Any) -> Response:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "drex-pr-shepherd"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        h.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.api_url + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 (https enforced above)
                raw = r.read().decode("utf-8", "replace")
                return Response(r.status, {k.lower(): v for k, v in r.headers.items()}, json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace") if e.fp else ""
            try:
                parsed = json.loads(raw) if raw else None
            except ValueError:
                parsed = {"message": raw[:200]}
            return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, parsed)
        except urllib.error.URLError as e:
            raise GitHubError(f"network error: {type(e.reason).__name__}") from None


class GhCliTransport:
    """Transport backed by `gh api --include`. Uses the CLI's own authentication."""

    def __init__(self, runner: Callable[..., Any] = subprocess.run, gh: str = "gh"):
        self.runner, self.gh = runner, gh

    def __call__(self, method: str, path: str, headers: Optional[dict], body: Any) -> Response:
        cmd = [self.gh, "api", "--include", "--method", method, path]
        for k, v in (headers or {}).items():
            cmd += ["-H", f"{k}: {v}"]
        if body is not None:
            cmd += ["--input", "-"]
        p = self.runner(cmd, input=json.dumps(body) if body is not None else None, capture_output=True, text=True, timeout=30)
        out = p.stdout or ""
        head, _, rest = out.replace("\r\n", "\n").partition("\n\n")
        lines = head.split("\n")
        m = re.match(r"HTTP/\S+\s+(\d+)", lines[0]) if lines else None
        if not m:
            raise GitHubError("gh produced no HTTP response")
        hdrs = {ln.split(":", 1)[0].strip().lower(): ln.split(":", 1)[1].strip() for ln in lines[1:] if ":" in ln}
        try:
            parsed = json.loads(rest) if rest.strip() else None
        except ValueError:
            parsed = None
        return Response(int(m.group(1)), hdrs, parsed)


# --------------------------------------------------------------------------- REST adapter


class ApiClientAdapter(GitHubAdapter):
    def __init__(self, transport: Transport, *, allow_writes: bool = False,
                 push_runner: Optional[Callable[[PushRequest], None]] = None, per_page: int = 100):
        self.transport = transport
        self.allow_writes = allow_writes
        self.push_runner = push_runner
        self.per_page = per_page
        self.last_rate: Optional[tuple[int, float]] = None  # (remaining, reset_epoch)

    # -- internals
    def _req(self, method: str, path: str, etag: Optional[str] = None, body: Any = None) -> Response:
        headers = {"If-None-Match": etag} if etag else None
        r = self.transport(method, path, headers, body)
        rem, reset = r.headers.get("x-ratelimit-remaining"), r.headers.get("x-ratelimit-reset")
        if rem is not None and reset is not None and rem.isdigit() and reset.isdigit():
            self.last_rate = (int(rem), float(reset))
        if r.status in (403, 429):
            msg = str(r.body.get("message", "")).lower() if isinstance(r.body, dict) else ""
            if r.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in r.headers or "rate limit" in msg:
                ra = r.headers.get("retry-after")
                reset_at = float(reset) if reset and reset.isdigit() else time.time() + float(ra or 60)
                raise RateLimited(reset_at)
        if r.status == 404:
            raise NotFound(path)
        if r.status >= 400:
            raise GitHubError(f"HTTP {r.status} for {method} {re.sub(r'[?].*', '', path)}")
        return r

    def _page(self, path: str, etag: Optional[str], key: Optional[str] = None) -> Page:
        sep = "&" if "?" in path else "?"
        r = self._req("GET", f"{path}{sep}per_page={self.per_page}", etag)
        if r.status == 304:
            return Page([], etag, True)
        body = r.body
        items = body.get(key, []) if key and isinstance(body, dict) else body
        return Page([i for i in (items or []) if isinstance(i, dict)], r.headers.get("etag"), False)

    # -- reads
    def get_pr(self, repo: str, number: int, etag: Optional[str] = None) -> PRSnapshot:
        r = self._req("GET", f"/repos/{repo}/pulls/{number}", etag)
        if r.status == 304:
            return PRSnapshot(number, "", False, "", "", "", "", None, "", etag, True)
        b = r.body or {}
        head, base = b.get("head") or {}, b.get("base") or {}
        return PRSnapshot(
            number=number, state=b.get("state", ""), merged=bool(b.get("merged")), head_sha=head.get("sha", ""),
            head_ref=head.get("ref", ""), head_repo=((head.get("repo") or {}).get("full_name", "")),
            base_ref=base.get("ref", ""), mergeable=b.get("mergeable"), merge_commit_sha=b.get("merge_commit_sha") or "",
            etag=r.headers.get("etag"),
        )

    def get_reviews(self, repo, number, etag=None):
        return self._page(f"/repos/{repo}/pulls/{number}/reviews", etag)

    def get_review_comments(self, repo, number, etag=None):
        return self._page(f"/repos/{repo}/pulls/{number}/comments", etag)

    def get_issue_comments(self, repo, number, etag=None):
        return self._page(f"/repos/{repo}/issues/{number}/comments", etag)

    def get_check_runs(self, repo, sha, etag=None):
        return self._page(f"/repos/{repo}/commits/{sha}/check-runs", etag, key="check_runs")

    def get_commits(self, repo, number, etag=None):
        return self._page(f"/repos/{repo}/pulls/{number}/commits", etag)

    def get_merge_status(self, repo, number):
        b = self._req("GET", f"/repos/{repo}/pulls/{number}").body or {}
        return MergeStatus(b.get("mergeable"), b.get("mergeable_state", ""))

    def get_changed_files(self, repo, number):
        page = self._page(f"/repos/{repo}/pulls/{number}/files", None)
        return [f["filename"] for f in page.items if isinstance(f.get("filename"), str)]

    # -- writes (each guarded)
    def _guard(self) -> None:
        if not self.allow_writes:
            raise WriteDisabled("adapter constructed without allow_writes")

    def push_update(self, req: PushRequest) -> None:
        self._guard()
        if not (security.is_safe_repo(req.repository) and security.is_safe_branch(req.branch)
                and security.is_safe_sha(req.expected_head_sha) and security.is_safe_sha(req.new_head_sha)):
            raise GitHubError("unsafe push request")
        if self.push_runner is None:
            raise GitHubError("no push_runner configured (a local checkout is required to push)")
        self.push_runner(req)

    def reply_to_comment(self, repo, number, comment_id, body):
        self._guard()
        self._req("POST", f"/repos/{repo}/pulls/{number}/comments/{int(comment_id)}/replies", body={"body": body})

    def post_pr_comment(self, repo, number, body):
        self._guard()
        self._req("POST", f"/repos/{repo}/issues/{number}/comments", body={"body": body})


def git_push_command(req: PushRequest, remote: str = "origin") -> list[str]:
    """Argument vector for a lease-protected push of the SAME branch. Never forces blindly."""
    return ["git", "push", f"--force-with-lease=refs/heads/{req.branch}:{req.expected_head_sha}",
            remote, f"{req.new_head_sha}:refs/heads/{req.branch}"]


# --------------------------------------------------------------------------- raw event builders


def _actor_fields(obj: dict[str, Any]) -> dict[str, Any]:
    return {"user": obj.get("user") or {}, "author_association": obj.get("author_association", "NONE")}


def snapshot_to_raw(repo: str, number: int, snap: PRSnapshot, *, reviews: list[dict], review_comments: list[dict],
                    issue_comments: list[dict], check_runs: list[dict], changed_files: list[str],
                    known_head: str = "") -> list[RawEvent]:
    """Convert a consistent read of a PR into RawEvents with stable, object-based source IDs.

    Object-based IDs (not delivery IDs) make webhook and polling paths dedupe against each other.
    """
    out: list[RawEvent] = []
    ref = f"{repo}#{number}"
    if snap.head_sha and snap.head_sha != known_head:
        out.append(RawEvent("head", f"head:{snap.head_sha}", repo, number, f"poll:{ref}:head",
                            {"sha": snap.head_sha, "head_repository": snap.head_repo}))
    for r in sorted(reviews, key=lambda x: x.get("id", 0)):
        state = str(r.get("state", "")).upper()
        if state == "COMMENTED" and not (r.get("body") or "").strip():
            continue  # wrapper for inline comments; those arrive as review_comment events
        out.append(RawEvent("review", f"review:{r.get('id')}:{state}", repo, number, f"poll:{ref}:review/{r.get('id')}",
                            {**r, **_actor_fields(r)}))
    for c in sorted(review_comments, key=lambda x: x.get("id", 0)):
        out.append(RawEvent("review_comment", f"review_comment:{c.get('id')}", repo, number,
                            f"poll:{ref}:review_comment/{c.get('id')}", {**c, **_actor_fields(c)}))
    for c in sorted(issue_comments, key=lambda x: x.get("id", 0)):
        out.append(RawEvent("issue_comment", f"issue_comment:{c.get('id')}", repo, number,
                            f"poll:{ref}:issue_comment/{c.get('id')}", {**c, **_actor_fields(c), "on_pull_request": True}))
    for cr in sorted(check_runs, key=lambda x: x.get("id", 0)):
        out.append(check_run_raw(repo, number, cr, changed_files, f"poll:{ref}:check_run/{cr.get('id')}"))
    if snap.mergeable is False and not snap.merged and snap.state == "open":
        out.append(RawEvent("conflict", f"conflict:{snap.head_sha}", repo, number, f"poll:{ref}:mergeable", {"sha": snap.head_sha}))
    if snap.merged:
        out.append(RawEvent("merged", f"merged:{number}", repo, number, f"poll:{ref}:merged",
                            {"merge_commit_sha": snap.merge_commit_sha}))
    elif snap.state == "closed":
        out.append(RawEvent("closed", f"closed:{number}", repo, number, f"poll:{ref}:closed", {}))
    return out


def check_run_raw(repo: str, number: int, cr: dict[str, Any], changed_files: list[str], raw_ref: str) -> RawEvent:
    out = cr.get("output") or {}
    log = "\n".join(str(x) for x in (out.get("title"), out.get("summary"), out.get("text")) if x)
    status, conclusion = str(cr.get("status", "")), str(cr.get("conclusion") or "")
    return RawEvent("check_run", f"check_run:{cr.get('id')}:{status}:{conclusion}", repo, number, raw_ref,
                    {"id": cr.get("id"), "name": cr.get("name", ""), "status": status, "conclusion": conclusion,
                     "head_sha": cr.get("head_sha", ""), "started_at": cr.get("started_at"),
                     "log_excerpt": log, "changed_files": list(changed_files)})


def verify_webhook_signature(secret: str, body: bytes, signature_header: str) -> bool:
    if not secret or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def webhook_to_raw(event_name: str, payload: dict[str, Any], delivery_id: str = "") -> list[RawEvent]:
    """Map a GitHub webhook payload to RawEvents. Unrecognized shapes yield one 'unknown' event."""
    repo = str(((payload.get("repository") or {}).get("full_name")) or "")
    ref = f"webhook:{delivery_id or 'nodelivery'}:{event_name}"
    action = str(payload.get("action", ""))

    def unknown() -> list[RawEvent]:
        n = int(((payload.get("pull_request") or payload.get("issue") or {}).get("number")) or 0)
        return [RawEvent("unknown", f"unknown:{event_name}:{action}:{delivery_id}", repo, n, ref, {})]

    if event_name == "pull_request":
        pr = payload.get("pull_request") or {}
        n = int(pr.get("number") or payload.get("number") or 0)
        head = pr.get("head") or {}
        if action in {"opened", "synchronize", "reopened"}:
            return [RawEvent("head", f"head:{head.get('sha', '')}", repo, n, ref,
                             {"sha": head.get("sha", ""), "head_repository": (head.get("repo") or {}).get("full_name", "")})]
        if action == "closed":
            if pr.get("merged"):
                return [RawEvent("merged", f"merged:{n}", repo, n, ref, {"merge_commit_sha": pr.get("merge_commit_sha") or ""})]
            return [RawEvent("closed", f"closed:{n}", repo, n, ref, {})]
        return unknown()
    if event_name == "pull_request_review" and action in {"submitted", "edited", "dismissed"}:
        rv, n = payload.get("review") or {}, int((payload.get("pull_request") or {}).get("number") or 0)
        state = "DISMISSED" if action == "dismissed" else str(rv.get("state", "")).upper()
        return [RawEvent("review", f"review:{rv.get('id')}:{state}", repo, n, ref, {**rv, "state": state, **_actor_fields(rv)})]
    if event_name == "pull_request_review_comment" and action == "created":
        c, n = payload.get("comment") or {}, int((payload.get("pull_request") or {}).get("number") or 0)
        return [RawEvent("review_comment", f"review_comment:{c.get('id')}", repo, n, ref, {**c, **_actor_fields(c)})]
    if event_name == "issue_comment" and action == "created":
        c, issue = payload.get("comment") or {}, payload.get("issue") or {}
        return [RawEvent("issue_comment", f"issue_comment:{c.get('id')}", repo, int(issue.get("number") or 0), ref,
                         {**c, **_actor_fields(c), "on_pull_request": "pull_request" in issue})]
    if event_name == "check_run":
        cr = payload.get("check_run") or {}
        return [check_run_raw(repo, int(p.get("number") or 0), cr, [], ref) for p in (cr.get("pull_requests") or [])
                if isinstance(p, dict)] or unknown()
    return unknown()
