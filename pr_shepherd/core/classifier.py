"""Deterministic normalization of source events and CI-failure classification.

No model calls. Same input always yields the same output.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from . import security
from .models import EventType, FailureClass, RawEvent, ShepherdEvent, digest, make_shepherd_id
from .policy import Policy

_QUESTION_RE = re.compile(r"(\?\s*$|\?\s|^\s*(why|what|how|could you|can you|would you|does|is there|did you)\b)", re.I | re.M)
_REQUEST_RE = re.compile(r"\b(please|should|needs? to|must|rename|remove|add|use|change|fix|replace|instead|don'?t|do not)\b", re.I)
_ACCEPT_RE = re.compile(r"(?i)\b(bounty|reward)\b[^\n]{0,80}\b(accepted|awarded|approved)\b|\b(accepted|awarded)\b[^\n]{0,40}\b(bounty|reward)\b")
_PAYOUT_RE = re.compile(r"(?i)\b(payout|payment)\b[^\n]{0,60}\b(sent|issued|released|completed|processed)\b|\bhas been paid\b|\bwe(?:'ve| have) paid\b")

_SUCCESS = {"success", "neutral", "skipped"}
_FAILURE = {"failure", "timed_out", "cancelled", "startup_failure", "action_required"}
_STARTED = {"queued", "in_progress", "pending", "waiting", "requested"}


def parse_ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def is_bot(user: dict[str, Any]) -> bool:
    login = str(user.get("login", ""))
    return user.get("type") == "Bot" or login.endswith("[bot]")


def is_trusted_actor(association: str, bot: bool, login: str, policy: Policy) -> bool:
    return (not bot) and association in policy.trusted_associations and login not in policy.self_logins


def looks_like_question(text: str) -> bool:
    return bool(_QUESTION_RE.search(text or ""))


def looks_like_request(text: str) -> bool:
    return bool(_REQUEST_RE.search(text or ""))


def normalize(raw: RawEvent, policy: Policy) -> ShepherdEvent:
    """Map a source-shaped RawEvent to a canonical ShepherdEvent. Never raises on odd input."""
    data = raw.data if isinstance(raw.data, dict) else {}
    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    login = security.clean_text(user.get("login", data.get("actor", "")), 100)
    assoc = str(data.get("author_association", "NONE"))
    bot = is_bot(user) if user else bool(data.get("actor_is_bot", False))
    trusted = is_trusted_actor(assoc, bot, login, policy)
    body_raw = str(data.get("body") or "")
    payload: dict[str, Any] = {"actor_association": assoc, "actor_is_bot": bot, "actor_trusted": trusted}
    etype = EventType.UNKNOWN_EVENT
    kind = raw.kind

    def add_body() -> None:
        payload["body"] = security.sanitize_untrusted(body_raw, max_chars=policy.max_text_chars, allowed_hosts=policy.allowed_url_hosts)
        payload["flags"] = list(security.injection_flags(body_raw))
        payload["body_digest"] = digest(re.sub(r"\s+", " ", body_raw.strip().lower()))

    if kind == "head":
        etype = EventType.PR_UPDATED
        payload.update(head_sha=str(data.get("sha", "")), head_repository=str(data.get("head_repository", "")))
    elif kind == "merged":
        etype = EventType.PR_MERGED
        payload.update(merge_commit_sha=str(data.get("merge_commit_sha", "")))
    elif kind == "closed":
        etype = EventType.PR_CLOSED
    elif kind == "conflict":
        etype = EventType.CONFLICT_DETECTED
        payload.update(head_sha=str(data.get("sha", "")))
    elif kind == "review":
        state = str(data.get("state", "")).upper()
        add_body()
        payload.update(review_id=str(data.get("id", "")), commit_id=str(data.get("commit_id", "")), comment_id=f"review:{data.get('id', '')}")
        if state == "CHANGES_REQUESTED":
            etype = EventType.REVIEW_CHANGES_REQUESTED
        elif state == "APPROVED":
            etype = EventType.REVIEW_APPROVED
        elif state in {"COMMENTED", "DISMISSED"}:
            etype = EventType.REVIEW_COMMENT
            payload["review_state"] = state
    elif kind == "review_comment":
        etype = EventType.REVIEW_COMMENT
        add_body()
        payload.update(
            comment_id=f"rc:{data.get('id', '')}",
            path=security.safe_relative_path(data.get("path")),
            line=data.get("line") if isinstance(data.get("line"), int) else None,
            commit_id=str(data.get("commit_id", "")),
            in_reply_to=str(data.get("in_reply_to_id", "") or ""),
            review_id=str(data.get("pull_request_review_id", "") or ""),
            inline=True,
        )
    elif kind == "issue_comment":
        add_body()
        payload["comment_id"] = f"ic:{data.get('id', '')}"
        on_pr = bool(data.get("on_pull_request", True))
        if trusted and _ACCEPT_RE.search(body_raw):
            etype = EventType.BOUNTY_ACCEPTED_SIGNAL
        elif trusted and _PAYOUT_RE.search(body_raw):
            etype = EventType.PAYOUT_SIGNAL
        elif not on_pr:
            etype = EventType.ISSUE_COMMENT
        elif trusted and looks_like_question(body_raw):
            etype = EventType.MAINTAINER_QUESTION
        else:
            etype = EventType.PR_COMMENT
    elif kind == "check_run":
        status = str(data.get("status", "")).lower()
        conclusion = str(data.get("conclusion") or "").lower()
        payload.update(
            check_name=security.clean_text(data.get("name", ""), 200),
            check_status=status,
            conclusion=conclusion,
            head_sha=str(data.get("head_sha", "")),
            check_run_id=str(data.get("id", "")),
        )
        if status == "completed" and conclusion in _SUCCESS:
            etype = EventType.CI_PASSED
        elif status == "completed" and conclusion in _FAILURE:
            etype = EventType.CI_FAILED
            log = security.clean_text(data.get("log_excerpt", ""), policy.max_text_chars)
            fc, evidence = classify_ci_failure(
                conclusion=conclusion,
                log_text=log,
                changed_files=[f for f in data.get("changed_files", []) if isinstance(f, str)],
                base_also_failing=bool(data.get("base_also_failing", False)),
            )
            payload.update(failure_class=fc.value, classifier_evidence=evidence, log_excerpt=log[:1500])
        elif status in _STARTED:
            etype = EventType.CI_STARTED
    elif kind == "platform_signal":
        # Text-derived only: never platform-verified.
        etype = EventType.PAYOUT_SIGNAL if data.get("signal") == "payout" else EventType.BOUNTY_ACCEPTED_SIGNAL

    ts = parse_ts(data.get("created_at") or data.get("submitted_at") or data.get("started_at") or data.get("updated_at"))
    payload_digest = digest({"kind": kind, "source_event_id": raw.source_event_id, "data": data})
    event_id = "ev_" + digest([raw.repository.lower(), raw.pr_number, raw.source_event_id])[7:23]
    return ShepherdEvent(
        event_id=event_id,
        source_event_id=raw.source_event_id,
        shepherd_id=make_shepherd_id(raw.repository, raw.pr_number),
        repository=raw.repository,
        pr_number=raw.pr_number,
        actor=login,
        timestamp=ts,
        raw_ref=raw.raw_ref,
        type=etype,
        payload_digest=payload_digest,
        payload=payload,
        trust="untrusted",
    )


# ---------------------------------------------------------------- CI classification

_ENV_PATTERNS = [
    r"could not resolve dependenc", r"eresolve", r"npm err! 404", r"could not find a version that satisfies",
    r"no matching distribution", r"no space left on device", r"command not found", r"enotfound",
    r"temporary failure in name resolution", r"unable to access .*(certificate|ssl)", r"docker: error response",
    r"cannot allocate memory", r"out of memory",
]
_UPSTREAM_PATTERNS = [
    r"\b50[234] (bad gateway|service unavailable|gateway time-?out)", r"registry.*(unavailable|down)",
    r"rate limit(ed)? exceeded", r"api rate limit", r"runner has received a shutdown signal",
    r"the hosted runner .* lost communication", r"github (is|has) .*(outage|degraded)",
]
_FLAKY_PATTERNS = [
    r"connection reset by peer", r"etimedout", r"econnreset", r"read timed out", r"resource temporarily unavailable",
    r"flaky", r"passed on retry", r"retry.*succeeded", r"socket hang up",
]
_PATCH_PATTERNS = [
    r"assertionerror", r"syntaxerror", r"typeerror", r"nameerror", r"importerror", r"attributeerror", r"error ts\d+",
    r"^failed ", r"\bFAILED\b", r"error\[E\d+\]", r"cannot find symbol", r"undefined reference", r"lint", r"mypy", r"expected .* (got|but)",
    r"--- fail:", r"test failed", r"compilation (error|failed)",
]
_PATH_REF = re.compile(r"(?:^|[\s'\"(])((?:[A-Za-z0-9_.\-]+/)*[A-Za-z0-9_.\-]+\.[A-Za-z0-9]{1,6})(?:[:,\"')\s]|$)", re.M)


def _first(patterns: list[str], text: str) -> Optional[str]:
    for p in patterns:
        m = re.search(p, text, re.I | re.M)
        if m:
            return p
    return None


def referenced_paths(log_text: str) -> list[str]:
    out: list[str] = []
    for m in _PATH_REF.finditer(log_text):
        p = security.safe_relative_path(m.group(1))
        if p and p not in out:
            out.append(p)
    return out


def classify_ci_failure(
    *, conclusion: str, log_text: str, changed_files: list[str], base_also_failing: bool = False
) -> tuple[FailureClass, list[str]]:
    """Conservative classifier. Infra/flaky evidence wins over patch evidence so that a
    transient failure never triggers an automatic code rewrite."""
    text = log_text or ""
    if conclusion == "startup_failure":
        return FailureClass.UPSTREAM_FAILURE, ["conclusion=startup_failure"]
    if hit := _first(_ENV_PATTERNS, text):
        return FailureClass.DEPENDENCY_ENVIRONMENT_FAILURE, [f"env_pattern={hit}"]
    if hit := _first(_UPSTREAM_PATTERNS, text):
        return FailureClass.UPSTREAM_FAILURE, [f"upstream_pattern={hit}"]
    if conclusion == "timed_out":
        return FailureClass.FLAKY_FAILURE, ["conclusion=timed_out"]
    if hit := _first(_FLAKY_PATTERNS, text):
        return FailureClass.FLAKY_FAILURE, [f"flaky_pattern={hit}"]
    if base_also_failing:
        return FailureClass.UPSTREAM_FAILURE, ["base_branch_also_failing"]
    if conclusion == "cancelled":
        return FailureClass.UNKNOWN_FAILURE, ["conclusion=cancelled"]
    patch_hit = _first(_PATCH_PATTERNS, text)
    changed = {c for c in changed_files if security.safe_relative_path(c)}
    refs = [p for p in referenced_paths(text) if p in changed]
    if patch_hit and refs:
        return FailureClass.PATCH_CAUSED_FAILURE, [f"patch_pattern={patch_hit}", "changed_files=" + ",".join(sorted(refs)[:10])]
    return FailureClass.UNKNOWN_FAILURE, ["no_deterministic_evidence"]
