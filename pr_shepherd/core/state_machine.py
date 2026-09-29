"""Explicit state machine. MERGED, APPROVED, SUBMITTED and PAID are separate facts."""
from __future__ import annotations

from .dedupe import feedback_from_event
from typing import Optional

from .models import (
    IN_FLIGHT_STATES,
    POST_MERGE_STATES,
    TERMINAL_STATES,
    CIState,
    EventType,
    MergeState,
    ReviewState,
    ShepherdEvent,
    State,
    WatchedPR,
)

S = State
_ANY_LIVE = {S.WATCHING, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED, S.MAINTAINER_RESPONSE_REQUIRED, S.REPAIR_QUEUED,
             S.REPAIRING, S.REVERIFYING, S.READY_TO_UPDATE, S.AWAITING_REVIEW, S.APPROVED, S.BLOCKED, S.HUMAN_ACTION_REQUIRED}
_END = {S.MERGED, S.CLOSED, S.HUMAN_ACTION_REQUIRED, S.BLOCKED}


def _t(*extra: State) -> set[State]:
    return set(extra) | _END

TRANSITIONS: dict[State, set[State]] = {
    S.WATCHING: _t(S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED, S.MAINTAINER_RESPONSE_REQUIRED, S.REPAIR_QUEUED, S.AWAITING_REVIEW, S.APPROVED),
    S.CI_FAILED: _t(S.WATCHING, S.REPAIR_QUEUED, S.REVIEW_CHANGES_REQUESTED, S.MAINTAINER_RESPONSE_REQUIRED, S.AWAITING_REVIEW),
    S.REVIEW_CHANGES_REQUESTED: _t(S.WATCHING, S.CI_FAILED, S.REPAIR_QUEUED, S.APPROVED, S.MAINTAINER_RESPONSE_REQUIRED),
    S.MAINTAINER_RESPONSE_REQUIRED: _t(S.WATCHING, S.AWAITING_REVIEW, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED, S.REPAIR_QUEUED, S.APPROVED),
    S.REPAIR_QUEUED: _t(S.REPAIRING, S.WATCHING, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED),
    S.REPAIRING: _t(S.REVERIFYING, S.REPAIR_QUEUED, S.WATCHING, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED),
    S.REVERIFYING: _t(S.READY_TO_UPDATE, S.REPAIR_QUEUED, S.WATCHING, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED),
    S.READY_TO_UPDATE: _t(S.AWAITING_REVIEW, S.WATCHING, S.REPAIR_QUEUED, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED),
    S.AWAITING_REVIEW: _t(S.WATCHING, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED, S.MAINTAINER_RESPONSE_REQUIRED, S.APPROVED, S.REPAIR_QUEUED),
    S.APPROVED: _t(S.WATCHING, S.AWAITING_REVIEW, S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED, S.MAINTAINER_RESPONSE_REQUIRED, S.REPAIR_QUEUED),
    S.BLOCKED: _t(S.WATCHING, S.REPAIR_QUEUED),
    S.HUMAN_ACTION_REQUIRED: _t(S.WATCHING, S.REPAIR_QUEUED),
    S.MERGED: {S.SETTLEMENT_PENDING},
    S.SETTLEMENT_PENDING: {S.ACCEPTED_PAYOUT, S.REALIZED_REVENUE},
    S.ACCEPTED_PAYOUT: {S.REALIZED_REVENUE},
    S.CLOSED: set(),
    S.REALIZED_REVENUE: set(),
}


class IllegalTransition(Exception):
    pass


Transition = tuple[State, State, str]


def transition(pr: WatchedPR, new: State, reason: str, log: list[Transition]) -> WatchedPR:
    if new == pr.state:
        return pr
    if new not in TRANSITIONS.get(pr.state, set()):
        raise IllegalTransition(f"{pr.state.value} -> {new.value} ({reason})")
    log.append((pr.state, new, reason))
    return pr.copy(state=new)


def _free(pr: WatchedPR) -> bool:
    """True when incoming feedback may change the visible state."""
    return pr.state not in IN_FLIGHT_STATES and pr.state not in (S.HUMAN_ACTION_REQUIRED, S.BLOCKED)


def apply_event(
    pr: WatchedPR, ev: ShepherdEvent, ci_agg: Optional[CIState] = None
) -> tuple[WatchedPR, list[Transition]]:
    """Pure fold of one event into the aggregate. Router/budget logic lives elsewhere.

    `ci_agg` is the aggregate CI state for the current head computed from per-check history
    (so one passing check cannot mask another failing check)."""
    log: list[Transition] = []
    t = ev.type
    p = ev.payload
    pr = pr.copy(last_event_at=max(pr.last_event_at, ev.timestamp))

    if pr.state in TERMINAL_STATES or pr.state in POST_MERGE_STATES:
        return pr, log

    if t == EventType.PR_MERGED:
        pr = pr.copy(merge_state=MergeState.MERGED)
        return transition(pr, S.MERGED, "pr merged (not payment)", log), log
    if t == EventType.PR_CLOSED:
        pr = pr.copy(merge_state=MergeState.CLOSED)
        return transition(pr, S.CLOSED, "pr closed without merge", log), log

    if t in (EventType.CI_STARTED, EventType.CI_PASSED, EventType.CI_FAILED):
        agg = ci_agg or {EventType.CI_STARTED: CIState.RUNNING, EventType.CI_PASSED: CIState.PASSING,
                         EventType.CI_FAILED: CIState.FAILING}[t]
        pr = pr.copy(ci_state=agg)
        if agg == CIState.PASSING:
            pr = pr.copy(nonactionable_streak=0)
        if agg == CIState.FAILING and _free(pr) and pr.state not in (S.CI_FAILED, S.REVIEW_CHANGES_REQUESTED):
            pr = transition(pr, S.CI_FAILED, "ci failed", log)
        elif agg != CIState.FAILING and pr.state == S.CI_FAILED:
            pr = transition(pr, S.WATCHING, "ci no longer failing", log)
        return pr, log

    if t == EventType.REVIEW_CHANGES_REQUESTED and p.get("actor_trusted"):
        pr = pr.copy(review_state=ReviewState.CHANGES_REQUESTED)
        if _free(pr):
            pr = transition(pr, S.REVIEW_CHANGES_REQUESTED, "changes requested", log)
        return pr, log
    if t == EventType.REVIEW_APPROVED and p.get("actor_trusted"):
        pr = pr.copy(review_state=ReviewState.APPROVED)
        if pr.state in (S.WATCHING, S.AWAITING_REVIEW, S.REVIEW_CHANGES_REQUESTED, S.MAINTAINER_RESPONSE_REQUIRED):
            pr = transition(pr, S.APPROVED, "review approved (not merged, not paid)", log)
        return pr, log
    if t in (EventType.REVIEW_COMMENT, EventType.PR_COMMENT):
        if feedback_from_event(ev) is not None and _free(pr):
            if pr.review_state == ReviewState.NONE:
                pr = pr.copy(review_state=ReviewState.COMMENTED)
            pr = transition(pr, S.REVIEW_CHANGES_REQUESTED, "actionable maintainer feedback", log)
        return pr, log
    if t == EventType.MAINTAINER_QUESTION:
        if pr.state in (S.WATCHING, S.AWAITING_REVIEW, S.APPROVED):
            pr = transition(pr, S.MAINTAINER_RESPONSE_REQUIRED, "maintainer question", log)
        return pr, log

    if t == EventType.PR_UPDATED:
        sha = p.get("head_sha", "")
        if sha and sha != pr.head_sha:
            shas = pr.known_shas if pr.head_sha in pr.known_shas else [*pr.known_shas, pr.head_sha]
            pr = pr.copy(head_sha=sha, known_shas=[*shas, sha][-50:], ci_state=CIState.NONE)
            if pr.state == S.CI_FAILED:
                pr = transition(pr, S.WATCHING, "new head commit", log)
        return pr, log
    if t == EventType.CONFLICT_DETECTED:
        return pr.copy(merge_state=MergeState.CONFLICTING), log
    # ISSUE_COMMENT, settlement signals (unverified), UNKNOWN_EVENT: recorded, no state change.
    return pr, log
