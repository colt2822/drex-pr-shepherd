"""Poll scheduling: adaptive intervals, exponential error backoff, rate-limit awareness.

Pure functions of (record, now); no sleeping and no I/O. Jitter is derived from a hash so
runs are reproducible.
"""
from __future__ import annotations

import hashlib
from typing import Any, Optional

from .models import IN_FLIGHT_STATES, POST_MERGE_STATES, TERMINAL_STATES, CIState, State, WatchedPR
from .policy import Policy

_ACTIVE = IN_FLIGHT_STATES | {State.CI_FAILED, State.REVIEW_CHANGES_REQUESTED, State.MAINTAINER_RESPONSE_REQUIRED}


def _jitter(key: str, n: int, span: float) -> float:
    h = int(hashlib.sha256(f"{key}:{n}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return span * 0.1 * h


def priority(pr: WatchedPR) -> int:
    """Lower runs first. Active PRs before quiet ones."""
    if pr.state in _ACTIVE or pr.ci_state == CIState.RUNNING:
        return 0
    if pr.state in POST_MERGE_STATES:
        return 2
    return 1


def schedule_next(
    pr: WatchedPR,
    now: float,
    policy: Policy,
    *,
    had_activity: bool,
    error: bool = False,
    rate_limit_reset: Optional[float] = None,
) -> tuple[Optional[float], dict[str, Any]]:
    """Return (next_check_at, updated backoff_state). None means: stop polling."""
    bs = dict(pr.backoff_state)
    if pr.state in TERMINAL_STATES:
        return None, bs
    if error:
        bs["failures"] = int(bs.get("failures", 0)) + 1
        delay = min(policy.error_max_interval_s, policy.error_base_interval_s * 2 ** (bs["failures"] - 1))
    else:
        bs["failures"] = 0
        bs["quiet_polls"] = 0 if had_activity else int(bs.get("quiet_polls", 0)) + 1
        if pr.state in _ACTIVE or pr.ci_state == CIState.RUNNING:
            delay = policy.active_interval_s
        elif pr.state in POST_MERGE_STATES:
            delay = min(policy.settlement_max_interval_s, policy.settlement_base_interval_s * 2 ** min(bs["quiet_polls"], 10))
        else:
            delay = min(policy.quiet_max_interval_s, policy.quiet_base_interval_s * 2 ** min(bs["quiet_polls"], 10))
    delay += _jitter(pr.shepherd_id, int(bs.get("failures", 0)) + int(bs.get("quiet_polls", 0)), delay)
    nxt = now + delay
    if rate_limit_reset is not None:
        nxt = max(nxt, rate_limit_reset + 1.0)
    return nxt, bs


def is_due(pr: WatchedPR, now: float) -> bool:
    return pr.next_check_at is not None and pr.next_check_at <= now and pr.state not in TERMINAL_STATES
