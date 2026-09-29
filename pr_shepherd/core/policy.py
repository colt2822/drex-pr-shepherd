"""Configurable policy. Conservative defaults; nothing here grants merge or payout authority."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping, Optional


def _csv(value: Optional[str], default: frozenset[str]) -> frozenset[str]:
    if value is None or not value.strip():
        return default
    return frozenset(p.strip() for p in value.split(",") if p.strip())


def _flag(value: Optional[str], default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Policy:
    max_revision_rounds: int = 3
    max_ci_repair_rounds: int = 3
    max_consecutive_unknown_failures: int = 3

    trusted_associations: frozenset[str] = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
    self_logins: frozenset[str] = frozenset()
    allowed_url_hosts: frozenset[str] = frozenset({"github.com"})

    preferred_worker: str = "codex"
    fallback_worker: str = "claude"

    # Feedback text that trips an injection heuristic is escalated to a human instead of routed.
    hold_suspicious_feedback: bool = True
    allow_factual_replies: bool = False
    reply_disclosure: str = "Automated update from Drex PR Shepherd: "

    # EXPERIMENTAL, embedding API only; not settable from the environment or CLI in v0.1.
    # Writes are recorded in the outbox and only executed when this is True AND the adapter allows it.
    live_writes: bool = False

    # Polling
    active_interval_s: float = 60.0
    quiet_base_interval_s: float = 300.0
    quiet_max_interval_s: float = 3600.0
    settlement_base_interval_s: float = 900.0
    settlement_max_interval_s: float = 21600.0
    error_base_interval_s: float = 30.0
    error_max_interval_s: float = 1800.0
    rate_limit_floor: int = 10
    max_prs_per_tick: int = 25

    nonactionable_stall_s: float = 86400.0
    max_text_chars: int = 4000

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Policy":
        e = os.environ if env is None else env
        d = cls()
        return cls(
            max_revision_rounds=int(e.get("PR_SHEPHERD_MAX_REVISION_ROUNDS", d.max_revision_rounds)),
            max_ci_repair_rounds=int(e.get("PR_SHEPHERD_MAX_CI_REPAIR_ROUNDS", d.max_ci_repair_rounds)),
            max_consecutive_unknown_failures=int(
                e.get("PR_SHEPHERD_MAX_CONSECUTIVE_UNKNOWN_FAILURES", d.max_consecutive_unknown_failures)
            ),
            trusted_associations=_csv(e.get("PR_SHEPHERD_TRUSTED_ASSOCIATIONS"), d.trusted_associations),
            self_logins=_csv(e.get("PR_SHEPHERD_SELF_LOGINS"), d.self_logins),
            preferred_worker=e.get("PR_SHEPHERD_PREFERRED_WORKER", d.preferred_worker),
            fallback_worker=e.get("PR_SHEPHERD_FALLBACK_WORKER", d.fallback_worker),
            allow_factual_replies=_flag(e.get("PR_SHEPHERD_ALLOW_FACTUAL_REPLIES"), d.allow_factual_replies),
        )
