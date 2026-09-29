"""Submission adapter boundary.

The "submission source" is whatever system opened the PR (a bounty pipeline, an agent
orchestrator, a CI bot). This module defines the narrow contract the shepherd needs: input
on watch start, outbound lifecycle events, and a settlement-evidence hook. There is
deliberately NO method to create opportunities, missions, or PRs: PR feedback never spawns
new missions. Integrate a specific system by subclassing SubmissionAdapter.
"""
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.models import SettlementEvidence


class SubmissionEventType(str, enum.Enum):
    PR_WATCH_STARTED = "PR_WATCH_STARTED"
    REVISION_REQUIRED = "REVISION_REQUIRED"
    REVISION_VERIFIED = "REVISION_VERIFIED"
    PR_MERGED = "PR_MERGED"
    PR_CLOSED = "PR_CLOSED"
    BOUNTY_ACCEPTED_SIGNAL = "BOUNTY_ACCEPTED_SIGNAL"
    PAYOUT_SIGNAL = "PAYOUT_SIGNAL"


# Only these may carry platform evidence; everything else is a lifecycle fact from GitHub state.
EVIDENCE_REQUIRED = frozenset({SubmissionEventType.BOUNTY_ACCEPTED_SIGNAL, SubmissionEventType.PAYOUT_SIGNAL})


@dataclass(frozen=True)
class Submission:
    mission_id: str
    task_id: str
    submission_receipt_id: str
    artifact_digest: str
    pr_url: str
    expected_payout: Optional[dict[str, Any]] = None
    acceptance_contract: dict[str, Any] = field(default_factory=dict)
    verification_summary: dict[str, Any] = field(default_factory=dict)  # {"tests": [...], "summary": "..."}


@dataclass(frozen=True)
class SubmissionEvent:
    type: SubmissionEventType
    mission_id: str
    task_id: str
    shepherd_id: str
    pr_url: str
    idem_key: str
    data: dict[str, Any] = field(default_factory=dict)
    evidence: Optional[SettlementEvidence] = None

    def __post_init__(self) -> None:
        if self.type in EVIDENCE_REQUIRED and self.evidence is None:
            raise ValueError(f"{self.type.value} requires platform settlement evidence")


class SubmissionAdapter(ABC):
    @abstractmethod
    def emit(self, event: SubmissionEvent) -> None: ...

    def fetch_settlement_evidence(self, mission_id: str, pr_url: str) -> list[SettlementEvidence]:
        """Bounty-platform hook. Default: no evidence available."""
        return []


class InMemorySubmissionAdapter(SubmissionAdapter):
    """Fake for tests and demo."""

    def __init__(self) -> None:
        self.events: list[SubmissionEvent] = []
        self.evidence: list[SettlementEvidence] = []

    def emit(self, event: SubmissionEvent) -> None:
        self.events.append(event)

    def fetch_settlement_evidence(self, mission_id: str, pr_url: str) -> list[SettlementEvidence]:
        return list(self.evidence)

    def types(self) -> list[str]:
        return [e.type.value for e in self.events]


class LogOnlySubmissionAdapter(SubmissionAdapter):
    """Default for the CLI: events are kept in the shepherd outbox only."""

    def emit(self, event: SubmissionEvent) -> None:  # pragma: no cover - trivial
        return None
