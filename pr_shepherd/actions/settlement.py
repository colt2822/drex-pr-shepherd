"""Settlement watching. Merge is progress, not payment. Only platform evidence moves settlement."""
from __future__ import annotations

from typing import Optional, Protocol

from ..core.models import SettlementEvidence, SettlementStage, WatchedPR

RANK = {SettlementStage.NONE: 0, SettlementStage.SUBMITTED_PAYOUT: 1, SettlementStage.ACCEPTED_PAYOUT: 2,
        SettlementStage.REALIZED_REVENUE: 3}


class SettlementProbe(Protocol):
    """Bounty-platform-specific hook. Implementations must return only facts observed on the platform."""

    def fetch_settlement_evidence(self, mission_id: str, pr_url: str) -> list[SettlementEvidence]: ...


def new_evidence(pr: WatchedPR, evidence: list[SettlementEvidence]) -> list[SettlementEvidence]:
    """Evidence that advances the stage, ascending, one per stage. Text-only stages are excluded."""
    out, seen = [], RANK[pr.settlement_stage]
    for ev in sorted(evidence, key=lambda e: (RANK[e.stage], e.observed_at)):
        if ev.stage in (SettlementStage.ACCEPTED_PAYOUT, SettlementStage.REALIZED_REVENUE) and RANK[ev.stage] > seen:
            if not ev.evidence_ref or not ev.platform:
                continue
            out.append(ev)
            seen = RANK[ev.stage]
    return out
