"""Review-feedback revision contracts: one bounded round groups related comments."""
from __future__ import annotations

from ..core import security
from ..core.models import FeedbackItem, RevisionContract, TaskKind, WatchedPR
from ..core.policy import Policy
from .common import INSTRUCTIONS, previous_verification


def build_revision_contract(pr: WatchedPR, feedback: tuple[FeedbackItem, ...], round_no: int, policy: Policy) -> RevisionContract:
    files: list[str] = []
    behavior = []
    for f in feedback:
        p = security.safe_relative_path(f.path)
        if p and p not in files:
            files.append(p)
        behavior.append({
            "comment_id": f.comment_id,
            "reviewer": f.actor,
            "path": p,
            "line": f.line,
            "kind": f.kind,
            "untrusted_evidence": security.quote_untrusted(f.body or "(no text)", source=f"review:{f.comment_id}",
                                                           allowed_hosts=policy.allowed_url_hosts),
        })
    return RevisionContract(
        contract_id=f"{pr.task_id}#rev{round_no}", mission_id=pr.mission_id, task_id=pr.task_id,
        kind=TaskKind.REVIEW_REVISION, round_no=round_no, repository=pr.repository, pr_number=pr.pr_number,
        branch=pr.head_branch, head_sha=pr.head_sha,
        reviewers=tuple(sorted({f.actor for f in feedback})), comment_ids=tuple(f.comment_id for f in feedback),
        affected_files=tuple(files), requested_behavior=tuple(behavior), ci_evidence={},
        acceptance_contract=pr.acceptance_contract, previous_verification=previous_verification(pr),
        instructions=INSTRUCTIONS,
    )
