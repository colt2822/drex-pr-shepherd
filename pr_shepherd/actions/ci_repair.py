"""CI-repair / conflict-repair contracts. Same mission, same PR, same branch, current head."""
from __future__ import annotations

from ..core import security
from ..core.models import RevisionContract, ShepherdEvent, TaskKind, WatchedPR
from ..core.policy import Policy
from .common import INSTRUCTIONS, previous_verification


def build_ci_repair_contract(pr: WatchedPR, failures: list[ShepherdEvent], round_no: int, policy: Policy,
                             kind: TaskKind = TaskKind.CI_REPAIR) -> RevisionContract:
    files: list[str] = []
    ci_evidence = []
    for e in failures:
        p = e.payload
        for item in p.get("classifier_evidence", []):
            if isinstance(item, str) and item.startswith("changed_files="):
                for f in item.split("=", 1)[1].split(","):
                    f = security.safe_relative_path(f)
                    if f and f not in files:
                        files.append(f)
        ci_evidence.append({
            "event_id": e.event_id,
            "check_name": p.get("check_name", ""),
            "conclusion": p.get("conclusion", ""),
            "failure_class": p.get("failure_class", ""),
            "classifier_evidence": p.get("classifier_evidence", []),
            "head_sha": p.get("head_sha", ""),
            "untrusted_evidence": security.quote_untrusted(p.get("log_excerpt", ""), source=f"ci:{p.get('check_name', '')}",
                                                           max_chars=1500, allowed_hosts=policy.allowed_url_hosts),
        })
    if kind == TaskKind.CONFLICT_REPAIR:
        ci_evidence = [{"conflict_with_base_branch": pr.base_branch, "head_sha": pr.head_sha}]
    return RevisionContract(
        contract_id=f"{pr.task_id}#{'c' if kind == TaskKind.CONFLICT_REPAIR else 'ci'}{round_no}",
        mission_id=pr.mission_id, task_id=pr.task_id, kind=kind, round_no=round_no,
        repository=pr.repository, pr_number=pr.pr_number, branch=pr.head_branch, head_sha=pr.head_sha,
        reviewers=(), comment_ids=(), affected_files=tuple(files),
        requested_behavior=(), ci_evidence={"failures": ci_evidence},
        acceptance_contract=pr.acceptance_contract, previous_verification=previous_verification(pr),
        instructions=INSTRUCTIONS,
    )
