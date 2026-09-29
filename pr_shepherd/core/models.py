"""Canonical data model. Pure data; no I/O."""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Optional


class State(str, enum.Enum):
    WATCHING = "WATCHING"
    CI_FAILED = "CI_FAILED"
    REVIEW_CHANGES_REQUESTED = "REVIEW_CHANGES_REQUESTED"
    MAINTAINER_RESPONSE_REQUIRED = "MAINTAINER_RESPONSE_REQUIRED"
    REPAIR_QUEUED = "REPAIR_QUEUED"
    REPAIRING = "REPAIRING"
    REVERIFYING = "REVERIFYING"
    READY_TO_UPDATE = "READY_TO_UPDATE"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    APPROVED = "APPROVED"
    MERGED = "MERGED"
    CLOSED = "CLOSED"
    SETTLEMENT_PENDING = "SETTLEMENT_PENDING"
    ACCEPTED_PAYOUT = "ACCEPTED_PAYOUT"
    REALIZED_REVENUE = "REALIZED_REVENUE"
    BLOCKED = "BLOCKED"
    HUMAN_ACTION_REQUIRED = "HUMAN_ACTION_REQUIRED"


TERMINAL_STATES = frozenset({State.CLOSED, State.REALIZED_REVENUE})
IN_FLIGHT_STATES = frozenset({State.REPAIR_QUEUED, State.REPAIRING, State.REVERIFYING, State.READY_TO_UPDATE})
POST_MERGE_STATES = frozenset({State.MERGED, State.SETTLEMENT_PENDING, State.ACCEPTED_PAYOUT, State.REALIZED_REVENUE})


class CIState(str, enum.Enum):
    NONE = "NONE"
    RUNNING = "RUNNING"
    PASSING = "PASSING"
    FAILING = "FAILING"


class ReviewState(str, enum.Enum):
    NONE = "NONE"
    COMMENTED = "COMMENTED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    APPROVED = "APPROVED"


class MergeState(str, enum.Enum):
    OPEN = "OPEN"
    CONFLICTING = "CONFLICTING"
    MERGED = "MERGED"
    CLOSED = "CLOSED"


class SettlementStage(str, enum.Enum):
    """Distinct economic facts. Order matters only for display."""
    NONE = "NONE"
    SUBMITTED_PAYOUT = "SUBMITTED_PAYOUT"
    ACCEPTED_PAYOUT = "ACCEPTED_PAYOUT"
    REALIZED_REVENUE = "REALIZED_REVENUE"


class EventType(str, enum.Enum):
    CI_STARTED = "CI_STARTED"
    CI_PASSED = "CI_PASSED"
    CI_FAILED = "CI_FAILED"
    REVIEW_COMMENT = "REVIEW_COMMENT"
    REVIEW_CHANGES_REQUESTED = "REVIEW_CHANGES_REQUESTED"
    REVIEW_APPROVED = "REVIEW_APPROVED"
    ISSUE_COMMENT = "ISSUE_COMMENT"
    PR_COMMENT = "PR_COMMENT"
    MAINTAINER_QUESTION = "MAINTAINER_QUESTION"
    PR_UPDATED = "PR_UPDATED"
    PR_MERGED = "PR_MERGED"
    PR_CLOSED = "PR_CLOSED"
    CONFLICT_DETECTED = "CONFLICT_DETECTED"
    BOUNTY_ACCEPTED_SIGNAL = "BOUNTY_ACCEPTED_SIGNAL"
    PAYOUT_SIGNAL = "PAYOUT_SIGNAL"
    UNKNOWN_EVENT = "UNKNOWN_EVENT"


class FailureClass(str, enum.Enum):
    PATCH_CAUSED_FAILURE = "PATCH_CAUSED_FAILURE"
    DEPENDENCY_ENVIRONMENT_FAILURE = "DEPENDENCY_ENVIRONMENT_FAILURE"
    UPSTREAM_FAILURE = "UPSTREAM_FAILURE"
    FLAKY_FAILURE = "FLAKY_FAILURE"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"


class Route(str, enum.Enum):
    NO_ACTION = "NO_ACTION"
    WAIT = "WAIT"
    ROUTE_CODEX = "ROUTE_CODEX"
    ROUTE_CLAUDE = "ROUTE_CLAUDE"
    RUN_VERIFIER = "RUN_VERIFIER"
    POST_FACTUAL_RESPONSE = "POST_FACTUAL_RESPONSE"
    SETTLEMENT_CHECK = "SETTLEMENT_CHECK"
    HUMAN_ACTION_REQUIRED = "HUMAN_ACTION_REQUIRED"


WORKER_ROUTES = frozenset({Route.ROUTE_CODEX, Route.ROUTE_CLAUDE})


class TaskKind(str, enum.Enum):
    CI_REPAIR = "CI_REPAIR"
    REVIEW_REVISION = "REVIEW_REVISION"
    CONFLICT_REPAIR = "CONFLICT_REPAIR"


class TaskStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    VERIFY_FAILED = "VERIFY_FAILED"
    WORKER_FAILED = "WORKER_FAILED"
    VERIFIED = "VERIFIED"  # verified, awaiting push (dry-run or write gate closed)
    STALE = "STALE"
    DONE = "DONE"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def digest(obj: Any) -> str:
    data = obj if isinstance(obj, str) else canonical_json(obj)
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def make_shepherd_id(repository: str, pr_number: int) -> str:
    return "shp_" + hashlib.sha256(f"{repository.lower()}#{pr_number}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class RawEvent:
    """A source-shaped event prior to normalization (from polling or a webhook)."""
    kind: str
    source_event_id: str
    repository: str
    pr_number: int
    raw_ref: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ShepherdEvent:
    event_id: str
    source_event_id: str
    shepherd_id: str
    repository: str
    pr_number: int
    actor: str
    timestamp: float
    raw_ref: str
    type: EventType
    payload_digest: str
    payload: dict[str, Any]
    # "untrusted": derived from GitHub text/API.  "platform_verified": produced only by
    # SettlementWatcher from bounty-platform evidence.
    trust: str = "untrusted"
    seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class WatchedPR:
    shepherd_id: str
    mission_id: str
    task_id: str
    repository: str
    pr_number: int
    pr_url: str
    head_branch: str
    head_sha: str
    base_branch: str
    state: State = State.WATCHING
    last_seen_at: float = 0.0
    last_event_at: float = 0.0
    submission_artifact_digest: str = ""
    verification_receipt_id: str = ""
    ci_state: CIState = CIState.NONE
    review_state: ReviewState = ReviewState.NONE
    merge_state: MergeState = MergeState.OPEN
    review_round: int = 0
    repair_round: int = 0
    next_check_at: Optional[float] = 0.0
    backoff_state: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0
    # Additions beyond the minimum record:
    head_repository: str = ""
    settlement_stage: SettlementStage = SettlementStage.NONE
    expected_payout: Optional[dict[str, Any]] = None
    acceptance_contract: dict[str, Any] = field(default_factory=dict)
    last_verification: dict[str, Any] = field(default_factory=dict)
    known_shas: list[str] = field(default_factory=list)
    nonactionable_streak: int = 0
    blocker: dict[str, Any] = field(default_factory=dict)
    resume_state: str = ""

    def copy(self, **changes: Any) -> "WatchedPR":
        return replace(self, **changes)


@dataclass(frozen=True)
class ResourceState:
    codex_available: bool = True
    claude_available: bool = True


@dataclass(frozen=True)
class RevisionBudget:
    revision_rounds_used: int
    revision_rounds_max: int
    ci_repairs_used: int
    ci_repairs_max: int
    nonactionable_streak: int
    nonactionable_max: int


@dataclass(frozen=True)
class FeedbackItem:
    comment_id: str
    actor: str
    path: str
    line: Optional[int]
    body: str
    kind: str  # changes_requested | inline | general
    flags: tuple[str, ...] = ()
    event_id: str = ""


@dataclass(frozen=True)
class DecisionInput:
    events: tuple[ShepherdEvent, ...]
    pr: WatchedPR
    budget: RevisionBudget
    resources: ResourceState
    pending_feedback: tuple[FeedbackItem, ...] = ()
    repair_in_flight: bool = False
    has_reply_evidence: bool = False
    open_ci_failures: tuple[ShepherdEvent, ...] = ()
    ci_failure_age_s: float = 0.0


@dataclass(frozen=True)
class Decision:
    route: Route
    reason: str
    kind: Optional[TaskKind] = None
    trigger_key: str = ""
    permitted_routes: tuple[Route, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    feedback: tuple[FeedbackItem, ...] = ()
    question_topic: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "route": self.route.value,
            "reason": self.reason,
            "kind": self.kind.value if self.kind else None,
            "trigger_key": self.trigger_key,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class RevisionContract:
    contract_id: str
    mission_id: str
    task_id: str
    kind: TaskKind
    round_no: int
    repository: str
    pr_number: int
    branch: str
    head_sha: str
    reviewers: tuple[str, ...]
    comment_ids: tuple[str, ...]
    affected_files: tuple[str, ...]
    requested_behavior: tuple[dict[str, Any], ...]  # quoted, untrusted evidence
    ci_evidence: dict[str, Any]
    acceptance_contract: dict[str, Any]
    previous_verification: dict[str, Any]
    instructions: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RevisionContract":
        return cls(
            contract_id=d["contract_id"], mission_id=d["mission_id"], task_id=d["task_id"], kind=TaskKind(d["kind"]),
            round_no=d["round_no"], repository=d["repository"], pr_number=d["pr_number"], branch=d["branch"],
            head_sha=d["head_sha"], reviewers=tuple(d["reviewers"]), comment_ids=tuple(d["comment_ids"]),
            affected_files=tuple(d["affected_files"]), requested_behavior=tuple(d["requested_behavior"]),
            ci_evidence=d["ci_evidence"], acceptance_contract=d["acceptance_contract"],
            previous_verification=d["previous_verification"], instructions=d["instructions"],
        )


@dataclass(frozen=True)
class WorkerResult:
    ok: bool
    new_head_sha: str = ""
    branch: str = ""
    summary: str = ""
    patch_digest: str = ""
    error: str = ""


@dataclass(frozen=True)
class VerificationResult:
    passed: bool
    receipt_id: str = ""
    evidence_digest: str = ""
    tests: tuple[str, ...] = ()
    summary: str = ""


@dataclass(frozen=True)
class SettlementEvidence:
    """Evidence produced by a bounty-platform probe. Never derived from GitHub text."""
    stage: SettlementStage
    platform: str
    evidence_ref: str
    observed_at: float
    amount: Optional[dict[str, Any]] = None
