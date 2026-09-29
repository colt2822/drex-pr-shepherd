"""The Shepherd: orchestrates ingestion, state, routing, bounded repair, and settlement watch.

Design rules enforced here:
  * GitHub content is untrusted data; routing is deterministic and never executes text.
  * Every write goes through `_write` (outbox first, dry-run unless the policy opens the gate).
  * Same mission / same PR / same branch: revisions never create missions or PRs.
  * Only SettlementEvidence from a platform probe moves settlement state.
"""
from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union

from ..actions.ci_repair import build_ci_repair_contract
from ..actions.common import Verifier, Worker
from ..actions.factual_reply import EvidenceRequired, UnsafeReply, build_reply
from ..actions.review_revision import build_revision_contract
from ..actions.settlement import SettlementProbe, new_evidence
from ..adapters.drex import DrexAdapter
from ..adapters.submission import SubmissionAdapter, SubmissionEvent, SubmissionEventType, Submission, LogOnlySubmissionAdapter
from ..adapters.github import (
    GitHubError,
    GitHubReader,
    GitHubWriter,
    PRSnapshot,
    PushRequest,
    RateLimited,
    WriteDisabled,
    parse_pr_url,
    snapshot_to_raw,
    webhook_to_raw,
)
from ..storage.sqlite import Store
from . import security
from .classifier import normalize
from .dedupe import feedback_from_event, group_feedback
from .models import (
    IN_FLIGHT_STATES,
    POST_MERGE_STATES,
    TERMINAL_STATES,
    CIState,
    Decision,
    DecisionInput,
    EventType,
    FailureClass,
    FeedbackItem,
    MergeState,
    RawEvent,
    ResourceState,
    RevisionBudget,
    RevisionContract,
    Route,
    SettlementEvidence,
    SettlementStage,
    ShepherdEvent,
    State,
    TaskKind,
    TaskStatus,
    VerificationResult,
    WatchedPR,
    WorkerResult,
    make_shepherd_id,
)
from .policy import Policy
from .scheduler import is_due, priority, schedule_next
from .state_machine import IllegalTransition, apply_event, transition

_OPEN_TASK = (TaskStatus.QUEUED.value, TaskStatus.RUNNING.value, TaskStatus.VERIFIED.value)
_TASK_KINDS = tuple(k.value for k in TaskKind)


class UnverifiedWebhook(Exception):
    pass


@dataclass
class IngestResult:
    new_events: list[ShepherdEvent] = field(default_factory=list)
    duplicates: int = 0
    rejected: int = 0
    decision: Optional[Decision] = None


@dataclass
class TickReport:
    polled: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rate_limited_until: Optional[float] = None


class Shepherd:
    def __init__(
        self,
        store: Store,
        *,
        reader: Optional[GitHubReader] = None,
        writer: Optional[GitHubWriter] = None,
        submissions: Optional[SubmissionAdapter] = None,
        router: Optional[Any] = None,
        policy: Optional[Policy] = None,
        worker: Optional[Worker] = None,
        verifier: Optional[Verifier] = None,
        probe: Optional[SettlementProbe] = None,
        resources: Union[ResourceState, Callable[[], ResourceState], None] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.store = store
        self.policy = policy or Policy()
        self.reader, self.writer = reader, writer
        self.submissions = submissions or LogOnlySubmissionAdapter()
        self.router = router or DrexAdapter(self.policy)
        self.worker, self.verifier = worker, verifier
        self.probe = probe or self.submissions
        self._resources = resources or ResourceState()
        self.clock = clock

    # ------------------------------------------------------------------ human release
    def release_human(self, shepherd_id: str, note: str, *, reset_budgets: bool = False) -> WatchedPR:
        """A human resolves HUMAN_ACTION_REQUIRED. Budgets only reset when explicitly requested."""
        with self.store.tx():
            pr = self.store.get_pr(shepherd_id)
            assert pr is not None
            if pr.state != State.HUMAN_ACTION_REQUIRED:
                return pr
            if reset_budgets:
                pr = pr.copy(review_round=0, repair_round=0, nonactionable_streak=0)
            pr = pr.copy(blocker={}, resume_state="")
            pr = self._move(pr, State.WATCHING, f"released by human: {security.clean_text(note, 200)}")
            self._audit("human_released", pr, {"reset_budgets": reset_budgets})
            return self._save(pr.copy(next_check_at=self._now()))

    # ------------------------------------------------------------------ helpers
    def _now(self) -> float:
        return float(self.clock())

    def _res(self) -> ResourceState:
        return self._resources() if callable(self._resources) else self._resources

    def _audit(self, kind: str, pr: Optional[WatchedPR] = None, data: Optional[dict] = None, level: str = "info") -> None:
        self.store.audit(self._now(), kind, pr.shepherd_id if pr else "", data, level)

    def _save(self, pr: WatchedPR) -> WatchedPR:
        pr = pr.copy(updated_at=self._now())
        self.store.save_pr(pr)
        return pr

    def _log_transitions(self, pr: WatchedPR, trans: list, event_id: str = "") -> None:
        for frm, to, why in trans:
            self.store.log_transition(pr.shepherd_id, frm, to, why, event_id, self._now())

    def _move(self, pr: WatchedPR, new: State, reason: str, event_id: str = "") -> WatchedPR:
        log: list = []
        try:
            pr = transition(pr, new, reason, log)
        except IllegalTransition as e:
            self._audit("illegal_transition", pr, {"error": str(e)}, "warn")
            return pr
        self._log_transitions(pr, log, event_id)
        return pr

    def _emit(self, pr: WatchedPR, etype: SubmissionEventType, suffix: str, data: Optional[dict] = None,
              evidence: Optional[SettlementEvidence] = None) -> None:
        key = f"{pr.shepherd_id}:{etype.value}:{suffix}"
        ev = SubmissionEvent(etype, pr.mission_id, pr.task_id, pr.shepherd_id, pr.pr_url, key, data or {}, evidence)
        if self.store.enqueue_outbox(key, pr.shepherd_id, "submission", etype.value, ev.data, "SENT", self._now()):
            try:
                self.submissions.emit(ev)
            except Exception as e:  # submissions outage must not corrupt shepherd state
                self.store.set_outbox_status(key, "FAILED")
                self._audit("submissions_emit_failed", pr, {"type": etype.value, "error": type(e).__name__}, "warn")

    def _live(self) -> bool:
        return bool(self.policy.live_writes and self.writer is not None and getattr(self.writer, "allow_writes", False))

    def _write(self, pr: WatchedPR, key: str, op: str, payload: dict, fn: Callable[[], None]) -> str:
        """Single choke point for GitHub writes: outbox first, dry-run by default, idempotent."""
        row = self.store.get_outbox(key)
        if row and row["status"] == "SENT":
            return "SKIPPED"
        if row is None:
            self.store.enqueue_outbox(key, pr.shepherd_id, "github", op, payload, "DRY_RUN", self._now())
        if not self._live():
            self._audit("write_dry_run", pr, {"op": op, "key": key})
            return "DRY_RUN"
        try:
            fn()
        except (WriteDisabled, GitHubError) as e:
            self.store.set_outbox_status(key, "FAILED")
            self._audit("write_failed", pr, {"op": op, "error": type(e).__name__}, "warn")
            return "FAILED"
        self.store.set_outbox_status(key, "SENT")
        self._audit("write_sent", pr, {"op": op, "key": key})
        return "SENT"

    # ------------------------------------------------------------------ watch
    def watch(self, submission: Submission, *, head_sha: str, head_branch: str, base_branch: str = "main",
              head_repository: str = "") -> WatchedPR:
        repo, number = parse_pr_url(submission.pr_url, self.policy.allowed_url_hosts)
        if not security.is_safe_branch(head_branch) or not security.is_safe_sha(head_sha):
            raise ValueError("unsafe branch or sha")
        existing = self.store.find_pr(repo, number)
        if existing:
            return existing  # idempotent: one shepherd per PR, one mission per PR
        now = self._now()
        payout = submission.expected_payout
        pr = WatchedPR(
            shepherd_id=make_shepherd_id(repo, number), mission_id=submission.mission_id, task_id=submission.task_id,
            repository=repo, pr_number=number, pr_url=submission.pr_url, head_branch=head_branch, head_sha=head_sha,
            base_branch=base_branch, state=State.WATCHING, last_seen_at=now, last_event_at=now,
            submission_artifact_digest=submission.artifact_digest, verification_receipt_id=submission.submission_receipt_id,
            next_check_at=now, created_at=now, updated_at=now, head_repository=head_repository or repo,
            settlement_stage=SettlementStage.SUBMITTED_PAYOUT if payout else SettlementStage.NONE,
            expected_payout=payout, acceptance_contract=submission.acceptance_contract,
            last_verification={**submission.verification_summary, "passed": bool(submission.submission_receipt_id
                                and submission.verification_summary.get("evidence_digest")),
                               "head_sha": head_sha, "receipt_id": submission.submission_receipt_id},
            known_shas=[head_sha],
        )
        with self.store.tx():
            self.store.save_pr(pr)
            self._audit("watch_started", pr, {"pr": f"{repo}#{number}"})
            self._emit(pr, SubmissionEventType.PR_WATCH_STARTED, "0", {"expected_payout_present": payout is not None})
        return pr

    # ------------------------------------------------------------------ ingestion
    def ingest(self, shepherd_id: str, raws: list[RawEvent]) -> IngestResult:
        with self.store.tx():
            return self._ingest(shepherd_id, raws)

    def _ci_view(self, sid: str, head_sha: str) -> dict[str, ShepherdEvent]:
        latest: dict[str, ShepherdEvent] = {}
        for e in self.store.events(sid, (EventType.CI_STARTED, EventType.CI_PASSED, EventType.CI_FAILED)):
            if e.payload.get("head_sha") == head_sha:
                latest[e.payload.get("check_name", "")] = e
        return latest

    @staticmethod
    def _ci_agg(view: dict[str, ShepherdEvent]) -> CIState:
        types = [e.type for e in view.values()]
        if EventType.CI_FAILED in types:
            return CIState.FAILING
        if EventType.CI_STARTED in types:
            return CIState.RUNNING
        return CIState.PASSING if types else CIState.NONE

    def _ingest(self, sid: str, raws: list[RawEvent]) -> IngestResult:
        pr = self.store.get_pr(sid)
        if pr is None:
            raise KeyError(sid)
        res = IngestResult()
        for raw in raws:
            if raw.repository.lower() != pr.repository.lower() or raw.pr_number != pr.pr_number:
                res.rejected += 1
                self._audit("event_rejected_wrong_pr", pr, {"source_event_id": raw.source_event_id}, "warn")
                continue
            ev = normalize(raw, self.policy)
            if ev.timestamp == 0.0:
                ev = dataclasses.replace(ev, timestamp=self._now())
            p = ev.payload
            p["seen_at"] = self._now()
            if ev.type in (EventType.CI_STARTED, EventType.CI_PASSED, EventType.CI_FAILED) and p.get("head_sha") != pr.head_sha:
                res.rejected += 1
                self._audit("ci_event_stale_or_early", pr, {"source_event_id": raw.source_event_id}, "info")
                continue
            if ev.type == EventType.PR_UPDATED and p.get("head_repository") and pr.head_repository and \
                    p["head_repository"].lower() != pr.head_repository.lower():
                res.rejected += 1
                self._audit("event_rejected_head_repo_mismatch", pr, {"source_event_id": raw.source_event_id}, "warn")
                continue
            stored = self.store.insert_event(ev)
            if stored is None:
                res.duplicates += 1
                continue
            res.new_events.append(stored)
            pr = self._apply(pr, stored)
        pr = self._save(pr)
        res.decision = self._evaluate(pr, res.new_events)
        return res

    def _apply(self, pr: WatchedPR, ev: ShepherdEvent) -> WatchedPR:
        ci_agg = None
        if ev.type in (EventType.CI_STARTED, EventType.CI_PASSED, EventType.CI_FAILED):
            ci_agg = self._ci_agg(self._ci_view(pr.shepherd_id, pr.head_sha))
        before = pr.state
        pr, trans = apply_event(pr, ev, ci_agg)
        self._log_transitions(pr, trans, ev.event_id)
        p = ev.payload

        if ev.type == EventType.CI_FAILED and p.get("failure_class") != FailureClass.PATCH_CAUSED_FAILURE.value:
            bs = dict(pr.backoff_state)
            shas = list(bs.get("na_shas", []))
            if pr.head_sha not in shas:
                shas.append(pr.head_sha)
                pr = pr.copy(nonactionable_streak=pr.nonactionable_streak + 1)
            bs["na_shas"] = shas[-20:]
            pr = pr.copy(backoff_state=bs)
        if pr.ci_state == CIState.PASSING and pr.backoff_state.get("na_shas"):
            pr = pr.copy(backoff_state={**pr.backoff_state, "na_shas": []})

        if ev.type in (EventType.PR_MERGED, EventType.PR_CLOSED) and before not in TERMINAL_STATES | POST_MERGE_STATES:
            self._cancel_open_tasks(pr, f"pr {ev.type.value.lower()}")
            if ev.type == EventType.PR_MERGED:
                self._emit(pr, SubmissionEventType.PR_MERGED, ev.event_id, {"merge_commit_sha": p.get("merge_commit_sha", "")})
                if pr.expected_payout is not None:
                    pr = self._move(pr, State.SETTLEMENT_PENDING, "merged; payment not implied, watching settlement", ev.event_id)
                    late = {SettlementStage.ACCEPTED_PAYOUT: State.ACCEPTED_PAYOUT, SettlementStage.REALIZED_REVENUE: State.REALIZED_REVENUE}
                    if pr.settlement_stage in late:  # platform evidence already observed before the merge
                        pr = self._move(pr, late[pr.settlement_stage], "earlier platform evidence", ev.event_id)
            else:
                self._emit(pr, SubmissionEventType.PR_CLOSED, ev.event_id)
        elif ev.type in (EventType.BOUNTY_ACCEPTED_SIGNAL, EventType.PAYOUT_SIGNAL):
            self._audit("unverified_settlement_signal", pr, {"event_id": ev.event_id, "type": ev.type.value}, "warn")
        elif ev.type == EventType.UNKNOWN_EVENT:
            self._audit("unknown_event_ignored", pr, {"event_id": ev.event_id, "source_event_id": ev.source_event_id}, "warn")
        return pr

    def ingest_webhook(self, event_name: str, payload: dict[str, Any], delivery_id: str = "", *, verified: bool) -> dict[str, IngestResult]:
        """Webhook ingestion. The caller must have verified the HMAC signature."""
        if not verified:
            raise UnverifiedWebhook("webhook signature not verified")
        out: dict[str, IngestResult] = {}
        by_pr: dict[tuple[str, int], list[RawEvent]] = {}
        for raw in webhook_to_raw(event_name, payload, delivery_id):
            by_pr.setdefault((raw.repository.lower(), raw.pr_number), []).append(raw)
        for (repo, n), raws in by_pr.items():
            pr = self.store.find_pr(repo, n)
            if pr is None:
                self.store.audit(self._now(), "webhook_unwatched", "", {"repo": repo, "pr": n})
                continue
            raws = [self._enrich(r) for r in raws]
            out[pr.shepherd_id] = self.ingest(pr.shepherd_id, raws)
        return out

    def _enrich(self, raw: RawEvent) -> RawEvent:
        if raw.kind == "check_run" and not raw.data.get("changed_files") and raw.data.get("conclusion") and self.reader:
            try:
                files = self.reader.get_changed_files(raw.repository, raw.pr_number)
            except GitHubError:
                return raw
            return dataclasses.replace(raw, data={**raw.data, "changed_files": files})
        return raw

    # ------------------------------------------------------------------ evaluation / routing
    def _claimed_ids(self, sid: str) -> set[str]:
        ids: set[str] = set()
        for a in self.store.actions(sid, TaskKind.REVIEW_REVISION.value, _OPEN_TASK + (TaskStatus.DONE.value,)):
            ids.update(a["payload"]["contract"]["comment_ids"])
        return ids

    def _pending_feedback(self, pr: WatchedPR) -> tuple[FeedbackItem, ...]:
        evs = self.store.events(pr.shepherd_id, (EventType.REVIEW_CHANGES_REQUESTED, EventType.REVIEW_COMMENT, EventType.PR_COMMENT))
        items = [f for f in (feedback_from_event(e) for e in evs) if f is not None]
        claimed = self._claimed_ids(pr.shepherd_id)
        return tuple(f for f in group_feedback(items) if f.comment_id not in claimed)

    def _open_ci_failures(self, pr: WatchedPR) -> tuple[ShepherdEvent, ...]:
        if pr.ci_state != CIState.FAILING:
            return ()
        return tuple(e for e in self._ci_view(pr.shepherd_id, pr.head_sha).values() if e.type == EventType.CI_FAILED)

    def _budget(self, pr: WatchedPR) -> RevisionBudget:
        p = self.policy
        return RevisionBudget(pr.review_round, p.max_revision_rounds, pr.repair_round, p.max_ci_repair_rounds,
                              pr.nonactionable_streak, p.max_consecutive_unknown_failures)

    def _evaluate(self, pr: WatchedPR, new_events: list[ShepherdEvent], allow_new_tasks: bool = True) -> Decision:
        pr = self._flush_verified(pr)
        in_flight = any(a["kind"] in _TASK_KINDS for a in self.store.actions(pr.shepherd_id, None, _OPEN_TASK))
        failures = self._open_ci_failures(pr)
        age = (self._now() - min(e.payload.get("seen_at", e.timestamp) for e in failures)) if failures else 0.0
        lv = pr.last_verification or {}
        inp = DecisionInput(
            events=tuple(new_events), pr=pr, budget=self._budget(pr), resources=self._res(),
            pending_feedback=self._pending_feedback(pr), repair_in_flight=in_flight,
            has_reply_evidence=bool(lv.get("passed") and pr.verification_receipt_id),
            open_ci_failures=failures, ci_failure_age_s=age,
        )
        decision = self.router.decide(inp)
        if new_events or decision.route not in (Route.NO_ACTION, Route.WAIT):
            self._audit("decision", pr, decision.to_dict())
        self._execute(pr, decision, failures, allow_new_tasks)
        return decision

    def _execute(self, pr: WatchedPR, d: Decision, failures: tuple[ShepherdEvent, ...], allow_new_tasks: bool) -> None:
        pr = self.store.get_pr(pr.shepherd_id) or pr
        if d.route in (Route.NO_ACTION, Route.WAIT):
            return
        if d.route == Route.HUMAN_ACTION_REQUIRED:
            self._escalate(pr, d.reason, d.evidence, d.trigger_key)
        elif d.route in (Route.ROUTE_CODEX, Route.ROUTE_CLAUDE):
            if not allow_new_tasks:
                return
            self._start_task(pr, d, failures)
        elif d.route == Route.POST_FACTUAL_RESPONSE:
            self._post_factual(pr, d)
        elif d.route == Route.SETTLEMENT_CHECK:
            self._settlement_check(pr, d.trigger_key)
        # RUN_VERIFIER is performed inside complete_task; it is a valid external-router route only.

    def _escalate(self, pr: WatchedPR, reason: str, evidence: dict, key: str) -> None:
        if pr.state in (State.HUMAN_ACTION_REQUIRED, *TERMINAL_STATES, *POST_MERGE_STATES):
            return
        if not self.store.create_action(f"{pr.shepherd_id}:{key}", pr.shepherd_id, Route.HUMAN_ACTION_REQUIRED.value,
                                        None, 0, {"reason": reason, "evidence": evidence}, "OPEN", self._now()):
            return
        self._cancel_open_tasks(pr, "escalated to human")
        pr = pr.copy(blocker={"reason": reason, "evidence": evidence, "at": self._now()}, resume_state=pr.state.value)
        pr = self._move(pr, State.HUMAN_ACTION_REQUIRED, reason)
        self._save(pr)
        self._audit("human_action_required", pr, {"reason": reason, "evidence": evidence}, "warn")

    # ------------------------------------------------------------------ tasks
    def _start_task(self, pr: WatchedPR, d: Decision, failures: tuple[ShepherdEvent, ...]) -> None:
        kind = d.kind or TaskKind.CI_REPAIR
        if kind == TaskKind.REVIEW_REVISION:
            round_no = pr.review_round + 1
            contract = build_revision_contract(pr, d.feedback, round_no, self.policy)
            pr2 = pr.copy(review_round=round_no)
        else:
            round_no = pr.repair_round + 1
            patch = [e for e in failures if e.payload.get("failure_class") == FailureClass.PATCH_CAUSED_FAILURE.value]
            contract = build_ci_repair_contract(pr, patch, round_no, self.policy, kind)
            pr2 = pr.copy(repair_round=round_no)
        key = f"{pr.shepherd_id}:{kind.value}:{round_no}"
        worker = "codex" if d.route == Route.ROUTE_CODEX else "claude"
        payload = {"contract": contract.to_dict(), "worker": worker, "base_sha": pr.head_sha, "trigger_key": d.trigger_key}
        if not self.store.create_action(key, pr.shepherd_id, d.route.value, kind.value, round_no, payload,
                                        TaskStatus.QUEUED.value, self._now()):
            return
        pr2 = self._move(pr2, State.REPAIR_QUEUED, f"{kind.value} round {round_no} queued ({d.reason})")
        pr2 = self._save(pr2)
        self._emit(pr2, SubmissionEventType.REVISION_REQUIRED, f"{kind.value}:{round_no}",
                   {"kind": kind.value, "round": round_no, "contract_id": contract.contract_id, "head_sha": pr.head_sha})
        if self.worker is not None and self.verifier is not None:
            self._run_task(key)

    def pending_tasks(self, shepherd_id: str = "") -> list[dict[str, Any]]:
        """Queued tasks for an external worker fleet; report back with complete_task()."""
        prs = [self.store.get_pr(shepherd_id)] if shepherd_id else self.store.list_prs()
        out: list[dict[str, Any]] = []
        for pr in prs:
            if pr:
                out += [a for a in self.store.actions(pr.shepherd_id, None, (TaskStatus.QUEUED.value,)) if a["kind"] in _TASK_KINDS]
        return out

    def _run_task(self, key: str) -> None:
        act = self.store.get_action(key)
        assert act is not None
        contract = RevisionContract.from_dict(act["payload"]["contract"])
        pr = self.store.get_pr(act["shepherd_id"])
        assert pr is not None and self.worker is not None
        self.store.update_action(key, TaskStatus.RUNNING.value, self._now())
        pr = self._save(self._move(pr, State.REPAIRING, "worker started"))
        try:
            result = self.worker.run(contract)
        except Exception as e:  # worker crash is a failed attempt, not a shepherd crash
            result = WorkerResult(ok=False, error=type(e).__name__)
        self.complete_task(key, result)

    def complete_task(self, key: str, result: WorkerResult, verification: Optional[VerificationResult] = None) -> str:
        """Finish a task: validate -> deterministic verify -> push SAME branch. Returns final action status."""
        with self.store.tx():
            return self._complete_task(key, result, verification)

    def _resume_state(self, pr: WatchedPR, kind: str) -> State:
        if kind == TaskKind.REVIEW_REVISION.value:
            return State.REVIEW_CHANGES_REQUESTED
        return State.CI_FAILED if pr.ci_state == CIState.FAILING else State.WATCHING

    def _fail_task(self, pr: WatchedPR, key: str, status: TaskStatus, why: str, kind: str) -> str:
        self.store.update_action(key, status.value, self._now(), {"reason": why})
        pr = self._save(self._move(pr, self._resume_state(pr, kind), f"task {status.value}: {why}"))
        self._audit("task_failed", pr, {"key": key, "status": status.value, "reason": why}, "warn")
        self._evaluate(pr, [], allow_new_tasks=False)
        return status.value

    def _complete_task(self, key: str, result: WorkerResult, verification: Optional[VerificationResult]) -> str:
        act = self.store.get_action(key)
        if act is None or act["status"] not in (TaskStatus.QUEUED.value, TaskStatus.RUNNING.value):
            return act["status"] if act else "UNKNOWN"
        pr = self.store.get_pr(act["shepherd_id"])
        assert pr is not None
        kind = act["kind"]
        contract = RevisionContract.from_dict(act["payload"]["contract"])
        if pr.state in TERMINAL_STATES or pr.state in POST_MERGE_STATES or pr.state in (State.HUMAN_ACTION_REQUIRED, State.BLOCKED):
            self.store.update_action(key, TaskStatus.STALE.value, self._now(), {"reason": f"pr in {pr.state.value}; no write performed"})
            return TaskStatus.STALE.value
        if pr.state == State.REPAIR_QUEUED:
            pr = self._save(self._move(pr, State.REPAIRING, "external worker picked up task"))
        if pr.head_sha != act["payload"]["base_sha"]:
            self.store.update_action(key, TaskStatus.STALE.value, self._now(), {"reason": "head moved during task"})
            pr = self._save(self._move(pr, State.WATCHING, "head moved; task stale"))
            self._evaluate(pr, [], allow_new_tasks=False)
            return TaskStatus.STALE.value
        if not result.ok:
            return self._fail_task(pr, key, TaskStatus.WORKER_FAILED, result.error or "worker reported failure", kind)
        if result.branch != pr.head_branch or not security.is_safe_sha(result.new_head_sha) or result.new_head_sha == pr.head_sha:
            return self._fail_task(pr, key, TaskStatus.WORKER_FAILED, "result branch/sha does not match the watched PR", kind)

        pr = self._save(self._move(pr, State.REVERIFYING, "deterministic verification"))
        if verification is None:
            if self.verifier is None:
                raise ValueError("no verifier configured and no verification supplied")
            try:
                verification = self.verifier.verify(contract, result)
            except Exception as e:
                verification = VerificationResult(passed=False, summary=f"verifier error: {type(e).__name__}")
        if not verification.passed or not verification.receipt_id or not verification.evidence_digest:
            return self._fail_task(pr, key, TaskStatus.VERIFY_FAILED, verification.summary or "verification failed", kind)

        lv = {"passed": True, "receipt_id": verification.receipt_id, "evidence_digest": verification.evidence_digest,
              "tests": list(verification.tests), "head_sha": result.new_head_sha,
              "summary": security.clean_text(result.summary, 160)}
        pr = pr.copy(verification_receipt_id=verification.receipt_id, last_verification=lv)
        self.store.update_action(key, TaskStatus.VERIFIED.value, self._now(), {"new_head_sha": result.new_head_sha, "verification": lv})
        pr = self._save(self._move(pr, State.READY_TO_UPDATE, "verification passed"))
        self._push(pr, key)
        return (self.store.get_action(key) or {}).get("status", "UNKNOWN")

    def _flush_verified(self, pr: WatchedPR) -> WatchedPR:
        if not self._live() or pr.state != State.READY_TO_UPDATE:
            return pr
        for a in self.store.actions(pr.shepherd_id, None, (TaskStatus.VERIFIED.value,)):
            self._push(pr, a["action_key"])
        return self.store.get_pr(pr.shepherd_id) or pr

    def _push(self, pr: WatchedPR, key: str) -> None:
        act = self.store.get_action(key)
        assert act is not None
        new_sha = act["result"]["new_head_sha"]
        if pr.head_sha != act["payload"]["base_sha"]:
            self.store.update_action(key, TaskStatus.STALE.value, self._now(), {"reason": "head moved before push"})
            self._save(self._move(pr, State.WATCHING, "head moved before push"))
            return
        req = PushRequest(pr.head_repository or pr.repository, pr.head_branch, act["payload"]["base_sha"], new_sha)
        status = self._write(pr, f"{pr.shepherd_id}:push:{key}", "push_update", dataclasses.asdict(req),
                             lambda: self.writer.push_update(req))  # type: ignore[union-attr]
        if status not in ("SENT", "SKIPPED"):
            return  # stays READY_TO_UPDATE / VERIFIED until the write gate opens
        kind = act["kind"]
        shas = [*pr.known_shas, new_sha][-50:]
        pr = pr.copy(head_sha=new_sha, known_shas=shas, ci_state=CIState.NONE, nonactionable_streak=0,
                     backoff_state={**pr.backoff_state, "na_shas": []})
        self.store.insert_event(ShepherdEvent(
            event_id="ev_" + make_shepherd_id(f"{pr.shepherd_id}:{new_sha}", 0)[4:], source_event_id=f"head:{new_sha}", shepherd_id=pr.shepherd_id,
            repository=pr.repository, pr_number=pr.pr_number, actor="shepherd", timestamp=self._now(),
            raw_ref=f"shepherd:push:{key}", type=EventType.PR_UPDATED, payload_digest="internal",
            payload={"head_sha": new_sha, "same_branch": pr.head_branch}, trust="internal"))
        self.store.update_action(key, TaskStatus.DONE.value, self._now())
        nxt = State.AWAITING_REVIEW if kind == TaskKind.REVIEW_REVISION.value else State.WATCHING
        pr = self._save(self._move(pr, nxt, "same branch updated; same PR continues"))
        self._emit(pr, SubmissionEventType.REVISION_VERIFIED, key, {"head_sha": new_sha, "receipt_id": pr.verification_receipt_id, "kind": kind})
        if kind == TaskKind.REVIEW_REVISION.value:
            self._reply_addressed(pr, act["payload"]["contract"]["comment_ids"])

    def _cancel_open_tasks(self, pr: WatchedPR, why: str) -> None:
        for a in self.store.actions(pr.shepherd_id, None, _OPEN_TASK):
            if a["kind"] in _TASK_KINDS:
                self.store.update_action(a["action_key"], TaskStatus.STALE.value, self._now(), {"reason": why})

    # ------------------------------------------------------------------ replies
    def _reply_addressed(self, pr: WatchedPR, comment_ids: list[str]) -> None:
        if not self.policy.allow_factual_replies:
            return
        try:
            reply = build_reply(self.policy, pr, "fixed")
        except (EvidenceRequired, UnsafeReply) as e:
            self._audit("reply_skipped", pr, {"reason": str(e)})
            return
        inline = [c[3:] for c in comment_ids if c.startswith("rc:") and c[3:].isdigit()][:10]
        for cid in inline:
            self._write(pr, f"{pr.shepherd_id}:reply:rc:{cid}:{pr.head_sha}", "reply_to_comment",
                        {"comment_id": cid, "text": reply.text},
                        lambda cid=cid: self.writer.reply_to_comment(pr.repository, pr.pr_number, cid, reply.text))  # type: ignore[union-attr]
        if len(inline) < len(comment_ids):
            self._write(pr, f"{pr.shepherd_id}:comment:fixed:{pr.head_sha}", "post_pr_comment", {"text": reply.text},
                        lambda: self.writer.post_pr_comment(pr.repository, pr.pr_number, reply.text))  # type: ignore[union-attr]

    def _post_factual(self, pr: WatchedPR, d: Decision) -> None:
        try:
            reply = build_reply(self.policy, pr, d.question_topic)
        except (EvidenceRequired, UnsafeReply) as e:
            self._escalate(pr, f"cannot ground a factual reply: {e}", {"topic": d.question_topic}, "reply:" + d.trigger_key)
            return
        status = self._write(pr, f"{pr.shepherd_id}:reply:{d.trigger_key}", "post_pr_comment",
                             {"text": reply.text, "evidence": reply.evidence},
                             lambda: self.writer.post_pr_comment(pr.repository, pr.pr_number, reply.text))  # type: ignore[union-attr]
        if status in ("SENT", "SKIPPED") and pr.state == State.MAINTAINER_RESPONSE_REQUIRED:
            self._save(self._move(pr, State.AWAITING_REVIEW, "factual reply posted"))

    # ------------------------------------------------------------------ settlement
    def _settlement_check(self, pr: WatchedPR, key: str) -> None:
        if self.probe is None or (pr.state not in POST_MERGE_STATES and pr.state != State.APPROVED) or pr.expected_payout is None:
            return
        try:
            evidence = self.probe.fetch_settlement_evidence(pr.mission_id, pr.pr_url)
        except Exception as e:
            self._audit("settlement_probe_failed", pr, {"error": type(e).__name__}, "warn")
            return
        self.apply_settlement_evidence(pr.shepherd_id, evidence)

    def apply_settlement_evidence(self, shepherd_id: str, evidence: list[SettlementEvidence]) -> WatchedPR:
        """The only path that advances settlement state. Requires platform evidence objects."""
        with self.store.tx():
            pr = self.store.get_pr(shepherd_id)
            assert pr is not None
            for ev in new_evidence(pr, evidence):
                etype = (EventType.BOUNTY_ACCEPTED_SIGNAL if ev.stage == SettlementStage.ACCEPTED_PAYOUT
                         else EventType.PAYOUT_SIGNAL)
                sev = ShepherdEvent(
                    event_id="ev_" + make_shepherd_id(f"{pr.shepherd_id}:{ev.platform}:{ev.evidence_ref}", 1)[4:], source_event_id=f"platform:{ev.platform}:{ev.evidence_ref}",
                    shepherd_id=pr.shepherd_id, repository=pr.repository, pr_number=pr.pr_number, actor=ev.platform,
                    timestamp=ev.observed_at or self._now(), raw_ref=f"platform:{ev.platform}", type=etype,
                    payload_digest="platform", payload={"stage": ev.stage.value, "amount": ev.amount, "platform_verified": True},
                    trust="platform_verified")
                if self.store.insert_event(sev) is None:
                    continue
                pr = pr.copy(settlement_stage=ev.stage)
                if pr.state == State.MERGED:
                    pr = self._move(pr, State.SETTLEMENT_PENDING, "settlement evidence observed")
                target = State.ACCEPTED_PAYOUT if ev.stage == SettlementStage.ACCEPTED_PAYOUT else State.REALIZED_REVENUE
                if pr.state in (State.SETTLEMENT_PENDING, State.ACCEPTED_PAYOUT):
                    pr = self._move(pr, target, f"platform evidence {ev.stage.value}", sev.event_id)
                ftype = SubmissionEventType.BOUNTY_ACCEPTED_SIGNAL if etype == EventType.BOUNTY_ACCEPTED_SIGNAL else SubmissionEventType.PAYOUT_SIGNAL
                self._emit(pr, ftype, ev.evidence_ref, {"stage": ev.stage.value}, evidence=ev)
            return self._save(pr)

    # ------------------------------------------------------------------ polling
    def _recover(self, pr: WatchedPR) -> WatchedPR:
        """After a crash, tasks left RUNNING have no live runner; requeue them."""
        for a in self.store.actions(pr.shepherd_id, None, (TaskStatus.RUNNING.value,)):
            if a["kind"] in _TASK_KINDS:
                self.store.update_action(a["action_key"], TaskStatus.QUEUED.value, self._now(), {"reason": "recovered after restart"})
                if pr.state in (State.REPAIRING, State.REVERIFYING):
                    pr = self._save(self._move(pr, State.REPAIR_QUEUED, "recovered after restart"))
                self._audit("task_recovered", pr, {"key": a["action_key"]})
        return pr

    def tick(self, now: Optional[float] = None) -> TickReport:
        now = self._now() if now is None else now
        rep = TickReport()
        until = self.store.kv_get("rate_limited_until")
        if until and now < until:
            rep.rate_limited_until = until
            return rep
        due = sorted((p for p in self.store.list_prs() if is_due(p, now)), key=lambda p: (priority(p), p.next_check_at or 0))
        for pr in due[: self.policy.max_prs_per_tick]:
            pr = self._recover(pr)
            try:
                self.poll_pr(pr.shepherd_id, now)
                rep.polled.append(pr.shepherd_id)
            except RateLimited as e:
                self.store.kv_set("rate_limited_until", e.reset_at)
                rep.rate_limited_until = e.reset_at
                self._defer(pr, now, rate_limit_reset=e.reset_at)
                self._audit("rate_limited", pr, {"until": e.reset_at}, "warn")
                break
            except GitHubError as e:
                rep.errors.append(f"{pr.shepherd_id}: {type(e).__name__}")
                self._defer(pr, now, error=True)
                self._audit("poll_error", pr, {"error": type(e).__name__}, "warn")
        return rep

    def _defer(self, pr: WatchedPR, now: float, *, error: bool = False, rate_limit_reset: Optional[float] = None) -> None:
        pr = self.store.get_pr(pr.shepherd_id) or pr
        nxt, bs = schedule_next(pr, now, self.policy, had_activity=False, error=error, rate_limit_reset=rate_limit_reset)
        self.store.save_pr(pr.copy(next_check_at=nxt, backoff_state=bs, updated_at=now))

    def poll_pr(self, shepherd_id: str, now: Optional[float] = None) -> IngestResult:
        now = self._now() if now is None else now
        pr = self.store.get_pr(shepherd_id)
        assert pr is not None
        res = IngestResult()
        if pr.state in TERMINAL_STATES:
            self.store.save_pr(pr.copy(next_check_at=None))
            return res
        if pr.state in POST_MERGE_STATES:
            self._settlement_check(pr, f"poll:{int(now)}")
        elif self.reader is not None:
            res = self._poll_github(pr, now)
            self._settlement_check(self.store.get_pr(shepherd_id) or pr, f"poll:{int(now)}")  # approval-time watch
        pr = self.store.get_pr(shepherd_id)
        assert pr is not None
        if pr.state == State.MERGED and pr.expected_payout is None:
            nxt, bs = None, pr.backoff_state
        else:
            nxt, bs = schedule_next(pr, now, self.policy, had_activity=bool(res.new_events))
        rl = getattr(self.reader, "last_rate", None)
        if rl and rl[0] < self.policy.rate_limit_floor:
            self.store.kv_set("rate_limited_until", rl[1])
            nxt = max(nxt or 0, rl[1] + 1)
        self.store.save_pr(pr.copy(next_check_at=nxt, backoff_state=bs, last_seen_at=now, updated_at=now))
        return res

    def _poll_github(self, pr: WatchedPR, now: float) -> IngestResult:
        r = self.reader
        assert r is not None
        et = dict(pr.backoff_state.get("etags", {}))
        snap = r.get_pr(pr.repository, pr.pr_number, et.get("pr"))
        if snap.not_modified:
            snap = PRSnapshot(pr.pr_number, "open", False, pr.head_sha, pr.head_branch, pr.head_repository, pr.base_branch, None, "", snap.etag, True)
        head = snap.head_sha or pr.head_sha
        reviews = r.get_reviews(pr.repository, pr.pr_number, et.get("reviews"))
        rcs = r.get_review_comments(pr.repository, pr.pr_number, et.get("rc"))
        ics = r.get_issue_comments(pr.repository, pr.pr_number, et.get("ic"))
        checks = r.get_check_runs(pr.repository, head, et.get(f"checks:{head}"))
        files: list[str] = []
        if any(str(c.get("conclusion") or "") in ("failure", "timed_out", "cancelled", "action_required") for c in checks.items):
            files = r.get_changed_files(pr.repository, pr.pr_number)
        if snap.mergeable is None and snap.state == "open" and not snap.not_modified:
            snap.mergeable = r.get_merge_status(pr.repository, pr.pr_number).mergeable
        et.update({"pr": snap.etag, "reviews": reviews.etag, "rc": rcs.etag, "ic": ics.etag, f"checks:{head}": checks.etag})
        et = {k: v for k, v in et.items() if v}
        raws = snapshot_to_raw(pr.repository, pr.pr_number, snap, reviews=reviews.items, review_comments=rcs.items,
                               issue_comments=ics.items, check_runs=checks.items, changed_files=files, known_head=pr.head_sha)
        cur = self.store.get_pr(pr.shepherd_id) or pr
        self.store.save_pr(cur.copy(backoff_state={**cur.backoff_state, "etags": et}))
        return self.ingest(pr.shepherd_id, raws)

    # ------------------------------------------------------------------ observability
    _REPAIRING = {State.REPAIR_QUEUED, State.REPAIRING, State.REVERIFYING, State.READY_TO_UPDATE}

    def pr_status(self, pr: WatchedPR) -> dict[str, Any]:
        blocker = pr.blocker.get("reason", "") if pr.state in (State.HUMAN_ACTION_REQUIRED, State.BLOCKED) else ""
        if not blocker and pr.state in self._REPAIRING:
            blocker = "awaiting worker/verification/push"
        return {
            "shepherd_id": pr.shepherd_id, "repository": pr.repository, "pr_number": pr.pr_number, "state": pr.state.value,
            "head_sha": pr.head_sha, "last_activity": pr.last_event_at, "review_round": pr.review_round,
            "repair_round": pr.repair_round, "ci_state": pr.ci_state.value, "review_state": pr.review_state.value,
            "merge_state": pr.merge_state.value, "settlement_stage": pr.settlement_stage.value,
            "next_check_at": pr.next_check_at, "blocker": blocker,
        }

    def status(self) -> dict[str, Any]:
        prs = self.store.list_prs()
        S = State

        def n(pred: Callable[[WatchedPR], bool]) -> int:
            return sum(1 for p in prs if pred(p))

        return {
            "watched_prs": len(prs),
            "awaiting_review": n(lambda p: p.state == S.AWAITING_REVIEW),
            "ci_failed": n(lambda p: p.state == S.CI_FAILED),
            "changes_requested": n(lambda p: p.state == S.REVIEW_CHANGES_REQUESTED),
            "repairing": n(lambda p: p.state in self._REPAIRING),
            "merged": n(lambda p: p.merge_state == MergeState.MERGED),
            "closed": n(lambda p: p.state == S.CLOSED),
            "settlement_pending": n(lambda p: p.state == S.SETTLEMENT_PENDING),
            "human_action_required": n(lambda p: p.state == S.HUMAN_ACTION_REQUIRED),
            "prs": [self.pr_status(p) for p in prs],
        }
