"""Deterministic Drex routing. Traffic control only.

Router output is a structured Decision. The router never inspects GitHub prose for
commands, never executes anything, and never judges whether code is correct.
"""
from __future__ import annotations

from typing import Optional

from .models import (
    IN_FLIGHT_STATES,
    POST_MERGE_STATES,
    Decision,
    DecisionInput,
    EventType,
    FailureClass,
    Route,
    State,
    TaskKind,
    digest,
)
from .policy import Policy

_SETTLEMENT_EVENTS = {EventType.PR_MERGED, EventType.PAYOUT_SIGNAL, EventType.BOUNTY_ACCEPTED_SIGNAL}


class DeterministicRouter:
    def __init__(self, policy: Policy):
        self.policy = policy

    # -- helpers
    def _worker_route(self, inp: DecisionInput) -> Optional[tuple[Route, tuple[Route, ...]]]:
        order = [self.policy.preferred_worker, self.policy.fallback_worker]
        avail = {"codex": inp.resources.codex_available, "claude": inp.resources.claude_available}
        routes = {"codex": Route.ROUTE_CODEX, "claude": Route.ROUTE_CLAUDE}
        usable = [routes[w] for w in order if w in routes and avail.get(w)]
        if not usable:
            return None
        return usable[0], tuple(usable)

    def _human(self, reason: str, inp: DecisionInput, **evidence) -> Decision:
        b = inp.budget
        ev = {
            "state": inp.pr.state.value,
            "head_sha": inp.pr.head_sha,
            "revision_rounds": f"{b.revision_rounds_used}/{b.revision_rounds_max}",
            "ci_repairs": f"{b.ci_repairs_used}/{b.ci_repairs_max}",
            "nonactionable_streak": f"{b.nonactionable_streak}/{b.nonactionable_max}",
            **evidence,
        }
        return Decision(Route.HUMAN_ACTION_REQUIRED, reason, trigger_key="human:" + digest([reason, sorted(ev.items())])[7:19],
                        permitted_routes=(Route.HUMAN_ACTION_REQUIRED,), evidence=ev)

    # -- main entry
    def decide(self, inp: DecisionInput) -> Decision:
        pr, b = inp.pr, inp.budget
        types = {e.type for e in inp.events}

        if pr.state == State.CLOSED:
            return Decision(Route.NO_ACTION, "pr closed: coding loop terminated")
        if pr.state == State.REALIZED_REVENUE:
            return Decision(Route.NO_ACTION, "settlement complete")
        if pr.state in POST_MERGE_STATES:
            if types & _SETTLEMENT_EVENTS:
                return Decision(Route.SETTLEMENT_CHECK, "merge/settlement signal; verify with platform evidence",
                                trigger_key="settle:" + ",".join(sorted(e.event_id for e in inp.events if e.type in _SETTLEMENT_EVENTS)))
            return Decision(Route.NO_ACTION, "post-merge: settlement watcher handles polling")
        if pr.state in (State.HUMAN_ACTION_REQUIRED, State.BLOCKED):
            return Decision(Route.NO_ACTION, f"held in {pr.state.value}")

        # Maintainer questions (edge-triggered).
        questions = [e for e in inp.events if e.type == EventType.MAINTAINER_QUESTION]
        if questions:
            q = questions[0]
            topic = question_topic(q.payload.get("body", ""))
            if self.policy.allow_factual_replies and inp.has_reply_evidence and topic:
                return Decision(Route.POST_FACTUAL_RESPONSE, f"grounded reply available for topic={topic}",
                                trigger_key=f"q:{q.event_id}", question_topic=topic,
                                evidence={"question_event": q.event_id, "topic": topic})
            return self._human("maintainer question needs a human answer", inp, question_event=q.event_id, topic=topic or "unclassified")

        if inp.repair_in_flight or pr.state in IN_FLIGHT_STATES:
            return Decision(Route.WAIT, "repair/revision already in flight")

        worker = self._worker_route(inp)

        # Conflict.
        if EventType.CONFLICT_DETECTED in types:
            if b.ci_repairs_used >= b.ci_repairs_max:
                return self._human("repair budget exhausted (conflict)", inp)
            if worker is None:
                return Decision(Route.WAIT, "no worker available")
            return Decision(worker[0], "merge conflict with base branch", kind=TaskKind.CONFLICT_REPAIR,
                            trigger_key=f"conflict:{pr.head_sha}", permitted_routes=worker[1])

        # Maintainer feedback (level-triggered from unclaimed feedback).
        if inp.pending_feedback:
            flagged = [f for f in inp.pending_feedback if f.flags]
            ids = tuple(f.comment_id for f in inp.pending_feedback)
            if flagged and self.policy.hold_suspicious_feedback:
                return self._human("feedback contains instruction-like text; not routed automatically", inp,
                                   comment_ids=list(ids), flags=sorted({x for f in flagged for x in f.flags}))
            if b.revision_rounds_used >= b.revision_rounds_max:
                return self._human("revision budget exhausted", inp, comment_ids=list(ids))
            if worker is None:
                return Decision(Route.WAIT, "no worker available")
            return Decision(worker[0], "maintainer feedback requires code change", kind=TaskKind.REVIEW_REVISION,
                            trigger_key="rev:" + digest(sorted(ids))[7:19], permitted_routes=worker[1],
                            feedback=inp.pending_feedback, evidence={"comment_ids": list(ids)})

        # CI failure (level-triggered from open failures on the current head).
        if inp.open_ci_failures:
            patch = [e for e in inp.open_ci_failures if e.payload.get("failure_class") == FailureClass.PATCH_CAUSED_FAILURE.value]
            if patch:
                if b.ci_repairs_used >= b.ci_repairs_max:
                    return self._human("ci repair budget exhausted", inp, failing_checks=[e.payload.get("check_name") for e in patch])
                if worker is None:
                    return Decision(Route.WAIT, "no worker available")
                return Decision(worker[0], "patch-caused ci failure", kind=TaskKind.CI_REPAIR,
                                trigger_key=f"ci:{pr.head_sha}", permitted_routes=worker[1],
                                evidence={"events": [e.event_id for e in patch]})
            classes = sorted({e.payload.get("failure_class", "UNKNOWN_FAILURE") for e in inp.open_ci_failures})
            if b.nonactionable_streak >= b.nonactionable_max or inp.ci_failure_age_s >= self.policy.nonactionable_stall_s:
                return self._human("non-actionable ci failure persisted", inp, failure_classes=classes,
                                   age_s=int(inp.ci_failure_age_s))
            return Decision(Route.WAIT, "ci failure is not deterministically patch-caused; no code change", evidence={"failure_classes": classes})

        if pr.state == State.APPROVED:
            return Decision(Route.NO_ACTION, "approved; merge is a maintainer decision")
        return Decision(Route.NO_ACTION, "nothing actionable")


def question_topic(body: str) -> str:
    b = (body or "").lower()
    if any(w in b for w in ("test", "pass", "ci", "coverage")):
        return "tests"
    if any(w in b for w in ("what changed", "what did you", "did you update", "fixed", "addressed", "updated")):
        return "changes"
    return ""
