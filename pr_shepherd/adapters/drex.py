"""Drex routing adapter.

Drex (or any external router) may PROPOSE a route. The deterministic router remains the
authority: a proposal is accepted only if it is one of the routes the deterministic router
permits for this exact input. Anything else is overridden and logged.
"""
from __future__ import annotations

from typing import Callable, Optional, Protocol

from ..core.models import Decision, DecisionInput, Route
from ..core.policy import Policy
from ..core.router import DeterministicRouter


class ExternalRouter(Protocol):
    def propose(self, inp: DecisionInput) -> Optional[Route]: ...


class DrexAdapter:
    def __init__(self, policy: Policy, external: Optional[ExternalRouter] = None,
                 on_override: Optional[Callable[[Route, Decision], None]] = None):
        self.det = DeterministicRouter(policy)
        self.external = external
        self.on_override = on_override

    def decide(self, inp: DecisionInput) -> Decision:
        det = self.det.decide(inp)
        if self.external is None:
            return det
        try:
            proposed = self.external.propose(inp)
        except Exception:  # an external router failure must never stall the shepherd
            return det
        permitted = det.permitted_routes or (det.route,)
        if proposed in permitted:
            if proposed != det.route:
                return Decision(proposed, det.reason, det.kind, det.trigger_key, det.permitted_routes, det.evidence,
                                det.feedback, det.question_topic)
            return det
        if proposed is not None and self.on_override:
            self.on_override(proposed, det)
        return det
