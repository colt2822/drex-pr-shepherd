"""Replay dedupe and feedback grouping."""
from __future__ import annotations

from typing import Iterable

from .models import EventType, FeedbackItem, ShepherdEvent


def feedback_from_event(ev: ShepherdEvent) -> FeedbackItem | None:
    """Return a FeedbackItem if this event is actionable feedback from a trusted human."""
    p = ev.payload
    if not p.get("actor_trusted"):
        return None
    body = p.get("body", "")
    flags = tuple(p.get("flags", ()))
    if ev.type == EventType.REVIEW_CHANGES_REQUESTED:
        kind = "changes_requested"
    elif ev.type == EventType.REVIEW_COMMENT and p.get("inline"):
        kind = "inline"
    elif ev.type == EventType.PR_COMMENT:
        from .classifier import looks_like_request

        if not looks_like_request(body):
            return None
        kind = "general"
    else:
        return None
    return FeedbackItem(
        comment_id=p.get("comment_id", ev.source_event_id),
        actor=ev.actor,
        path=p.get("path", ""),
        line=p.get("line"),
        body=body,
        kind=kind,
        flags=flags,
        event_id=ev.event_id,
    )


def group_feedback(items: Iterable[FeedbackItem], event_digests: dict[str, str] | None = None) -> tuple[FeedbackItem, ...]:
    """Collapse duplicate feedback (same actor/path/line/body) keeping the earliest; stable order."""
    seen: set[tuple] = set()
    out: list[FeedbackItem] = []
    for it in items:
        key = (it.actor, it.path, it.line, " ".join(it.body.lower().split()))
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return tuple(out)
