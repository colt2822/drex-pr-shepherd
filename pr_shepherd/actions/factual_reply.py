"""Evidence-grounded, template-only maintainer replies.

No model writes free text here. Every reply is one of a few fixed templates whose only
interpolations are values from stored verification/mission evidence, each validated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.models import WatchedPR
from ..core.policy import Policy


class EvidenceRequired(Exception):
    pass


class UnsafeReply(Exception):
    pass


_FORBIDDEN = re.compile(
    r"(?i)\b(pay|paid|payout|payment|bounty|reward|invoice|wallet|price|legal|licen[cs]e|liab|warrant|guarantee|"
    r"promise|i am (a )?human|as a human|kyc|tax)\w*"
)
_VALUE = re.compile(r"^[A-Za-z0-9_.:/\-\[\]@ ,()#]{1,160}$")


@dataclass(frozen=True)
class Reply:
    text: str
    topic: str
    evidence: dict


def _val(name: str, v: str) -> str:
    if not isinstance(v, str) or not _VALUE.match(v):
        raise UnsafeReply(f"unsafe value for {name}")
    return v


def build_reply(policy: Policy, pr: WatchedPR, topic: str) -> Reply:
    lv = pr.last_verification or {}
    if not policy.allow_factual_replies:
        raise EvidenceRequired("factual replies disabled by policy")
    if not lv.get("passed") or not pr.verification_receipt_id or not lv.get("evidence_digest"):
        raise EvidenceRequired("no passing stored verification receipt")
    sha = _val("sha", lv.get("head_sha", ""))[:12]
    receipt = _val("receipt", pr.verification_receipt_id)
    tests = [t for t in lv.get("tests", []) if isinstance(t, str)]
    if topic == "fixed":
        body = f"Fixed in {sha}. Verification receipt {receipt} passed."
    elif topic == "tests":
        if not tests:
            raise EvidenceRequired("no test names recorded in verification evidence")
        names = ", ".join(_val("test", t) for t in tests[:5])
        body = f"The verification run for {sha} passed. Tests covered: {names}. Receipt {receipt}."
    elif topic == "changes":
        summary = lv.get("summary", "")
        if not summary:
            raise EvidenceRequired("no change summary recorded")
        body = f"Updated in {sha}: {_val('summary', summary)}. Receipt {receipt}."
    else:
        raise EvidenceRequired(f"unsupported topic {topic!r}")
    text = policy.reply_disclosure + body
    if _FORBIDDEN.search(body):
        raise UnsafeReply("reply text contains a forbidden term")
    return Reply(text=text, topic=topic, evidence={"receipt_id": receipt, "head_sha": lv.get("head_sha", ""),
                                                    "evidence_digest": lv.get("evidence_digest", "")})
