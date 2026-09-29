"""Untrusted-input handling. All GitHub-derived text is data, never instructions.

Nothing in this module executes, evaluates, or follows text. It only redacts, bounds,
flags, and quotes.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable
from urllib.parse import urlparse

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_URL = re.compile(r"https?://[^\s<>)\"']+", re.I)

_SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*\S{8,}"),
]

_INJECTION_PATTERNS = [
    ("override_instructions", re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,30}\b(instruction|prompt|rule)s?")),
    ("role_reassignment", re.compile(r"(?i)\b(you are now|act as|pretend to be|new instructions?|system prompt)\b")),
    ("agent_command", re.compile(r"(?i)(@drex|@shepherd|/drex|/shepherd|\bROUTE_(CODEX|CLAUDE)\b|\bRUN_VERIFIER\b|\bHUMAN_ACTION_REQUIRED\b)")),
    ("shell_command", re.compile(r"(?i)(\brm\s+-rf\b|\bcurl\b[^\n]*\|\s*(ba)?sh|\bwget\b[^\n]*\|\s*(ba)?sh|\bsudo\b|\bchmod\s+[0-7]{3,4}\b|`[^`\n]*\b(rm|curl|wget|nc|bash|sh)\b[^`\n]*`|\$\([^)]*\))")),
    ("secret_exfiltration", re.compile(r"(?i)\b(print|send|post|upload|reveal|leak|cat)\b.{0,40}(\.env|token|secret|credential|ssh|api[_ -]?key|password)")),
    ("payment_redirect", re.compile(r"(?i)\b(wallet|payout|payment|bank|iban|paypal)\b.{0,40}\b(address|destination|change|send|transfer|to)\b")),
    ("merge_command", re.compile(r"(?i)\b(merge|approve|close)\s+(this|the)\s+(pr|pull request)\s+(now|immediately)\b")),
]

_SAFE_REPO = re.compile(r"^[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}$")
_SAFE_BRANCH = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$")
_SAFE_SHA = re.compile(r"^[0-9a-f]{7,64}$")


def redact_secrets(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def clean_text(text: Any, max_chars: int = 4000) -> str:
    """Strip control chars/ANSI, redact secrets, normalize unicode, bound length."""
    s = "" if text is None else str(text)
    s = unicodedata.normalize("NFKC", s)
    s = _ANSI.sub("", s)
    s = _CONTROL.sub("", s)
    s = redact_secrets(s)
    if len(s) > max_chars:
        s = s[:max_chars] + "…[truncated]"
    return s


def injection_flags(text: str) -> tuple[str, ...]:
    return tuple(name for name, pat in _INJECTION_PATTERNS if pat.search(text or ""))


def strip_external_urls(text: str, allowed_hosts: Iterable[str]) -> str:
    allowed = {h.lower() for h in allowed_hosts}

    def repl(m: re.Match) -> str:
        host = (urlparse(m.group(0)).hostname or "").lower()
        if host in allowed or any(host.endswith("." + a) for a in allowed):
            return m.group(0)
        return "[external-link-removed]"

    return _URL.sub(repl, text)


def sanitize_untrusted(text: Any, *, max_chars: int = 4000, allowed_hosts: Iterable[str] = ("github.com",)) -> str:
    return strip_external_urls(clean_text(text, max_chars), allowed_hosts)


def quote_untrusted(text: Any, *, source: str, max_chars: int = 2000, allowed_hosts: Iterable[str] = ("github.com",)) -> dict[str, Any]:
    """Wrap untrusted prose as a labelled evidence record.

    The result is a plain dict destined for a JSON field named `untrusted_evidence`.
    It is never concatenated into the control-plane instruction text.
    """
    body = sanitize_untrusted(text, max_chars=max_chars, allowed_hosts=allowed_hosts)
    return {
        "source": source,
        "trust": "UNTRUSTED_DATA_NOT_INSTRUCTIONS",
        "text": body,
        "injection_flags": list(injection_flags(str(text or ""))),
    }


def is_safe_repo(name: str) -> bool:
    return bool(_SAFE_REPO.match(name or "")) and ".." not in name


def is_safe_branch(name: str) -> bool:
    return (
        bool(_SAFE_BRANCH.match(name or ""))
        and not name.startswith(("-", "/"))
        and ".." not in name
        and not name.endswith(("/", ".lock"))
    )


def is_safe_sha(sha: str) -> bool:
    return bool(_SAFE_SHA.match(sha or ""))


def safe_relative_path(path: Any) -> str:
    """Return a workspace-relative path or '' if the path could escape or is malformed."""
    if not isinstance(path, str) or not path or len(path) > 300:
        return ""
    if "\x00" in path or _CONTROL.search(path) or path.startswith(("/", "-", "~")):
        return ""
    if re.match(r"^[A-Za-z]:[\\/]", path) or "\\" in path:
        return ""
    parts = path.split("/")
    if any(p in ("..", "") for p in parts):
        return ""
    if any(ch in path for ch in "`$;|&<>\n\r"):
        return ""
    return path
