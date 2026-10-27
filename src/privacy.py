"""Bound and sanitize evidence before external AI analysis."""

import re

MAX_EVENTS = 20
MAX_MESSAGE_LENGTH = 300

PATTERNS = (
    # Common bearer tokens and API-key assignments
    (
        re.compile(
            r"(?i)\b(?:bearer)\s+[A-Za-z0-9._~+/-]+"
        ),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|password|secret)"
            r"\s*[:=]\s*[^\s,;]+"
        ),
        "[REDACTED_CREDENTIAL]",
    ),
    # Email addresses
    (
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "[REDACTED_EMAIL]",
    ),
    # IPv4 addresses, including addresses embedded in logs
    (
        re.compile(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        "[REDACTED_IP]",
    ),
    # Common absolute Linux home-directory paths
    (
        re.compile(r"/home/[^/\s]+"),
        "/home/[REDACTED_USER]",
    ),
)


def redact_text(value: str) -> str:
    """Apply basic defense-in-depth redaction to text."""
    text = str(value)

    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)

    return text


def prepare_evidence(events: list[dict]) -> list[dict]:
    """Return a small, sanitized evidence bundle.

    Reject malformed input rather than silently accepting arbitrary
    event structures.
    """
    if not isinstance(events, list):
        raise TypeError("events must be a list")

    if len(events) > MAX_EVENTS:
        raise ValueError(
            f"Too many events: maximum is {MAX_EVENTS}"
        )

    prepared = []

    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise TypeError("each event must be a dictionary")

        # Only explicitly approved fields leave this boundary.
        prepared.append({
            "evidence_id": f"E{index:03d}",
            "timestamp": redact_text(
                event.get("timestamp") or "unknown"
            )[:40],
            "source": redact_text(
                event.get("source") or "unknown"
            )[:80],
            "priority": str(
                event.get("priority", "unknown")
            )[:12],
            "message": redact_text(
                event.get("message") or ""
            )[:MAX_MESSAGE_LENGTH],
        })

    return prepared
