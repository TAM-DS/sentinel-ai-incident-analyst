"""Validated incident reports; no shell execution authority."""

from dataclasses import dataclass

ALLOWED_RUNBOOKS = {
    "RB-OBSERVE": "Observe and gather additional diagnostics",
    "RB-SERVICE": "Review failed service and its journal",
    "RB-STORAGE": "Investigate filesystem or disk health",
    "RB-AUTH": "Investigate authentication failures",
}

ALLOWED_SEVERITIES = {"informational", "warning", "critical"}


@dataclass(frozen=True)
class IncidentReport:
    title: str
    summary: str
    severity: str
    evidence_ids: tuple[str, ...]
    runbook_id: str
    uncertainty: str


def validate_report(payload: dict, evidence: list[dict]) -> IncidentReport:
    """Reject unsupported evidence, runbooks, or malformed fields."""
    if not isinstance(payload, dict):
        raise ValueError("Report must be an object")

    required = {
        "title", "summary", "severity", "evidence_ids",
        "runbook_id", "uncertainty"
    }
    if set(payload) != required:
        raise ValueError("Report has missing or unexpected fields")

    for field in ("title", "summary", "uncertainty"):
        value = payload[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 1000:
            raise ValueError(f"Invalid {field}")

    if payload["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError("Unrecognized severity")

    if payload["runbook_id"] not in ALLOWED_RUNBOOKS:
        raise ValueError("Unapproved runbook")

    ids = payload["evidence_ids"]
    if not isinstance(ids, list) or not ids or not all(
        isinstance(item, str) for item in ids
    ):
        raise ValueError("Invalid evidence references")

    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate evidence references")

    available = {item["evidence_id"] for item in evidence}
    if not set(ids).issubset(available):
        raise ValueError("Report references missing evidence")

    return IncidentReport(
        title=payload["title"],
        summary=payload["summary"],
        severity=payload["severity"],
        evidence_ids=tuple(ids),
        runbook_id=payload["runbook_id"],
        uncertainty=payload["uncertainty"],
    )


def offline_example(evidence: list[dict]) -> IncidentReport:
    """Synthetic demonstration, not an actual model-generated report."""
    if not evidence:
        raise ValueError("Evidence required")

    return validate_report(
        {
            "title": "Synthetic service startup failure",
            "summary": "A simulated service failed to start.",
            "severity": "warning",
            "evidence_ids": [evidence[0]["evidence_id"]],
            "runbook_id": "RB-SERVICE",
            "uncertainty": "Root cause not established.",
        },
        evidence,
    )
