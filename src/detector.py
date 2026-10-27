"""Deterministic incident detection for normalized Linux events."""

import re
from collections import Counter

RULES = (
    (
        "ssh_auth_failure",
        "Authentication failures",
        "warning",
        re.compile(r"failed password|authentication failure", re.I),
    ),
    (
        "service_failure",
        "Service failures",
        "critical",
        re.compile(r"failed to start|entered failed state|main process exited", re.I),
    ),
    (
        "filesystem_error",
        "Filesystem errors",
        "critical",
        re.compile(r"EXT4-fs error|I/O error|no space left on device", re.I),
    ),
    (
        "kernel_workqueue_delay",
        "Kernel workqueue delays",
        "warning",
        re.compile(r"workqueue:.*hogged CPU", re.I),
    ),
)


def detect_events(events):
    """Classify events using explicit, inspectable rules."""
    findings = []

    for event in events:
        message = str(event.get("message", ""))

        for rule_id, title, severity, pattern in RULES:
            if pattern.search(message):
                findings.append({
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "timestamp": event.get("timestamp"),
                    "source": event.get("source", "unknown"),
                    "evidence": message[:300],
                })
                break

    return findings


def summarize_findings(findings):
    """Aggregate matching event counts by rule."""
    counts = Counter(item["rule_id"] for item in findings)
    return dict(sorted(counts.items()))



def cluster_findings(findings):
    """Group matching observations by rule and source."""
    clusters = {}

    for finding in findings:
        key = (finding["rule_id"], finding["source"])

        if key not in clusters:
            clusters[key] = {
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "source": finding["source"],
                "event_count": 0,
                "first_seen": finding["timestamp"],
                "last_seen": finding["timestamp"],
            }

        cluster = clusters[key]
        cluster["event_count"] += 1

        timestamp = finding["timestamp"]
        if timestamp:
            if not cluster["first_seen"] or timestamp < cluster["first_seen"]:
                cluster["first_seen"] = timestamp
            if not cluster["last_seen"] or timestamp > cluster["last_seen"]:
                cluster["last_seen"] = timestamp

    return sorted(
        clusters.values(),
        key=lambda item: (-item["event_count"], item["rule_id"], item["source"]),
    )


if __name__ == "__main__":
    sample_events = [
        {"message": "Failed password for invalid user test from 192.0.2.10"},
        {"message": "example.service: Failed to start"},
        {"message": "EXT4-fs error on device"},
        {"message": "workqueue: e1000_watchdog hogged CPU for >10000us"},
        {"message": "Normal service heartbeat"},
    ]

    findings = detect_events(sample_events)
    print("Findings:", len(findings))
    print("Summary:", summarize_findings(findings))

    assert len(findings) == 4
    print("PASS: Deterministic incident detection")
