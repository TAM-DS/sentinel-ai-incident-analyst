"""Deterministic regression tests for SENTINEL."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.collector import collect_events
from src.detector import (
    cluster_findings,
    detect_events,
    summarize_findings,
)
from src.storage import count_events, save_events


def event(message, timestamp="2026-10-27T12:00:00+00:00", source="kernel"):
    """Create a synthetic normalized journal event."""
    return {
        "timestamp": timestamp,
        "source": source,
        "priority": "4",
        "message": message,
    }


class TestCollector(unittest.TestCase):

    def test_normalizes_journal_record(self):
        journal_record = {
            "__REALTIME_TIMESTAMP": "1793127930667901",
            "_TRANSPORT": "kernel",
            "PRIORITY": "4",
            "MESSAGE": "Synthetic test message",
        }

        with patch("src.collector.subprocess.run") as run:
            run.return_value.stdout = json.dumps(journal_record) + "\n"

            records = collect_events(1)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source"], "kernel")
        self.assertEqual(records[0]["priority"], "4")
        self.assertEqual(records[0]["message"], "Synthetic test message")
        self.assertIsNotNone(records[0]["timestamp"])

        arguments = run.call_args.args[0]
        self.assertEqual(arguments[0], "journalctl")
        self.assertNotIn("sudo", arguments)

    def test_rejects_invalid_limits(self):
        for limit in (0, -1, 1001):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    collect_events(limit)


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.directory.name) / "test.db"

    def tearDown(self):
        self.directory.cleanup()

    def test_deduplicates_exact_records(self):
        records = [
            event("Synthetic SSH authentication failure"),
            event("Synthetic service failure"),
        ]

        self.assertEqual(save_events(records, self.db_path), 2)
        self.assertEqual(save_events(records, self.db_path), 0)
        self.assertEqual(count_events(self.db_path), 2)

    def test_preserves_different_timestamps(self):
        first = event("Repeated workqueue warning", "2026-10-27T12:00:00+00:00")
        second = event("Repeated workqueue warning", "2026-10-27T12:01:00+00:00")

        self.assertEqual(save_events([first, second], self.db_path), 2)
        self.assertEqual(count_events(self.db_path), 2)


class TestDetection(unittest.TestCase):

    def test_known_incident_patterns(self):
        messages = [
            "Failed password for invalid user demo",
            "example.service: Failed to start",
            "EXT4-fs error on device",
            "workqueue: e1000_watchdog hogged CPU for >10000us",
        ]

        findings = detect_events([event(message) for message in messages])

        self.assertEqual(len(findings), 4)
        self.assertEqual(
            {finding["rule_id"] for finding in findings},
            {
                "ssh_auth_failure",
                "service_failure",
                "filesystem_error",
                "kernel_workqueue_delay",
            },
        )

    def test_normal_event_has_no_findings(self):
        self.assertEqual(
            detect_events([event("System operating normally")]),
            [],
        )

    def test_repeated_warnings_become_one_cluster(self):
        records = [
            event(
                "workqueue: e1000_watchdog hogged CPU",
                f"2026-10-27T12:{minute:02d}:00+00:00",
            )
            for minute in range(10)
        ]

        findings = detect_events(records)
        clusters = cluster_findings(findings)

        self.assertEqual(len(findings), 10)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["event_count"], 10)
        self.assertEqual(clusters[0]["source"], "kernel")
        self.assertEqual(clusters[0]["first_seen"], records[0]["timestamp"])
        self.assertEqual(clusters[0]["last_seen"], records[-1]["timestamp"])

    def test_groups_different_sources_separately(self):
        records = [
            event("workqueue: a hogged CPU", source="kernel"),
            event("workqueue: b hogged CPU", source="other"),
        ]

        clusters = cluster_findings(detect_events(records))

        self.assertEqual(len(clusters), 2)
        self.assertEqual(sum(c["event_count"] for c in clusters), 2)

    def test_summarizes_rule_counts(self):
        findings = detect_events([
            event("Failed password for user demo"),
            event("Failed password for user test"),
            event("EXT4-fs error detected"),
        ])

        self.assertEqual(
            summarize_findings(findings),
            {"filesystem_error": 1, "ssh_auth_failure": 2},
        )


if __name__ == "__main__":
    unittest.main()
