"""Regression tests for SENTINEL incident report validation."""

import unittest
from dataclasses import replace

from src.analysis import (
    ALLOWED_RUNBOOKS,
    offline_example,
    validate_report,
)
from src.privacy import prepare_evidence


class TestAnalysis(unittest.TestCase):

    def setUp(self):
        self.evidence = prepare_evidence([{
            "timestamp": "2026-10-27T12:00:00Z",
            "source": "systemd",
            "priority": "3",
            "message": "synthetic-demo.service: Failed to start",
        }])

        self.valid = {
            "title": "Service failure",
            "summary": "A synthetic service failed to start.",
            "severity": "warning",
            "evidence_ids": ["E001"],
            "runbook_id": "RB-SERVICE",
            "uncertainty": "Root cause unknown.",
        }

    def test_valid_report(self):
        report = validate_report(self.valid, self.evidence)
        self.assertEqual(report.runbook_id, "RB-SERVICE")
        self.assertEqual(report.evidence_ids, ("E001",))

    def test_rejects_unknown_evidence(self):
        invalid = {**self.valid, "evidence_ids": ["E999"]}
        with self.assertRaises(ValueError):
            validate_report(invalid, self.evidence)

    def test_rejects_unauthorized_runbook(self):
        invalid = {**self.valid, "runbook_id": "RUN-EXECUTE-SHELL"}
        with self.assertRaises(ValueError):
            validate_report(invalid, self.evidence)

    def test_rejects_unrecognized_severity(self):
        invalid = {**self.valid, "severity": "emergency"}
        with self.assertRaises(ValueError):
            validate_report(invalid, self.evidence)

    def test_rejects_unexpected_command_field(self):
        invalid = {**self.valid, "command": "sudo reboot"}
        with self.assertRaises(ValueError):
            validate_report(invalid, self.evidence)

    def test_offline_example_uses_approved_runbook(self):
        report = offline_example(self.evidence)
        self.assertIn(report.runbook_id, ALLOWED_RUNBOOKS)
        self.assertEqual(report.evidence_ids, ("E001",))


if __name__ == "__main__":
    unittest.main()
