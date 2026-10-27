"""Offline regression tests for the OpenAI adapter."""

import json
import unittest
from types import SimpleNamespace

from src.openai_adapter import analyze_synthetic_events


EVENTS = [{
    "timestamp": "2026-10-27T12:00:00Z",
    "source": "systemd",
    "priority": "3",
    "message": "synthetic-demo.service: Failed to start",
}]

VALID_REPORT = {
    "title": "Synthetic service failure",
    "summary": "The supplied event reports a failed service startup.",
    "severity": "warning",
    "evidence_ids": ["E001"],
    "runbook_id": "RB-SERVICE",
    "uncertainty": "Root cause not established.",
}


class FakeResponses:
    def __init__(self, payload=None, status="completed", output_text=None):
        self.payload = VALID_REPORT if payload is None else payload
        self.status = status
        self.output_text = output_text
        self.call_count = 0
        self.last_kwargs = None

    def create(self, **kwargs):
        self.call_count += 1
        self.last_kwargs = kwargs
        text = (
            self.output_text
            if self.output_text is not None
            else json.dumps(self.payload)
        )
        return SimpleNamespace(status=self.status, output_text=text)


class TestOpenAIAdapter(unittest.TestCase):

    def setUp(self):
        self.responses = FakeResponses()
        self.client = SimpleNamespace(responses=self.responses)

    def test_disabled_by_default(self):
        with self.assertRaises(PermissionError):
            analyze_synthetic_events(EVENTS, client=self.client)

        self.assertEqual(self.responses.call_count, 0)

    def test_valid_model_response(self):
        report = analyze_synthetic_events(
            EVENTS, allow_live=True, client=self.client
        )

        self.assertEqual(report.runbook_id, "RB-SERVICE")
        self.assertEqual(report.evidence_ids, ("E001",))
        self.assertEqual(self.responses.call_count, 1)

    def test_rejects_unapproved_runbook(self):
        self.responses.payload = {
            **VALID_REPORT,
            "runbook_id": "RUN-EXECUTE-SHELL",
        }

        with self.assertRaises(ValueError):
            analyze_synthetic_events(
                EVENTS, allow_live=True, client=self.client
            )

    def test_rejects_missing_evidence(self):
        self.responses.payload = {
            **VALID_REPORT,
            "evidence_ids": ["E999"],
        }

        with self.assertRaises(ValueError):
            analyze_synthetic_events(
                EVENTS, allow_live=True, client=self.client
            )

    def test_rejects_incomplete_response(self):
        self.responses.status = "incomplete"

        with self.assertRaises(ValueError):
            analyze_synthetic_events(
                EVENTS, allow_live=True, client=self.client
            )

    def test_rejects_malformed_json(self):
        self.responses.output_text = "not valid JSON"

        with self.assertRaises(json.JSONDecodeError):
            analyze_synthetic_events(
                EVENTS, allow_live=True, client=self.client
            )

    def test_rejects_empty_evidence(self):
        with self.assertRaises(ValueError):
            analyze_synthetic_events(
                [], allow_live=True, client=self.client
            )

        self.assertEqual(self.responses.call_count, 0)

    def test_structured_output_and_no_storage(self):
        analyze_synthetic_events(
            EVENTS, allow_live=True, client=self.client
        )

        kwargs = self.responses.last_kwargs

        self.assertFalse(kwargs["store"])
        self.assertEqual(
            kwargs["text"]["format"]["type"], "json_schema"
        )
        self.assertEqual(kwargs["max_output_tokens"], 500)


if __name__ == "__main__":
    unittest.main()
