"""Tests for SENTINEL's evidence privacy boundary."""

import unittest

from src.privacy import prepare_evidence, redact_text


class TestPrivacy(unittest.TestCase):

    def test_redacts_sensitive_values(self):
        raw = (
            "Failed password from 192.0.2.10 "
            "email=demo@example.com "
            "api_key=synthetic-secret "
            "Bearer synthetic-token"
        )

        cleaned = redact_text(raw)

        for secret in (
            "192.0.2.10",
            "demo@example.com",
            "synthetic-secret",
            "synthetic-token",
        ):
            self.assertNotIn(secret, cleaned)

    def test_only_exports_approved_fields(self):
        prepared = prepare_evidence([{
            "timestamp": "2026-10-27T12:00:00+00:00",
            "source": "sshd",
            "priority": "4",
            "message": "Failed password",
            "private_metadata": "DO_NOT_EXPORT",
        }])

        self.assertEqual(
            set(prepared[0]),
            {"evidence_id", "timestamp", "source", "priority", "message"},
        )
        self.assertNotIn("DO_NOT_EXPORT", str(prepared))

    def test_rejects_more_than_twenty_events(self):
        with self.assertRaises(ValueError):
            prepare_evidence([{"message": "test"}] * 21)

    def test_truncates_long_messages(self):
        prepared = prepare_evidence([{"message": "X" * 500}])
        self.assertEqual(len(prepared[0]["message"]), 300)

    def test_rejects_malformed_input(self):
        with self.assertRaises(TypeError):
            prepare_evidence("not a list")

        with self.assertRaises(TypeError):
            prepare_evidence(["not a dictionary"])

    def test_assigns_stable_evidence_ids(self):
        prepared = prepare_evidence([
            {"message": "event one"},
            {"message": "event two"},
        ])
        self.assertEqual(
            [item["evidence_id"] for item in prepared],
            ["E001", "E002"],
        )


if __name__ == "__main__":
    unittest.main()
