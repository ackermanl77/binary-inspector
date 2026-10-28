from __future__ import annotations

import json
import unittest

from binary_inspector.sandbox_report import (
    MAX_SANDBOX_EVENTS,
    MAX_SANDBOX_REPORT_BYTES,
    SandboxReportError,
    parse_sandbox_report,
)

SAMPLE_HASH = "a" * 64


def report_payload(**overrides):
    payload = {
        "schema": "binary-inspector-sandbox-v1",
        "source_sha256": SAMPLE_HASH,
        "events": [
            {
                "category": "network",
                "action": "connection-attempt",
                "target": "example.invalid:443",
                "details": "Observed by an independent isolated sandbox.",
                "timestamp": "2026-10-27T12:00:00Z",
            }
        ],
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


class SandboxReportTests(unittest.TestCase):
    def test_imports_normalized_events_and_matches_sample_hash(self):
        report = parse_sandbox_report(report_payload(), SAMPLE_HASH)
        self.assertEqual(len(report.events), 1)
        self.assertEqual(report.events[0].category, "network")
        self.assertTrue(report.source_hash_matches)

    def test_warns_when_report_hash_does_not_match(self):
        self.assertFalse(parse_sandbox_report(report_payload(), "b" * 64).source_hash_matches)
        self.assertIsNone(parse_sandbox_report(report_payload(source_sha256=None), SAMPLE_HASH).source_hash_matches)

    def test_rejects_wrong_schema_and_invalid_event(self):
        with self.assertRaisesRegex(SandboxReportError, "schema"):
            parse_sandbox_report(report_payload(schema="unknown"))
        with self.assertRaisesRegex(SandboxReportError, "category"):
            parse_sandbox_report(report_payload(events=[{"category": "command", "action": "run"}]))
        with self.assertRaisesRegex(SandboxReportError, "action"):
            parse_sandbox_report(report_payload(events=[{"category": "process"}]))

    def test_bounds_report_size_and_event_count(self):
        with self.assertRaisesRegex(SandboxReportError, "5 MiB"):
            parse_sandbox_report(b" " * (MAX_SANDBOX_REPORT_BYTES + 1))
        too_many = [{"category": "other", "action": "event"}] * (MAX_SANDBOX_EVENTS + 1)
        with self.assertRaisesRegex(SandboxReportError, "at most"):
            parse_sandbox_report(report_payload(events=too_many))


if __name__ == "__main__":
    unittest.main()
