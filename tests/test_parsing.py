"""Behavioral checks for authentication input validation."""

import json
import unittest
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

from traceledger.parsing import parse_auth_lines, read_auth_log


def record(**changes):
    event = dict(event_id="test-001", timestamp="2026-01-01T09:00:00Z",
                 account="lab-alex", source_ip="192.0.2.10",
                 destination_ip="198.51.100.20", outcome="failure")
    event.update(changes)
    return event


def parse(*records):
    return parse_auth_lines(json.dumps(item) for item in records)


class ParsingTests(unittest.TestCase):
    def test_fixture_has_twelve_typed_events(self):
        path = Path(__file__).resolve().parents[1] / "data/synthetic-auth.jsonl"
        result = read_auth_log(path)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.events), 12)
        self.assertEqual(result.events[0].timestamp,
                         datetime(2026, 1, 1, 9, tzinfo=timezone.utc))
        self.assertEqual(result.events[0].source_ip, ip_address("192.0.2.10"))

    def test_offset_normalizes_to_utc_and_ipv6_is_supported(self):
        result = parse(record(timestamp="2026-01-01T10:00:00+01:00",
                              source_ip="2001:db8::1", outcome="success"))
        self.assertEqual(result.errors, [])
        self.assertEqual(result.events[0].timestamp.hour, 9)
        self.assertEqual(result.events[0].timestamp.tzinfo, timezone.utc)
        self.assertEqual(result.events[0].source_ip, ip_address("2001:db8::1"))

    def test_invalid_line_does_not_hide_later_valid_event(self):
        result = parse_auth_lines(["{broken", "", json.dumps(record())])
        self.assertEqual([e.line_number for e in result.errors], [1, 2])
        self.assertEqual(len(result.events), 1)

    def test_invalid_record_shapes_and_fields(self):
        missing = record()
        del missing["account"]
        cases = [([], "JSON object"), (None, "JSON object"),
                 (missing, "missing fields: account"),
                 (record(account=""), "nonempty string"),
                 (record(account=7), "nonempty string"),
                 (record(account=" lab-alex"), "whitespace"),
                 (record(outcome="denied"), "outcome"),
                 (record(timestamp="not a date"), "ISO 8601"),
                 (record(timestamp="2026-01-01T09:00:00"), "timezone"),
                 (record(source_ip="999.0.0.1"), "source_ip"),
                 (record(destination_ip="hostname"), "destination_ip"),
                 (record(source_ip="fe80::1%en0"), "scope ID")]
        for item, reason in cases:
            with self.subTest(item=item):
                result = parse(item)
                self.assertEqual(result.events, [])
                self.assertEqual(len(result.errors), 1)
                self.assertIn(reason, result.errors[0].reason)

    def test_duplicate_keeps_first_valid_event(self):
        result = parse(record(), record(outcome="success"))
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].outcome, "failure")
        self.assertEqual(result.errors[0].line_number, 2)
        self.assertEqual(result.errors[0].reason, "duplicate event_id")

    def test_invalid_record_does_not_reserve_id(self):
        result = parse(record(outcome="invalid"), record())
        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.errors), 1)

    def test_empty_input_and_extra_fields(self):
        self.assertEqual(parse_auth_lines([]).events, [])
        self.assertEqual(parse_auth_lines([]).errors, [])
        self.assertEqual(parse(record(extra="ignored")).errors, [])


if __name__ == "__main__":
    unittest.main()
