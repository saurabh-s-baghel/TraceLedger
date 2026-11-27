"""Known outcomes and boundaries for the repeated-failure lab rule."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from traceledger.detection import detect_repeated_failures
from traceledger.parsing import AuthEvent, parse_auth_lines, read_auth_log


def event(number, seconds, account="lab-user", source="192.0.2.1",
          outcome="failure", destination="198.51.100.1"):
    return AuthEvent(str(number), datetime(2026, 1, 1, tzinfo=timezone.utc)
                     + timedelta(seconds=seconds), account, ip_address(source),
                     ip_address(destination), outcome)


class DetectionTests(unittest.TestCase):
    def test_two_triggering_groups_keep_their_own_evidence(self):
        first = [event(n, n * 60) for n in range(5)]
        second = [event(n + 10, n * 60, account="lab-other",
                        source="192.0.2.2") for n in range(5)]
        findings = detect_repeated_failures(list(reversed(first + second)))
        self.assertEqual(len(findings), 2)
        actual = {(f.account, str(f.source_ip)): {e.event_id for e in f.evidence}
                  for f in findings}
        self.assertEqual(actual, {
            ("lab-user", "192.0.2.1"): {str(n) for n in range(5)},
            ("lab-other", "192.0.2.2"): {str(n + 10) for n in range(5)},
        })

    def test_qualifying_intervals_sharing_endpoint_merge(self):
        # Two two-event intervals [0, 300] and [300, 600] share an endpoint.
        events = [event(n, seconds) for n, seconds in enumerate([0, 300, 600])]
        findings = detect_repeated_failures(events, threshold=2)
        self.assertEqual(len(findings), 1)
        self.assertEqual([e.event_id for e in findings[0].evidence], ["0", "1", "2"])
        self.assertEqual(findings[0].last_seen - findings[0].first_seen,
                         timedelta(minutes=10))

    def test_simultaneous_unique_failures_count_separately(self):
        events = [event(n, 0) for n in reversed(range(6))]
        findings = detect_repeated_failures(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 6)
        self.assertEqual([e.event_id for e in findings[0].evidence],
                         [str(n) for n in range(6)])
        self.assertEqual(findings[0].first_seen, findings[0].last_seen)

    def test_mixed_timezone_offsets_produce_correct_finding(self):
        timestamps = ["2026-01-01T09:00:00Z", "2026-01-01T10:01:00+01:00",
                      "2026-01-01T04:02:00-05:00", "2026-01-01T09:03:00Z",
                      "2026-01-01T09:04:00Z"]
        lines = [json.dumps(dict(event_id=str(n), timestamp=timestamp,
                                 account="lab-user", source_ip="192.0.2.1",
                                 destination_ip="198.51.100.1", outcome="failure"))
                 for n, timestamp in enumerate(timestamps)]
        parsed = parse_auth_lines(lines)
        self.assertEqual(parsed.errors, [])
        findings = detect_repeated_failures(parsed.events)
        self.assertEqual(len(findings), 1)
        self.assertEqual([e.event_id for e in findings[0].evidence],
                         [str(n) for n in range(5)])
        self.assertEqual(findings[0].last_seen - findings[0].first_seen,
                         timedelta(minutes=4))

    def test_invalid_records_do_not_inflate_failure_count(self):
        lines = [json.dumps(dict(event_id=str(n), timestamp=f"2026-01-01T09:0{n}:00Z",
                                 account="lab-user", source_ip="192.0.2.1",
                                 destination_ip="198.51.100.1", outcome="failure"))
                 for n in range(5)]
        # Invalid JSON, then a duplicate of a valid record between valid attempts.
        parsed = parse_auth_lines(lines[:2] + ["{broken", lines[0]] + lines[2:4])
        self.assertEqual([error.line_number for error in parsed.errors], [3, 4])
        self.assertEqual(len(parsed.events), 4)
        self.assertEqual(detect_repeated_failures(parsed.events), [])
        complete = parse_auth_lines(lines[:2] + ["{broken", lines[0]] + lines[2:])
        self.assertEqual(len(complete.errors), 2)
        findings = detect_repeated_failures(complete.events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 5)

    def test_isolated_failures_stay_outside_finding_evidence(self):
        events = [event(99, -600)] + [event(n, n * 60) for n in range(5)]
        events.append(event(100, 1200))
        findings = detect_repeated_failures(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual([e.event_id for e in findings[0].evidence],
                         [str(n) for n in range(5)])

    def test_fixture_produces_only_alex_finding(self):
        path = Path(__file__).resolve().parents[1] / "data/synthetic-auth.jsonl"
        parsed = read_auth_log(path)
        self.assertEqual(parsed.errors, [])
        findings = detect_repeated_failures(parsed.events)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.account, "lab-alex")
        self.assertEqual([e.event_id for e in finding.evidence],
                         [f"auth-{n:03d}" for n in range(1, 6)])
        self.assertEqual(finding.count, 5)
        self.assertEqual(finding.last_seen - finding.first_seen, timedelta(minutes=4))
        self.assertEqual(finding.threshold, 5)
        self.assertEqual(finding.window, timedelta(minutes=5))
        self.assertEqual(finding.label, "rule-based lab finding")

    def test_threshold_and_inclusive_time_boundary(self):
        events = [event(n, seconds) for n, seconds in enumerate([0, 60, 120, 180, 300])]
        self.assertEqual(detect_repeated_failures(events[:4]), [])
        self.assertEqual(len(detect_repeated_failures(events)), 1)
        events[-1] = event(4, 301)
        self.assertEqual(detect_repeated_failures(events), [])

    def test_accounts_and_sources_are_separate_groups(self):
        events = [event(n, n) for n in range(4)]
        for extra in (event(5, 5, account="other"), event(5, 5, source="192.0.2.2")):
            with self.subTest(extra=extra):
                self.assertEqual(detect_repeated_failures(events + [extra]), [])

    def test_sorting_is_deterministic_and_input_is_unchanged(self):
        events = [event(n, 0) for n in reversed(range(5))]
        original = list(events)
        finding = detect_repeated_failures(events)[0]
        self.assertEqual([e.event_id for e in finding.evidence], [str(n) for n in range(5)])
        self.assertEqual(events, original)

    def test_success_does_not_count_or_reset_and_destinations_do_not_split(self):
        events = [event(n, n * 60, destination=f"198.51.100.{n + 1}") for n in range(5)]
        events.insert(2, event(99, 90, outcome="success"))
        finding = detect_repeated_failures(events)[0]
        self.assertEqual(finding.count, 5)
        self.assertNotIn("99", [e.event_id for e in finding.evidence])

    def test_overlapping_windows_merge_unique_evidence_beyond_five_minutes(self):
        events = [event(n, n * 60) for n in range(8)]
        findings = detect_repeated_failures(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 8)
        self.assertEqual(findings[0].last_seen - findings[0].first_seen, timedelta(minutes=7))

    def test_disjoint_bursts_remain_separate(self):
        events = [event(n, n * 60) for n in range(5)]
        events += [event(n + 5, 3600 + n * 60) for n in range(5)]
        findings = detect_repeated_failures(events)
        self.assertEqual([f.count for f in findings], [5, 5])

    def test_empty_success_only_and_custom_settings(self):
        self.assertEqual(detect_repeated_failures([]), [])
        self.assertEqual(detect_repeated_failures([event(1, 0, outcome="success")]), [])
        self.assertEqual(len(detect_repeated_failures(
            [event(1, 0), event(2, 10)], threshold=2, window=timedelta(seconds=10))), 1)

    def test_duplicate_ids_and_invalid_settings_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            detect_repeated_failures([event(1, 0), event(1, 10)])
        for threshold in (0, -1, True, 1.5):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                detect_repeated_failures([], threshold=threshold)
        for window in (timedelta(0), timedelta(seconds=-1), 300):
            with self.subTest(window=window), self.assertRaises(ValueError):
                detect_repeated_failures([], window=window)


if __name__ == "__main__":
    unittest.main()
