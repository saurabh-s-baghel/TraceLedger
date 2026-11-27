"""Known outcomes and boundaries for the repeated-failure lab rule."""

import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from traceledger.detection import detect_repeated_failures
from traceledger.parsing import AuthEvent, read_auth_log


def event(number, seconds, account="lab-user", source="192.0.2.1",
          outcome="failure", destination="198.51.100.1"):
    return AuthEvent(str(number), datetime(2026, 1, 1, tzinfo=timezone.utc)
                     + timedelta(seconds=seconds), account, ip_address(source),
                     ip_address(destination), outcome)


class DetectionTests(unittest.TestCase):
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
