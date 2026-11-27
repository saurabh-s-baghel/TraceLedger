import json
import unittest
from dataclasses import replace
from pathlib import Path

from traceledger.detection import detect_repeated_failures
from traceledger.parsing import read_auth_log
from traceledger.reporting import build_report, finding_key, report_json, report_markdown


class ReportingTests(unittest.TestCase):
    def setUp(self):
        events = read_auth_log(Path(__file__).resolve().parents[1] / "data/synthetic-auth.jsonl").events
        self.finding = detect_repeated_failures(events)[0]

    def test_json_preserves_evidence_settings_and_separate_assessment(self):
        report = build_report(self.finding, "fixture", "synthetic", {"observations": "Review needed"}, 2)
        decoded = json.loads(report_json(report))
        self.assertEqual(decoded["computed"]["count"], 5)
        self.assertEqual(decoded["computed"]["threshold"], 5)
        self.assertEqual(decoded["computed"]["window_seconds"], 300)
        self.assertEqual([e["event_id"] for e in decoded["computed"]["evidence"]],
                         [f"auth-{n:03d}" for n in range(1, 6)])
        self.assertEqual(decoded["analyst_assessment"]["observations"], "Review needed")
        self.assertEqual(decoded["dataset"]["rejected_records"], 2)

    def test_note_identity_changes_with_source_settings_or_evidence(self):
        original = finding_key(self.finding, "a")
        self.assertNotEqual(original, finding_key(self.finding, "b"))
        self.assertNotEqual(original, finding_key(replace(self.finding, threshold=4), "a"))
        modified = replace(self.finding.evidence[0], account="changed")
        changed = replace(self.finding, evidence=(modified,) + self.finding.evidence[1:])
        self.assertNotEqual(original, finding_key(changed, "a"))

    def test_markdown_contains_exact_evidence_and_simulation_limitations(self):
        report = build_report(self.finding, "fixture", "synthetic", {"observations": "# My note\nsecond line"})
        text = report_markdown(report)
        self.assertIn("auth-001", text)
        self.assertIn("auth-005", text)
        self.assertIn("> # My note\n> second line", text)
        self.assertIn("not proof of compromise", text)
        self.assertIn("Not recorded.", text)
