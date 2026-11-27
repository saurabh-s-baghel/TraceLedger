"""Headless checks of the actual Streamlit evidence viewer."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


class DashboardTests(unittest.TestCase):
    def test_notes_do_not_carry_to_changed_source_or_rule(self):
        app = self.app().run()
        app.text_area[0].input("Observed five failed attempts").run()
        self.assertEqual(app.text_area[0].value, "Observed five failed attempts")
        app.number_input[1].set_value(4).run()
        self.assertEqual(app.text_area[0].value, "")
        app.text_area[0].input("Four-minute review").run()
        app.selectbox[0].select("Synthetic: generated scenario").run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.text_area[0].value, "")

    def test_display_filters_do_not_remove_finding_evidence(self):
        app = self.app().run()
        app.multiselect[0].select("lab-casey").run()
        self.assertEqual(set(app.dataframe[0].value["account"]), {"lab-casey"})
        self.assertEqual([m.value for m in app.metric], ["12", "0", "1"])
        self.assertEqual(list(app.dataframe[1].value["event_id"]),
                         [f"auth-{n:03d}" for n in range(1, 6)])

    def test_source_and_outcome_filters(self):
        app = self.app().run()
        app.multiselect[1].select("192.0.2.11").run()
        app.multiselect[2].select("failure").run()
        self.assertEqual(len(app.dataframe[0].value), 5)
        self.assertEqual(set(app.dataframe[0].value["source_ip"]), {"192.0.2.11"})

    def test_time_filter_inclusive_and_invalid_bounds(self):
        app = self.app().run()
        app.text_input[0].input("2026-01-01T09:01:00Z").run()
        app.text_input[1].input("2026-01-01T09:03:00+00:00").run()
        self.assertEqual(list(app.dataframe[0].value["event_id"]),
                         ["auth-002", "auth-003", "auth-004"])
        for text in ("not-a-time", "2026-01-01T09:01:00", "2026-01-02T09:00:00Z"):
            app.text_input[0].input(text).run()
            self.assertEqual(len(app.exception), 0)
            self.assertEqual(len(app.error), 1)
            self.assertEqual(app.metric[2].value, "1")

    def test_rule_controls_recompute_findings_and_show_parameters(self):
        app = self.app().run()
        app.number_input[0].set_value(6).run()
        self.assertEqual(app.metric[2].value, "0")
        app.number_input[0].set_value(5).run()
        app.number_input[1].set_value(3).run()
        self.assertEqual(app.metric[2].value, "0")
        app.number_input[1].set_value(4).run()
        self.assertEqual(app.metric[2].value, "1")
        self.assertTrue(any("window: 0:04:00" in item.value for item in app.markdown))

    def app(self):
        return AppTest.from_file(str(ROOT / "app.py"), default_timeout=10)

    def test_original_fixture_displays_counts_and_exact_evidence(self):
        app = self.app().run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual([metric.value for metric in app.metric], ["12", "0", "1"])
        self.assertEqual(list(app.dataframe[1].value["event_id"]),
                         [f"auth-{n:03d}" for n in range(1, 6)])
        self.assertEqual(set(app.dataframe[1].value["source_subnet"]), {"workstation lab"})

    def test_generated_source_selection(self):
        app = self.app().run()
        app.selectbox[0].select("Synthetic: generated scenario").run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual([metric.value for metric in app.metric], ["19", "0", "1"])

    def test_local_session_refresh_and_invalid_record_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = Path(temporary) / "lab-auth-test.jsonl"
            session.write_text("")
            # Redirect session discovery to a temporary file; do not touch user logs.
            with patch.object(Path, "glob", return_value=[session]), \
                 patch.object(Path, "relative_to", return_value=Path("logs/lab-auth-test.jsonl")):
                app = self.app().run()
                app.selectbox[0].select("Observed local lab: lab-auth-test.jsonl").run()
                self.assertEqual([metric.value for metric in app.metric], ["0", "0", "0"])
                event = dict(event_id="local-test", timestamp="2026-01-01T09:00:00Z",
                             account="lab-user", source_ip="127.0.0.1",
                             destination_ip="127.0.0.1", outcome="failure")
                session.write_text(json.dumps(event) + "\n{broken\n")
                app.button[0].click().run()
                self.assertEqual(len(app.exception), 0)
                self.assertEqual([metric.value for metric in app.metric], ["1", "1", "0"])
                self.assertEqual(app.dataframe[0].value.iloc[0]["source_subnet"], "loopback lab")
                self.assertEqual(app.dataframe[1].value.iloc[0]["line_number"], 2)
                with patch("traceledger.parsing.read_auth_log", side_effect=OSError("unreadable")):
                    app.button[0].click().run()
                    self.assertEqual(len(app.exception), 0)
                    self.assertEqual(len(app.error), 1)


if __name__ == "__main__":
    unittest.main()
