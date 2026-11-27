"""Headless checks of the actual Streamlit evidence viewer."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


class DashboardTests(unittest.TestCase):
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
