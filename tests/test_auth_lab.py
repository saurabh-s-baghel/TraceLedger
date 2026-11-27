"""Exercise real HTTP requests against an isolated loopback lab server."""

import http.client
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lab.auth_server import DEMO_PASSWORD, make_server, new_session_log
from traceledger.detection import detect_repeated_failures
from traceledger.parsing import read_auth_log


class AuthLabTests(unittest.TestCase):
    def test_new_sessions_get_separate_logs_and_preserve_existing_data(self):
        root = Path(self.temporary.name) / "sessions"
        first = new_session_log(root)
        first.write_text("previous evidence\n")
        second = new_session_log(root)
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_text(), "previous evidence\n")
        self.assertEqual(second.read_text(), "")

    def test_restarted_server_does_not_mix_session_evidence(self):
        self.assertEqual(self.request()[0], 401)
        previous = self.log.read_bytes()
        fresh = new_session_log(Path(self.temporary.name) / "sessions")
        other = make_server(fresh, port=0)
        thread = threading.Thread(target=other.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", other.server_port, timeout=3)
            try:
                connection.request("POST", "/login",
                    body=urlencode(dict(account="lab-user", password=DEMO_PASSWORD)),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
            finally:
                connection.close()
        finally:
            other.shutdown()
            thread.join(timeout=3)
            other.server_close()
        self.assertEqual(self.log.read_bytes(), previous)
        parsed = read_auth_log(fresh)
        self.assertEqual(parsed.errors, [])
        self.assertEqual([event.outcome for event in parsed.events], ["success"])
        self.assertEqual(detect_repeated_failures(parsed.events), [])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.log = Path(self.temporary.name) / "auth.jsonl"
        self.server = make_server(self.log, port=0)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=3)

    def request(self, method="POST", path="/login", account="lab-user",
                password="wrong-lab-password", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            body = urlencode(dict(account=account, password=password)) if method == "POST" else None
            request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
            request_headers.update(headers or {})
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_form_is_available_on_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Never enter real credentials", body)
        self.assertFalse(self.log.exists())

    def test_success_failure_and_log_privacy(self):
        self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.request(password=DEMO_PASSWORD)[0], 200)
        parsed = read_auth_log(self.log)
        self.assertEqual(parsed.errors, [])
        self.assertEqual([event.outcome for event in parsed.events], ["failure", "success"])
        self.assertEqual(len({event.event_id for event in parsed.events}), 2)
        raw = self.log.read_text()
        self.assertNotIn("wrong-lab-password", raw)
        self.assertNotIn(DEMO_PASSWORD, raw)
        self.assertNotIn('"password"', raw)

    def test_live_requests_produce_expected_finding(self):
        for _ in range(5):
            self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.request(password=DEMO_PASSWORD)[0], 200)
        parsed = read_auth_log(self.log)
        self.assertEqual(parsed.errors, [])
        findings = detect_repeated_failures(parsed.events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 5)
        self.assertEqual(str(findings[0].source_ip), "127.0.0.1")
        self.assertEqual([event.event_id for event in findings[0].evidence],
                         [event.event_id for event in parsed.events[:5]])

    def test_arbitrary_account_is_not_logged(self):
        self.assertEqual(self.request(account="do-not-store-this")[0], 400)
        self.assertFalse(self.log.exists())

    def test_cross_origin_and_wrong_host_are_rejected(self):
        self.assertEqual(self.request(headers={"Origin": "https://example.com"})[0], 403)
        self.assertEqual(self.request(headers={"Host": "example.com"})[0], 403)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
