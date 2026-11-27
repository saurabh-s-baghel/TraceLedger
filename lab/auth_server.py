"""Loopback-only authentication simulator. Never enter real credentials."""

import argparse
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from uuid import uuid4


DEMO_ACCOUNT = "lab-user"
DEMO_PASSWORD = "demo-only-password"  # Public disposable fixture, not a secret.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PAGE = b'''<!doctype html><html lang="en"><meta charset="utf-8">
<title>TraceLedger local lab</title><h1>Local authentication lab</h1>
<p>Simulator only. Never enter real credentials. No sessions are created.</p>
<p>Account: lab-user / disposable password: demo-only-password</p>
<form method="post" action="/login" autocomplete="off">
<label>Demo account <input name="account" value="lab-user" required></label>
<label>Demo password <input name="password" type="password" required></label>
<button>Submit lab attempt</button></form></html>'''


def make_server(log_path: str | Path, port: int = 8765) -> HTTPServer:
    """Create a single-threaded IPv4 loopback server; port 0 is useful in tests."""
    log_path = Path(log_path)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Do not echo request paths, headers, or submitted values to stderr.
            pass

        def reply(self, status, body, content_type="text/plain; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def allowed_request(self):
            # Restrict Host to the numeric loopback origin; reject cross-origin POSTs.
            expected_host = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != expected_host:
                self.reply(403, b"Use the printed numeric loopback URL.")
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin != f"http://{expected_host}":
                self.reply(403, b"Cross-origin requests are not accepted.")
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self.reply(403, b"Cross-site requests are not accepted.")
                return False
            return True

        def do_GET(self):
            if not self.allowed_request():
                return
            if self.path != "/":
                self.reply(404, b"Not found")
                return
            self.reply(200, PAGE, "text/html; charset=utf-8")

        def do_POST(self):
            if not self.allowed_request():
                return
            if self.path != "/login":
                self.reply(404, b"Not found")
                return
            if self.headers.get("Content-Type", "").split(";")[0] != "application/x-www-form-urlencoded":
                self.reply(415, b"Use the lab form.")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError
                body = self.rfile.read(length).decode("utf-8")
                fields = parse_qs(body, keep_blank_values=True, max_num_fields=4)
            except (ValueError, UnicodeError):
                self.reply(400, b"Invalid form.")
                return
            if set(fields) != {"account", "password"} or any(len(v) != 1 for v in fields.values()):
                self.reply(400, b"Supply one demo account and password.")
                return
            # Reject other account labels without storing arbitrary user input.
            if fields["account"][0] != DEMO_ACCOUNT:
                self.reply(400, b"Use the displayed fictional account; no event recorded.")
                return
            success = fields["password"][0] == DEMO_PASSWORD
            event = dict(event_id=str(uuid4()), timestamp=datetime.now(timezone.utc).isoformat(),
                         account=DEMO_ACCOUNT, source_ip=self.client_address[0],
                         destination_ip=self.server.server_address[0],
                         outcome="success" if success else "failure")
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with log_path.open("a", encoding="utf-8") as file:
                    file.write(json.dumps(event) + "\n")
            except OSError:
                self.reply(500, b"Could not record event; stop and check the log path.")
                return
            self.reply(200 if success else 401,
                       b"Lab success recorded. No session created.\nReturn to / for another attempt."
                       if success else b"Lab failure recorded.\nReturn to / for another attempt.")

    server = HTTPServer(("127.0.0.1", port), Handler)
    server.timeout = 2
    return server


def new_session_log(log_dir: str | Path) -> Path:
    """Reserve an empty unique log for a server run; never reuse earlier logs."""
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"lab-auth-{stamp}-{uuid4().hex}.jsonl"
    with path.open("x", encoding="utf-8"):
        pass
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    log_path = new_session_log(PROJECT_ROOT / "logs")
    with make_server(log_path, args.port) as server:
        print(f"Local demo: http://127.0.0.1:{server.server_port}", flush=True)
        print(f"Events: {log_path}\nStop with Ctrl+C. Never enter real credentials.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
