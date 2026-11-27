# TraceLedger
A defensive log investigation lab using Python. Implemented: authentication JSONL validation, tested repeated-failure detection, configured subnet context, reproducible synthetic examples, a local authentication simulator, and a Streamlit evidence dashboard. Case exports and advanced investigation controls are planned.

## Evidence dashboard

The dashboard uses Streamlit 1.67.0. With the approved virtual environment installed:

```sh
.venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Open the local URL printed by Streamlit, normally http://127.0.0.1:8501. Select a synthetic fixture or observed lab session. Click Refresh to rediscover sessions and reread the selected file after new attempts. The dashboard displays accepted events, rejected-record diagnostics, findings, exact evidence IDs, and configured subnet labels. All timestamps are UTC. The loopback range 127.0.0.0/8 is explicitly labelled loopback lab; this is not an inferred device identity. There are no uploads, continuous monitoring, exports, case-note storage, or external integrations in this slice. Stop with Ctrl+C. Keep the dashboard local.

`requirements.txt` pins the direct Streamlit dependency; it is not a complete lock of transitive dependencies. To reproduce the approved setup in a fresh environment, use `.venv/bin/python -m pip install -r requirements.txt` after approving installation.

### Investigation controls

Failure threshold (1–1000) and window length (1–1440 whole minutes) recompute findings over the full selected file. Each finding displays the parameters used. These interactive limits are dashboard choices, not validated operational thresholds.

Account, source-IP, outcome, and inclusive UTC start/end filters affect only the accepted-event table. Empty selections mean all values; blank time bounds are unbounded. Enter timezone-aware UTC bounds such as `2026-01-01T09:00:00Z`. Invalid or reversed bounds show an error and no table rows. Counts, diagnostics, findings, and complete evidence remain based on the full dataset, preventing filters from silently changing an investigation's evidence. Filter selections are separate for each source. No advanced network-event correlation is implemented.

## Local authentication lab

Requires Python 3.11 or newer; no third-party dependencies for current features. Run commands from the project root.

```sh
python3 -m lab.auth_server
```

Open http://127.0.0.1:8765 in your browser. Use only the fictional account `lab-user` and public disposable password `demo-only-password`. Submit a wrong demo password five times within five minutes, returning to `/` between attempts, then optionally submit the correct one. Do not refresh a submitted form: resubmission creates another attempt. Stop the server with Ctrl+C.

The server binds only to IPv4 loopback. Each run reserves a new empty log named `logs/lab-auth-<UTC-start>-<unique-id>.jsonl` and prints its full path as `Events:`. Attempts append only to that run's log. Earlier logs, including the legacy `logs/lab-auth.jsonl`, remain intact and are not automatically included in a new session. All runtime logs are ignored by Git. Each record contains a random event ID, actual UTC timestamp, fixed fictional account, loopback source/destination, and success/failure outcome. Submitted passwords, headers, cookies, and tokens are not logged. Other account labels are rejected without logging.

In another terminal, analyze the recorded events. Replace the example path below with the exact `Events:` path printed by your server:

```sh
python3 - <<'PY'
from traceledger.parsing import read_auth_log
from traceledger.detection import detect_repeated_failures

result = read_auth_log("logs/REPLACE-WITH-YOUR-SESSION-FILENAME.jsonl")
print(f"Accepted: {len(result.events)}; errors: {len(result.errors)}")
for error in result.errors:
    print(error)
for finding in detect_repeated_failures(result.events):
    print(finding.label, finding.account, finding.source_ip, finding.count)
    print(finding.first_seen, finding.last_seen)
    print([event.event_id for event in finding.evidence])
PY
```

The new session log is initially empty. Restarting the server starts a fresh evidence file; it does not erase old files. An analysis of an old file can still produce historical findings. Findings mean review is warranted, not proven compromise. The rule groups by account/source, includes failures exactly five minutes apart, and does not reset on a successful login. Overlapping qualifying windows merge and can span more than five minutes.

This is an intentionally minimal authentication simulator: no sessions, secure credential storage, HTTPS, lockouts, or remediation. It is not production authentication or a service to deploy publicly. Loopback activity does not demonstrate diverse network sources, VLAN discovery, or enterprise monitoring. It does not capture arbitrary website logins. Only use disposable demo inputs.

## Validation

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Lab tests open an ephemeral loopback HTTP server, send actual local requests, and store temporary logs outside the repository. Other tests cover parser validation, detection boundaries and evidence, subnet membership, and synthetic reproducibility. See `MILESTONES.md` for recorded results and planned work.
