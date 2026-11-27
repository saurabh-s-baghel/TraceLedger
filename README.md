# TraceLedger
A defensive log investigation lab using Python. Implemented: authentication JSONL validation, tested repeated-failure detection, configured subnet context, reproducible synthetic examples, a local authentication simulator, and a Streamlit evidence dashboard. Investigation filters, configurable rules, session-only case notes, and JSON/Markdown case exports are implemented.

## Setup

Use Python 3.11 or newer. Development validation was performed on Python 3.14 with Streamlit 1.67.0; other Python versions have not been verified here. From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

The analysis engine and local authentication server use the standard library; the dashboard requires Streamlit and its dependencies. The direct Streamlit version is pinned, but transitive dependencies are not fully locked.

## Architecture

```text
Synthetic authentication JSONL OR observed local login attempts
    -> parsing.py: validate fields, normalize UTC/IP values, report bad records
    -> detection.py: group failures, evaluate windows, retain exact evidence
    -> network.py: add explicitly configured subnet labels
    -> app.py: review events, diagnostics, settings, and findings
    -> reporting.py: export evidence and simulated analyst assessment
```

`lab/auth_server.py` produces observed local events. `traceledger/synthetic.py` generates controlled examples. The generated network JSONL is a scripted context fixture; network-event parsing and correlation are not implemented in the dashboard.

## Five-minute demonstration

1. Start the dashboard using the command below. Choose the original synthetic fixture: expect 12 accepted events, zero rejected records, and one finding with auth-001 through auth-005.
2. Raise the threshold to six: the finding disappears. Restore five. Filter the table to lab-casey: Alex's complete finding remains because display filters do not alter detector input.
3. In another terminal start the local authentication lab. Submit five wrong demo passwords within five minutes, then optionally the correct password.
4. In the dashboard click Refresh and select the session filename printed by the lab. Inspect the five-failure evidence and loopback labels. Existing sessions remain selectable; timestamps are actual UTC times.
5. Enter an observation, alternative explanation, missing context, and simulated next step. Leave the note field to apply the edit, then download JSON and Markdown. Check evidence IDs, rule settings, provenance, and assessment text.
6. Stop both servers with Ctrl+C. Runtime logs stay local. Downloaded reports remain wherever the browser saved them.

The observed lab walkthrough produced five failures and one success, parsed without errors and yielding one finding. Browser review confirmed the dashboard and controls; JSON export contents and the saved observation were inspected, and the user confirmed Markdown download. An earlier download returned “File not found”; a subsequent download succeeded, but its cause was not established.

## Evidence dashboard

The dashboard uses Streamlit 1.67.0. With the approved virtual environment installed:

```sh
.venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Open the local URL printed by Streamlit, normally http://127.0.0.1:8501. Select a synthetic fixture or observed lab session. Click Refresh to rediscover sessions and reread the selected file after new attempts. The dashboard displays accepted events, rejected-record diagnostics, findings, exact evidence IDs, and configured subnet labels. All timestamps are UTC. The loopback range 127.0.0.0/8 is explicitly labelled loopback lab; this is not an inferred device identity. There are no uploads, continuous monitoring, durable case-note storage, or external integrations in this slice. Stop with Ctrl+C. Keep the dashboard local.

`requirements.txt` pins the direct Streamlit dependency; it is not a complete lock of transitive dependencies. To reproduce the approved setup in a fresh environment, use `.venv/bin/python -m pip install -r requirements.txt` after approving installation.

### Investigation controls

Failure threshold (1–1000) and window length (1–1440 whole minutes) recompute findings over the full selected file. Each finding displays the parameters used. These interactive limits are dashboard choices, not validated operational thresholds.

Account, source-IP, outcome, and inclusive UTC start/end filters affect only the accepted-event table. Empty selections mean all values; blank time bounds are unbounded. Enter timezone-aware UTC bounds such as `2026-01-01T09:00:00Z`. Invalid or reversed bounds show an error and no table rows. Counts, diagnostics, findings, and complete evidence remain based on the full dataset, preventing filters from silently changing an investigation's evidence. Filter selections are separate for each source. No advanced network-event correlation is implemented.

## Local authentication lab

The local lab itself uses only the Python standard library. Run commands from the project root.

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

## Simulated case notes and exports

Each finding has fields for observations, alternative explanations, missing context, and an escalation recommendation. These are analyst-entered simulated assessments, separate from computed evidence. Notes are held only in the Streamlit browser session and can be lost on reload, disconnect, widget removal, or server restart. Download a report to retain them. Different sources, rule settings, or finding evidence use different note identities; notes are not silently transferred between findings. No durable case management is implemented.

Download JSON for structured evidence and Markdown for a readable report. Both include source provenance, rejected-record count, rule parameters, exact finding evidence, simulation labels, and limitations. They export the selected finding, not the complete dataset or all diagnostics. Display filters do not trim exported evidence. Downloads go to your browser's download location, not automatically into the repository. Keep local lab reports private; never enter secrets or personal information in notes. Reports do not send tickets or perform escalation actions.

## Synthetic examples

The original fixture has 12 fictional attempts. The generated example has 19 authentication events and 19 scripted network events. To create another repeatable dataset without overwriting those files:

```sh
.venv/bin/python -m traceledger.synthetic --seed 99 --output-dir reports/generated/seed-99
```

The same seed produces identical output for this generator implementation. Scenarios remain controlled: variation is not a realistic traffic model or evidence of effectiveness against unknown attacks.

## Validation results and limits

The final core validation passed 54 unittest methods, including parser, detector, subnet, generator, local HTTP/session, dashboard, and reporting checks. Subtests exercise additional invalid inputs. Tests verify defined behavior; no detection accuracy rate or enterprise performance benchmark is claimed. Human review covered local login activity, dashboard interaction, and report downloads.

This application is a rule-based defensive learning lab. It does not capture arbitrary browser logins, collect enterprise telemetry, prove compromise, automatically remediate, or provide durable incident case management. Shared source addresses can combine users' activity, while distributed account/source patterns can evade this rule. No Azure, ServiceNow, PowerShell, Power BI, or IoT integration is implemented. Coursework concepts informed learning; university solutions are not included.

## Public demo boundary

Deployment has not been performed. A future Streamlit deployment would use repository synthetic fixtures; it would not receive ignored logs from a developer's Mac. Deploy only the dashboard entry point app.py, never the disposable authentication simulator. No hosted ingestion, uploads, or remote link to the local lab is implemented. Review Python/dependency compatibility on the hosting platform before deploying. Once hosting tracks a branch, pushes may trigger deployments and must be reviewed accordingly.

## Privacy and repository contents

Runtime logs, virtual environments, local reports under reports/generated/, secrets files, and private learning notes are excluded. AGENTS.md and BLUEPRINT.md are local working documents, not current tracked files. Earlier Git history may still contain the initial agent instructions; exclusions do not erase history. The displayed demo password is deliberately public test data, never a real credential. Never enter personal information in demo forms or notes. No license has been selected yet.
