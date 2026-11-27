# TraceLedger milestones

This tracker separates completed work from planned features. Individual milestone descriptions record what existed at that checkpoint; later features supersede historical limitations. The current summary below reconciles implementation and publication status. TraceLedger is a defensive learning lab using synthetic data, not evidence of operational incident-response experience.

## Current core status — November 27, 2026

Milestones 1–10 are implemented and committed locally. The last verified fetched GitHub reference includes milestones through subnet classification; five later commits remain ahead of that reference. No fresh remote fetch or deployment was performed during final preparation. Milestone 11 is a local documentation change pending its own review and commit. Routine milestone tags are not used.

Manual checks completed: observed local login attempts produced one evidence-backed finding; the user reviewed dashboard display and rule controls, JSON report evidence and saved assessment, and confirmed Markdown download. Per-run log separation and note identity also have automated coverage. Final regression: 54 unittest methods pass. There are no runtime logs, secrets files, private learning notes, AGENTS.md, or BLUEPRINT.md in the current tracked file list. This is a current-tree review, not a guarantee about all historical commits. The intentionally public disposable demo password is expected in code/docs/tests.

## Milestone 1 — synthetic authentication fixture

Status: implemented and committed. The initially proposed tag was dropped; routine tags are not required.

Deliverable: `data/synthetic-auth.jsonl`, containing 12 original fictional sign-in attempts. No records were collected from a real system. Dates are fixed at 2026-01-01 UTC, accounts are fictional, and addresses come from documentation example ranges. Re-reading the file gives the same input; a data generator is not implemented yet.

Each JSONL line is one JSON object with these fields:

| Field | Meaning |
|---|---|
| event_id | Unique evidence reference |
| timestamp | Time of the attempt in UTC |
| account | Fictional account used |
| source_ip | Address initiating the attempt |
| destination_ip | Address receiving the attempt |
| outcome | Authentication success or failure |

Expected outcomes for the planned rule (at least five failures for the same account/source pair within an inclusive five-minute sliding window):

| Evidence | Scenario | Expected findings |
|---|---|---|
| auth-001–auth-005 | lab-alex / 192.0.2.10: five failures from 09:00 through 09:04 UTC | One, referencing all five events |
| auth-006–auth-010 | lab-blair / 192.0.2.11: failures at 10:00, 10:06, 10:12, 10:18, 10:24 UTC | None; attempts are too far apart |
| auth-011–auth-012 | lab-casey / 203.0.113.12: successes at 11:00 and 11:10 UTC | None |

All records target 198.51.100.20. A rule match would require review and would not establish compromise. A forgotten password or stale application credentials are possible alternative explanations, not known causes.

Validation performed using a one-off Python standard-library check: 12 valid JSON objects, exact required fields, nonempty string values, unique IDs, UTC timestamps, valid IP addresses, supported outcomes, 10 failures and two successes. Scenario timing was also checked against the expected fixture values.

Limitations: the parser, detector, subnet classifier, dashboard, and integrations are not implemented. Expected findings above are fixture expectations, not output from a working detector. Exact-boundary, malformed-input, duplicate, and overlapping-window cases will be added during later testing.

## Milestone 2 — authentication parser

Status at implementation checkpoint: verified locally. Current commit/publication status is summarized above.

Added `traceledger/parsing.py`, package initialization, and `tests/test_parsing.py`. The parser returns typed authentication events plus line-numbered diagnostics. Timestamps normalize to UTC; addresses become ipaddress objects. It preserves input order and keeps the first valid occurrence of each event ID. Invalid records do not reserve IDs. Blank lines are errors; extra fields are ignored. Required values must be nonempty strings without surrounding whitespace. File access and UTF-8 decoding failures propagate to the caller rather than masquerading as record errors. No detection logic or dashboard is implemented.

Verification: `python3 -m unittest discover -s tests -v` passed seven test methods, including invalid-input subcases. Coverage includes all 12 fixture events, UTC conversion, IPv6, malformed/blank lines, missing or invalid fields, duplicate handling, empty input, and extra fields.

## Milestone 3 — repeated-failure detector

Status: implemented and verified locally; publication not yet verified.

Added `traceledger/detection.py` and `tests/test_detection.py`. The detector groups validated failures by account/source IP, sorts without modifying input, and applies an inclusive sliding window (default: five failures in five minutes). Overlapping qualifying evidence intervals merge, retaining unique events; separated intervals remain separate findings. Merged evidence can span longer than the rule window. Successes neither count nor reset failures; destinations do not split groups. Duplicate input IDs and invalid rule settings raise ValueError.

Findings preserve evidence events, first/last evidence times, count, threshold, window, rule identifier, and the label "rule-based lab finding". They do not establish compromise.

Verification: `python3 -m unittest discover -s tests -v` passed all 16 test methods (seven parser, nine detector). The fixture produces exactly one finding for lab-alex with auth-001 through auth-005. Tests also verify inclusive boundaries, separate groups, deterministic ordering, unchanged input, successes, multiple destinations, overlapping and disjoint intervals, custom settings, duplicates, and invalid settings. Dashboard and network classification remain unimplemented.

Milestone 2 Git publication is tracked separately from these local implementation results. Routine milestone tags are no longer part of the workflow.

## Milestone 4 — investigation scenario checks

Status at implementation checkpoint: verified locally. Current commit/publication status is summarized above.

Extended `tests/test_detection.py` with six scenarios: two independently triggering groups with isolated evidence; qualifying intervals sharing an endpoint; simultaneous failures with unique IDs; mixed timezone offsets through the parser and detector; invalid JSON and duplicate records among valid failures; and isolated failures excluded from finding evidence.

Verification: `python3 -m unittest discover -s tests -v` passed all 22 test methods (seven parser and 15 detector). Four valid failures plus rejected records produce no finding; adding a fifth valid failure produces one finding while retaining the two parser diagnostics. No production changes were needed. These tests validate defined lab behavior, not operational threat-detection effectiveness.

## Milestone 5 — configured subnet context

Status at implementation checkpoint: verified locally. Current commit/publication status is summarized above.

Added `traceledger/network.py` and `tests/test_network.py`. SubnetClassifier validates labelled CIDR pairs once and classifies IP strings or parsed address objects. Labels must be unique and nonempty; CIDRs must explicitly specify a prefix with host bits zero. Overlapping ranges are rejected, including duplicate CIDRs. IPv4 and IPv6 can coexist. Empty configuration is allowed. Invalid addresses raise errors rather than being labelled unmatched. The unmatched result is "outside configured lab ranges", which says nothing about trust or maliciousness.

Membership includes the IPv4 network and broadcast addresses; this is range classification, not a claim that every member is an assignable host. No real network interfaces, routes, ownership, or VLANs are discovered. Configuration is supplied in Python; no dashboard configuration or network-event collection exists yet.

Verification: `python3 -m unittest discover -s tests -v` passed all 30 test methods, including eight new subnet tests for IPv4/IPv6 boundaries, individual-address ranges, empty configuration, invalid inputs, ambiguous ranges, and parser-to-detector-to-classifier integration. The fixture finding's source maps to workstation lab and its destinations map to server lab without changing evidence. Test labels use explicit synthetic configuration, not inferred device roles.

## Milestone 6 — reproducible synthetic scenarios

Status at implementation checkpoint: verified locally. Current commit/publication status is summarized above.

Added `traceledger/synthetic.py`, `tests/test_synthetic.py`, `data/generated-auth.jsonl`, and `data/generated-network.jsonl`. The original 12-event fixture is unchanged. Seed 42 generates 19 authentication records and 19 paired fictional network records with fixed UTC start time. Accounts, source addresses, and routine-success timings vary by seed; scenario structure remains controlled. These examples are not realistic traffic simulation or real collected evidence.

Authentication scenarios: five failures over four minutes followed by a success, five failures six minutes apart for another account/source, and eight routine successes. Expected detector result is exactly one finding with generated-auth-001 through generated-auth-005. Every paired network record is a scripted TCP/443 allow event sharing the authentication timestamp and endpoints. This pairing is synthetic context, not independent corroboration, and does not imply a failed login means a denied network connection. A production network-event parser and network threat detector are not implemented.

Run `python3 -m traceledger.synthetic --seed 42 --output-dir data` only when those output paths do not exist. For another dataset use a fresh output directory. Existing outputs are refused; writing two files is not a transactional operation, so filesystem failures can leave partial output.

Verification: generated both example files through the command-line entry point. All 36 test methods passed, including six new generator tests covering stable output bytes, variation across seeds, four seeds with the expected parser/detector result, network field structure and pairing, UTC normalization, and preservation of existing outputs. No dependencies were added.

## Milestone 7 — local authentication lab and session evidence

Status: implemented and verified locally. Manual browser activity was analyzed successfully; per-run session separation has automated verification. No publication is claimed.

Added `lab/auth_server.py` and `tests/test_auth_lab.py`, expanded README with run/analyze commands, and clarified the existing ignored `/logs/` directory. The standard-library server binds only to 127.0.0.1. The fixed fictional account lab-user uses the public disposable fixture password demo-only-password. It records actual UTC times, UUID event IDs, loopback endpoints, and success/failure outcomes. Passwords and arbitrary account labels are not stored. Host/origin checks reject unexpected browser origins. No sessions, lockouts, or remediation are implemented; this is not production authentication.

Automated verification: all 41 test methods pass after granting loopback network access (the initial restricted-sandbox run could not bind sockets). Five HTTP lab tests exercise the form, success/failure logging, exclusion of submitted passwords, rejection of arbitrary accounts and cross-origin/wrong-host requests, and actual five-failure HTTP activity flowing through the parser into one evidence-backed finding. Tests use temporary logs and ephemeral loopback ports; no manual runtime log was created by this verification.

Manual walkthrough: six observed events (five failures and one success) parsed without errors and produced one finding containing the five failed-attempt IDs. Runtime evidence remains local. Each new server run now reserves a separate empty `logs/lab-auth-<UTC-start>-<UUID>.jsonl` and prints its path; previous logs are preserved. README analysis requires selecting that exact path. All 43 tests pass, including two added checks for unique session paths, preservation of existing evidence, and separate restarted-server HTTP activity. Session files are not automatically deleted. All activity remains an explicitly controlled local lab; diverse source networks and real enterprise traffic are not demonstrated.

## Milestone 8 — evidence dashboard foundation

Status: committed locally. User browser walkthrough confirmed the dashboard; publication remains separate.

Added `app.py`, `requirements.txt` (direct dependency streamlit==1.67.0), and `tests/test_app.py`; updated README with local launch and virtual-environment test commands. The viewer selects original/generated synthetic auth fixtures or discovered local `lab-auth*.jsonl` sessions. Manual Refresh rereads data and rediscovers sessions. It shows accepted-event counts, line-numbered diagnostics, exact finding evidence, UTC timestamps, and explicitly configured workstation/server/loopback labels. No uploads, continuous monitoring, exports, or case-note persistence are implemented. It does not analyze network JSONL yet.

Verification: all 46 test methods pass in the installed virtual environment, including three Streamlit AppTest methods. Tests verify both synthetic datasets, exact fixture evidence, session selection and refresh using temporary logs, invalid-record visibility, loopback context, and readable handling of inaccessible files. Tests do not alter user runtime logs. The tests use Streamlit's headless app execution, not a browser visual walkthrough. The dependency file pins Streamlit only, not its complete transitive dependency set.

Run `.venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false` and inspect the displayed local URL. Keep runtime logs excluded and the server local.

## Milestone 9 — investigation filters and rule controls

Status: committed locally. User confirmed the investigation controls; publication remains separate.

Updated `app.py`, `tests/test_app.py`, and README. Account/source/outcome filters and inclusive UTC time bounds affect the accepted-event table only. Invalid bounds show a visible error and no table rows. Detection, diagnostics, and headline counts remain based on the full selected dataset. Source-specific filter keys avoid carrying selected values into a different dataset. Threshold and whole-minute window controls recompute findings and display active settings. Finding evidence remains complete regardless of display filters. No network-event correlation or exports are included.

Verification: seven dashboard test methods pass, including four added methods for independent display filtering, source/outcome selection, inclusive/invalid time bounds, and rule-setting changes with displayed parameters. The full suite passed all 50 test methods.

## Milestone 10 — simulated case notes and report export

Status: committed locally. JSON evidence and assessment were manually inspected; the user confirmed Markdown download. Publication remains separate.

Added traceledger/reporting.py and tests/test_reporting.py; updated app.py, tests/test_app.py, and README. Each finding has four analyst-note fields and JSON/Markdown download controls. Reports separate computed evidence from simulated assessment, include provenance and rule settings, and preserve exact evidence IDs and timestamps. Source, rule parameters, and full finding evidence determine note identity. Notes are transient Streamlit session/widget state and may disappear when widgets are removed or a session ends; downloads are required for retention. No durable storage or escalation action is performed.

Verification: all 54 test methods pass, including three report tests and one additional dashboard test. Checks cover JSON evidence/settings round-trip, source/settings/evidence identity changes, Markdown labels and note separation, and UI notes not carrying to different rules or datasets. Browser download review was completed after implementation: JSON contents and saved note were inspected and the user confirmed Markdown download. An initial failed download was followed by success; its cause remains unconfirmed.

## Milestone 11 — final core documentation and verification

Status: complete locally, pending review and commit. No push or deployment performed.

Updated README with reproducible setup, architecture, the full observed-login-to-report demonstration, synthetic generation, validation evidence, limitations, and public hosting boundaries. Reconciled historical milestone statuses without claiming remote publication. Re-ran all 54 tests successfully in the existing virtual environment. Reviewed tracked paths and privacy exclusions: runtime logs, personal working documents, and secrets files are not currently tracked. Only synthetic examples and the explicit public demo credential are intended for publication. Earlier history is not erased or certified by this check. Fresh-environment installation and hosted runtime compatibility have not been verified in this milestone.

## Milestone roadmap

Milestones 2 through 10 are implemented locally as recorded above. Later items remain planned and require individual implementation review and approval. Tests accompany logic changes.

| Number | Goal | Completion evidence |
|---|---|---|
| 2 | Parse and validate JSONL — verified locally | Seven passing test methods; valid Python values and readable diagnostics |
| 3 | Implement repeated-failure detection — verified locally | Nine passing detector test methods; fixture produces the expected evidence |
| 4 | Exercise investigation scenarios — verified locally | Six additional scenarios; all 22 test methods pass |
| 5 | Add configured subnet context — verified locally | Eight new subnet tests; all 30 test methods pass |
| 6 | Generate varied synthetic data — verified locally | Six new generator tests; all 36 test methods pass |
| 7 | Local authentication lab and session evidence — verified locally | Manual evidence finding; all 43 tests pass |
| 8 | Build dashboard foundation — verified headlessly | Three dashboard tests; all 46 test methods pass; browser walkthrough confirmed |
| 9 | Investigation filters and rule controls — verified headlessly | Seven dashboard tests; manual controls confirmed |
| 10 | Case notes and exports — verified headlessly | All 54 tests pass; manual downloads confirmed |
| 11 | Finish and document core — complete locally | Updated README, current-tree privacy review, all 54 tests pass |

Optional subsequent extensions: PowerShell format conversion, Azure ingestion and KQL comparison, ServiceNow developer-instance lab tickets, a contextual second rule, and Power BI reporting. None is implemented or required to complete the core lab.

Personal learning notes, agent instructions, and the detailed working blueprint remain locally excluded. This public tracker contains project scope and verification facts only.
