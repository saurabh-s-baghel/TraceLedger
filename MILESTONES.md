# TraceLedger milestones

This tracker separates completed work from planned features. TraceLedger is a defensive learning lab using synthetic data, not evidence of operational incident-response experience.

## Milestone 1 — synthetic authentication fixture

Status: complete locally. Planned Git checkpoint: `milestone-1`; remote publication must be verified separately.

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

Status: implemented and verified locally; not yet committed or published.

Added `traceledger/parsing.py`, package initialization, and `tests/test_parsing.py`. The parser returns typed authentication events plus line-numbered diagnostics. Timestamps normalize to UTC; addresses become ipaddress objects. It preserves input order and keeps the first valid occurrence of each event ID. Invalid records do not reserve IDs. Blank lines are errors; extra fields are ignored. Required values must be nonempty strings without surrounding whitespace. File access and UTF-8 decoding failures propagate to the caller rather than masquerading as record errors. No detection logic or dashboard is implemented.

Verification: `python3 -m unittest discover -s tests -v` passed seven test methods, including invalid-input subcases. Coverage includes all 12 fixture events, UTC conversion, IPv6, malformed/blank lines, missing or invalid fields, duplicate handling, empty input, and extra fields.

## Milestone 3 — repeated-failure detector

Status: implemented and verified locally; publication not yet verified.

Added `traceledger/detection.py` and `tests/test_detection.py`. The detector groups validated failures by account/source IP, sorts without modifying input, and applies an inclusive sliding window (default: five failures in five minutes). Overlapping qualifying evidence intervals merge, retaining unique events; separated intervals remain separate findings. Merged evidence can span longer than the rule window. Successes neither count nor reset failures; destinations do not split groups. Duplicate input IDs and invalid rule settings raise ValueError.

Findings preserve evidence events, first/last evidence times, count, threshold, window, rule identifier, and the label "rule-based lab finding". They do not establish compromise.

Verification: `python3 -m unittest discover -s tests -v` passed all 16 test methods (seven parser, nine detector). The fixture produces exactly one finding for lab-alex with auth-001 through auth-005. Tests also verify inclusive boundaries, separate groups, deterministic ordering, unchanged input, successes, multiple destinations, overlapping and disjoint intervals, custom settings, duplicates, and invalid settings. Dashboard and network classification remain unimplemented.

Milestone 2 Git publication is tracked separately from these local implementation results. Routine milestone tags are no longer part of the workflow.

## Milestone 4 — investigation scenario checks

Status: implemented and verified locally; not yet committed or published.

Extended `tests/test_detection.py` with six scenarios: two independently triggering groups with isolated evidence; qualifying intervals sharing an endpoint; simultaneous failures with unique IDs; mixed timezone offsets through the parser and detector; invalid JSON and duplicate records among valid failures; and isolated failures excluded from finding evidence.

Verification: `python3 -m unittest discover -s tests -v` passed all 22 test methods (seven parser and 15 detector). Four valid failures plus rejected records produce no finding; adding a fifth valid failure produces one finding while retaining the two parser diagnostics. No production changes were needed. These tests validate defined lab behavior, not operational threat-detection effectiveness.

## Milestone 5 — configured subnet context

Status: implemented and verified locally; not yet committed or published.

Added `traceledger/network.py` and `tests/test_network.py`. SubnetClassifier validates labelled CIDR pairs once and classifies IP strings or parsed address objects. Labels must be unique and nonempty; CIDRs must explicitly specify a prefix with host bits zero. Overlapping ranges are rejected, including duplicate CIDRs. IPv4 and IPv6 can coexist. Empty configuration is allowed. Invalid addresses raise errors rather than being labelled unmatched. The unmatched result is "outside configured lab ranges", which says nothing about trust or maliciousness.

Membership includes the IPv4 network and broadcast addresses; this is range classification, not a claim that every member is an assignable host. No real network interfaces, routes, ownership, or VLANs are discovered. Configuration is supplied in Python; no dashboard configuration or network-event collection exists yet.

Verification: `python3 -m unittest discover -s tests -v` passed all 30 test methods, including eight new subnet tests for IPv4/IPv6 boundaries, individual-address ranges, empty configuration, invalid inputs, ambiguous ranges, and parser-to-detector-to-classifier integration. The fixture finding's source maps to workstation lab and its destinations map to server lab without changing evidence. Test labels use explicit synthetic configuration, not inferred device roles.

## Milestone 6 — reproducible synthetic scenarios

Status: implemented and verified locally; not yet committed or published.

Added `traceledger/synthetic.py`, `tests/test_synthetic.py`, `data/generated-auth.jsonl`, and `data/generated-network.jsonl`. The original 12-event fixture is unchanged. Seed 42 generates 19 authentication records and 19 paired fictional network records with fixed UTC start time. Accounts, source addresses, and routine-success timings vary by seed; scenario structure remains controlled. These examples are not realistic traffic simulation or real collected evidence.

Authentication scenarios: five failures over four minutes followed by a success, five failures six minutes apart for another account/source, and eight routine successes. Expected detector result is exactly one finding with generated-auth-001 through generated-auth-005. Every paired network record is a scripted TCP/443 allow event sharing the authentication timestamp and endpoints. This pairing is synthetic context, not independent corroboration, and does not imply a failed login means a denied network connection. A production network-event parser and network threat detector are not implemented.

Run `python3 -m traceledger.synthetic --seed 42 --output-dir data` only when those output paths do not exist. For another dataset use a fresh output directory. Existing outputs are refused; writing two files is not a transactional operation, so filesystem failures can leave partial output.

Verification: generated both example files through the command-line entry point. All 36 test methods passed, including six new generator tests covering stable output bytes, variation across seeds, four seeds with the expected parser/detector result, network field structure and pairing, UTC normalization, and preservation of existing outputs. No dependencies were added.

## Milestone roadmap

Milestones 2 through 6 are implemented locally as recorded above. Later items remain planned and require individual implementation review and approval. Tests accompany logic changes.

| Number | Goal | Completion evidence |
|---|---|---|
| 2 | Parse and validate JSONL — verified locally | Seven passing test methods; valid Python values and readable diagnostics |
| 3 | Implement repeated-failure detection — verified locally | Nine passing detector test methods; fixture produces the expected evidence |
| 4 | Exercise investigation scenarios — verified locally | Six additional scenarios; all 22 test methods pass |
| 5 | Add configured subnet context — verified locally | Eight new subnet tests; all 30 test methods pass |
| 6 | Generate varied synthetic data — verified locally | Six new generator tests; all 36 test methods pass |
| 7 | Build dashboard foundation | Separately approved environment/dependency setup; event and error views |
| 8 | Add investigation views | Filters, finding evidence, network context, and rule controls |
| 9 | Add case notes and exports | Simulated assessment, alternative explanations, JSON/Markdown reports |
| 10 | Finish and document core | Verified end-to-end walkthrough and accurate public README |

Optional subsequent extensions: PowerShell format conversion, Azure ingestion and KQL comparison, ServiceNow developer-instance lab tickets, a contextual second rule, and Power BI reporting. None is implemented or required to complete the core lab.

Personal learning notes, agent instructions, and the detailed working blueprint remain locally excluded. This public tracker contains project scope and verification facts only.
