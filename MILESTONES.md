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

## Remaining milestones

All items below are planned and require individual implementation review and approval. Tests accompany logic changes.

| Number | Goal | Completion evidence |
|---|---|---|
| 2 | Parse and validate JSONL | Valid Python values and readable invalid-record diagnostics |
| 3 | Implement repeated-failure detection | Findings with rule settings and exact evidence IDs |
| 4 | Exercise detection edge cases | Passing threshold, boundary, grouping, duplicate, and ordering tests |
| 5 | Add configured subnet context | Tested ipaddress classification with explicit unmatched labels |
| 6 | Generate varied synthetic data | Reproducible authentication/network scenarios with known expectations |
| 7 | Build dashboard foundation | Separately approved environment/dependency setup; event and error views |
| 8 | Add investigation views | Filters, finding evidence, network context, and rule controls |
| 9 | Add case notes and exports | Simulated assessment, alternative explanations, JSON/Markdown reports |
| 10 | Finish and document core | Verified end-to-end walkthrough and accurate public README |

Optional subsequent extensions: PowerShell format conversion, Azure ingestion and KQL comparison, ServiceNow developer-instance lab tickets, a contextual second rule, and Power BI reporting. None is implemented or required to complete the core lab.

Personal learning notes, agent instructions, and the detailed working blueprint remain locally excluded. This public tracker contains project scope and verification facts only.
