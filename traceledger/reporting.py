"""Portable lab reports separating computed evidence from analyst assessment."""

import hashlib
import json

from traceledger.detection import FailureFinding


NOTE_FIELDS = ("observations", "alternative_explanations", "missing_context", "escalation_recommendation")


def finding_key(finding: FailureFinding, source: str) -> str:
    """Bind notes to a source, settings, and full evidence content, not row number."""
    identity = dict(source=source, rule=finding.rule_id, threshold=finding.threshold,
                    window_seconds=finding.window.total_seconds(),
                    evidence=[event_dict(event) for event in finding.evidence])
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def event_dict(event):
    return dict(event_id=event.event_id, timestamp=event.timestamp.isoformat(),
                account=event.account, source_ip=str(event.source_ip),
                destination_ip=str(event.destination_ip), outcome=event.outcome)


def build_report(finding: FailureFinding, source: str, provenance: str, notes: dict,
                 rejected_records: int = 0) -> dict:
    return dict(
        report_type="simulated lab investigation", schema_version=1,
        finding_key=finding_key(finding, source),
        dataset=dict(source=source, provenance=provenance, rejected_records=rejected_records),
        computed=dict(label=finding.label, rule_id=finding.rule_id,
                      threshold=finding.threshold, window_seconds=finding.window.total_seconds(),
                      account=finding.account, source_ip=str(finding.source_ip),
                      count=finding.count, first_seen=finding.first_seen.isoformat(),
                      last_seen=finding.last_seen.isoformat(),
                      evidence=[event_dict(event) for event in finding.evidence]),
        analyst_assessment={field: notes.get(field, "") for field in NOTE_FIELDS},
        limitations=["Rule-based lab finding, not proof of compromise.",
                     "Assessment and escalation recommendations are simulated; no action is performed.",
                     "Overlapping qualifying windows merge; the evidence period can exceed the rule window.",
                     "Evidence is limited to this finding, not a complete dataset export."],
    )


def report_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def report_markdown(report: dict) -> str:
    computed = report["computed"]
    lines = ["# TraceLedger simulated investigation", "", "## Dataset provenance", "",
             "```json", json.dumps(report["dataset"], indent=2), "```", "",
             "## Computed finding and exact evidence", "", "```json",
             json.dumps(computed, indent=2), "```", "", "## Analyst assessment (simulated)", ""]
    for field, text in report["analyst_assessment"].items():
        lines.extend([f"### {field.replace('_', ' ').capitalize()}", ""])
        # Quote each line so user-entered Markdown is visibly assessment content.
        lines.extend("> " + line for line in (text or "Not recorded.").splitlines())
        lines.append("")
    lines.extend(["## Limitations", ""] + ["- " + item for item in report["limitations"]])
    return "\n".join(lines) + "\n"
