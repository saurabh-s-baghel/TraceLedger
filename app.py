"""Local evidence viewer for synthetic fixtures and observed lab sessions."""

from pathlib import Path
from datetime import datetime, timedelta, timezone

import streamlit as st

from traceledger.detection import detect_repeated_failures
from traceledger.network import SubnetClassifier
from traceledger.parsing import read_auth_log
from traceledger.reporting import NOTE_FIELDS, build_report, finding_key, report_json, report_markdown


ROOT = Path(__file__).resolve().parent


def main():
    st.set_page_config(page_title="TraceLedger", layout="wide")
    st.title("TraceLedger")
    st.caption("Authentication evidence review · local defensive lab")
    st.warning("Rule-based lab findings are not proof of compromise. Only synthetic fixtures and authorized local lab events are shown.")
    # No caching: every interaction, including Refresh, reads the selected file anew.
    st.button("Refresh", key="refresh")
    sources = {
        "Synthetic: original fixture": ROOT / "data/synthetic-auth.jsonl",
        "Synthetic: generated scenario": ROOT / "data/generated-auth.jsonl",
    }
    for path in sorted((ROOT / "logs").glob("lab-auth*.jsonl"), reverse=True):
        if path.is_file() and not path.is_symlink():
            sources[f"Observed local lab: {path.name}"] = path
    selected = st.selectbox("Evidence source", list(sources), key="source")
    path = sources[selected]
    st.caption(f"Selected file: {path.relative_to(ROOT)} · timestamps shown in UTC")
    if selected.startswith("Synthetic"):
        st.info("Fictional events with controlled expected outcomes.")
    else:
        st.info("Observed activity from the loopback-only demo server. Earlier sessions are retained separately.")
    try:
        result = read_auth_log(path)
    except (OSError, UnicodeError):
        st.error("Cannot read this evidence file as UTF-8. Check that it still exists and is readable.")
        return
    classifier = SubnetClassifier([
        ("workstation lab", "192.0.2.0/24"),
        ("server lab", "198.51.100.0/24"),
        ("loopback lab", "127.0.0.0/8"),
    ])
    st.subheader("Detection settings")
    threshold = st.number_input("Failure threshold", min_value=1, max_value=1000,
                                value=5, step=1, key="threshold")
    minutes = st.number_input("Window (minutes)", min_value=1, max_value=1440,
                              value=5, step=1, key="window_minutes")
    findings = detect_repeated_failures(result.events, threshold=int(threshold),
                                         window=timedelta(minutes=int(minutes)))
    columns = st.columns(3)
    columns[0].metric("Accepted events", len(result.events))
    columns[1].metric("Rejected records", len(result.errors))
    columns[2].metric("Findings", len(findings))
    st.caption(f"Rule: at least {threshold} failures per account/source in an inclusive {minutes}-minute window. Successes do not reset the count; destinations do not split groups.")

    def event_row(event):
        return dict(event_id=event.event_id, timestamp_utc=event.timestamp.isoformat(),
                    account=event.account, source_ip=str(event.source_ip),
                    source_subnet=classifier.classify(event.source_ip).label,
                    destination_ip=str(event.destination_ip),
                    destination_subnet=classifier.classify(event.destination_ip).label,
                    outcome=event.outcome)

    st.subheader("Accepted events")
    st.caption("Display filters affect only this event table. Detection and finding evidence always use the full selected dataset.")
    # Source-specific keys prevent stale filter selections crossing datasets.
    accounts = st.multiselect("Accounts", sorted({e.account for e in result.events}),
                              key=f"accounts:{selected}")
    addresses = st.multiselect("Source IPs", sorted({str(e.source_ip) for e in result.events}),
                               key=f"addresses:{selected}")
    outcomes = st.multiselect("Outcomes", ["failure", "success"], key=f"outcomes:{selected}")
    start_text = st.text_input("From UTC (ISO 8601, optional)", key=f"start:{selected}")
    end_text = st.text_input("Through UTC (ISO 8601, optional)", key=f"end:{selected}")
    visible = result.events
    try:
        bounds = []
        for text in (start_text, end_text):
            bound = datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None
            if bound is not None and (bound.tzinfo is None or bound.utcoffset() != timedelta(0)):
                raise ValueError("Use an explicit UTC timezone: Z or +00:00.")
            bounds.append(bound.astimezone(timezone.utc) if bound else None)
        start, end = bounds
        if start and end and start > end:
            raise ValueError("Start must not be later than end.")
        visible = [e for e in result.events
                   if (not accounts or e.account in accounts)
                   and (not addresses or str(e.source_ip) in addresses)
                   and (not outcomes or e.outcome in outcomes)
                   and (start is None or e.timestamp >= start)
                   and (end is None or e.timestamp <= end)]
    except ValueError as error:
        st.error(f"Invalid display time filter: {error}")
        visible = []
    st.caption(f"Showing {len(visible)} of {len(result.events)} accepted events. Empty selections mean all values.")
    if result.events:
        if visible:
            st.dataframe([event_row(event) for event in visible], hide_index=True)
        else:
            st.info("No events to display under these filters. Findings below are unchanged by display filters.")
    else:
        st.info("No accepted events yet. Submit a demo attempt and click Refresh.")
    st.subheader("Parsing diagnostics")
    if result.errors:
        st.dataframe([dict(line_number=error.line_number, reason=error.reason)
                      for error in result.errors], hide_index=True)
    else:
        st.caption("No rejected records.")
    st.subheader("Findings and evidence")
    if not findings:
        st.info("No findings under the current rule. This does not establish that activity is safe.")
    for index, finding in enumerate(findings, 1):
        with st.expander(f"Finding {index}: {finding.account} · {finding.source_ip}", expanded=True):
            st.write(finding.label)
            st.write(f"Rule: {finding.rule_id} | threshold: {finding.threshold} | window: {finding.window}")
            st.write(f"Unique failures: {finding.count} | evidence period: {finding.first_seen.isoformat()} to {finding.last_seen.isoformat()}")
            st.caption("Overlapping qualifying windows merge; the full evidence period may exceed five minutes.")
            st.dataframe([event_row(event) for event in finding.evidence], hide_index=True)
            st.caption("Possible explanations include password guessing, a forgotten password, or stale application credentials. Additional context is needed before escalation.")
            identity = finding_key(finding, selected)
            st.write("Simulated case notes")
            st.caption("Notes remain in this browser session until downloaded; they are not written to the repository. Do not enter personal information or secrets.")
            notes = {field: st.text_area(field.replace("_", " ").capitalize(),
                                        key=f"case:{identity}:{field}", max_chars=5000)
                     for field in NOTE_FIELDS}
            report = build_report(finding, selected,
                                  "synthetic fixture" if selected.startswith("Synthetic")
                                  else "observed authorized loopback authentication lab",
                                  notes, rejected_records=len(result.errors))
            st.download_button("Download JSON report", report_json(report),
                               file_name=f"traceledger-{identity[:12]}.json",
                               mime="application/json", key=f"json:{identity}")
            st.download_button("Download Markdown report", report_markdown(report),
                               file_name=f"traceledger-{identity[:12]}.md",
                               mime="text/markdown", key=f"markdown:{identity}")
    st.caption("Subnet labels are explicitly configured descriptions, not inferred device identity, trust, or VLAN membership. Refresh is manual; this is not continuous monitoring.")


if __name__ == "__main__":
    main()
