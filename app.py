"""Local evidence viewer for synthetic fixtures and observed lab sessions."""

from pathlib import Path

import streamlit as st

from traceledger.detection import detect_repeated_failures
from traceledger.network import SubnetClassifier
from traceledger.parsing import read_auth_log


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
    findings = detect_repeated_failures(result.events)
    columns = st.columns(3)
    columns[0].metric("Accepted events", len(result.events))
    columns[1].metric("Rejected records", len(result.errors))
    columns[2].metric("Findings", len(findings))
    st.caption("Rule: at least 5 failures per account/source in an inclusive 5-minute window. Successes do not reset the count; destinations do not split groups.")

    def event_row(event):
        return dict(event_id=event.event_id, timestamp_utc=event.timestamp.isoformat(),
                    account=event.account, source_ip=str(event.source_ip),
                    source_subnet=classifier.classify(event.source_ip).label,
                    destination_ip=str(event.destination_ip),
                    destination_subnet=classifier.classify(event.destination_ip).label,
                    outcome=event.outcome)

    st.subheader("Accepted events")
    if result.events:
        st.dataframe([event_row(event) for event in result.events], hide_index=True)
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
    st.caption("Subnet labels are explicitly configured descriptions, not inferred device identity, trust, or VLAN membership. Refresh is manual; this is not continuous monitoring.")


if __name__ == "__main__":
    main()
