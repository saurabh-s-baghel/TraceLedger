"""Rule-based lab findings, not determinations of compromise."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Iterable

from traceledger.parsing import AuthEvent


@dataclass(frozen=True)
class FailureFinding:
    account: str
    source_ip: IPv4Address | IPv6Address
    evidence: tuple[AuthEvent, ...]
    threshold: int
    window: timedelta
    rule_id: str = "repeated-auth-failures"
    label: str = "rule-based lab finding"

    @property
    def first_seen(self) -> datetime:
        return self.evidence[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.evidence[-1].timestamp

    @property
    def count(self) -> int:
        return len(self.evidence)


def detect_repeated_failures(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> list[FailureFinding]:
    """Evaluate validated events using inclusive sliding windows.

    Merge qualifying intervals that overlap or share an endpoint. A merged
    finding may span longer than the configured window. Destinations do not
    split groups; successes do not reset failure counts. Duplicate IDs are
    rejected defensively; callers normally supply the parser's unique events.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if not isinstance(window, timedelta) or window <= timedelta(0):
        raise ValueError("window must be a positive timedelta")

    groups = defaultdict(list)
    seen_ids = set()
    for event in events:
        if event.event_id in seen_ids:
            raise ValueError("duplicate event_id in detector input")
        seen_ids.add(event.event_id)
        if event.outcome == "failure":
            groups[(event.account, event.source_ip)].append(event)

    findings = []
    for (account, source_ip), failures in groups.items():
        failures.sort(key=lambda event: (event.timestamp, event.event_id))
        active = deque()
        cluster: dict[str, AuthEvent] = {}
        cluster_end = None

        def finish_cluster():
            evidence = tuple(sorted(cluster.values(),
                                    key=lambda event: (event.timestamp, event.event_id)))
            findings.append(FailureFinding(account, source_ip, evidence, threshold, window))

        for event in failures:
            active.append(event)
            # Equality is retained: exactly five minutes old still counts.
            while event.timestamp - active[0].timestamp > window:
                active.popleft()
            if len(active) < threshold:
                continue
            interval_start = active[0].timestamp
            if cluster and interval_start > cluster_end:
                finish_cluster()
                cluster = {}
            cluster.update((item.event_id, item) for item in active)
            cluster_end = event.timestamp
        if cluster:
            finish_cluster()

    return sorted(findings, key=lambda finding: (
        finding.first_seen, finding.account, str(finding.source_ip)))
