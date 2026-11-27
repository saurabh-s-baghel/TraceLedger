"""Read authentication JSONL without silently discarding invalid records."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class AuthEvent:
    event_id: str
    timestamp: datetime
    account: str
    source_ip: IPv4Address | IPv6Address
    destination_ip: IPv4Address | IPv6Address
    outcome: str


@dataclass(frozen=True)
class ParseError:
    line_number: int
    reason: str


@dataclass
class ParseResult:
    events: list[AuthEvent]
    errors: list[ParseError]


FIELDS = {"event_id", "timestamp", "account", "source_ip", "destination_ip", "outcome"}


def validate_event(record: object) -> AuthEvent:
    """Convert one record to typed values, or raise ValueError with a reason.

    Extra fields are ignored for forward compatibility. Required string values
    must be nonempty and have no surrounding whitespace.
    """
    if not isinstance(record, dict):
        raise ValueError("record must be a JSON object")
    missing = FIELDS - record.keys()
    if missing:
        raise ValueError("missing fields: " + ", ".join(sorted(missing)))
    for field in sorted(FIELDS):
        value = record[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a nonempty string")
        if value != value.strip():
            raise ValueError(f"{field} must not have surrounding whitespace")
    if record["outcome"] not in {"success", "failure"}:
        raise ValueError("outcome must be success or failure")
    try:
        timestamp = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must be an ISO 8601 datetime") from None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    addresses = {}
    for field in ("source_ip", "destination_ip"):
        # Scoped IPv6 addresses require interface context absent from this schema.
        if "%" in record[field]:
            raise ValueError(f"{field} must not include an IPv6 scope ID")
        try:
            addresses[field] = ip_address(record[field])
        except ValueError:
            raise ValueError(f"{field} must be a valid IPv4 or IPv6 address") from None
    return AuthEvent(
        event_id=record["event_id"],
        timestamp=timestamp.astimezone(timezone.utc),
        account=record["account"],
        source_ip=addresses["source_ip"],
        destination_ip=addresses["destination_ip"],
        outcome=record["outcome"],
    )


def parse_auth_lines(lines: Iterable[str]) -> ParseResult:
    """Validate each line; retain the first valid occurrence of an event ID.

    Blank lines are reported as errors. Invalid records do not reserve IDs.
    Errors contain reasons and line numbers, not copies of raw input.
    """
    result = ParseResult(events=[], errors=[])
    seen_ids: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            result.errors.append(ParseError(line_number, "invalid JSON"))
            continue
        try:
            event = validate_event(record)
            if event.event_id in seen_ids:
                raise ValueError("duplicate event_id")
        except ValueError as error:
            result.errors.append(ParseError(line_number, str(error)))
            continue
        seen_ids.add(event.event_id)
        result.events.append(event)
    return result


def read_auth_log(path: str | Path) -> ParseResult:
    """Read UTF-8 JSONL. File-access and decoding errors propagate to the caller."""
    with Path(path).open(encoding="utf-8") as file:
        return parse_auth_lines(file)
