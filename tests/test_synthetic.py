"""Reproducibility and expected investigation outcomes for synthetic scenarios."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from traceledger.detection import detect_repeated_failures
from traceledger.parsing import parse_auth_lines
from traceledger.synthetic import generate_events, write_dataset


class SyntheticTests(unittest.TestCase):
    def test_seed_repeats_and_other_seed_changes_data(self):
        self.assertEqual(generate_events(42), generate_events(42))
        self.assertNotEqual(generate_events(42), generate_events(43))

    def test_multiple_seeds_have_one_known_finding(self):
        for seed in (0, 1, 42, 99):
            with self.subTest(seed=seed):
                auth, network = generate_events(seed)
                parsed = parse_auth_lines(json.dumps(row) for row in auth)
                self.assertEqual(parsed.errors, [])
                self.assertEqual(len(parsed.events), 19)
                findings = detect_repeated_failures(parsed.events)
                self.assertEqual(len(findings), 1)
                self.assertEqual([event.event_id for event in findings[0].evidence],
                                 [f"generated-auth-{n:03d}" for n in range(1, 6)])
                self.assertEqual(findings[0].account, auth[0]["account"])
                self.assertEqual(findings[0].last_seen - findings[0].first_seen,
                                 timedelta(minutes=4))

    def test_network_schema_and_scripted_pairing(self):
        auth, network = generate_events()
        self.assertEqual(len(network), 19)
        self.assertEqual(len({row["event_id"] for row in network}), 19)
        for attempt, connection in zip(auth, network):
            self.assertEqual(set(connection), {"event_id", "timestamp", "source_ip",
                "destination_ip", "destination_port", "protocol", "action"})
            for field in ("timestamp", "source_ip", "destination_ip"):
                self.assertEqual(attempt[field], connection[field])
            ip_address(connection["source_ip"])
            ip_address(connection["destination_ip"])
            self.assertEqual(connection["destination_port"], 443)
            self.assertEqual(connection["protocol"], "TCP")
            self.assertEqual(connection["action"], "allow")

    def test_start_is_normalized_and_naive_time_rejected(self):
        offset_start = datetime(2026, 1, 1, 10, tzinfo=timezone(timedelta(hours=1)))
        auth, _ = generate_events(start=offset_start)
        self.assertEqual(auth[0]["timestamp"], "2026-01-01T09:00:00Z")
        with self.assertRaises(ValueError):
            generate_events(start=datetime(2026, 1, 1))

    def test_output_bytes_repeat_and_existing_outputs_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_dataset(root / "first")
            second = write_dataset(root / "second")
            before = [path.read_bytes() for path in first]
            self.assertEqual(before, [path.read_bytes() for path in second])
            with self.assertRaises(FileExistsError):
                write_dataset(root / "first", seed=99)
            self.assertEqual(before, [path.read_bytes() for path in first])

    def test_one_existing_output_prevents_writing_other(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "generated-network.jsonl").write_text("keep me")
            with self.assertRaises(FileExistsError):
                write_dataset(root)
            self.assertFalse((root / "generated-auth.jsonl").exists())
            self.assertEqual((root / "generated-network.jsonl").read_text(), "keep me")


if __name__ == "__main__":
    unittest.main()
