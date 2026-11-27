"""Membership and configuration checks for descriptive subnet context."""

import unittest
from ipaddress import ip_address
from pathlib import Path

from traceledger.detection import detect_repeated_failures
from traceledger.network import SubnetClassifier
from traceledger.parsing import read_auth_log


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.classifier = SubnetClassifier([
            ("workstation lab", "192.0.2.0/24"),
            ("server lab", "198.51.100.0/24"),
            ("IPv6 lab", "2001:db8::/126"),
        ])

    def test_configured_membership_and_unmatched_address(self):
        result = self.classifier.classify("192.0.2.10")
        self.assertEqual(result.label, "workstation lab")
        self.assertEqual(str(result.subnet.network), "192.0.2.0/24")
        unmatched = self.classifier.classify("203.0.113.12")
        self.assertEqual(unmatched.label, "outside configured lab ranges")
        self.assertIsNone(unmatched.subnet)

    def test_ipv4_network_and_broadcast_addresses_are_members(self):
        for address in ("192.0.2.0", "192.0.2.255"):
            with self.subTest(address=address):
                self.assertEqual(self.classifier.classify(address).label, "workstation lab")
        for address in ("192.0.1.255", "192.0.3.0"):
            self.assertIsNone(self.classifier.classify(address).subnet)

    def test_ipv6_boundaries_and_address_objects(self):
        for address in ("2001:db8::", "2001:db8::3"):
            self.assertEqual(self.classifier.classify(ip_address(address)).label, "IPv6 lab")
        self.assertIsNone(self.classifier.classify("2001:db8::4").subnet)

    def test_empty_configuration_and_single_address_ranges(self):
        self.assertIsNone(SubnetClassifier([]).classify("192.0.2.1").subnet)
        classifier = SubnetClassifier([("one", "192.0.2.1/32"),
                                       ("six", "2001:db8::1/128")])
        self.assertEqual(classifier.classify("192.0.2.1").label, "one")
        self.assertEqual(classifier.classify("2001:db8::1").label, "six")
        self.assertIsNone(classifier.classify("192.0.2.2").subnet)

    def test_invalid_configuration(self):
        cases = [[("", "192.0.2.0/24")], [(" lab", "192.0.2.0/24")],
                 [("lab", "invalid/24")], [("lab", "192.0.2.1/24")],
                 [("lab", "192.0.2.0")], [("lab", "192.0.2.0/33")],
                 [("lab", "2001:db8::/129")],
                 [("outside configured lab ranges", "192.0.2.0/24")],
                 [("same", "192.0.2.0/24"), ("same", "198.51.100.0/24")]]
        for configuration in cases:
            with self.subTest(configuration=configuration), self.assertRaises(ValueError):
                SubnetClassifier(configuration)

    def test_overlap_rejected_in_either_order_for_both_families(self):
        for first, second in [("192.0.2.0/24", "192.0.2.0/25"),
                              ("192.0.2.0/24", "192.0.2.0/24"),
                              ("2001:db8::/32", "2001:db8:1::/48")]:
            for a, b in ((first, second), (second, first)):
                with self.subTest(a=a, b=b), self.assertRaisesRegex(ValueError, "overlap"):
                    SubnetClassifier([("a", a), ("b", b)])

    def test_invalid_addresses_are_not_unmatched(self):
        for address in ("hostname", "999.0.0.1", "fe80::1%en0", 123, None):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.classifier.classify(address)

    def test_parsed_finding_can_receive_context_without_changing_evidence(self):
        path = Path(__file__).resolve().parents[1] / "data/synthetic-auth.jsonl"
        parsed = read_auth_log(path)
        self.assertEqual(parsed.errors, [])
        finding = detect_repeated_failures(parsed.events)[0]
        evidence_ids = tuple(e.event_id for e in finding.evidence)
        self.assertEqual(self.classifier.classify(finding.source_ip).label, "workstation lab")
        for item in finding.evidence:
            self.assertEqual(self.classifier.classify(item.destination_ip).label, "server lab")
        self.assertEqual(tuple(e.event_id for e in finding.evidence), evidence_ids)


if __name__ == "__main__":
    unittest.main()
