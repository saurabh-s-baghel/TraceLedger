"""Configured subnet context, not an assessment of address trust."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from ipaddress import ip_address, ip_network
from typing import Iterable


@dataclass(frozen=True)
class SubnetLabel:
    label: str
    network: IPv4Network | IPv6Network


@dataclass(frozen=True)
class AddressContext:
    address: IPv4Address | IPv6Address
    subnet: SubnetLabel | None

    @property
    def label(self) -> str:
        if self.subnet is None:
            return "outside configured lab ranges"
        return self.subnet.label


class SubnetClassifier:
    """Validate (label, CIDR) pairs once, then classify many addresses.

    CIDRs must explicitly include a prefix and use the network address (host
    bits must be zero). Overlap, including duplicate ranges, is rejected so
    classification cannot depend on configuration order. Mixed IP families
    are allowed; they cannot overlap. Labels are descriptive, not trust levels.
    """

    def __init__(self, ranges: Iterable[tuple[str, str]]):
        configured = []
        labels = set()
        for label, cidr in ranges:
            if not isinstance(label, str) or not label.strip() or label != label.strip():
                raise ValueError("subnet label must be nonempty without surrounding whitespace")
            if label == "outside configured lab ranges" or label in labels:
                raise ValueError("subnet labels must be unique and not use the unmatched label")
            if not isinstance(cidr, str) or "/" not in cidr:
                raise ValueError("subnet must be an explicit CIDR string")
            try:
                network = ip_network(cidr, strict=True)
            except ValueError:
                raise ValueError("invalid CIDR or host bits set in network address") from None
            for existing in configured:
                if network.version == existing.network.version and network.overlaps(existing.network):
                    raise ValueError("configured subnet ranges must not overlap")
            configured.append(SubnetLabel(label, network))
            labels.add(label)
        self._subnets = tuple(configured)

    def classify(self, address: str | IPv4Address | IPv6Address) -> AddressContext:
        if not isinstance(address, (str, IPv4Address, IPv6Address)):
            raise ValueError("address must be an IP string or address object")
        if "%" in str(address):
            raise ValueError("IPv6 scope IDs are unsupported")
        try:
            parsed = ip_address(address)
        except ValueError:
            raise ValueError("address must be a valid IPv4 or IPv6 address") from None
        for subnet in self._subnets:
            if parsed.version == subnet.network.version and parsed in subnet.network:
                return AddressContext(parsed, subnet)
        return AddressContext(parsed, None)
