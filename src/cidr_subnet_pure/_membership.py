"""Membership test (CIDR string contains IP string)."""
from __future__ import annotations
import ipaddress as _ip
from ._errors import InvalidCIDR, MixedFamilyError
from ._parser import parse_cidr

__all__ = ["contains"]


def contains(network, address) -> bool:
    """Return True iff ``address`` (IP literal) is in ``network`` (Network or str).

    Both inputs must share an address family (IPv4 with IPv4, IPv6 with IPv6);
    mixed-family raises :class:`MixedFamilyError`. Non-string ``address`` raises
    :class:`InvalidCIDR` (Invariant 21: total over arbitrary input).
    """
    if isinstance(network, str):
        network = parse_cidr(network)
    if not isinstance(address, str):
        raise InvalidCIDR(f"address must be str, got {type(address).__name__}")
    try:
        ip = _ip.ip_address(address.strip())
    except (ValueError, TypeError) as exc:
        raise InvalidCIDR(f"invalid IP address: {address!r}") from exc
    if (isinstance(network, _ip.IPv4Network)) != (ip.version == 4):
        raise MixedFamilyError(
            f"mixed IPv4/IPv6 not supported in contains({network}, {address!r})"
        )
    return ip in network