"""CIDR parsing and validation."""
from __future__ import annotations
import ipaddress as _ip
from ._errors import InvalidCIDR

__all__ = ["parse_cidr", "is_cidr"]


def parse_cidr(value):
    """Parse ``value`` as a CIDR string into an :mod:`ipaddress` Network.

    Total over arbitrary input (Invariant 21): non-str / None / bytes / int
    raise :class:`InvalidCIDR`. Whitespace around the value is stripped.
    """
    if not isinstance(value, str):
        raise InvalidCIDR(
            f"invalid CIDR: expected str, got {type(value).__name__}"
        )
    stripped = value.strip()
    if "%" in stripped:
        raise InvalidCIDR(
            f"invalid CIDR: IPv6 zone identifier not supported: {value!r}"
        )
    try:
        net = _ip.ip_network(stripped, strict=True)
    except (ValueError, TypeError) as exc:
        raise InvalidCIDR(f"invalid CIDR: {value!r}") from exc
    if (
        isinstance(net, _ip.IPv6Network)
        and net.network_address.ipv4_mapped is not None
    ):
        raise InvalidCIDR(
            f"invalid CIDR: IPv4-mapped IPv6 not supported: {value!r}"
        )
    return net


def is_cidr(value) -> bool:
    """Return True iff ``value`` is a parseable CIDR string.

    Total over arbitrary input (Invariant 21): non-str returns False rather
    than raising.
    """
    if not isinstance(value, str):
        return False
    try:
        parse_cidr(value)
    except InvalidCIDR:
        return False
    return True