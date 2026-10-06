"""Bounded host iteration (prevents accidental /8 / /64 explosions)."""
from __future__ import annotations
import ipaddress as _ip
from typing import Iterator, Union
from ._parser import parse_cidr

__all__ = ["hosts"]


def hosts(
    network: Union[str, _ip._BaseNetwork], limit: int = 256
) -> Iterator[str]:
    """Yield host IP strings in ``network`` (excluding network/broadcast).

    Bounded: refuses networks larger than /16 IPv4 or /112 IPv6; refuses to
    yield more than ``limit`` addresses. ``limit`` defaults to 256 so callers
    cannot accidentally materialize 16M strings on a /8. Use
    ``ipaddress.ip_network().hosts()`` directly for unbounded iteration.

    Raises :class:`ValueError` for oversize networks or when iteration
    would exceed ``limit``.
    """
    if isinstance(network, str):
        network = parse_cidr(network)
    if network.prefixlen < (16 if network.version == 4 else 112):
        raise ValueError(
            f"hosts() refuses networks larger than /16 (IPv4) or /112 (IPv6); "
            f"got /{network.prefixlen}"
        )
    n = 0
    for h in network.hosts():
        if n >= limit:
            raise ValueError(
                f"hosts() limit ({limit}) exceeded; raise limit / cap iterations"
            )
        yield str(h)
        n += 1