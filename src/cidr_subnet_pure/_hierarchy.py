"""Hierarchy: supernet, subnets, longest-prefix-match."""
from __future__ import annotations
import ipaddress as _ip
from typing import Iterable, List, Optional, Tuple, TypeVar
from ._errors import CIDRError
from ._parser import parse_cidr

__all__ = ["smallest_supernet", "subnets", "longest_prefix_match"]
T = TypeVar("T")


def smallest_supernet(networks: Iterable) -> Optional[_ip._BaseNetwork]:
    """Most-specific network containing all inputs.

    Computes the bitwise-AND of all input network addresses, then finds the
    longest prefix length that does not change any bit the AND zeroed (i.e.,
    the actual common prefix length, not the minimum input prefix length).

    Returns ``None`` for empty input.  Raises :class:`CIDRError` for mixed
    families.
    """
    nets = [parse_cidr(n) if isinstance(n, str) else n for n in networks]
    if not nets:
        return None
    versions = {n.version for n in nets}
    if len(versions) > 1:
        raise CIDRError("smallest_supernet requires a single address family")
    v = next(iter(versions))
    width = 32 if v == 4 else 128
    # bitwise-AND of masked network addresses
    addr = (1 << width) - 1
    for n in nets:
        net_mask = ((1 << width) - 1) ^ ((1 << (width - n.prefixlen)) - 1)
        addr &= int(n.network_address) & net_mask
    # Find longest prefix length where (addr & mask) still equals addr_masked
    # by finding the highest-order bit that's different from zero across inputs.
    # We need: for every input n, (int(n.network_address) & candidate_mask) == addr
    # The longest such mask corresponds to the longest common prefix of all
    # input network addresses (when they overlap).
    # If no common bit exists (disjoint), prefixlen = 0.
    candidate_mask = ((1 << width) - 1) ^ ((1 << (width - 1)) - 1)  # MSB? = /1
    if addr == 0:
        prefixlen = 0
    else:
        prefixlen = width
        for n in nets:
            n_addr = int(n.network_address)
            while prefixlen > 0:
                mask = ((1 << width) - 1) ^ ((1 << (width - prefixlen)) - 1)
                if (n_addr & mask) == (addr & mask):
                    break
                prefixlen -= 1
    cls = _ip.IPv4Network if v == 4 else _ip.IPv6Network
    return cls((addr, prefixlen))


def subnets(network, new_prefixlen: int) -> List:
    if isinstance(network, str):
        network = parse_cidr(network)
    if new_prefixlen < network.prefixlen:
        raise ValueError(f"new_prefixlen ({new_prefixlen}) must be >= network.prefixlen ({network.prefixlen})")
    return list(network.subnets(new_prefix=new_prefixlen))


def longest_prefix_match(address: str, table: Iterable[Tuple]) -> Optional[T]:
    target = _ip.ip_address(address.strip()) if isinstance(address, str) else address
    best_prefix, best_value = -1, None
    for entry in table:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise TypeError(f"longest_prefix_match table entries must be (Network, value) tuples; got {entry!r}")
        net, value = entry
        if isinstance(net, str):
            net = parse_cidr(net)
        if net.version != target.version:
            continue
        if target in net and net.prefixlen > best_prefix:
            best_prefix, best_value = net.prefixlen, value
    return best_value
