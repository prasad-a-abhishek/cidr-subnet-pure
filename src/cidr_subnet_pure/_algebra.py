"""Set arithmetic: union, intersection, subtract, complement, aggregate.

All operations are pure: never mutate inputs, always return a new list.
Built on ``ipaddress.IPv4Network`` / ``IPv6Network`` (hashable + value-comparable).
"""
from __future__ import annotations
import ipaddress as _ip
from typing import Iterable, List, Union
from ._errors import MixedFamilyError
from ._parser import parse_cidr

__all__ = ["union", "intersection", "subtract", "complement", "aggregate"]

_Network = Union[_ip.IPv4Network, _ip.IPv6Network]


def _coerce(value):
    return value if isinstance(value, (_ip.IPv4Network, _ip.IPv6Network)) else parse_cidr(value)


def _cls(net):
    return _ip.IPv4Network if net.version == 4 else _ip.IPv6Network


def _make_net(cls, addr: int, prefixlen: int):
    return cls((addr, prefixlen))


def _check_homogeneous(nets):
    versions = {n.version for n in nets}
    if len(versions) > 1:
        raise MixedFamilyError("mixed IPv4/IPv6 not supported")


def _key(net):
    return (int(net.network_address), -net.prefixlen)


def union(networks: Iterable) -> List[_Network]:
    nets = [_coerce(n) for n in networks]
    if not nets:
        return []
    _check_homogeneous(nets)
    return _collapse(nets)


def intersection(left: Iterable, right: Iterable) -> List[_Network]:
    L = [_coerce(n) for n in left]
    R = [_coerce(n) for n in right]
    if not L or not R:
        return []
    _check_homogeneous(L + R)
    out: List[_Network] = []
    for a in L:
        for b in R:
            if a.overlaps(b):
                # intersection = more-specific's address masked to common prefix
                common = max(a.prefixlen, b.prefixlen)
                more = b if b.prefixlen >= a.prefixlen else a
                bits = more.max_prefixlen - common
                mask = ((1 << more.max_prefixlen) - 1) ^ ((1 << bits) - 1)
                out.append(_make_net(_cls(a), int(more.network_address) & mask, common))
    return _collapse(out) if out else []


def subtract(a, b) -> List[_Network]:
    A, B = _coerce(a), _coerce(b)
    _check_homogeneous([A, B])
    return _subtract_one(A, B)


def complement(network, address_space) -> List[_Network]:
    return subtract(address_space, network)


def aggregate(networks: Iterable) -> List[_Network]:
    return union(networks)


def _collapse(nets: List[_Network]) -> List[_Network]:
    if not nets:
        return []
    nets = sorted(set(nets), key=_key)
    # Split into same-family buckets so supernet_of() narrows the Union.
    v4 = [n for n in nets if isinstance(n, _ip.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, _ip.IPv6Network)]
    return sorted(set(_collapse_one(v4) + _collapse_one(v6)), key=_key)


def _collapse_one(nets):
    if not nets:
        return []
    changed = True
    while changed:
        changed = False
        for i in range(len(nets)):
            if i >= len(nets):
                break
            a = nets[i]
            for j in range(i + 1, len(nets)):
                if j >= len(nets):
                    break
                b = nets[j]
                if a.supernet_of(b):
                    nets.pop(j); changed = True; break
                if b.supernet_of(a):
                    nets.pop(i); changed = True; break
                if a.prefixlen == b.prefixlen and _are_adjacent(a, b):
                    nets.pop(j)
                    nets[i] = a.supernet(1)  # supernet(1) = up one level
                    changed = True
                    break
        nets = sorted(set(nets), key=_key)
    return nets


def _are_adjacent(a, b) -> bool:
    if a.prefixlen != b.prefixlen or a.version != b.version:
        return False
    return int(a.broadcast_address) + 1 == int(b.network_address) or int(b.broadcast_address) + 1 == int(a.network_address)


def _subtract_one(a, b) -> List[_Network]:
    if not a.overlaps(b):
        return [a]
    if b.supernet_of(a) or a == b:
        return []
    if a.prefixlen == (32 if a.version == 4 else 128):
        return [a]
    # Split a in half; keep pieces that don't overlap b, recurse on those that do.
    out: List[_Network] = []
    for half in a.subnets(prefixlen_diff=1):
        if not half.overlaps(b):
            out.append(half)
        elif b.supernet_of(half) or half == b:
            continue
        else:
            out.extend(_subtract_one(half, b))
    return out
