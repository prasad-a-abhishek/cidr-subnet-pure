"""cidr_subnet_pure — pure-stdlib CIDR set arithmetic for Python 3.8+.

Public API:

    parse_cidr, is_cidr, contains, union, intersection, subtract,
    complement, aggregate, smallest_supernet, longest_prefix_match,
    subnets, hosts

``ipaddress`` (stdlib) handles single-prefix operations
(``overlaps()``, ``subnet_of()``, ``subnets()``) but provides no
union, intersection, aggregation, or longest-prefix-match.  This
package is the missing thin set-arithmetic layer over ``ipaddress`` —
PEP-561 typed, pure-stdlib, ≤ 200 LOC.
"""
from __future__ import annotations

from ._algebra import aggregate, complement, intersection, subtract, union
from ._errors import CIDRError, InvalidCIDR, MixedFamilyError
from ._hierarchy import longest_prefix_match, smallest_supernet, subnets
from ._iter import hosts
from ._membership import contains
from ._parser import is_cidr, parse_cidr

__all__ = [
    "parse_cidr", "is_cidr", "contains", "union", "intersection",
    "subtract", "complement", "aggregate", "smallest_supernet",
    "longest_prefix_match", "subnets", "hosts",
    "CIDRError", "InvalidCIDR", "MixedFamilyError",
]

__version__ = "0.1.0"