"""Hierarchy: smallest_supernet, subnets, longest_prefix_match."""
import pytest
from cidr_subnet_pure import (
    smallest_supernet, subnets, longest_prefix_match, parse_cidr,
)
from cidr_subnet_pure._errors import CIDRError, InvalidCIDR


# ---- smallest_supernet (AC-11) ---------------------------------------------

def test_smallest_supernet_single():
    """For a single /24, smallest_supernet is the most-specific network
    containing it: /32 (the address itself)."""
    r = smallest_supernet([parse_cidr("10.0.0.0/24")])
    assert r == parse_cidr("10.0.0.0/32")


def test_smallest_supernet_universal_via_zero_ip():
    """The universal supernet is /0 with address 0.0.0.0."""
    assert smallest_supernet([parse_cidr("0.0.0.0/0")]) == parse_cidr("0.0.0.0/0")


def test_smallest_supernet_two_disjoint():
    """Two disjoint /24s → /0 (no common high bit)."""
    r = smallest_supernet([
        parse_cidr("10.0.0.0/24"),
        parse_cidr("192.168.0.0/24"),
    ])
    # Result is the universal supernet since the inputs are disjoint.
    assert r.prefixlen == 0
    # Both inputs must be subnets of the result
    assert parse_cidr("10.0.0.0/24").subnet_of(r)
    assert parse_cidr("192.168.0.0/24").subnet_of(r)


def test_smallest_supernet_empty():
    """Empty input → None."""
    assert smallest_supernet([]) is None


def test_smallest_supernet_two_overlapping():
    """Two overlapping /24s → /23 (smallest common prefix)."""
    r = smallest_supernet([
        parse_cidr("10.0.0.0/24"),
        parse_cidr("10.0.1.0/24"),
    ])
    assert r == parse_cidr("10.0.0.0/23")


def test_smallest_supernet_three_overlapping():
    """Three /24s in same /22 → /22."""
    r = smallest_supernet([
        parse_cidr("10.0.0.0/24"),
        parse_cidr("10.0.1.0/24"),
        parse_cidr("10.0.2.0/24"),
    ])
    assert r == parse_cidr("10.0.0.0/22")


def test_smallest_supernet_mixed_rejected():
    with pytest.raises(CIDRError):
        smallest_supernet([
            parse_cidr("10.0.0.0/24"),
            parse_cidr("2001:db8::/32"),
        ])


def test_smallest_supernet_ipv6():
    """IPv6 single /48 → /128 (the address itself)."""
    r = smallest_supernet([parse_cidr("2001:db8::/48")])
    assert r == parse_cidr("2001:db8::/128")


def test_smallest_supernet_from_strings():
    r = smallest_supernet(["10.0.0.0/24", "10.0.1.0/24"])
    assert r == parse_cidr("10.0.0.0/23")


# ---- subnets (AC-13) -------------------------------------------------------

def test_subnets_split_into_two():
    """AC-13."""
    r = subnets(parse_cidr("10.0.0.0/16"), 17)
    assert list(r) == [parse_cidr("10.0.0.0/17"), parse_cidr("10.0.128.0/17")]


def test_subnets_split_into_four():
    r = list(subnets(parse_cidr("10.0.0.0/16"), 18))
    assert len(r) == 4


def test_subnets_same_prefixlen():
    """new_prefixlen == prefixlen returns single-element list."""
    r = list(subnets(parse_cidr("10.0.0.0/24"), 24))
    assert r == [parse_cidr("10.0.0.0/24")]


def test_subnets_smaller_prefix_raises():
    """new_prefixlen smaller than network's prefixlen is invalid."""
    with pytest.raises(ValueError):
        subnets(parse_cidr("10.0.0.0/24"), 16)


def test_subnets_from_string():
    r = list(subnets("10.0.0.0/16", 17))
    assert parse_cidr("10.0.0.0/17") in r


def test_subnets_ipv6():
    r = list(subnets(parse_cidr("2001:db8::/32"), 33))
    assert len(r) == 2


def test_subnets_total_order():
    """Subnets are returned in address order."""
    r = list(subnets(parse_cidr("10.0.0.0/16"), 18))
    addrs = [int(s.network_address) for s in r]
    assert addrs == sorted(addrs)


# ---- longest_prefix_match (AC-12) -----------------------------------------

def test_lpm_picks_most_specific():
    """AC-12."""
    r = longest_prefix_match(
        "10.0.5.13",
        [(parse_cidr("10.0.0.0/16"), "us"), (parse_cidr("10.0.5.0/24"), "us-west")],
    )
    assert r == "us-west"


def test_lpm_falls_back_to_less_specific():
    r = longest_prefix_match(
        "10.0.5.13",
        [(parse_cidr("10.0.0.0/16"), "us")],
    )
    assert r == "us"


def test_lpm_no_match_returns_none():
    r = longest_prefix_match(
        "192.168.5.13",
        [(parse_cidr("10.0.0.0/16"), "us")],
    )
    assert r is None


def test_lpm_empty_table():
    r = longest_prefix_match("10.0.0.1", [])
    assert r is None


def test_lpm_skips_wrong_family():
    """IPv6 entry should not match IPv4 target."""
    r = longest_prefix_match(
        "10.0.0.1",
        [(parse_cidr("2001:db8::/32"), "v6")],
    )
    assert r is None


def test_lpm_string_in_table():
    r = longest_prefix_match(
        "10.0.0.5",
        [("10.0.0.0/16", "us")],
    )
    assert r == "us"


def test_lpm_returns_value_types_vary():
    """Values can be any T (object return)."""
    obj = object()
    r = longest_prefix_match("10.0.0.5", [(parse_cidr("10.0.0.0/16"), obj)])
    assert r is obj


def test_lpm_invalid_tuple_raises():
    with pytest.raises(TypeError):
        longest_prefix_match("10.0.0.5", [(parse_cidr("10.0.0.0/16"),)])  # 1-tuple


def test_lpm_three_tiers():
    """Three nested entries — picks deepest."""
    r = longest_prefix_match(
        "10.0.5.13",
        [
            (parse_cidr("10.0.0.0/8"), "corp"),
            (parse_cidr("10.0.0.0/16"), "us"),
            (parse_cidr("10.0.5.0/24"), "us-west"),
        ],
    )
    assert r == "us-west"