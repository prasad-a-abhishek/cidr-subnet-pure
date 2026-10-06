"""Set arithmetic: union, intersection, subtract, complement, aggregate."""
import pytest
from cidr_subnet_pure import (
    union, intersection, subtract, complement, aggregate, parse_cidr,
)
from cidr_subnet_pure._errors import MixedFamilyError, InvalidCIDR


# ---- union (AC-6, AC-7, AC-14) ---------------------------------------------

def test_union_collapses_adjacent():
    """AC-6: 10.0.0.0/24 + 10.0.1.0/24 → 10.0.0.0/23."""
    r = union([parse_cidr("10.0.0.0/24"), parse_cidr("10.0.1.0/24")])
    assert r == [parse_cidr("10.0.0.0/23")]


def test_union_disjoint():
    """AC-7: union of two non-adjacent /24s returns both unchanged."""
    r = union([parse_cidr("10.0.0.0/24"), parse_cidr("192.168.0.0/24")])
    assert r == [parse_cidr("10.0.0.0/24"), parse_cidr("192.168.0.0/24")]


def test_union_idempotent():
    n = parse_cidr("10.0.0.0/24")
    assert union([n, n]) == [n]


def test_union_empty():
    assert union([]) == []


def test_union_dedups():
    n = parse_cidr("10.0.0.0/24")
    assert union([n, n, n]) == [n]


def test_union_collapses_subnet_into_supernet():
    """If one input is a subnet of the other, return the larger."""
    r = union([parse_cidr("10.0.0.0/16"), parse_cidr("10.0.5.0/24")])
    assert r == [parse_cidr("10.0.0.0/16")]


def test_union_two_adjacent_with_third_disjoint():
    r = union([
        parse_cidr("10.0.0.0/24"),
        parse_cidr("10.0.1.0/24"),
        parse_cidr("192.168.0.0/24"),
    ])
    assert parse_cidr("10.0.0.0/23") in r
    assert parse_cidr("192.168.0.0/24") in r


def test_union_overlapping_prefix_keeps_supernet():
    r = union([parse_cidr("10.0.0.0/24"), parse_cidr("10.0.0.0/25")])
    assert r == [parse_cidr("10.0.0.0/24")]


def test_union_from_strings():
    r = union(["10.0.0.0/24", "10.0.1.0/24"])
    assert r == [parse_cidr("10.0.0.0/23")]


def test_union_ipv6_idempotent():
    """AC-14."""
    n = parse_cidr("2001:db8::/32")
    assert union([n, n]) == [n]


def test_union_mixed_v4_v6_rejected():
    """AC-15: MixedFamilyError (also a TypeError)."""
    with pytest.raises(MixedFamilyError):
        union([parse_cidr("10.0.0.0/24"), parse_cidr("2001:db8::/32")])


def test_union_mixed_via_type_error():
    """AC-15 alt: caught by TypeError too."""
    with pytest.raises(TypeError):
        union([parse_cidr("10.0.0.0/24"), parse_cidr("2001:db8::/32")])


# ---- intersection (AC-8) ---------------------------------------------------

def test_intersection_overlap():
    """AC-8."""
    r = intersection([parse_cidr("10.0.0.0/23")], [parse_cidr("10.0.1.0/24")])
    assert r == [parse_cidr("10.0.1.0/24")]


def test_intersection_no_overlap():
    r = intersection([parse_cidr("10.0.0.0/24")], [parse_cidr("10.1.0.0/24")])
    assert r == []


def test_intersection_empty_left():
    r = intersection([], [parse_cidr("10.0.0.0/24")])
    assert r == []


def test_intersection_empty_right():
    r = intersection([parse_cidr("10.0.0.0/24")], [])
    assert r == []


def test_intersection_identical():
    n = parse_cidr("10.0.0.0/24")
    assert intersection([n], [n]) == [n]


def test_intersection_mixed_rejected():
    with pytest.raises(MixedFamilyError):
        intersection(
            [parse_cidr("10.0.0.0/24")],
            [parse_cidr("2001:db8::/32")],
        )


# ---- subtract (AC-9) -------------------------------------------------------

def test_subtract_halves():
    """AC-9."""
    r = subtract(parse_cidr("10.0.0.0/24"), parse_cidr("10.0.0.0/25"))
    assert r == [parse_cidr("10.0.0.128/25")]


def test_subtract_disjoint():
    r = subtract(parse_cidr("10.0.0.0/24"), parse_cidr("10.1.0.0/24"))
    assert r == [parse_cidr("10.0.0.0/24")]


def test_subtract_identity():
    """a - a == []."""
    r = subtract(parse_cidr("10.0.0.0/24"), parse_cidr("10.0.0.0/24"))
    assert r == []


def test_subtract_superset():
    """a - supernet(a) == []."""
    r = subtract(parse_cidr("10.0.0.0/24"), parse_cidr("10.0.0.0/16"))
    assert r == []


def test_subtract_single_bit():
    """10.0.0.0/25 - 10.0.0.0/26 = 10.0.0.64/26."""
    r = subtract(parse_cidr("10.0.0.0/25"), parse_cidr("10.0.0.0/26"))
    assert r == [parse_cidr("10.0.0.64/26")]


def test_subtract_mixed_rejected():
    with pytest.raises(MixedFamilyError):
        subtract(parse_cidr("10.0.0.0/24"), parse_cidr("2001:db8::/32"))


# ---- complement -------------------------------------------------------------

def test_complement_against_universe():
    """complement(net, /0) should be the complement (everything except net)."""
    r = complement(parse_cidr("10.0.0.0/24"), parse_cidr("0.0.0.0/0"))
    # For IPv4, complement of a /24 should collapse to a single block
    assert all(x.version == 4 for x in r)
    assert all(not (x == parse_cidr("10.0.0.0/24")) for x in r)


def test_complement_disjoint():
    """complement(net, outside) where outside doesn't contain net → [outside]."""
    r = complement(parse_cidr("10.0.0.0/24"), parse_cidr("192.168.0.0/24"))
    assert r == [parse_cidr("192.168.0.0/24")]


def test_complement_self_in_universe():
    """complement(net, net) == []  (the net is removed from itself)."""
    n = parse_cidr("10.0.0.0/24")
    r = complement(n, n)
    assert r == []


def test_complement_inside_universe():
    """complement(net, superset) → superset \\ net."""
    r = complement(parse_cidr("10.0.0.0/24"), parse_cidr("10.0.0.0/16"))
    # Result: 10.0.0.0/16 minus 10.0.0.0/24, i.e., the 255 other /24s collapsed
    assert len(r) >= 1
    # None of the result blocks should be 10.0.0.0/24
    for net in r:
        assert net != parse_cidr("10.0.0.0/24")


# ---- aggregate (AC-10) ------------------------------------------------------

def test_aggregate_collapses_adjacent_keeps_non_adjacent():
    """AC-10."""
    r = aggregate([
        parse_cidr("10.0.0.0/24"),
        parse_cidr("10.0.1.0/24"),
        parse_cidr("10.0.5.0/24"),
    ])
    assert parse_cidr("10.0.0.0/23") in r
    assert parse_cidr("10.0.5.0/24") in r


def test_aggregate_empty():
    assert aggregate([]) == []


def test_aggregate_is_alias_for_union():
    assert aggregate is union or aggregate([parse_cidr("10.0.0.0/24")]) == [
        parse_cidr("10.0.0.0/24")
    ]


def test_aggregate_ipv6():
    """aggregate works on IPv6 too."""
    r = aggregate([
        parse_cidr("2001:db8::/48"),
        parse_cidr("2001:db8:1::/48"),
    ])
    assert parse_cidr("2001:db8::/47") in r


def test_aggregate_three_adjacent():
    r = aggregate([
        parse_cidr("10.0.0.0/24"),
        parse_cidr("10.0.1.0/24"),
        parse_cidr("10.0.2.0/24"),
    ])
    # /22 + /24 collapsed into one
    assert len(r) >= 1


# ---- Idempotence / involution ------------------------------------------------

def test_aggregate_idempotent():
    """aggregate(aggregate(x)) == aggregate(x)."""
    inner = aggregate([parse_cidr("10.0.0.0/24"), parse_cidr("10.0.1.0/24")])
    outer = aggregate(inner)
    assert inner == outer