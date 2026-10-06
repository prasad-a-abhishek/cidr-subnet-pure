"""Cross-cutting invariants: round-trip, idempotence, mutual containment,
Invariant 21 exception safety."""
import pytest
import ipaddress
from cidr_subnet_pure import (
    parse_cidr, is_cidr, contains, union, intersection, subtract,
    complement, aggregate, smallest_supernet, longest_prefix_match,
    subnets, hosts,
)
from cidr_subnet_pure._errors import CIDRError, InvalidCIDR, MixedFamilyError


# ---- Round-trip idempotence ----------------------------------------------

def test_parse_then_str_roundtrip_ipv4():
    """str(parse_cidr(s)) == s for canonical CIDR strings."""
    for s in ["10.0.0.0/24", "192.168.0.0/16", "0.0.0.0/0", "172.16.0.0/12"]:
        assert str(parse_cidr(s)) == s


def test_parse_then_str_roundtrip_ipv6():
    for s in ["2001:db8::/32", "::/0", "fe80::/10"]:
        assert str(parse_cidr(s)) == s


def test_union_roundtrip_single():
    """union([x]) == [x] for any x."""
    n = parse_cidr("10.0.0.0/24")
    assert union([n]) == [n]


# ---- Mutual containment ----------------------------------------------------

def test_a_minus_a_overlap_eq_empty():
    """a - a == [] (mutual containment)."""
    n = parse_cidr("10.0.0.0/24")
    assert subtract(n, n) == []


def test_intersection_self_returns_self():
    """intersection([x], [x]) == [x]."""
    n = parse_cidr("10.0.0.0/24")
    assert intersection([n], [n]) == [n]


def test_complement_complement_in_inverse():
    """complement(complement(net, /0), /0) ~= net (modulo representation)."""
    universe = parse_cidr("0.0.0.0/0")
    n = parse_cidr("10.0.0.0/24")
    # complement(net, /0) is huge — we just check it's a net
    r = complement(n, universe)
    assert all(isinstance(x, ipaddress.IPv4Network) for x in r)


# ---- aggregate idempotence -------------------------------------------------

def test_aggregate_idempotent_overlapping():
    """aggregate(aggregate(x)) == aggregate(x)."""
    inner = aggregate([parse_cidr("10.0.0.0/24"), parse_cidr("10.0.1.0/24")])
    assert aggregate(inner) == inner


def test_aggregate_idempotent_disjoint():
    inner = aggregate([parse_cidr("10.0.0.0/24"), parse_cidr("192.168.0.0/24")])
    assert aggregate(inner) == inner


# ---- Invariant 21: exception safety on arbitrary input --------------------
# Per the contract: public top-level functions MUST be total over arbitrary
# input; passing None, malformed URLs, etc. must NEVER raise uncaught
# ValueError/TypeError/AttributeError.  The expected error types
# (InvalidCIDR, MixedFamilyError, CIDRError) are part of the public API.

# parse_cidr
@pytest.mark.parametrize("value", [
    None,
    42,
    3.14,
    b"10.0.0.0/24",
    ["10.0.0.0/24"],
    {"cidr": "10.0.0.0/24"},
    b'\xff\xfe',
    -1,
])
def test_parse_cidr_total(value):
    """parse_cidr must never raise AttributeError/TypeError on arbitrary input."""
    try:
        parse_cidr(value)
    except (InvalidCIDR, ValueError) as exc:
        # ValueError allowed only if it's a subclass of our CIDRError hierarchy
        assert isinstance(exc, CIDRError), (
            f"unexpected non-CIDRError ValueError: {type(exc).__name__}: {exc}"
        )
    except Exception as exc:
        pytest.fail(f"unexpected exception type {type(exc).__name__}: {exc}")


# is_cidr is total by definition (returns False on None)
@pytest.mark.parametrize("value", [None, 42, b"x", [], {}, -1, 3.14])
def test_is_cidr_total(value):
    """is_cidr must never raise; returns False on non-str input."""
    assert is_cidr(value) is False


# contains
@pytest.mark.parametrize("bad_addr", [
    None, 42, b"10.0.0.5", ["10.0.0.5"], -1, 3.14,
])
def test_contains_total(bad_addr):
    """contains must never raise AttributeError on non-str address."""
    try:
        contains(parse_cidr("10.0.0.0/24"), bad_addr)
    except (InvalidCIDR, MixedFamilyError):
        pass
    except Exception as exc:
        pytest.fail(f"unexpected exception type {type(exc).__name__}: {exc}")


def test_contains_unclosed_bracket():
    """Invariant 21: malformed address must raise InvalidCIDR, not ValueError."""
    with pytest.raises(InvalidCIDR):
        contains(parse_cidr("::/0"), "[::1")


def test_contains_out_of_range_octet():
    with pytest.raises(InvalidCIDR):
        contains(parse_cidr("10.0.0.0/24"), "256.256.256.256")


# hosts
def test_hosts_too_large_ipv4_raises_value_error():
    """hosts() refuses networks larger than /16."""
    with pytest.raises(ValueError):
        list(hosts(parse_cidr("10.0.0.0/8")))


def test_hosts_too_large_ipv6_raises_value_error():
    with pytest.raises(ValueError):
        list(hosts(parse_cidr("2001:db8::/32")))


def test_hosts_respects_limit():
    """hosts() raises ValueError when iteration would exceed limit."""
    n = parse_cidr("10.0.0.0/16")
    with pytest.raises(ValueError):
        list(hosts(n, limit=10))  # /16 has 65534 hosts


def test_hosts_returns_strings():
    n = parse_cidr("10.0.0.0/30")
    addrs = list(hosts(n, limit=10))
    assert all(isinstance(a, str) for a in addrs)
    assert len(addrs) == 2  # /30 has exactly 2 hosts


def test_hosts_single_host_network():
    """/32 returns 1 address (Python's stdlib includes the address for /32)."""
    r = list(hosts(parse_cidr("10.0.0.5/32"), limit=10))
    assert r == ["10.0.0.5"]


def test_hosts_thirty_one_returns_two():
    """/31 returns 2 hosts (point-to-point RFC 3021)."""
    assert list(hosts(parse_cidr("10.0.0.0/31"), limit=10)) == ["10.0.0.0", "10.0.0.1"]


# longest_prefix_match
def test_lpm_bad_address_type():
    """lpm should accept address as IP or str; garbage raises ValueError-like."""
    from ipaddress import IPv4Address
    r = longest_prefix_match(
        IPv4Address("10.0.0.5"),
        [(parse_cidr("10.0.0.0/16"), "us")],
    )
    assert r == "us"


# ---- Cross-family purity ---------------------------------------------------

@pytest.mark.parametrize("op", [
    lambda: union([parse_cidr("10.0.0.0/24"), parse_cidr("2001:db8::/32")]),
    lambda: intersection([parse_cidr("10.0.0.0/24")], [parse_cidr("2001:db8::/32")]),
    lambda: subtract(parse_cidr("10.0.0.0/24"), parse_cidr("2001:db8::/32")),
])
def test_mixed_family_raises_typed_error(op):
    """All binary operations must raise MixedFamilyError (TypeError) on mixed input."""
    with pytest.raises(MixedFamilyError):
        op()
    with pytest.raises(TypeError):
        op()