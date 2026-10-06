"""contains() — membership of an IP literal in a CIDR (AC-5)."""
import pytest
from cidr_subnet_pure import contains, parse_cidr
from cidr_subnet_pure._errors import InvalidCIDR, MixedFamilyError


# ---- IPv4 happy path --------------------------------------------------------

def test_contains_in_range_ipv4():
    assert contains(parse_cidr("10.0.0.0/16"), "10.0.5.13") is True


def test_contains_out_of_range_ipv4():
    assert contains(parse_cidr("10.0.0.0/16"), "10.1.0.1") is False


def test_contains_at_network_address_ipv4():
    assert contains(parse_cidr("10.0.0.0/24"), "10.0.0.0") is True


def test_contains_at_broadcast_ipv4():
    assert contains(parse_cidr("10.0.0.0/24"), "10.0.0.255") is True


def test_contains_just_past_broadcast_ipv4():
    assert contains(parse_cidr("10.0.0.0/24"), "10.0.1.0") is False


def test_contains_single_host_match_ipv4():
    assert contains(parse_cidr("10.0.0.5/32"), "10.0.0.5") is True


def test_contains_single_host_miss_ipv4():
    assert contains(parse_cidr("10.0.0.5/32"), "10.0.0.6") is False


# ---- IPv6 happy path --------------------------------------------------------

def test_contains_in_range_ipv6():
    assert contains(parse_cidr("2001:db8::/32"), "2001:db8::1") is True


def test_contains_out_of_range_ipv6():
    assert contains(parse_cidr("2001:db8::/32"), "2001:db9::1") is False


# ---- String CIDR input ------------------------------------------------------

def test_contains_with_string_cidr():
    assert contains("10.0.0.0/24", "10.0.0.5") is True


def test_contains_with_string_cidr_invalid():
    """Invariant 21: invalid string CIDR surfaces as InvalidCIDR."""
    with pytest.raises(InvalidCIDR):
        contains("not-a-cidr", "10.0.0.5")


# ---- Mixed-family rejection -------------------------------------------------

def test_contains_mixed_v4_net_v6_ip():
    with pytest.raises(MixedFamilyError):
        contains(parse_cidr("10.0.0.0/24"), "2001:db8::1")


def test_contains_mixed_v6_net_v4_ip():
    with pytest.raises(MixedFamilyError):
        contains(parse_cidr("2001:db8::/32"), "10.0.0.1")


# ---- Invariant 21: total over arbitrary input -------------------------------

def test_contains_none_address():
    with pytest.raises(InvalidCIDR):
        contains(parse_cidr("10.0.0.0/24"), None)


def test_contains_int_address():
    with pytest.raises(InvalidCIDR):
        contains(parse_cidr("10.0.0.0/24"), 42)


def test_contains_garbage_string():
    with pytest.raises(InvalidCIDR):
        contains(parse_cidr("10.0.0.0/24"), "256.256.256.256")


def test_contains_empty_address():
    with pytest.raises(InvalidCIDR):
        contains(parse_cidr("10.0.0.0/24"), "")