"""parse_cidr + is_cidr (AC-1..AC-4, AC-14)."""
import pytest
import ipaddress
from cidr_subnet_pure import parse_cidr, is_cidr
from cidr_subnet_pure._errors import InvalidCIDR


# ---- parse_cidr happy path -------------------------------------------------

def test_parse_ipv4_basic():
    n = parse_cidr("10.0.0.0/24")
    assert isinstance(n, ipaddress.IPv4Network)
    assert str(n) == "10.0.0.0/24"


def test_parse_ipv4_single_host():
    n = parse_cidr("192.168.1.1/32")
    assert str(n) == "192.168.1.1/32"


def test_parse_ipv4_slash_zero():
    n = parse_cidr("0.0.0.0/0")
    assert n.prefixlen == 0


def test_parse_ipv4_strips_whitespace():
    n = parse_cidr("  10.0.0.0/24  ")
    assert str(n) == "10.0.0.0/24"


def test_parse_ipv6_basic():
    n = parse_cidr("2001:db8::/32")
    assert isinstance(n, ipaddress.IPv6Network)
    assert str(n) == "2001:db8::/32"


def test_parse_ipv6_slash_zero():
    n = parse_cidr("::/0")
    assert n.prefixlen == 0


def test_parse_ipv6_full():
    n = parse_cidr("2001:0db8:0000:0000:0000:0000:0000:0000/32")
    assert isinstance(n, ipaddress.IPv6Network)


# ---- parse_cidr rejection ---------------------------------------------------

def test_parse_rejects_garbage():
    with pytest.raises(InvalidCIDR):
        parse_cidr("not-a-cidr")


def test_parse_rejects_octet_overflow():
    with pytest.raises(InvalidCIDR):
        parse_cidr("256.0.0.0/24")


def test_parse_rejects_prefix_too_large_ipv4():
    with pytest.raises(InvalidCIDR):
        parse_cidr("10.0.0.0/33")


def test_parse_rejects_prefix_too_large_ipv6():
    with pytest.raises(InvalidCIDR):
        parse_cidr("2001:db8::/129")


def test_parse_rejects_ipv4_mapped():
    """::ffff:10.0.0.1 is intentionally rejected (no IPv4-mapped IPv6)."""
    with pytest.raises(InvalidCIDR):
        parse_cidr("::ffff:10.0.0.0/120")


def test_parse_rejects_none():
    with pytest.raises(InvalidCIDR):
        parse_cidr(None)


def test_parse_rejects_bytes():
    with pytest.raises(InvalidCIDR):
        parse_cidr(b"10.0.0.0/24")


def test_parse_rejects_int():
    with pytest.raises(InvalidCIDR):
        parse_cidr(42)


def test_parse_rejects_empty_string():
    with pytest.raises(InvalidCIDR):
        parse_cidr("")


def test_parse_rejects_host_bits_set_ipv4():
    """ip_network(..., strict=True) rejects host bits set."""
    with pytest.raises(InvalidCIDR):
        parse_cidr("10.0.0.5/24")


# ---- is_cidr ----------------------------------------------------------------

def test_is_cidr_valid_ipv4():
    assert is_cidr("10.0.0.0/24") is True


def test_is_cidr_valid_ipv6():
    assert is_cidr("2001:db8::/32") is True


def test_is_cidr_invalid_octet():
    assert is_cidr("256.0.0.0/24") is False


def test_is_cidr_invalid_prefix_ipv4():
    assert is_cidr("10.0.0.0/33") is False


def test_is_cidr_garbage():
    assert is_cidr("not-a-cidr") is False


def test_is_cidr_empty():
    assert is_cidr("") is False


def test_is_cidr_none():
    """Invariant 21: total over arbitrary input. None → False, not crash."""
    assert is_cidr(None) is False


def test_is_cidr_int():
    assert is_cidr(42) is False


# ---- Round-trip / idempotence ----------------------------------------------

def test_parse_idempotent():
    s = "10.0.0.0/24"
    assert str(parse_cidr(s)) == s


def test_parse_ipv6_idempotent():
    s = "2001:db8::/32"
    assert str(parse_cidr(s)) == s


def test_parse_returns_unique_per_value():
    """Parsing same string twice returns equal but distinct objects."""
    assert parse_cidr("10.0.0.0/24") == parse_cidr("10.0.0.0/24")
    assert parse_cidr("10.0.0.0/24") is not parse_cidr("10.0.0.0/24")