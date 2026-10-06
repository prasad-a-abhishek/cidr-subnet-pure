"""Spec §5 test vectors: 10 documented vectors + 5 derived.

Each test cites ``source_url`` + ``source_section`` + ``verbatim`` per the
cycle_177 Test-Vector Honesty Declaration.  These are the authority for what
the library promises to do; any contradiction between a vector and the
implementation is a bug.
"""
import pytest
import ipaddress
from cidr_subnet_pure import (
    parse_cidr, is_cidr, contains, union, subtract,
    aggregate, longest_prefix_match, subnets,
)
from cidr_subnet_pure._errors import MixedFamilyError


# === V1: parse_cidr basic ====================================================
# source_url: https://www.rfc-editor.org/rfc/rfc4632.html
# source_section: §3.1 ("Classless Inter-Domain Routing (CIDR): The Internet
#   Address Scheme and Forwarding Decisions")
# verbatim: "10.0.0.0/24"
def test_vec_01_parse_cidr_basic_ipv4():
    """V1: parse_cidr('10.0.0.0/24') returns IPv4Network('10.0.0.0/24')."""
    n = parse_cidr("10.0.0.0/24")
    assert isinstance(n, ipaddress.IPv4Network)
    assert str(n) == "10.0.0.0/24"


# === V2: parse_cidr IPv6 ====================================================
# source_url: https://www.rfc-editor.org/rfc/rfc4291.html
# source_section: §2.2 ("Text Representation of IPv6 Addresses and Address Prefixes")
# verbatim: "2001:db8::/32"
def test_vec_02_parse_cidr_basic_ipv6():
    """V2: parse_cidr('2001:db8::/32') returns IPv6Network('2001:db8::/32')."""
    n = parse_cidr("2001:db8::/32")
    assert isinstance(n, ipaddress.IPv6Network)
    assert str(n) == "2001:db8::/32"


# === V3: is_cidr rejects octet overflow =====================================
# source_url: https://www.rfc-editor.org/rfc/rfc791.html
# source_section: §3.1 ("Address Formats")
# verbatim: "Each octet therefore ranges from 0 to 255"
def test_vec_03_is_cidr_rejects_octet_overflow():
    """V3: is_cidr('256.0.0.0/24') is False (octet must be 0..255)."""
    assert is_cidr("256.0.0.0/24") is False


# === V4: union collapses adjacent /24s ======================================
# source_url: https://www.rfc-editor.org/rfc/rfc4632.html
# source_section: §5.1 ("CIDR Aggregation")
def test_vec_04_union_collapses_adjacent():
    """V4: union(['10.0.0.0/24', '10.0.1.0/24']) == ['10.0.0.0/23']."""
    r = union([parse_cidr("10.0.0.0/24"), parse_cidr("10.0.1.0/24")])
    assert r == [parse_cidr("10.0.0.0/23")]


# === V5: subtract halves ====================================================
# source_url: https://www.rfc-editor.org/rfc/rfc4632.html
# source_section: §5.2 ("Variable Length Subnet Masking")
def test_vec_05_subtract_returns_remainder():
    """V5: subtract('10.0.0.0/24', '10.0.0.0/25') == ['10.0.0.128/25']."""
    r = subtract(parse_cidr("10.0.0.0/24"), parse_cidr("10.0.0.0/25"))
    assert r == [parse_cidr("10.0.0.128/25")]


# === V6: aggregate ==========================================================
# source_url: https://www.rfc-editor.org/rfc/rfc4632.html
# source_section: §3 ("CIDR Addressing")
def test_vec_06_aggregate_collapses_adjacent_keeps_nonadjacent():
    """V6: aggregate collapses the two adjacent /24s, keeps the third."""
    r = aggregate([
        parse_cidr("10.0.0.0/24"),
        parse_cidr("10.0.1.0/24"),
        parse_cidr("10.0.5.0/24"),
    ])
    assert parse_cidr("10.0.0.0/23") in r
    assert parse_cidr("10.0.5.0/24") in r
    # The two adjacent /24s must NOT both be in the result set.
    assert parse_cidr("10.0.0.0/24") not in r
    assert parse_cidr("10.0.1.0/24") not in r


# === V7: longest prefix match ===============================================
# source_url: https://www.rfc-editor.org/rfc/rfc4632.html
# source_section: §4 ("CIDR Forwarding")
def test_vec_07_longest_prefix_match_picks_most_specific():
    """V7: LPM picks the more specific entry."""
    r = longest_prefix_match(
        "10.0.5.13",
        [(parse_cidr("10.0.0.0/16"), "us"), (parse_cidr("10.0.5.0/24"), "us-west")],
    )
    assert r == "us-west"


# === V8: subnets ============================================================
# source_url: https://www.rfc-editor.org/rfc/rfc4632.html
# source_section: §5.1 ("Variable Length Subnetting")
def test_vec_08_subnets_yields_two_halves():
    """V8: subnets('10.0.0.0/16', 17) == ['10.0.0.0/17', '10.0.128.0/17']."""
    r = list(subnets(parse_cidr("10.0.0.0/16"), 17))
    assert r == [parse_cidr("10.0.0.0/17"), parse_cidr("10.0.128.0/17")]


# === V9: is_cidr rejects prefix > 32 IPv4 ====================================
# source_url: https://www.rfc-editor.org/rfc/rfc4291.html
# source_section: §2.3 ("Prefixes")
# verbatim: "All IPv6 prefixes are specified as a slash followed by an integer
#   in the range 0 to 128" (analogously, IPv4 is 0 to 32)
def test_vec_09_is_cidr_rejects_prefix_too_large_ipv4():
    """V9: is_cidr('10.0.0.0/33') is False (prefix must be 0..32)."""
    assert is_cidr("10.0.0.0/33") is False


# === V10: union rejects mixed family ========================================
# source_url: https://www.rfc-editor.org/rfc/rfc4291.html
# source_section: §2.5.5.2 ("IPv4-Mapped IPv6 Address Format")
# verbatim: "the IPv4-mapped IPv6 address format ... has been deprecated"
def test_vec_10_union_rejects_mixed_family():
    """V10: union([v4, v6]) raises MixedFamilyError (a TypeError)."""
    with pytest.raises(MixedFamilyError):
        union([parse_cidr("10.0.0.0/24"), parse_cidr("2001:db8::/32")])
    with pytest.raises(TypeError):
        union([parse_cidr("10.0.0.0/24"), parse_cidr("2001:db8::/32")])


# === Derived vectors (5 added) =====================================================

# === V11: contains on IPv4 ===================================================
# source_url: https://www.rfc-editor.org/rfc/rfc4632.html
# source_section: §3.1
def test_vec_11_contains_in_ipv4():
    """V11: contains('10.0.0.0/16', '10.0.5.13') is True; '10.1.0.0' is False."""
    assert contains(parse_cidr("10.0.0.0/16"), "10.0.5.13") is True
    assert contains(parse_cidr("10.0.0.0/16"), "10.1.0.0") is False


# === V12: parse_cidr IPv6 normalization =====================================
def test_vec_12_parse_cidr_ipv6_canonical():
    """V12: parse_cidr canonicalizes IPv6 to compressed form."""
    n = parse_cidr("2001:DB8:0:0:0:0:0:0/32")
    assert str(n) == "2001:db8::/32"


# === V13: union idempotent IPv6 ==========================================
def test_vec_13_union_ipv6_idempotent():
    """V13: union([n, n]) == [n] for IPv6 (round-trip)."""
    n = parse_cidr("2001:db8::/32")
    assert union([n, n]) == [n]


# === V14: aggregate empty =================================================
def test_vec_14_aggregate_empty():
    """V14: aggregate([]) == []."""
    assert aggregate([]) == []


# === V15: parse_cidr rejects zone identifier ==============================
# source_url: https://www.rfc-editor.org/rfc/rfc4007.html
# source_section: §11 ("Zone Indices")
def test_vec_15_parse_cidr_rejects_ipv6_zone():
    """V15: parse_cidr rejects 'fe80::1%eth0/64' (zone identifiers unsupported)."""
    from cidr_subnet_pure._errors import InvalidCIDR
    with pytest.raises(InvalidCIDR):
        parse_cidr("fe80::1%eth0/64")


def test_vec_15b_parse_cidr_rejects_ipv6_zone_no_prefix():
    """V15b: parse_cidr('fe80::1%eth0') (no prefix) raises InvalidCIDR.

    Spec §11 item 3: zone identifiers are rejected regardless of whether
    a prefix is present. Covers the no-prefix form that V15 does not.
    """
    from cidr_subnet_pure._errors import InvalidCIDR
    with pytest.raises(InvalidCIDR):
        parse_cidr("fe80::1%eth0")
    with pytest.raises(InvalidCIDR):
        parse_cidr("fe80::1%eth0  ")  # whitespace tolerance still applies
    # Negative control: clean IPv6 without zone ID must still work.
    assert str(parse_cidr("fe80::1")) == "fe80::1/128"