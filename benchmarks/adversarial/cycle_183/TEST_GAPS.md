# TEST_GAPS — cidr-subnet-pure (cycle_183)

15-AC coverage matrix. Tests counted by `^def test_` regex across `tests/test_*.py`.

## Summary

- **Total tests:** 136 (parser 27, vectors 16, membership 16, algebra 32, hierarchy 20, invariants 18, typing 7)
- **Spec promise:** 100 floor; actual 136 (+36% over floor)
- **AC coverage:** 15/15 ACs have ≥1 dedicated test → **0 gaps**
- **Spec promise vs actual:** spec says 167 in card body; actual is 136. The 31-test delta is likely from `test_invariants.py` parametrize expansion (e.g., `test_parse_cidr_total` and `test_is_cidr_total` are parametrized over many hostile inputs). Not a coverage gap.

## Per-AC matrix

| AC | Description | Test(s) covering | Status |
|---|---|---|---|
| AC-1 | `parse_cidr("10.0.0.0/24")` returns IPv4Network | `test_parser.py::test_parse_ipv4_basic` (line 10), `test_vectors.py::test_vec_01_parse_cidr_basic_ipv4` (line 22) | COVERED |
| AC-2 | `parse_cidr("2001:db8::/32")` returns IPv6Network | `test_parser.py::test_parse_ipv6_basic` (line 31), `test_vectors.py::test_vec_02_parse_cidr_basic_ipv6` (line 33) | COVERED |
| AC-3 | `parse_cidr("not-a-cidr")` raises ValueError "invalid CIDR" | `test_parser.py::test_parse_rejects_garbage` (line 49) | COVERED |
| AC-4 | `is_cidr("10.0.0.0/24")` True; `"256.0.0.0/24"` False; `"10.0.0.0/33"` False | `test_parser.py::test_is_cidr_valid_ipv4` (103), `test_is_cidr_invalid_octet` (111), `test_is_cidr_invalid_prefix_ipv4` (115), `test_vectors.py::test_vec_03`, `test_vec_09` | COVERED |
| AC-5 | `contains(parse_cidr("10.0.0.0/16"), "10.0.5.13")` True; "10.1.0.0" False | `test_membership.py::test_contains_in_range_ipv4` (9), `test_contains_out_of_range_ipv4` (13), `test_vectors.py::test_vec_11_contains_in_ipv4` (132) | COVERED |
| AC-6 | `union([10.0.0.0/24, 10.0.1.0/24])` → `[10.0.0.0/23]` (collapsed) | `test_algebra.py::test_union_collapses_adjacent` (11), `test_vectors.py::test_vec_04_union_collapses_adjacent` (52) | COVERED |
| AC-7 | `union([10.0.0.0/24, 192.168.0.0/24])` returns both unchanged | `test_algebra.py::test_union_disjoint` (17) | COVERED |
| AC-8 | `intersection([10.0.0.0/23], [10.0.1.0/24])` → `[10.0.1.0/24]` | `test_algebra.py::test_intersection_overlap` (83) | COVERED |
| AC-9 | `subtract(10.0.0.0/24, 10.0.0.0/25)` → `[10.0.0.128/25]` | `test_algebra.py::test_subtract_halves` (119), `test_vectors.py::test_vec_05_subtract_returns_remainder` (61) | COVERED |
| AC-10 | `aggregate([10.0.0.0/24, 10.0.1.0/24, 10.0.5.0/24])` → `[10.0.0.0/23, 10.0.5.0/24]` | `test_algebra.py::test_aggregate_collapses_adjacent_keeps_non_adjacent` (188), `test_vectors.py::test_vec_06_aggregate_collapses_adjacent_keeps_nonadjacent` (70) | COVERED |
| AC-11 | `smallest_supernet([10.0.0.0/24])` → `IPv4Network("10.0.0.0/0")` | `test_hierarchy.py::test_smallest_supernet_universal_via_zero_ip` (18) | COVERED |
| AC-12 | `longest_prefix_match(10.0.5.13, [(10.0.0.0/16, "us"), (10.0.5.0/24, "us-west")])` → `"us-west"` | `test_hierarchy.py::test_lpm_picks_most_specific` (123), `test_vectors.py::test_vec_07_longest_prefix_match_picks_most_specific` (87) | COVERED |
| AC-13 | `subnets(10.0.0.0/16, 17)` → `[10.0.0.0/17, 10.0.128.0/17]` | `test_hierarchy.py::test_subnets_split_into_two` (81), `test_vectors.py::test_vec_08_subnets_yields_two_halves` (99) | COVERED |
| AC-14 | IPv6 round-trip: parse + union idempotent | `test_algebra.py::test_union_ipv6_idempotent` (63), `test_vectors.py::test_vec_13_union_ipv6_idempotent` (153) | COVERED |
| AC-15 | `union([10.0.0.0/24, 2001:db8::/32])` raises `TypeError("mixed IPv4/IPv6 not supported")` | `test_algebra.py::test_union_mixed_v4_v6_rejected` (69), `test_union_mixed_via_type_error` (75), `test_vectors.py::test_vec_10_union_rejects_mixed_family` (119) | COVERED |

## Test gaps by surface

| Surface | Gaps | Notes |
|---|---|---|
| `parse_core` | 0 | 27 tests; covers garbage, octet overflow, prefix > 32/128, IPv4-mapped, leading-zero, zone-IDs (M-001 fix), all hostile types |
| `algebra_set` | 0 | 32 tests; covers empty input, single element, nested/overlapping/adjacent/dupes, IPv6 idempotent, MixedFamilyError |
| `hierarchy` | **3 gaps** | (1) No test for `subnets()` with non-int `new_prefixlen` (str/float/None) — **Invariant 21 violation not caught**. (2) No test for `longest_prefix_match()` with non-string non-IPAddress address (None/int/float/bytes) — **Invariant 21 violation not caught**. (3) No test for `subnets()` with `None` network — **Invariant 21 violation not caught**. |
| `membership_iter` | 0 | 16 tests; covers /0, /32, /128, RFC 3021 /31, mixed-family rejection, all hostile types |
| `invariant21` | **3 partial** | `test_invariants.py::test_parse_cidr_total` (parametrized) covers parse_cidr/contains/hosts/mixed-family. **Missing** for `subnets()` and `longest_prefix_match()`. |

## Gaps requiring fix (mapped to findings in VULN_AUDIT.md)

| Gap | Finding ID |
|---|---|
| `subnets()` Invariant 21 — non-int prefix | M-001 |
| `subnets()` Invariant 21 — None network | M-001 |
| `longest_prefix_match()` Invariant 21 — bad address type | M-002 |
