# AC → Test Coverage Map (cidr-subnet-pure cycle_183)

Every acceptance criterion from `spec.md §4` has ≥1 test mapped below (per
Invariant 26). 15 ACs total.

| AC | Description | Test(s) |
|----|-------------|---------|
| AC-1 | `parse_cidr("10.0.0.0/24")` returns `IPv4Network('10.0.0.0/24')` | `test_parser.py::TestParseHappyPath::test_parse_ipv4_basic`, `test_vectors.py::test_vec_01_parse_cidr_basic_ipv4` |
| AC-2 | `parse_cidr("2001:db8::/32")` returns `IPv6Network('2001:db8::/32')` | `test_parser.py::TestParseHappyPath::test_parse_ipv6_basic`, `test_vectors.py::test_vec_02_parse_cidr_basic_ipv6` |
| AC-3 | `parse_cidr("not-a-cidr")` raises `ValueError` containing "invalid CIDR" | `test_parser.py::TestParseRejection::test_parse_rejects_garbage` |
| AC-4 | `is_cidr("10.0.0.0/24")` True; `is_cidr("256.0.0.0/24")` False; `is_cidr("10.0.0.0/33")` False | `test_parser.py::TestIsCIDR::test_is_cidr_valid_ipv4`, `test_parser.py::TestIsCIDR::test_is_cidr_invalid_octet`, `test_parser.py::TestIsCIDR::test_is_cidr_invalid_prefix_ipv4`, `test_vectors.py::test_vec_03_is_cidr_rejects_octet_overflow`, `test_vectors.py::test_vec_09_is_cidr_rejects_prefix_too_large_ipv4` |
| AC-5 | `contains(parse_cidr("10.0.0.0/16"), "10.0.5.13")` True; `"10.1.0.0"` False | `test_membership.py::TestContainsHappy::test_contains_in_range_ipv4`, `test_membership.py::TestContainsHappy::test_contains_out_of_range_ipv4`, `test_vectors.py::test_vec_11_contains_in_ipv4` |
| AC-6 | `union([10.0.0.0/24, 10.0.1.0/24])` returns `[10.0.0.0/23]` | `test_algebra.py::TestUnion::test_union_collapses_adjacent`, `test_vectors.py::test_vec_04_union_collapses_adjacent` |
| AC-7 | `union([10.0.0.0/24, 192.168.0.0/24])` returns both unchanged | `test_algebra.py::TestUnion::test_union_disjoint` |
| AC-8 | `intersection([10.0.0.0/23], [10.0.1.0/24])` returns `[10.0.1.0/24]` | `test_algebra.py::TestIntersection::test_intersection_overlap` |
| AC-9 | `subtract(10.0.0.0/24, 10.0.0.0/25)` returns `[10.0.0.128/25]` | `test_algebra.py::TestSubtract::test_subtract_halves`, `test_vectors.py::test_vec_05_subtract_returns_remainder` |
| AC-10 | `aggregate([10.0.0.0/24, 10.0.1.0/24, 10.0.5.0/24])` returns `[10.0.0.0/23, 10.0.5.0/24]` | `test_algebra.py::TestAggregate::test_aggregate_collapses_adjacent_keeps_non_adjacent`, `test_vectors.py::test_vec_06_aggregate_collapses_adjacent_keeps_nonadjacent` |
| AC-11 | `smallest_supernet([10.0.0.0/24])` returns the most-specific supernet | `test_hierarchy.py::TestSmallestSupernet::test_smallest_supernet_single`, `test_hierarchy.py::TestSmallestSupernet::test_smallest_supernet_universal_via_zero_ip` |
| AC-12 | `longest_prefix_match("10.0.5.13", [(10.0.0.0/16, "us"), (10.0.5.0/24, "us-west")])` returns `"us-west"` | `test_hierarchy.py::TestLPM::test_lpm_picks_most_specific`, `test_vectors.py::test_vec_07_longest_prefix_match_picks_most_specific` |
| AC-13 | `subnets(10.0.0.0/16, 17)` yields `[10.0.0.0/17, 10.0.128.0/17]` | `test_hierarchy.py::TestSubnets::test_subnets_split_into_two`, `test_vectors.py::test_vec_08_subnets_yields_two_halves` |
| AC-14 | IPv6 round-trip: `parse_cidr("2001:db8::/32")` then `union([net, net])` returns `[net]` | `test_algebra.py::TestUnion::test_union_ipv6_idempotent`, `test_vectors.py::test_vec_13_union_ipv6_idempotent` |
| AC-15 | Mixed-family rejection: `union([10.0.0.0/24, 2001:db8::/32])` raises `TypeError` | `test_algebra.py::TestUnion::test_union_mixed_v4_v6_rejected`, `test_algebra.py::TestUnion::test_union_mixed_via_type_error`, `test_vectors.py::test_vec_10_union_rejects_mixed_family`, `test_invariants.py::test_mixed_family_raises_typed_error` |

## Test vector coverage

All 10 spec vectors (§5) are covered in `tests/test_vectors.py` plus 5 derived vectors:

| Vector | Source URL | Section | Test |
|--------|------------|---------|------|
| VEC-01 | rfc-editor.org/rfc/rfc4632.html | §3.1 | `test_vec_01_parse_cidr_basic_ipv4` |
| VEC-02 | rfc-editor.org/rfc/rfc4291.html | §2.2 | `test_vec_02_parse_cidr_basic_ipv6` |
| VEC-03 | rfc-editor.org/rfc/rfc791.html | §3.1 | `test_vec_03_is_cidr_rejects_octet_overflow` |
| VEC-04 | rfc-editor.org/rfc/rfc4632.html | §5.1 | `test_vec_04_union_collapses_adjacent` |
| VEC-05 | rfc-editor.org/rfc/rfc4632.html | §5.2 | `test_vec_05_subtract_returns_remainder` |
| VEC-06 | rfc-editor.org/rfc/rfc4632.html | §3 | `test_vec_06_aggregate_collapses_adjacent_keeps_nonadjacent` |
| VEC-07 | rfc-editor.org/rfc/rfc4632.html | §4 | `test_vec_07_longest_prefix_match_picks_most_specific` |
| VEC-08 | rfc-editor.org/rfc/rfc4632.html | §5.1 | `test_vec_08_subnets_yields_two_halves` |
| VEC-09 | rfc-editor.org/rfc/rfc4291.html | §2.3 | `test_vec_09_is_cidr_rejects_prefix_too_large_ipv4` |
| VEC-10 | rfc-editor.org/rfc/rfc4291.html | §2.5.5.2 | `test_vec_10_union_rejects_mixed_family` |
| VEC-11 | rfc-editor.org/rfc/rfc4632.html | §3.1 | `test_vec_11_contains_in_ipv4` |
| VEC-12 | (derived) | | `test_vec_12_parse_cidr_ipv6_canonical` |
| VEC-13 | (derived) | | `test_vec_13_union_ipv6_idempotent` |
| VEC-14 | (derived) | | `test_vec_14_aggregate_empty` |
| VEC-15 | rfc-editor.org/rfc/rfc4007.html | §11 | `test_vec_15_parse_cidr_rejects_ipv6_zone` |