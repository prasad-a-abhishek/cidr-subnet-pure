# CWE_MAP — cidr-subnet-pure (cycle_183)

MITRE CWE entries mapped to each attack surface. Mappings derived from CWE-1000 (Research Concepts) viewed 2026-10-06.

## parse_core (`_parser.py`)

| CWE | Title | Why applicable | Mitigated? |
|---|---|---|---|
| CWE-20 | Improper Input Validation | Must reject zone-IDs, leading-zero, sign, whitespace, host-bits-set | **Yes** — `parse_cidr` strips, rejects `%`, delegates to `ip_network(strict=True)` which rejects host-bits-set, leading-zero, prefix-out-of-range, IPv4-mapped |
| CWE-190 | Integer Overflow or Wraparound | Huge prefix values (e.g. `/999999999999`) | **Yes** — stdlib `ip_network` raises `ValueError` on prefix >32/128; wrapped in `InvalidCIDR` |
| CWE-1284 | Improper Validation of Specified Quantity | prefixlen out of range, mixed v4-in-v6 | **Yes** — IPv4-mapped detection at `_parser.py:28-34` |

## algebra_set (`_algebra.py`)

| CWE | Title | Why applicable | Mitigated? |
|---|---|---|---|
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | empty input, single-element, homogeneous vs heterogeneous | **Yes** — `_check_homogeneous` at line 29-32, `if not nets: return []` at line 41-42 |
| CWE-682 | Incorrect Calculation | adjacent collapse, overlap detection | **Yes** — `_collapse_one` (lines 90-114) + `_are_adjacent` (lines 117-120) tested with V4 (adjacent), V6 (idempotent), K (overlap+adjacent combined) |
| CWE-1284 | Improper Validation of Specified Quantity | homogeneity check | **Yes** — covered above |

## hierarchy (`_hierarchy.py`)

| CWE | Title | Why applicable | Mitigated? |
|---|---|---|---|
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | empty input, no-supernet case, new_prefixlen invalid | **Partial** — empty input returns `None` (line 23-24); smallest_supernet mixed raises `CIDRError`. **But** subnets() with non-int new_prefixlen (e.g. `'24'`) raises uncaught `TypeError`; subnets() with `None` net raises uncaught `AttributeError`; longest_prefix_match with non-string non-IPAddress address (None, int, float, bytes) raises uncaught `AttributeError` (lines 65-78) |
| CWE-682 | Incorrect Calculation | subnets() arithmetic — new_prefixlen <= current must reject | **Partial** — `new_prefixlen < network.prefixlen` raises `ValueError` (correct for ints). Boundary case: `new_prefixlen == network.prefixlen` does NOT raise (probe P3a — returns list of 1 network) — this is `ipaddress` stdlib behavior and matches spec AC-13 spirit |
| CWE-20 | Improper Input Validation | LPM address input must be valid; bad address input handling | **Partial** — empty/whitespace address raises stdlib `ValueError` (uncought). Non-string non-IPAddress raises `AttributeError` (uncought). **Invariant 21 violated** for `longest_prefix_match(None, ...)` |

## membership_iter (`_membership.py`, `_iter.py`)

| CWE | Title | Why applicable | Mitigated? |
|---|---|---|---|
| CWE-190 | Integer Overflow or Wraparound | hosts() on /0 v4 = 2^32 ints | **Yes** — bounded by `prefixlen < 16` (v4) / `< 112` (v6) check at `_iter.py:25-29`; also bounded by `limit` param defaulting to 256 |
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | contains on bad address | **Yes** — `_membership.py:19-24` raises `InvalidCIDR` for non-str or unparseable; raises `MixedFamilyError` for v4/v6 mismatch |
| CWE-682 | Incorrect Calculation | RFC 3021 /31 2-host semantics | **Yes** — probe P14: `hosts(10.0.0.0/31)` returns `['10.0.0.0', '10.0.0.1']` (2 hosts, RFC 3021) |

## invariant21 (cross-cutting)

| CWE | Title | Why applicable | Mitigated? |
|---|---|---|---|
| CWE-754 | Improper Check for Unusual or Exceptional Conditions | All public functions must NEVER raise uncaught on hostile input | **Mostly yes** — parse_cidr, is_cidr, contains, union, intersection, subtract, complement, aggregate, smallest_supernet, hosts all handle the hostile-input suite (None, int, float, bool, list, dict, bytes). **No** — `subnets()` and `longest_prefix_match()` do NOT validate input types and leak `AttributeError`/`TypeError` from stdlib |
| CWE-476 | NULL Pointer Dereference | Hostile None input | **Mostly yes** — same exceptions; same exceptions for `subnets()` and `longest_prefix_match()` |
