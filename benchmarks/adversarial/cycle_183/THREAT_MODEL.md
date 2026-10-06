# THREAT_MODEL — cidr-subnet-pure (cycle_183)

Attack vectors enumerated per surface. Library is pure-CPU with no I/O — only DoS / integrity threats are in scope (no confidentiality threat; no shell injection possible).

## Threat T-1: Uncaught `AttributeError` on `longest_prefix_match(None, ...)`
- **Surface:** `hierarchy` (surface #3)
- **Vector:** `longest_prefix_match(None, [(parse_cidr('10.0.0.0/8'), 'v4')])`
- **Result:** `AttributeError: 'NoneType' object has no attribute 'version'`
- **Leak:** Internal call site `_hierarchy.py:66` (`target.version` without isinstance check) and `target.strip()` (NoneType has no strip). `_parser.py::parse_cidr` validates the address IS a str first; this code bypasses that.
- **Exploit scenario:** Caller receives a JSON-parsed table from an untrusted config (AWS security group), passes a None address. Expects a typed exception (`InvalidCIDR`); gets `AttributeError`. Caller's `except InvalidCIDR` does not catch → unhandled exception bubbles up, kills the worker, may leak stack trace.
- **Severity:** **Medium** (no security boundary crossed; total-function contract violation per spec §1 Invariant 21)
- **CWE:** CWE-754, CWE-476

## Threat T-2: Uncaught `TypeError` on `subnets(parse_cidr('10.0.0.0/16'), '24')`
- **Surface:** `hierarchy` (surface #3)
- **Vector:** `subnets(parse_cidr('10.0.0.0/16'), '24')` (str passed for prefix)
- **Result:** `TypeError: '<' not supported between instances of 'str' and 'int'` from `_hierarchy.py:60`
- **Exploit scenario:** Caller receives prefix from YAML config (always str), passes directly to `subnets()`. Expects `ValueError` or `InvalidCIDR`; gets `TypeError`. Same uncaught-exception leak as T-1.
- **Severity:** **Medium** (no security boundary crossed; total-function contract violation)
- **CWE:** CWE-754, CWE-20

## Threat T-3: Uncaught `AttributeError` on `subnets(None, 24)`
- **Surface:** `hierarchy` (surface #3)
- **Vector:** `subnets(None, 24)`
- **Result:** `AttributeError: 'NoneType' object has no attribute 'prefixlen'` from `_hierarchy.py:60`
- **Exploit scenario:** Caller passes None for network; gets uncaught exception. Same pattern as T-1.
- **Severity:** **Medium**
- **CWE:** CWE-754, CWE-476

## Threat T-4: Probe exhausted — no DoS via hostile input
- **Surface:** `invariant21` (surface #5)
- **Vector:** I tried `parse_cidr(b'\xff' * 1000000)`, `parse_cidr('A' * 1000000)`, `is_cidr('10.0.0.0/' + '9' * 1000000)`, `union([parse_cidr('10.0.0.0/' + str(p)) for p in range(33)])` (33-element list — stdlib rejects all individually)
- **Result:** All hostile inputs raise `InvalidCIDR` quickly. No regex catastrophic backtracking (stdlib uses C-impl). No OOM observed in 30s test. **No DoS surface found.**
- **Severity:** N/A — confirmed not vulnerable.

## Threat T-5: Probe exhausted — no shell injection / no I/O
- **Surface:** all
- **Vector:** Library has zero I/O surface (no `open`, no `subprocess`, no `os.system`, no `socket`, no `urllib`). Cannot be coerced into shell/file/network operations. Pure functions over `ipaddress.IPv4Network`/`IPv6Network`.
- **Severity:** N/A — out of scope by construction.

## Threat T-6: Probe exhausted — no infinite loop / stack overflow
- **Surface:** `algebra_set` (`_subtract_one` recursion at `_algebra.py:123-139`)
- **Vector:** I tried `subtract(parse_cidr('10.0.0.0/16'), parse_cidr('10.0.0.0/32'))` (max recursion depth: subtract /16 minus a /32 → 16 levels of recursion).
- **Result:** Completed in <1ms, no RecursionError, no stack overflow. Python's default recursion limit is 1000; subtract's recursion depth is bounded by `prefixlen_diff`, max 32 (IPv4) or 128 (IPv6) — well within limit.
- **Severity:** N/A — confirmed safe.

## Threat T-7: Probe exhausted — `aggregate([])` / `union([])` / `intersection([], [])`
- **Surface:** `algebra_set`
- **Vector:** Empty input
- **Result:** All return `[]` cleanly. No exception, no None. **Correctly handled.**
- **Severity:** N/A — confirmed safe.

## Threat T-8: Probe exhausted — duplicate / nested CIDR in `aggregate`
- **Surface:** `algebra_set`
- **Vector:** `aggregate([parse_cidr('10.0.0.0/24'), parse_cidr('10.0.0.0/24'), parse_cidr('10.0.0.0/25')])`
- **Result:** `set()` deduplicates → 2 unique → collapse to `[10.0.0.0/24]`. **Correctly handled** (probe P1).
- **Severity:** N/A — confirmed safe.

## Threat T-9: Probe exhausted — `subnets()` with `new_prefixlen > max`
- **Surface:** `hierarchy`
- **Vector:** `subnets(parse_cidr('10.0.0.0/16'), 33)`
- **Result:** `ValueError: prefix length diff 33 is invalid for netblock 10.0.0.0/16` — caught and re-raised by `ipaddress.subnets()`. **Correctly handled.**
- **Severity:** N/A — confirmed safe.

## Threat T-10: Probe exhausted — leading-zero, host-bits-set, octet overflow
- **Surface:** `parse_core`
- **Vector:** `parse_cidr('010.0.0.0/24')`, `parse_cidr('10.0.0.1/24')`, `parse_cidr('256.0.0.0/24')`
- **Result:** All raise `InvalidCIDR` (probe P11a, P3a failing case, V3). **Correctly handled** — `ip_network(strict=True)` rejects host-bits-set; leading-zero is also rejected by Python 3 stdlib.
- **Severity:** N/A — confirmed safe.

## Threat T-11: Probe exhausted — IPv6 zone-ID with and without prefix
- **Surface:** `parse_core`
- **Vector:** `parse_cidr('fe80::1%eth0/64')`, `parse_cidr('fe80::1%eth0')`
- **Result:** Both raise `InvalidCIDR` with message "IPv6 zone identifier not supported" (M-001 fix from commit 32bd3b8, probe P12, P13). **Correctly handled** — `_parser.py:20-23` guards before delegating to `ip_network`.
- **Severity:** N/A — confirmed safe.

## Threat T-12: Probe exhausted — mixed-family rejection
- **Surface:** all
- **Vector:** `union([v4, v6])`, `intersection([v4], [v6])`, `subtract(v4, v6)`, `smallest_supernet([v4, v6])`
- **Result:** All raise `MixedFamilyError` (inherits `TypeError`, so `except TypeError` catches per spec AC-15). **Correctly handled.**
- **Severity:** N/A — confirmed safe.

## Threat T-13: Probe exhausted — `hosts()` /31 and /32 (RFC 3021 / RFC 950)
- **Surface:** `membership_iter`
- **Vector:** `list(hosts(parse_cidr('10.0.0.0/31')))`, `list(hosts(parse_cidr('10.0.0.1/32')))`
- **Result:** `/31` returns 2 hosts (RFC 3021); `/32` returns 1 host (probe P14, P15). **Correctly handled** — stdlib's `network.hosts()` implements RFC 3021 /31 semantics.
- **Severity:** N/A — confirmed safe.
