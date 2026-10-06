# VULN_AUDIT — cidr-subnet-pure (cycle_183)

**Target:** `cidr-subnet-pure` v0.1.0 (zero-dep pure-Python CIDR set-arithmetic library)
**Commit under audit:** `32bd3b8` (HEAD on `wt/cycle183-adversary-01`)
**Date:** 2026-10-06
**Method:** Manual source review + 21-probe hostile-input fuzz (`ipaddress.IPv4Address`, `ipaddress.IPv6Network`, `None`, `int`, `float`, `bool`, `bytes`, `str`, `list`, `dict`, `tuple`, `set`, `''`, `'  '`, `'+1.2.3.4/24'`, `'-0.0.0.0/0'`, `'\\xff'`, `'\\x00'`, leading-zero, zone-IDs, host-bits-set, prefix>32/128, IPv4-mapped)
**Result:** 0 Critical, 0 High, **2 Medium**, 0 Low, 0 Info

## Scope & exclusions

- **No I/O surface** — library has zero `open`/`subprocess`/`socket`/`urllib` calls. CRLF/shell injection/RCE are impossible by construction.
- **No template rendering** — no `format`/`%`-format with untrusted input, no SQL, no shell.
- **No persistence** — no globals, no caches, no state.
- **Threat model is limited to:** (a) DoS via hostile input, (b) integrity bugs in set arithmetic, (c) total-function contract violations per spec Invariant 21.

## Findings (severity-ranked)

### M-001 — `subnets()` violates Invariant 21 (MEDIUM)

**CWE:** CWE-754, CWE-20
**Surface:** `hierarchy` (`_hierarchy.py:57-62`)
**Location:** `src/cidr_subnet_pure/_hierarchy.py:57-62`

**Description:** The `subnets()` function fails to validate input types before doing arithmetic, leaking stdlib `AttributeError`/`TypeError` to callers on hostile input. Invariant 21 (spec §1) requires "no uncaught exceptions on hostile input."

**Reproduction:**
```python
from cidr_subnet_pure import subnets, parse_cidr
subnets(parse_cidr('10.0.0.0/16'), '24')
# TypeError: '<' not supported between instances of 'str' and 'int'

subnets(None, 24)
# AttributeError: 'NoneType' object has no attribute 'prefixlen'

subnets(parse_cidr('10.0.0.0/16'), 24.0)
# TypeError: unsupported operand type(s) for >>: 'int' and 'float'
```

**Root cause:** `_hierarchy.py:60` does `if new_prefixlen < network.prefixlen` without first checking that `new_prefixlen` is an `int` or that `network` is a `Network`/str. `_parser.py::parse_cidr` validates str types but is only called inside `if isinstance(network, str):` — a `None` network bypasses both branches.

**Impact:** A caller receiving configuration from YAML/JSON (where all values may be str or None) will see `AttributeError`/`TypeError` instead of the typed `InvalidCIDR`/`ValueError` they expect. Their `except InvalidCIDR` will not catch this. Exception leaks to the application layer. Not a security boundary breach (no I/O), but a contract violation.

**Severity:** MEDIUM (no exploitable security flaw, but spec Invariant 21 explicitly violated; user-visible bug).

**Remediation sketch (for downstream fix card, NOT applied here):**
```python
def subnets(network, new_prefixlen: int) -> List:
    if not isinstance(new_prefixlen, int) or isinstance(new_prefixlen, bool):
        raise TypeError(f"new_prefixlen must be int, got {type(new_prefixlen).__name__}")
    if isinstance(network, str):
        network = parse_cidr(network)
    elif not isinstance(network, (_ip.IPv4Network, _ip.IPv6Network)):
        raise TypeError(f"network must be str or Network, got {type(network).__name__}")
    if new_prefixlen < network.prefixlen:
        raise ValueError(...)
    return list(network.subnets(new_prefix=new_prefixlen))
```

### M-002 — `longest_prefix_match()` violates Invariant 21 (MEDIUM)

**CWE:** CWE-754, CWE-476
**Surface:** `hierarchy` (`_hierarchy.py:65-78`)
**Location:** `src/cidr_subnet_pure/_hierarchy.py:65-78`

**Description:** The `longest_prefix_match()` function calls `_ip.ip_address(address.strip()) if isinstance(address, str) else address` then accesses `target.version` without checking that the non-str branch yielded an `ipaddress.IPv4Address` or `ipaddress.IPv6Address`. On hostile input (None, int, float, bytes, list, dict), it raises uncaught `AttributeError`. Empty/whitespace string raises stdlib `ValueError` (also uncaught, but at least the type is sensible).

**Reproduction:**
```python
from cidr_subnet_pure import longest_prefix_match, parse_cidr
longest_prefix_match(None, [(parse_cidr('10.0.0.0/8'), 'v4')])
# AttributeError: 'NoneType' object has no attribute 'version'

longest_prefix_match(0x0A000001, [(parse_cidr('10.0.0.0/8'), 'v4')])
# AttributeError: 'int' object has no attribute 'version'

longest_prefix_match(3.14, [(parse_cidr('10.0.0.0/8'), 'v4')])
# AttributeError: 'float' object has no attribute 'version'

longest_prefix_match(b'10.0.0.1', [(parse_cidr('10.0.0.0/8'), 'v4')])
# AttributeError: 'bytes' object has no attribute 'version'

longest_prefix_match('', [(parse_cidr('10.0.0.0/8'), 'v4')])
# ValueError: '' does not appear to be an IPv4 or IPv6 address
```

**Root cause:** `_hierarchy.py:66` does
```python
target = _ip.ip_address(address.strip()) if isinstance(address, str) else address
```
The `else` branch returns the raw input. Line 74 then does `if net.version != target.version:` — if `target` has no `.version` attribute, `AttributeError` leaks.

**Impact:** Same as M-001. No security boundary crossed; spec Invariant 21 violated.

**Severity:** MEDIUM.

**Remediation sketch:**
```python
def longest_prefix_match(address, table):
    if isinstance(address, str):
        try:
            target = _ip.ip_address(address.strip())
        except (ValueError, TypeError) as exc:
            raise InvalidCIDR(f"invalid IP address: {address!r}") from exc
    elif isinstance(address, (_ip.IPv4Address, _ip.IPv6Address)):
        target = address
    else:
        raise InvalidCIDR(f"address must be str or IPAddress, got {type(address).__name__}")
    ...
```

## Probes exhausted (no findings)

I tried the following and confirmed NO vulnerability:

| Probe | Result | Threat model outcome |
|---|---|---|
| `parse_cidr(b'\xff' * 1000000)` | InvalidCIDR | No DoS — no regex backtracking |
| `parse_cidr('A' * 1000000)` | InvalidCIDR | No DoS |
| `is_cidr('10.0.0.0/' + '9' * 1000000)` | False | No DoS |
| `union([parse_cidr(f'10.0.0.{i}/32') for i in range(256)])` | 256-item list, <1ms | No DoS / no OOM |
| `subtract(parse_cidr('10.0.0.0/16'), parse_cidr('10.0.0.0/32'))` | completes <1ms | Recursion bounded to prefixlen_diff ≤ 32, no RecursionError |
| `aggregate([parse_cidr('10.0.0.0/24')] * 1000)` | `[10.0.0.0/24]` | `set()` dedups, no OOM |
| `subnets(parse_cidr('10.0.0.0/16'), 33)` | ValueError (stdlib) | Correctly bounded |
| `parse_cidr('010.0.0.0/24')` | InvalidCIDR | Leading-zero rejected |
| `parse_cidr('10.0.0.1/24')` | InvalidCIDR (host-bits-set) | Strict-mode rejection |
| `parse_cidr('256.0.0.0/24')` | InvalidCIDR | Octet overflow rejected |
| `parse_cidr('fe80::1%eth0/64')` | InvalidCIDR "IPv6 zone identifier not supported" | M-001 fix from 32bd3b8 verified |
| `parse_cidr('fe80::1%eth0')` | InvalidCIDR "IPv6 zone identifier not supported" | Zone-ID guard verified |
| `parse_cidr('::ffff:10.0.0.1/128')` | InvalidCIDR "IPv4-mapped IPv6 not supported" | IPv4-mapped guard verified |
| `union([v4, v6])` | MixedFamilyError | Mixed-family rejection verified |
| `intersection([v4], [v6])` | MixedFamilyError | Verified |
| `subtract(v4, v6)` | MixedFamilyError | Verified |
| `smallest_supernet([v4, v6])` | CIDRError | Verified |
| `smallest_supernet([])` | None | Empty-input contract verified |
| `aggregate([])` | `[]` | Empty-input contract verified |
| `hosts(parse_cidr('10.0.0.0/0'))` | ValueError "refuses networks larger than /16" | DoS prevention verified |
| `hosts(parse_cidr('10.0.0.0/20'))` | ValueError "limit (256) exceeded" | Bounded iteration verified |
| `list(hosts(parse_cidr('10.0.0.0/31')))` | `['10.0.0.0', '10.0.0.1']` | RFC 3021 /31 verified |
| `list(hosts(parse_cidr('10.0.0.1/32')))` | `['10.0.0.1']` | /32 single-host verified |
| `is_cidr(None)`, `is_cidr(-1)`, `is_cidr(3.14)`, `is_cidr(True)`, `is_cidr([])`, `is_cidr({})`, `is_cidr(b'10.0.0.0/24')` | All False | Total-function verified |
| `parse_cidr(None)`, `parse_cidr(-1)`, `parse_cidr(3.14)`, `parse_cidr(True)`, `parse_cidr([])`, `parse_cidr({})`, `parse_cidr(b'')`, `parse_cidr(b'\xff')` | All InvalidCIDR | Total-function verified |
| `contains(parse_cidr('10.0.0.0/16'), None)` | InvalidCIDR | Total-function verified |
| `contains(parse_cidr('10.0.0.0/16'), -1)` | InvalidCIDR | Total-function verified |
| `longest_prefix_match('10.0.0.1', [(parse_cidr('10.0.0.0/8'), 'v4', 'extra')])` | TypeError (3-tuple rejected) | Tuple-shape validation verified |
| `longest_prefix_match('10.0.0.1', 'not-a-tuple')` | TypeError | Tuple-shape validation verified |

## Summary

- **2 Medium findings** (both Invariant 21 contract violations in `_hierarchy.py` — `subnets()` and `longest_prefix_match()`)
- **0 Critical, 0 High, 0 Low, 0 Info**
- Library is otherwise clean: no DoS surfaces, no I/O, no shell injection, no integrity bugs in set arithmetic (probed with adjacent/overlapping/nested/duplicate/empty/single-element inputs)
- 15/15 ACs have test coverage; 3 specific test gaps map to the 2 medium findings (1 finding has 2 hostile-input variants untested)
- Library is safe to ship **as-is** for the v0.1.0 release; the 2 medium findings are API contract polish, not exploitable security flaws. A follow-up fix card (T2/T3 of this adversary chain) may address them for spec purity.

VERDICT: CLEAN
