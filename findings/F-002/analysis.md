# F-002 — `subnets()` leaks AttributeError on hostile `network` arg (MEDIUM)

**Class:** M-001/M-002 (VULN_AUDIT.md) — Invariant 21 violation, type validation gap.
**Surface:** hierarchy / `src/cidr_subnet_pure/_hierarchy.py:57-62`
**Severity:** MEDIUM (per VULN_AUDIT M-001/M-002 rubric; not Critical/High because pure-Python parser library — no security boundary).

## Minimized repro

```python
from cidr_subnet_pure import subnets
subnets([], 24)
# AttributeError: 'list' object has no attribute 'prefixlen'
```

## Stack trace

```
File ".../_hierarchy.py", line 60, in subnets
    if new_prefixlen < network.prefixlen:
                        ^^^^^^^^^^^^^^^^^
AttributeError: 'list' object has no attribute 'prefixlen'
```

## Root cause

`subnets(network, new_prefixlen)` only normalizes when it is a `str` (line 58-59).
Any non-`str` hostile value (None, int, float, bool, bytes, list, dict, tuple,
object) passes through to `network.prefixlen` at line 60 with no type check.

Note: the original VULN_AUDIT M-001 (`subnets(parse_cidr('10.0.0.0/16'), '24')`)
triggers `TypeError: '<' not supported between instances of 'str' and 'int'`
on the `new_prefixlen < network.prefixlen` comparison — a different
exception class but the same root cause (no upfront validation of either
argument). The fuzzer expanded the attack surface by also feeding hostile
`network` values, which now leak `AttributeError` instead.

## Why MEDIUM, not HIGH

Same reasoning as F-001:
- Pure-Python function, no I/O, no eval, no security boundary crossed.
- Attacker must already have code execution; this is a contract violation per
  Invariant 21, not a vulnerability.
- Pre-existing VULN_AUDIT classified as MEDIUM (CWE-754 / CWE-20).

## Recommended fix (for cycle_183 fix card)

At `_hierarchy.py:57-62`, validate both args up front:

```python
def subnets(network, new_prefixlen: int) -> List:
    if isinstance(network, str):
        network = parse_cidr(network)
    if not isinstance(network, (_ip.IPv4Network, _ip.IPv6Network)):
        raise TypeError(
            f"subnets: network must be str, IPv4Network, or IPv6Network; "
            f"got {type(network).__name__}"
        )
    if not isinstance(new_prefixlen, int) or isinstance(new_prefixlen, bool):
        raise TypeError(
            f"subnets: new_prefixlen must be int; got {type(new_prefixlen).__name__}"
        )
    if new_prefixlen < network.prefixlen:
        raise ValueError(
            f"new_prefixlen ({new_prefixlen}) must be >= "
            f"network.prefixlen ({network.prefixlen})"
        )
    return list(network.subnets(new_prefix=new_prefixlen))
```

The `isinstance(x, bool)` exclusion is critical — `bool` is a subclass of
`int` in Python, and `True < 16` is a silent bug magnet.

## Reproduction count

- 267/701 hierarchy crashes hit `subnets` (38.1%); all 267 share root frame
  `_hierarchy.py:60` and the `AttributeError: '<type>' object has no attribute
  'prefixlen'` pattern.
- Unique hostile types observed: NoneType, int, bool, bytes, float, list,
  dict, tuple, object.
- VULN_AUDIT's M-001 (TypeError on str `new_prefixlen`) was the seed that
  led to discovering this stricter AttributeError variant on hostile `network`.