# F-003 — `longest_prefix_match()` leaks AttributeError on hostile `address` arg (MEDIUM)

**Class:** M-002 (VULN_AUDIT.md) — Invariant 21 violation, type validation gap.
**Surface:** hierarchy / `src/cidr_subnet_pure/_hierarchy.py:65-78`
**Severity:** MEDIUM (per VULN_AUDIT M-002 rubric; not Critical/High because pure-Python parser library — no security boundary).

## Minimized repro

```python
from cidr_subnet_pure import longest_prefix_match, parse_cidr
longest_prefix_match(False, [(parse_cidr('10.0.0.0/8'), 'v')])
# AttributeError: 'bool' object has no attribute 'version'
```

## Stack trace

```
File ".../_hierarchy.py", line 74, in longest_prefix_match
    if net.version != target.version:
                      ^^^^^^^^^^^^^^
AttributeError: 'bool' object has no attribute 'version'
```

## Root cause

`longest_prefix_match(address, table)` line 66 converts `str` to
`ip_address(...)`, but passes any non-`str` through unchanged. The loop at
line 68-78 then accesses `target.version` at line 74 without verifying that
`target` is an `IPv4Address` or `IPv6Address`. Any hostile non-`str` value
(None, int, float, bool, bytes, list, dict, tuple, object) reaches `.version`
and leaks `AttributeError`.

A secondary hostile path exists for `net` at line 72-73: a non-`str` table
entry passes through `parse_cidr` and reaches `net.version` similarly. Same
root cause, same severity.

## Why MEDIUM, not HIGH

Same reasoning as F-001/F-002:
- Pure-Python function, no I/O, no eval, no security boundary crossed.
- VULN_AUDIT M-002 explicitly classified as MEDIUM (CWE-754 / CWE-476).

## Recommended fix (for cycle_183 fix card)

At `_hierarchy.py:65-78`, validate `address` after str-normalization:

```python
def longest_prefix_match(address: str, table: Iterable[Tuple]) -> Optional[T]:
    if isinstance(address, str):
        target = _ip.ip_address(address.strip())
    elif isinstance(address, (_ip.IPv4Address, _ip.IPv6Address)):
        target = address
    else:
        raise TypeError(
            f"longest_prefix_match: address must be str, IPv4Address, "
            f"or IPv6Address; got {type(address).__name__}"
        )
    best_prefix, best_value = -1, None
    for entry in table:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise TypeError(
                f"longest_prefix_match: table entries must be (Network, value) "
                f"tuples; got {entry!r}"
            )
        net, value = entry
        if isinstance(net, str):
            net = parse_cidr(net)
        if not isinstance(net, (_ip.IPv4Network, _ip.IPv6Network)):
            raise TypeError(
                f"longest_prefix_match: table network must be str, "
                f"IPv4Network, or IPv6Network; got {type(net).__name__}"
            )
        if net.version != target.version:
            continue
        if target in net and net.prefixlen > best_prefix:
            best_prefix, best_value = net.prefixlen, value
    return best_value
```

## Reproduction count

- 90/701 hierarchy crashes hit `longest_prefix_match` (12.8%); all 90 share
  root frame `_hierarchy.py:74` and the `AttributeError: '<type>' object
  has no attribute 'version'` pattern on the `address` arg.
- Unique hostile types observed: NoneType, int, bool, bytes, list, dict,
  tuple, object, float.
- VULN_AUDIT M-002 canonical repro was `longest_prefix_match(None, [(parse_cidr('10.0.0.0/8'), 'v4')])`
  — confirmed by `fuzz/crashes/hierarchy_*.stack.txt` in this run.