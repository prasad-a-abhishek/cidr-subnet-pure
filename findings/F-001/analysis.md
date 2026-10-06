# F-001 — `smallest_supernet()` leaks AttributeError on hostile element type (MEDIUM)

**Class:** M-001/M-002 (VULN_AUDIT.md) — Invariant 21 violation, type validation gap.
**Surface:** hierarchy / `src/cidr_subnet_pure/_hierarchy.py:22-25`
**Severity:** MEDIUM (per VULN_AUDIT M-001/M-002 rubric; not Critical/High because pure-Python parser library — no I/O, no eval/exec, no remote trigger; type leakage is a correctness/UX defect, not a security boundary).

## Minimized repro

```python
from cidr_subnet_pure import smallest_supernet
smallest_supernet([None])
# AttributeError: 'NoneType' object has no attribute 'version'
```

## Stack trace

```
File ".../_hierarchy.py", line 25, in smallest_supernet
    versions = {n.version for n in nets}
File ".../_hierarchy.py", line 25, in <setcomp>
    versions = {n.version for n in nets}
                 ^^^^^^^^^
AttributeError: 'NoneType' object has no attribute 'version'
```

## Root cause

`smallest_supernet` accepts any iterable and only normalizes `str` to a CIDR via
`parse_cidr` at line 22. Non-`str` entries (None, int, float, bool, bytes,
list, dict, tuple, object) pass through unchanged and reach
`{n.version for n in nets}` at line 25 with no type check. The setcomp calls
`AttributeError`-raising `.version` on the hostile object.

## Why MEDIUM, not HIGH

- No security boundary crossed: pure-Python function, no I/O, no eval/exec, no
  network access, no resource exhaustion.
- Attacker must already have code execution to call `smallest_supernet([None])`
  with a literal hostile element. The exception is no worse than `int / 0` for
  caller hygiene.
- Spec Invariant 21 mandates "no uncaught exceptions on hostile input" — the
  library should raise a documented error type (CIDRError/TypeError with a
  helpful message) rather than leaking stdlib `AttributeError`. This is
  contract/documentation enforcement, not a CVE.
- Pre-existing VULN_AUDIT (cycle_183 T1) classified the same root cause as
  MEDIUM via the CWE-754 (improper error handling) / CWE-20 (input validation)
  mapping.

## Recommended fix (for cycle_183 fix card)

At `_hierarchy.py:22-25`, after parsing strings, validate each entry is a
`ipaddress.IPv4Network | IPv6Network`; if not, raise `TypeError` (or
`CIDRError`) with a clear message:

```python
nets = [parse_cidr(n) if isinstance(n, str) else n for n in networks]
for i, n in enumerate(nets):
    if not isinstance(n, (_ip.IPv4Network, _ip.IPv6Network)):
        raise TypeError(
            f"smallest_supernet: entry {i} must be str, IPv4Network, "
            f"or IPv6Network; got {type(n).__name__}"
        )
```

## Reproduction count

- 344/701 hierarchy crashes hit `smallest_supernet` (49.1%); all 344 share
  this root frame (`_hierarchy.py:25`) and `AttributeError: '<type>' object
  has no attribute 'version'` on a hostile element.
- Unique hostile types observed: NoneType (348 total across all 3 ops),
  int, bool, bytes, float, list, dict, tuple, object.
- Seed: 42. Deterministic — same seed reproduces the same 344-iter subset.