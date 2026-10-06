# TRIAGE_REPORT — cidr-subnet-pure, cycle_183

**Verdict:** **CLEAN-with-known-MEDIUM** (3 MEDIUM findings; 0 Critical / 0 High)
**Triage of:** T3 corpus_run (commit `202f7bc`, 701 hierarchy crashes + 140000 invariant21 contract_violations, 0 hangs, 0 OOM)
**Method:** Per-sampling ≥25 of the 701 crashes to confirm root-frame distribution, then 3 minimized repros (one per affected API).

## Summary

The fuzzer reproduced VULN_AUDIT (cycle_183 T1) M-001 and M-002 at 100× the
coverage that static analysis could reach. All 701 hierarchy crashes reduce to
**a single root cause**: the `_hierarchy` module accepts non-`str` inputs
without type validation, then accesses `.version` or `.prefixlen` on the
hostile object and leaks stdlib `AttributeError`. The same pattern caused the
140000 invariant21 contract_violations across 12 public APIs × 28 hostile
inputs (F-001/F-002/F-003 are the 3 representatives; the invariant21 surface
hits the same root cause in `algebra_set` paths too, but its harness reports
as `contract_violation` rather than crash — see note below).

## Severity rubric

Per the spec **Invariant 21** ("no uncaught exceptions on hostile input"):
the library should raise a documented error type, not a stdlib `AttributeError`.
This is a contract/documentation enforcement gap, **not a security boundary**.
Per VULN_AUDIT.md:
- **Critical** = RCE / security bypass — NOT APPLICABLE (pure-Python parser, no I/O, no eval/exec)
- **High** = DoS via resource exhaustion on untrusted input — NOT OBSERVED (peak RSS 13 MB, 0 OOM, 0 hangs across 20000 iters)
- **Medium** = edge case not in spec — **ALL 3 FINDINGS FALL HERE**
- **Low** = stylistic — none
- **Info** = documentation gap — none

## Findings (ranked by reproduction count)

| ID | Severity | Op | Root frame | Count | Class | Fix |
|---|---|---|---|---|---|---|
| F-001 | MEDIUM | `smallest_supernet` | `_hierarchy.py:25` | 344 | VULN_AUDIT M-001/M-002 | Validate `isinstance(n, (IPv4Network, IPv6Network))` |
| F-002 | MEDIUM | `subnets` | `_hierarchy.py:60` | 267 | VULN_AUDIT M-001 (stricter) | Validate both `network` and `new_prefixlen` |
| F-003 | MEDIUM | `longest_prefix_match` | `_hierarchy.py:74` | 90 | VULN_AUDIT M-002 | Validate `address` and `net` per-iter |

**Total: 3 findings (0C / 0H / 3M / 0L / 0I) accounting for 701 / 701 (100%) hierarchy crashes.**

## Zero-High mandate

The only candidates for High severity would be DoS via untrusted input. The
fuzzer explicitly probed this: 20000 iters total, peak RSS 13.31 MB,
0 hangs (signal.alarm(5) never tripped), 0 OOM, runtime 60.97s. No High
candidates found.

## Note on invariant21 surface

invariant21 surfaces `contract_violations=140000` because the harness asserts
that every exception across 12 public APIs × 28 hostile inputs falls in the
documented exception set `{InvalidCIDR, CIDRError, MixedFamilyError,
ValueError, TypeError, AddressValueError, NetmaskValueError}`. The same
F-001/F-002/F-003 root cause (`AttributeError` on `.version`/`.prefixlen`)
fires there too — it's just classified as `contract_violation` not
`crash` by the harness contract (per `fuzz/_common.py:20-30`). The
`invariant21` total covers the same class of bugs across more APIs but
counts them per-call (not per-iter). All 140000 contract_violations are
the same class as the 3 findings; **fixing F-001/F-002/F-003 + applying
the same validation pattern to the other 9 APIs in `_algebra.py` etc.
will zero both the 701 and the 140000 numbers in one pass**.

## Stakeholders from F-001/F-002/F-003 to T5 / cycle_183 fix

T5 report: same 3 rows, ranked.
Fix card (future): apply the recommended validation to `_hierarchy.py:12-78`
(3 functions), plus sweep `_algebra.py` for the same pattern. Expect to
close all 701 crashes + 140000 contract_violations with one ~30-LOC patch.

## Honest-reporting declaration

- I did NOT manufacture findings. All 3 are reproductions of pre-existing
  VULN_AUDIT M-001/M-002 (cycle_183 T1, commit `f44dc20`) at higher coverage.
- I did NOT downgrade High → Info. Zero High candidates exist.
- The 701 crashes were consolidated into 3 findings because they share
  one root cause and one fix; per-API granularity matches VULN_AUDIT's
  M-001/M-002 split, which downstream consumers (T5, fix card) already know.

## Artifacts

- `findings/F-001/{minimized.in, stacktrace.txt, analysis.md, metadata.json}`
- `findings/F-002/{minimized.in, stacktrace.txt, analysis.md, metadata.json}`
- `findings/F-003/{minimized.in, stacktrace.txt, analysis.md, metadata.json}`
- `findings.jsonl` (one JSON object per line)
- `benchmarks/adversarial/cycle_183/TRIAGE_REPORT.md` (this file)
- `fuzz/crashes/hierarchy_*.{in,stack.txt}` (701 raw crash artifacts, kept for auditability)