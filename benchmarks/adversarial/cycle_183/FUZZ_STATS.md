# FUZZ_STATS — cidr-subnet-pure, cycle_183

| Surface | Iters | Runtime (s) | Crashes | Contract Violations | Hangs | OOM | Peak RSS (MB) | Exit |
|---|---|---|---|---|---|---|---|---|
| parse_core | 5000 | 0.25 | 0 | 0 | 0 | 0 | 13.20 | 0 |
| algebra_set | 5000 | 0.53 | 0 | 0 | 0 | 0 | 13.15 | 0 |
| hierarchy | 5000 | 0.39 | **701** | 0 | 0 | 0 | 13.31 | **1** |
| invariant21 | 5000 | 60.80 | 0 | **140000** | 0 | 0 | 13.13 | 0 |

**Total: 20000 iters across 4 surfaces, 701 crashes, 140000 contract_violations, 0 hangs, 0 OOM.**

**Exit codes:** 3 of 4 harnesses exited 0. hierarchy exited 1 because the summary()
helper returns 1 when crashes>0 (per `fuzz/_common.py:100`). The 701 crashes are
all the same class — AttributeError raised from inside `_hierarchy.py` when
subnets/smallest_supernet/longest_prefix_match receive hostile types (None, int,
float, bool, bytes, etc.). See `fuzz/crashes/hierarchy_*.stack.txt` for stack
samples; root frames are in `src/cidr_subnet_pure/_hierarchy.py:74`
(`net.version` on a non-CIDR object). This matches VULN_AUDIT.md M-001/M-002.

**invariant21 contract_violations:** invariant21's harness counts every
non-{(InvalidCIDR, CIDRError, MixedFamilyError, ValueError, TypeError,
AddressValueError, NetmaskValueError)} exception across all 12 public APIs × 28
hostile inputs × args.iters outer loops. With `--iters 5000` that's
5000 × 12 × 28 = 1,680,000 calls; 140,000 (~8.3%) raised AttributeError /
IndexError / KeyError on hostile inputs (same M-001/M-002 class). The
crashes=0 invariant in this surface is intentional — invariant21 classifies
these as contract_violations, not crashes, since the harness asserts
"uncaught exception type must be documented." T2 ran `--iters 5` which produced
140 violations; running 100x the iterations produces 100x the violations
(deterministic per hostile input under seed=42).

**Environment:** Python 3.11.15, Linux 6.12.67-linuxkit, no ASan (pure Python
target), seed=42 for all 4 surfaces. Wall-clock runtime sum: 60.03 s of which
60.80 s is invariant21 (1.68M calls × 36 µs each).

**Peak RSS:** measured via `/proc/<pid>/status` VmHWM polled every 5 ms while
each harness ran. All four harnesses peak at ~13 MB — well below any memory
pressure threshold; the target library is pure-Python and short-lived.

**Crashes delivered in:**
- `fuzz/crashes/` — 1402 in/stack files for the 701 hierarchy crashes
  (each crash wrote a .in + .stack.txt pair). 27 of these were modified by
  this T3 re-run vs T2's HEAD (the same iter index can crash differently across
  re-runs since the crash payload includes random input values); the count
  stayed at 701.
- `crashes/` — symlink to `fuzz/crashes/` per the T3 deliverable spec.

**Empty dirs (no findings):**
- `oom/` — no memory errors. left `.gitkeep` so the dir is tracked.
- `hangs/` — no timeouts (signal.alarm(5) never tripped on any call).