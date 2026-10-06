# cidr-subnet-pure fuzzing harnesses (cycle_183 adversary T2)

Four pure-stdlib fuzzing harnesses covering the public API surface. No
external dependencies (no atheris, no hypothesis, no coverage tools) — just
`random` + `itertools` + `signal.alarm` for hang protection.

## Surfaces

| Harness | File | Targets |
|---|---|---|
| `parse_core` | `fuzz/parse_core_harness.py` | `parse_cidr()` with random strings: leading zeros, sign, whitespace, zone-IDs, overflow, host-bits-set, mixed v4/v6, weird prefixlen (33 for v4, 129 for v6) |
| `algebra_set` | `fuzz/algebra_set_harness.py` | `union/intersection/subtract/complement/aggregate` with random Network iterables: empty, single, duplicate, heterogeneous (v4+v6 must raise `MixedFamilyError`), /0, nested |
| `hierarchy` | `fuzz/hierarchy_harness.py` | `smallest_supernet/subnets/longest_prefix_match` with random inputs: empty iterable, no-supernet, `subnets(new_prefixlen <= current)`, LPM with no match, LPM with multiple matches, and a hostile-type battery that confirms the M-001/M-002 contract violations in `VULN_AUDIT.md` |
| `invariant21` | `fuzz/invariant21_harness.py` | Every public API hit with a fixed battery of hostile inputs (`None, -1, 3.14, True, False, [], {}, b"", "?", "  192.168.0.0/24", "+1.2.3.4/24", "-0.0.0.0/0", b"\xff", "\x00"`, etc.) — must never raise an undocumented exception type per spec Invariant 21 |

## Usage

```bash
PYTHONPATH=src python3 fuzz/parse_core_harness.py --iters 5000 --seed 42
PYTHONPATH=src python3 fuzz/algebra_set_harness.py --iters 5000 --seed 42
PYTHONPATH=src python3 fuzz/hierarchy_harness.py --iters 5000 --seed 42
PYTHONPATH=src python3 fuzz/invariant21_harness.py --iters 5 --seed 42
```

Default iterations:
- `parse_core`/`algebra_set`/`hierarchy`: 5000 iters (per-surface smoke completes in <1s on a single core)
- `invariant21`: `--iters` is the per-API multiplier; with the default 28-hostile-input battery and 12 public APIs, `--iters 5` runs ~1680 calls in <1s

## Crash vs. contract violation

- A **crash** is an exception whose type is NOT in the documented set
  (`InvalidCIDR`, `CIDRError`, `MixedFamilyError`, stdlib `ValueError`/`TypeError`,
  `ipaddress.AddressValueError`/`NetmaskValueError`). Crashes are written to
  `fuzz/crashes/SURFACE_<iter>.in` + `SURFACE_<iter>.stack.txt`.
- A **contract violation** is the M-001/M-002 class of bug from `VULN_AUDIT.md`:
  hostile inputs that leak stdlib `AttributeError`/`IndexError`/etc. instead
  of the documented `InvalidCIDR`/`CIDRError`. The harness counts these but
  does NOT crash; they map to the medium-severity findings already enumerated
  in `benchmarks/adversarial/cycle_183/VULN_AUDIT.md`.

## Output

Each harness prints one summary line:

```
[fuzz] surface=<name> iters=<N> crashes=<C> contract_violations=<V> timeouts=<T> elapsed=<S>s
```

Exit code is 0 iff `crashes == 0 and timeouts == 0`. A non-zero exit means
at least one previously-unseen crash was found and a follow-up
`FUZZING_REPORT` (T3) should triage it.

## Determinism

All randomness is seeded via `random.Random(args.seed)`. Default seed = 42
(matches the value used in `benchmarks/adversarial/cycle_183/VULN_AUDIT.md`
and `cycle_182/adversary/05`). `--seed <N>` produces a deterministic run.

## Hang protection

Each call is wrapped in `signal.alarm(5)`. On Unix, a 5-second timeout
raises an internal `TimeoutError_` which is recorded as a crash with a
`*.timeout` suffix. The harness never hangs the caller.

## Where the run logs go

`logs/run_<surface>.log` — captured from a real 5000-iter (or 5-iter for
`invariant21`) run. These are committed so the `FUZZING_REPORT` card (T3)
can cite them as the artifact-of-record.
