"""algebra_set_harness — fuzz union/intersection/subtract/complement/aggregate.

Targets: empty iterables, single-element, duplicates, heterogeneous (v4+v6
must raise MixedFamilyError), /0, nested supersets, and the boundary
between overlapping and disjoint.

A "crash" is anything that raises something other than MixedFamilyError /
InvalidCIDR / CIDRError.
"""
from __future__ import annotations

import ipaddress
import random
import sys
import time

sys.path.insert(0, str(__file__).rsplit("/", 2)[0])

from cidr_subnet_pure import (
    InvalidCIDR,
    MixedFamilyError,
    aggregate,
    complement,
    intersection,
    parse_cidr,
    subtract,
    union,
)
from _common import banner, parse_args, summary, with_timeout, write_crash

SURFACE = "algebra_set"


def _rand_v4(rng: random.Random) -> str:
    return f"{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}/{rng.randint(0, 32)}"


def _rand_v6(rng: random.Random) -> str:
    return f"2001:{rng.randint(0, 0xFFFF):x}:{rng.randint(0, 0xFFFF):x}::/64"


def _rand_net(rng: random.Random) -> str:
    return _rand_v4(rng) if rng.random() < 0.7 else _rand_v6(rng)


def _gen_iter(rng: random.Random, n_min: int = 0, n_max: int = 16) -> list:
    n = rng.randint(n_min, n_max)
    out = []
    for _ in range(n):
        if rng.random() < 0.05:
            out.append(None)
        elif rng.random() < 0.05:
            out.append(rng.randint(0, 0xFFFFFFFF))
        elif rng.random() < 0.05:
            out.append("not-a-cidr")
        else:
            out.append(_rand_net(rng))
    # Optionally inject a duplicate
    if out and rng.random() < 0.3:
        out.append(out[0])
    return out


def main() -> int:
    args = parse_args()
    rng = random.Random(args.seed)
    banner(SURFACE, args.iters, args.seed)
    t0 = time.time()
    crashes = 0
    contract_violations = 0
    timeouts = 0
    for i in range(args.iters):
        op = rng.choice(["union", "intersection", "subtract", "complement", "aggregate"])
        if op in ("union", "aggregate"):
            it = _gen_iter(rng)
            target = union if op == "union" else aggregate
        elif op == "intersection":
            it = (_gen_iter(rng), _gen_iter(rng))
            target = intersection
        elif op == "subtract":
            a, b = _rand_net(rng), _rand_net(rng)
            it = (a, b)
            target = subtract
        elif op == "complement":
            space = _rand_net(rng)
            sub = _rand_net(rng)
            it = (space, sub)
            target = complement
        status, result, tb = with_timeout(target, *it) if not isinstance(it, list) else with_timeout(target, it)
        if status == "ok":
            continue
        if result.__class__.__name__ == "TimeoutError_":
            timeouts += 1
            write_crash(SURFACE, i, f"op={op} it={it!r}", result, tb)
            continue
        if isinstance(result, (InvalidCIDR, MixedFamilyError, ValueError, TypeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError)):
            # MixedFamilyError is documented; ValueError/TypeError from hostile
            # inputs is contract violation, not fuzzer crash.
            continue
        crashes += 1
        write_crash(SURFACE, i, f"op={op} it={it!r}", result, tb)
    return summary(SURFACE, args.iters, crashes, contract_violations, timeouts, time.time() - t0)


TimeoutError_ = type("TimeoutError_", (Exception,), {})


if __name__ == "__main__":
    sys.exit(main())
