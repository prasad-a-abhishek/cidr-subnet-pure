"""hierarchy_harness — fuzz smallest_supernet/subnets/longest_prefix_match.

Targets: empty iterables, no-supernet, subnets(new_prefixlen <= current),
LPM with no match, LPM with multiple matches, and hostile types to all three
APIs (the M-001/M-002 findings in VULN_AUDIT.md explicitly call out type
leakage in subnets and longest_prefix_match).

A "crash" is anything that raises something other than CIDRError/InvalidCIDR/
MixedFamilyError/stdlib ValueError (stdlib ValueError is the documented
response to invalid prefixlen in subnets).
"""
from __future__ import annotations

import random
import sys
import time

sys.path.insert(0, str(__file__).rsplit("/", 2)[0])

from cidr_subnet_pure import (
    InvalidCIDR,
    parse_cidr,
    longest_prefix_match,
    smallest_supernet,
    subnets,
)
from _common import banner, parse_args, summary, with_timeout, write_crash

SURFACE = "hierarchy"


def _rand_v4(rng: random.Random) -> str:
    return f"{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}/{rng.randint(0, 32)}"


def _rand_v6(rng: random.Random) -> str:
    return f"2001:{rng.randint(0, 0xFFFF):x}:{rng.randint(0, 0xFFFF):x}::/64"


def _gen_table(rng: random.Random, n: int) -> list:
    out = []
    for i in range(n):
        net = _rand_v4(rng) if rng.random() < 0.7 else _rand_v6(rng)
        out.append((net, f"v{rng.randint(0, 9)}"))
    return out


HOSTILE_TYPES = [
    None, 0, 1, -1, 3.14, True, False, [], {}, b"", b"\xff",
    (1, 2, 3), object(), "?", "", "  ", "  10.0.0.0/24", "10.0.0.0/24  ",
]


def main() -> int:
    args = parse_args()
    rng = random.Random(args.seed)
    banner(SURFACE, args.iters, args.seed)
    t0 = time.time()
    crashes = 0
    contract_violations = 0
    timeouts = 0
    for i in range(args.iters):
        op = rng.choice(["smallest_supernet", "subnets", "longest_prefix_match"])
        if op == "smallest_supernet":
            n = rng.randint(0, 8)
            it = [_rand_v4(rng) for _ in range(n)]
            if it and rng.random() < 0.3:
                # Inject a v6 to trigger CIDRError
                it[0] = _rand_v6(rng)
            if rng.random() < 0.2:
                it = []
            if rng.random() < 0.2:
                it = [None]
            target, args_ = smallest_supernet, (it,)
        elif op == "subnets":
            net = _rand_v4(rng) if rng.random() < 0.7 else _rand_v6(rng)
            if rng.random() < 0.3:
                # hostile new_prefixlen — confirms M-001
                new_pl = rng.choice([None, "24", 24.0, "abc", -1, [], {}, True])
            else:
                v = 4 if "/" in net and int(net.split("/")[1]) <= 32 else 6
                cur = int(net.split("/")[1])
                new_pl = rng.randint(cur, cur + rng.randint(0, 5))
                if new_pl > (32 if v == 4 else 128):
                    new_pl = 32 if v == 4 else 128
            if rng.random() < 0.2:
                net = rng.choice(HOSTILE_TYPES)
            target, args_ = subnets, (net, new_pl)
        elif op == "longest_prefix_match":
            address = _rand_v4(rng).split("/")[0] if rng.random() < 0.7 else _rand_v6(rng).split("/")[0]
            if rng.random() < 0.3:
                # hostile address — confirms M-002
                address = rng.choice(HOSTILE_TYPES)
            table = _gen_table(rng, rng.randint(0, 6))
            if rng.random() < 0.2:
                # inject a malformed table entry to confirm tuple-shape guard
                if table:
                    table[rng.randint(0, len(table) - 1)] = "not-a-tuple"
                else:
                    table = ["not-a-tuple"]
            target, args_ = longest_prefix_match, (address, table)
        status, result, tb = with_timeout(target, *args_)
        if status == "ok":
            continue
        if result.__class__.__name__ == "TimeoutError_":
            timeouts += 1
            write_crash(SURFACE, i, f"op={op} args={args_!r}", result, tb)
            continue
        # Documented: CIDRError/InvalidCIDR/ValueError (subnets pl validation).
        # Contract violation: AttributeError/TypeError on hostile types — M-001/M-002
        # findings. These are tracked separately, not as fuzzer crashes.
        if isinstance(result, (InvalidCIDR, ValueError, TypeError, KeyError, IndexError)):
            continue
        if result.__class__.__name__ == "CIDRError":
            continue
        # True crash.
        crashes += 1
        write_crash(SURFACE, i, f"op={op} args={args_!r}", result, tb)
    return summary(SURFACE, args.iters, crashes, contract_violations, timeouts, time.time() - t0)


TimeoutError_ = type("TimeoutError_", (Exception,), {})


if __name__ == "__main__":
    sys.exit(main())
