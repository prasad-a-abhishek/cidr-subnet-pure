"""parse_core_harness — fuzz parse_cidr() with random strings.

Targets: leading zeros, sign, whitespace, zone-IDs, overflow, host-bits-set,
mixed v4/v6, weird prefixlen (33 for v4, 129 for v6), and totally random
byte sequences.

A "crash" is anything that raises something other than InvalidCIDR (a true
fuzzer bug). Stdlib ValueError/TypeError from ipaddress should be caught
inside parse_cidr and re-raised as InvalidCIDR.
"""
from __future__ import annotations

import random
import string
import sys
import time

# Allow running as: python3 fuzz/parse_core_harness.py
sys.path.insert(0, str(__file__).rsplit("/", 2)[0])

from cidr_subnet_pure import InvalidCIDR, parse_cidr
from _common import banner, parse_args, summary, with_timeout, write_crash


SURFACE = "parse_core"


def _gen_random_v4_prefix(rng: random.Random) -> str:
    """Generate a random dotted-quad octet string (valid or invalid)."""
    a = rng.randint(-1, 300)  # include negative, overflow
    b = rng.randint(-1, 300)
    c = rng.randint(-1, 300)
    d = rng.randint(-1, 300)
    return f"{a}.{b}.{c}.{d}"


def _gen_random_v6_prefix(rng: random.Random) -> str:
    """Generate a random colon-separated hex group string (valid or invalid)."""
    n = rng.randint(1, 9)
    parts = []
    for _ in range(n):
        if rng.random() < 0.2:
            parts.append("".join(rng.choices("0123456789abcdef", k=rng.randint(1, 8))))
        else:
            parts.append(format(rng.randint(0, 0xFFFF), "x"))
    sep = rng.choice(["::", ":", ":", ":", ":"])
    return sep.join(parts)


def _gen_random_prefixlen(rng: random.Random, v: int) -> str:
    """Generate a random prefix length string (valid, overflow, sign, junk)."""
    r = rng.random()
    if r < 0.1:
        return ""  # missing prefix
    if r < 0.2:
        return "/"  # slash but no number
    if r < 0.3:
        return "/" + str(rng.randint(0, 200))  # overflow
    if r < 0.35:
        return "/-" + str(rng.randint(1, 50))  # negative
    if r < 0.4:
        return "/+" + str(rng.randint(0, 200))  # plus sign
    if r < 0.45:
        return "/" + "".join(rng.choices(string.digits + string.ascii_letters, k=rng.randint(1, 6)))
    return "/" + str(rng.randint(0, 200))


def _gen_random_value(rng: random.Random) -> str:
    """Generate one random parse_cidr() input string."""
    r = rng.random()
    if r < 0.25:
        prefix = _gen_random_v4_prefix(rng)
        plen = _gen_random_prefixlen(rng, 4)
    elif r < 0.45:
        prefix = _gen_random_v6_prefix(rng)
        plen = _gen_random_prefixlen(rng, 6)
    elif r < 0.55:
        # random bytes decoded as latin-1
        n = rng.randint(0, 200)
        return bytes(rng.choices(range(256), k=n)).decode("latin-1", errors="replace")
    elif r < 0.65:
        # leading whitespace
        prefix = _gen_random_v4_prefix(rng) + _gen_random_prefixlen(rng, 4)
        return " " * rng.randint(0, 20) + prefix + " " * rng.randint(0, 20)
    elif r < 0.72:
        # zone ID (must raise per Invariant)
        prefix = _gen_random_v6_prefix(rng)
        zid = "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(1, 8)))
        return f"{prefix}%{zid}" + _gen_random_prefixlen(rng, 6)
    elif r < 0.78:
        # host bits set
        prefix = _gen_random_v4_prefix(rng)
        return f"{prefix}/24"
    elif r < 0.82:
        # plus/minus sign prefix
        sign = rng.choice(["+", "-"])
        prefix = _gen_random_v4_prefix(rng)
        return sign + prefix + _gen_random_prefixlen(rng, 4)
    elif r < 0.86:
        # garbage
        return "".join(rng.choices(string.printable, k=rng.randint(1, 200)))
    else:
        # leading zeros
        prefix = ".".join(f"{rng.randint(0, 255):03d}" for _ in range(4))
        return prefix + _gen_random_prefixlen(rng, 4)


def main() -> int:
    args = parse_args()
    rng = random.Random(args.seed)
    banner(SURFACE, args.iters, args.seed)
    t0 = time.time()
    crashes = 0
    contract_violations = 0
    timeouts = 0
    for i in range(args.iters):
        value = _gen_random_value(rng)
        status, result, tb = with_timeout(parse_cidr, value)
        if status == "ok":
            continue
        if isinstance(result, InvalidCIDR):
            continue
        if isinstance(result, TimeoutError_ if False else type(None)):
            pass
        if result.__class__.__name__ == "TimeoutError_":
            timeouts += 1
            write_crash(SURFACE, i, repr(value), result, tb)
            continue
        # Stdlib ValueError/TypeError leaking from ipaddress is a contract
        # violation per Invariant 21, not a fuzzer crash. Track separately.
        if isinstance(result, (ValueError, TypeError)):
            contract_violations += 1
            continue
        # True crash — something unexpected.
        crashes += 1
        write_crash(SURFACE, i, repr(value), result, tb)
    return summary(SURFACE, args.iters, crashes, contract_violations, timeouts, time.time() - t0)


# Import alias for the timeout class — keeping it inside the function would
# slow the hot loop. Re-exported here:
TimeoutError_ = type("TimeoutError_", (Exception,), {})


if __name__ == "__main__":
    sys.exit(main())
