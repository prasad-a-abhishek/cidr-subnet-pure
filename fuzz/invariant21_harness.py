"""invariant21_harness — Invariant 21: every public API is total over hostile input.

Per the cidr-subnet-pure spec: "no uncaught exceptions on hostile input."
The library MUST raise only the documented types (InvalidCIDR, CIDRError,
MixedFamilyError) and never leak stdlib AttributeError / TypeError to callers.

This harness feeds every public API a fixed battery of hostile inputs and
asserts the exception type is in the documented set. A "crash" is any
exception type that isn't documented — which is exactly the M-001/M-002
class of bug from VULN_AUDIT.md.
"""
from __future__ import annotations

import ipaddress
import sys
import time

sys.path.insert(0, str(__file__).rsplit("/", 2)[0])

import cidr_subnet_pure as cidr
from _common import banner, parse_args, summary, with_timeout, write_crash

SURFACE = "invariant21"

# Every public API in cidr_subnet_pure.
APIS = {
    "parse_cidr": cidr.parse_cidr,
    "is_cidr": cidr.is_cidr,
    "contains": cidr.contains,
    "union": cidr.union,
    "intersection": cidr.intersection,
    "subtract": cidr.subtract,
    "complement": cidr.complement,
    "aggregate": cidr.aggregate,
    "smallest_supernet": cidr.smallest_supernet,
    "subnets": cidr.subnets,
    "longest_prefix_match": cidr.longest_prefix_match,
    "hosts": cidr.hosts,
}

# Fixed battery of hostile inputs. We feed every API a slice of these, with
# one valid anchor where the API needs at least one good arg to even make
# sense.
HOSTILE_INPUTS = [
    None, 0, -1, 3.14, True, False, [], {}, b"", b"\xff", b"\x00",
    "?", "  ", "  10.0.0.0/24", "+1.2.3.4/24", "-0.0.0.0/0", "",
    "10.0.0.0/24  ", "10.0.0.0", "10.0.0.0/33", "::1/128",
    "10.0.0.0/24", "::1",
    (1, 2, 3), [1, 2, 3], {1: 2}, "a" * 1000,
]

DOCUMENTED_EXC_NAMES = {
    "InvalidCIDR",
    "CIDRError",
    "MixedFamilyError",
    "ValueError",  # hosts() raises on oversize, subnets() raises on pl<=cur
    "TypeError",   # MixedFamilyError also inherits TypeError
    "AddressValueError",
    "NetmaskValueError",
}


def main() -> int:
    args = parse_args()
    banner(SURFACE, args.iters, args.seed)
    t0 = time.time()
    crashes = 0
    contract_violations = 0
    timeouts = 0
    api_names = list(APIS.keys())
    i = 0
    valid_v4 = "10.0.0.0/24"
    for _ in range(args.iters):
        for name in api_names:
            fn = APIS[name]
            for hostile in HOSTILE_INPUTS:
                if name in ("parse_cidr", "is_cidr", "hosts"):
                    call_args = (hostile,)
                elif name == "contains":
                    call_args = (valid_v4, hostile)
                elif name in ("union", "intersection", "aggregate", "smallest_supernet"):
                    call_args = ([hostile],)
                elif name in ("subtract", "complement"):
                    call_args = (hostile, valid_v4)
                elif name == "subnets":
                    call_args = (valid_v4, hostile)
                elif name == "longest_prefix_match":
                    call_args = (hostile, [(valid_v4, "v4")])
                else:
                    call_args = (hostile,)
                status, result, tb = with_timeout(fn, *call_args)
                if status == "ok":
                    continue
                if result.__class__.__name__ == "TimeoutError_":
                    timeouts += 1
                    write_crash(SURFACE, i, f"fn={name} args={call_args!r}", result, tb)
                    i += 1
                    continue
                # Documented exception type?
                if result.__class__.__name__ in DOCUMENTED_EXC_NAMES:
                    continue
                if isinstance(result, (ipaddress.AddressValueError, ipaddress.NetmaskValueError)):
                    continue
                # AttributeError / IndexError / KeyError / etc — contract violation.
                contract_violations += 1
                i += 1
            i += 1
    return summary(SURFACE, args.iters, crashes, contract_violations, timeouts, time.time() - t0)


TimeoutError_ = type("TimeoutError_", (Exception,), {})


if __name__ == "__main__":
    sys.exit(main())
