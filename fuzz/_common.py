"""Common harness infrastructure: deterministic random, crash capture, timeout."""
from __future__ import annotations

import argparse
import os
import random
import signal
import sys
import time
import traceback
from pathlib import Path

CRASHES = Path(__file__).parent / "crashes"
CRASHES.mkdir(parents=True, exist_ok=True)

# Exceptions the library is allowed to raise on hostile input. Anything else
# is a true crash. InvalidCIDR/CIDRError/MixedFamilyError are the documented
# error types; ValueError/TypeError/AttributeError on hostile types are
# contract violations per spec Invariant 21 but NOT a fuzzer crash — the
# harness records them as "contract_violation" and continues.
ALLOWED_EXCEPTIONS = (
    "cidr_subnet_pure.InvalidCIDR",
    "cidr_subnet_pure.CIDRError",
    "cidr_subnet_pure.MixedFamilyError",
)

# Inherits from ValueError/TypeError, so catching the bases would also cover
# legitimate total-function defenses. Track them separately:
DOCUMENTED_BASES = (ValueError, TypeError)


class TimeoutError_(Exception):
    pass


def _alarm_handler(signum, frame):
    raise TimeoutError_("call exceeded TIMEOUT_SECS")


def with_timeout(fn, *args, **kwargs):
    """Run fn(*args, **kwargs) under signal.alarm(5). Returns (ok, result_or_exc, traceback_str).

    On Unix. On Windows the alarm is installed but never fires — the fuzzer
    still works (we just don't get the hang protection).
    """
    installed = False
    if hasattr(signal, "SIGALRM"):
        try:
            signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(5)
            installed = True
        except (ValueError, OSError):
            # Not in main thread, or unsupported; skip alarm.
            installed = False
    try:
        result = fn(*args, **kwargs)
        return ("ok", result, "")
    except Exception as exc:
        return ("exception", exc, traceback.format_exc())
    finally:
        if installed:
            signal.alarm(0)


def write_crash(surface: str, idx: int, inputs_repr: str, exc: BaseException, tb: str) -> None:
    """Write a fuzz crash artifact (input + stack)."""
    safe = surface.replace("/", "_")
    in_path = CRASHES / f"{safe}_{idx}.in"
    txt_path = CRASHES / f"{safe}_{idx}.stack.txt"
    in_path.write_text(inputs_repr)
    txt_path.write_text(
        f"surface: {surface}\niter: {idx}\nexc: {type(exc).__name__}: {exc}\n"
        f"--- traceback ---\n{tb}\n"
    )


def parse_args(default_iters: int = 5000) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--iters", type=int, default=default_iters)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--surface", type=str, default=None,
                   help="Optional human-readable surface name for crash artifacts")
    return p.parse_args()


def banner(surface: str, iters: int, seed: int) -> None:
    sys.stderr.write(
        f"[fuzz] surface={surface} iters={iters} seed={seed} pid={os.getpid()}\n"
    )
    sys.stderr.flush()


def summary(surface: str, iters: int, crashes: int, contract_violations: int, timeouts: int, elapsed: float) -> int:
    line = (
        f"[fuzz] surface={surface} iters={iters} crashes={crashes} "
        f"contract_violations={contract_violations} timeouts={timeouts} "
        f"elapsed={elapsed:.2f}s"
    )
    print(line)
    return 0 if crashes == 0 and timeouts == 0 else 1


def rnd(rng: random.Random):
    """Shorthand for rng.random()."""
    return rng.random()
