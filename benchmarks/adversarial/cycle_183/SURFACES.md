# SURFACES — cidr-subnet-pure (cycle_183)

5 attack surfaces enumerated across 7 source files. No CLI surface (library only).

| # | Surface | Entry point (module::function) | Inputs | Outputs | Trust boundary |
|---|---|---|---|---|---|
| 1 | `parse_core` | `_parser.py::parse_cidr`, `_parser.py::is_cidr` | `str` (CIDR) | `IPv4Network`/`IPv6Network`, `bool` | External — untrusted string from user/network config |
| 2 | `algebra_set` | `_algebra.py::union`, `_algebra.py::intersection`, `_algebra.py::subtract`, `_algebra.py::complement`, `_algebra.py::aggregate` | `Iterable[Network\|str]`, `Network\|str` | `List[Network]` | External — collections of CIDR strings (AWS/GCP routing tables) |
| 3 | `hierarchy` | `_hierarchy.py::smallest_supernet`, `_hierarchy.py::subnets`, `_hierarchy.py::longest_prefix_match` | `Iterable[Network\|str]`, `Network\|str`, `int`, `str` IP, `Iterable[(Network, T)]` | `Network\|None`, `List[Network]`, `T\|None` | External — IP addresses from DNS/HTTP, prefix tables from config |
| 4 | `membership_iter` | `_membership.py::contains`, `_iter.py::hosts` | `Network\|str`, `str` IP, `int` limit | `bool`, `Iterator[str]` | External — IPs from headers/JSON |
| 5 | `invariant21` | ALL public functions (cross-cutting) | None, int, float, bool, list, dict, bytes, malformed strings | Must NEVER raise uncaught | External — untrusted typed input from JSON/YAML/env |

**Excluded:** no I/O surface (no file/network/shell), no template rendering, no logging. Library is pure CPU + set arithmetic.
