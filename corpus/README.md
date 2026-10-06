# corpus/ — fuzzing seed corpus (cycle_183)

The fuzzing harnesses in `fuzz/` are seeded deterministically with seed=42,
but they don't persist a corpus of generated inputs. The four files here are
a 4 KiB deterministic RNG byte stream per surface (from `random.Random(42)`)
that T3 (FUZZ_EXECUTE) recorded so future fuzzer runs have a reproducible
starting point — the same RNG bytes will produce the same first N inputs
under each harness's specific draw sequence.

These are NOT the actual crash-producing inputs. The crash payloads live in
`fuzz/crashes/` (symlinked as `crashes/`) and are committed from T2 (cycle_183
adversary card 02).

| File | Surface | Size |
|---|---|---|
| parse_core_seed_42.bin | parse_core | 4096 B |
| algebra_set_seed_42.bin | algebra_set | 4096 B |
| hierarchy_seed_42.bin | hierarchy | 4096 B |
| invariant21_seed_42.bin | invariant21 | 4096 B |