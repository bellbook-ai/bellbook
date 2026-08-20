# Fuzzing Bellbook

Coverage-guided fuzz targets (libFuzzer, via [`cargo-fuzz`]) over the receipt
**trust boundary** - the surface that takes untrusted bytes: `validate`,
`Receipt::from_bytes`, and `canonical_json` (issue #65).

This is the deep layer. A fast, deterministic, always-on layer runs in the
ordinary test suite on every push (`tests/fuzz_trust_boundary.rs`); it hammers
the same entry points with a seeded generator and asserts the same invariants.
Use these libFuzzer targets for long, coverage-guided campaigns that reach
states a fixed seed corpus does not.

## Targets

- **`validate`** - arbitrary bytes through `validate`; must never panic and must
  return a self-consistent report.
- **`receipt_parse`** - a receipt that parses must survive a canonical
  round-trip (serialize, re-parse) unchanged.
- **`canonical_json`** - RFC 8785 canonicalization must be total and idempotent
  over any parseable JSON value.

## Running

Requires a nightly toolchain (libFuzzer needs `-Z` flags):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run validate            # runs until a crash or Ctrl-C
cargo +nightly fuzz run validate -- -max_total_time=120   # time-bounded
cargo +nightly fuzz run receipt_parse
cargo +nightly fuzz run canonical_json
```

A crash writes a reproducer under `fuzz/artifacts/<target>/`; replay it with:

```sh
cargo +nightly fuzz run validate fuzz/artifacts/validate/crash-<hash>
```

CI runs these on a weekly schedule and on manual dispatch (`.github/workflows/fuzz.yml`),
never as a pull-request gate - fuzzing is long-running and non-deterministic.
A finding here is a security issue; see `../SECURITY.md`.

[`cargo-fuzz`]: https://github.com/rust-fuzz/cargo-fuzz
