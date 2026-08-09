# Independent conformance validator (Python)

A **from-scratch** validation-only implementation of the Bellbook v0.2 wire
format, written in Python with no shared code path to the Rust crate. It exists
to make the specification's central interoperability claim *checkable* rather
than merely asserted: that an independent implementation in any language
computes the same canonical forms, record ids, and hashes, and reaches the same
structural decisions.

This is issue #5's first increment. Python bindings that wrap the Rust core would
not count as an independent implementation; this shares nothing with it but the
published data files.

## What it reproduces

Run against `spec/test-vectors-v0.2.json` and the entire `spec/conformance/v0.2/`
corpus, all independently:

- **RFC 8785 (JCS) canonicalization** - rebuilds each record's canonical form
  byte-for-byte from the published vectors.
- **Record ids** - SHA-256 of the canonical id form (which omits `id` and a null
  `author.signature`, matching the reference). Recomputed for all 112
  record-case records - and, via the structural check, every receipt-case record
  - and confirmed equal to the stored ids.
- **Head hash and rules hash** - confirmed equal to the corpus's expected values.
- **Ed25519 signatures** - the domain-wrapped signing form is recomputed
  independently and confirmed equal to the published one, the signed vector's
  signature is verified over it, and the key-substitution case is confirmed to
  change the id and fail verification. (The signature check uses the
  `cryptography` package; in CI it is required, and elsewhere it degrades to a
  clear skip. Everything else is pure standard library.)
- **Strict wire decoding** - unknown fields, wrong spec version, non-JSON,
  truncated input, and validation-limit overruns are all rejected, agreeing with
  the reference on every malformed case.
- **Structural log integrity** - recomputed id chain, genesis time, gap-free
  time, and subject/verdict pairing; reproduces the structural `Invalid` cases
  (tampered id, dropped verdict).

## What it does NOT do yet

It does not re-derive verdicts - the full per-record rule battery, retraction,
and taint propagation. Corpus cases that hinge on that (verdict forgery, the
`Tainted` taint sets, the record-case verdict reasons) are reported as
**deferred**, never silently skipped. Reproducing them is the next increment of
#5, and the conformance corpus (issue #7) is the oracle it will be built against.

## Running it

```
python3 conformance/python/run_conformance.py
```

Exit code 0 means every independent check agreed with the reference; non-zero
prints the first disagreement. CI runs this on every push and pull request.

## Files

- `bellbook_conformance.py` - the validator: JCS canonicalization, ids, hashes,
  strict decoding, structural checks.
- `run_conformance.py` - the runner: drives the validator against the vectors and
  the corpus and asserts agreement.
