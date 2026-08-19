# Independent conformance validator (Python)

A **from-scratch** validation-only implementation of the Bellbook v0.2 wire
format, written in Python with no shared code path to the Rust crate. It exists
to make the specification's central interoperability claim *checkable* rather
than merely asserted: that an independent implementation in any language
computes the same canonical forms, record ids, and hashes, and reaches the same
structural decisions.

This now covers **both increments of issue #5**. Python bindings that wrap the
Rust core would not count as an independent implementation; this shares nothing
with it but the published data files.

- `bellbook_conformance.py` - canonicalization, ids, hashes, strict decoding,
  and structural log integrity.
- `bellbook_verdict.py` - the semantic layer: the full per-record rule battery
  (`verify_record`), the retraction + transitive-taint state machine, and
  whole-log replay (`verify_log`) with its Clean / Tainted / Invalid status.

## What it reproduces

Run against `spec/test-vectors-v0.3.json` and the entire `spec/conformance/v0.3/`
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
- **Strict wire decoding** - unknown fields, missing fields, duplicate keys
  (at any nesting level), mistyped nested fields (a non-string signature
  `key_id`, a non-byte `sig`), wrong spec version, non-JSON, truncated input,
  and validation-limit overruns are all rejected, agreeing with the reference
  on every malformed case.
- **Structural log integrity** - recomputed id chain, genesis time, gap-free
  time, and subject/verdict pairing; reproduces the structural `Invalid` cases
  (tampered id, dropped verdict).
- **Verdict rule battery** - every record case's verdict (Accept, or Reject with
  its exact `ReasonCode`) is independently re-derived and matched: author-role
  binding, schema/kind checks, signatures, request/capability/approval lifecycle
  (with expiry and single-use consumption), `Require`/`Replace` semantics, the
  evidence lattice and per-kind thresholds, plan consistency, and more.
- **Whole-log replay** - every receipt case is replayed from genesis to the same
  status (Clean / Tainted / Invalid), the same first-violation reason, and the
  same `retracted` and `tainted` id sets, including verdict forgery
  (re-derivation catches the flipped result) and taint that follows `Use`/
  `Require` but not `Cause`.

## Scope and limitations

- **Signatures.** Re-deriving a verdict for a record that carries a signature
  needs the `cryptography` package (Ed25519). In CI it is required; elsewhere
  those specific cases degrade to a clear skip. Every unsigned case - which is
  all receipt cases and most record cases - is pure standard library.
- **Payload typing.** The canonical-payload rule is reproduced as a typed
  decode - every payload field, including nested plan tasks and attachments, is
  checked for its serde type and enum-variant membership, and the exact field
  set is enforced - plus a JCS round-trip confirming the bytes are the canonical
  serialization. Envelope enums (kind, author type, evidence, ref types) are
  validated structurally before any rule runs, so an unknown variant is a clean
  rejection, matching the reference's typed decode.
- **Numbers.** Canonicalization is integer-only (inherited from the JCS module),
  matching the wire format's typed payloads. The one free-form field,
  `ActionData.params` (`serde_json::Value`), is accepted as-is; a floating-point
  number inside it would be rejected here rather than canonicalized, so it is out
  of scope. No corpus case exercises it.
- **Checkpoints** are a host-side acceleration and never travel in a receipt, so
  the checkpoint replay path is out of scope here (receipts always verify from
  genesis).

## Running it

```
python3 conformance/python/run_conformance.py
```

Exit code 0 means every independent check agreed with the reference; non-zero
prints the first disagreement. CI runs this on every push and pull request.

## Files

- `bellbook_conformance.py` - the wire validator: JCS canonicalization, ids,
  hashes, strict decoding, structural checks.
- `bellbook_verdict.py` - the verdict engine: the per-record rule battery,
  retraction + taint state machine, and whole-log replay.
- `run_conformance.py` - the runner: drives both against the vectors and the
  corpus and asserts agreement.
