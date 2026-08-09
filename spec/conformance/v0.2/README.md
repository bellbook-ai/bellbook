# Bellbook conformance corpus, spec version 0.2

A machine-readable set of verification cases. Each case pairs a portable input
with the expected verification outcome, so a second, independent implementation
(tracked in issue #5) can reproduce Bellbook's verification behavior byte for
byte, not just its record hashing (which the per-kind vectors in
[`../../test-vectors-v0.2.json`](../../test-vectors-v0.2.json) already fix).

The corpus is generated from, and continuously checked against, the reference
implementation by the `conformance` test
([`tests/conformance.rs`](../../../tests/conformance.rs)). Regenerate after any
intended behavior change:

```
UPDATE_CONFORMANCE=1 cargo test --test conformance
```

Running the test with no flag both re-checks the committed corpus against the
current code (drift) and re-derives every outcome from the stored inputs
(correctness) - the exact contract an independent implementation follows.

## Wire encoding

Every case is plain JSON matching the crate's `serde` wire form:

- 32-byte values (`id`, `space`, `thread`, `schema`, ref `target`, hashes) are
  JSON **arrays of bytes**, not hex.
- A record's `data` is a JSON **array of the payload's UTF-8 bytes**. The
  payload must be the exact RFC 8785 (JCS) serialization; the verifier decodes,
  re-encodes, and compares bytes.
- `author.type` is written as `type`.

## Files

### `record-cases.json`

Per-record rule checks. Each case:

```
{ name, description, rules, prior: [Record], candidate: Record, expect: { result, reason } }
```

The runner builds derived state over `prior`, calls
`verify_record(candidate, prior, rules, state)`, and asserts the returned
verdict equals `expect`. Covers author-role acceptance and rejection, the
signature matrix (missing / invalid / pinned-and-valid), schema binding,
payload canonicality, request lifecycle, capability and approval resolution
(including expiry and single-use exact approvals), authority binding, and
evidence thresholds. Collectively these cases trigger **every verdict rejection
reason the portable wire format can express** (see coverage note below).

### `receipt-cases.json`

Whole-log receipt validation. Each case:

```
{ name, description, receipt: Receipt, expect: { status, reason, record_count, head_hash, rules_hash, retracted, tainted } }
```

The runner serializes `receipt`, calls `validate(bytes)`, and asserts the
`Report`. Covers a `Clean` multi-kind log, `Tainted` logs (taint propagates
through `Use`/`Require` but **not** through `Cause`), and `Invalid` logs
(forged verdict, tampered id, dropped verdict).

### `malformed-cases.json`

Hostile raw documents. Each case:

```
{ name, description, input: String, limits: Option<Limits>, expect: { status, reason, problem_contains } }
```

The runner feeds `input` bytes to `validate` (or `validate_with_limits` when
`limits` is set) and asserts the resulting `Report`. Covers strict-decoding
failures (unknown fields), an unsupported spec version, non-JSON and truncated
input, and validation-limit rejections (`max_bytes`, `max_records`). Structural
failures surface in `Report.problem`, not `Report.reason`.

## Reason-code coverage

The corpus triggers 17 of the 20 `ReasonCode` variants as verdicts. The other
three are excluded for two different reasons:

- **`Refused`** is never emitted as a verdict at all - it is a reason a
  `Refusal` *record* may cite in its own payload. No verdict carries it, so
  there is nothing to trigger.
- **`InvalidCheckpoint`** and **`RefCrossSpace`** *are* genuine verdict reasons,
  but neither can be expressed in the portable wire format this corpus uses:
  `InvalidCheckpoint` arises only on the trusted-checkpoint replay path, and
  checkpoints are opaque and never travel inside a receipt; `RefCrossSpace`
  needs a reference into a second space, which a single-space log (what a
  receipt is) cannot carry. The crate's own integration suite exercises both.

The `conformance` test asserts that the 17 wire-expressible verdict reasons each
have at least one triggering case, so a future reason code added to the verifier
without a corpus case fails the build.
