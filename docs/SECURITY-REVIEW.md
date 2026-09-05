# Internal adversarial review of the trust boundary

**Status: review of the 0.10.x line at commit `4c08030` (main after #142),
2026-09-05.** This is gate item 1 of the 1.0 security gate in
[SECURITY.md](../SECURITY.md) (RFC-0003 decision 10, issue #114). It is
re-run and re-dated at the 1.0.0 release commit; sections 4 and 5 are the
parts that change.

An internal review is what it says: the maintainer walking the trust
boundary as an attacker, surface by surface, and writing down for each one
what is claimed, how it is enforced, what evidence exists that the
enforcement holds, what was found, and what remains. It is not an external
review, it is not a proof, and the reviewer wrote most of the code under
review. Those limits are stated in section 6 rather than implied away. The
value of the exercise is that the claims, the enforcement, and the evidence
are written in one place where a later reader can check them against the
code, and that everything found doing it was fixed before this document
was published.

## 1. Scope

The captured trust boundary, per SPEC section 13 and issue #75: the surfaces
that take bytes the verifier did not produce and must reach the same
decision every conforming implementation reaches.

1. Canonicalization (RFC 8785) and content-addressed record ids.
2. The canonical-payload rule.
3. Replay: id recomputation, logical time, subject/verdict pairing, verdict
   re-derivation.
4. The governance rules a verdict is derived from.
5. Retraction, transitive taint, standing, reaffirmation.
6. Ed25519 signatures and actor key pinning.
7. Receipt parsing, validation limits, and the `bellbook validate` boundary.
8. Profiles: declared and required.
9. The single-writer log and its recovery protocol.

Out of scope, by SPEC section 13: capture completeness (an untrusted host
decides what reaches the log), confidentiality (payloads are in the clear),
and rewriting from genesis by the log's owner (tamper-evident, not
tamper-proof; mitigated by signatures and external anchoring, SPEC section
11). Key generation, storage, and rotation are host concerns.

## 2. Method

For each surface: the **claim** the receipt makes; the **moves** an attacker
who controls the bytes can make against it; what **enforces** the claim;
the **evidence** that the enforcement holds (unit tests, integration tests,
committed conformance vectors that the independent Python implementation
must reproduce byte-for-byte, and the fuzz targets); the **findings**; and
the **residual** risk. Evidence is named so it can be re-run:

- `cargo test --all-features` runs 17 test binaries: the unit tests, the
  integration suites under `tests/integration/`, the receipt suites under
  `tests/receipt/`, the conformance corpus drift check, the frozen-epoch
  checks (0.2 and 0.3 are byte-frozen and re-validated on every push,
  including under the published 0.7.0 binary), the profile vector sets, the
  CLI story tests, and the seeded fuzz harness.
- `python3 conformance/python/run_conformance.py` re-derives every corpus
  case and every profile vector with an implementation written from the
  specification, not ported from the Rust; it shares no code with the
  reference and refuses to run with the `bellbook` package imported.
- `.github/workflows/fuzz.yml` runs three coverage-guided libFuzzer targets
  (`validate`, `receipt_parse`, `canonical_json`) weekly and on demand;
  `.github/workflows/audit.yml` runs `cargo audit` weekly.

Corpus size at this review, epoch 0.4: 98 record cases, 19 receipt cases,
14 malformed documents, 1 query case; profile vectors: 12 for
`bellbook-core-v1`, 16 for `delivery-receipt-v1`, 12 for
`bellbook-core-signed-v1`. Epoch 0.3: 66 record, 19 receipt, 9 malformed.
Epoch 0.2: 30 record, 8 receipt, 8 malformed.

Severity, used in section 4: **blocker** (a forgery the verifier accepts,
or two different records with one id); **high** (two conforming
implementations reach different decisions on the same bytes, or a valid
record is rejected); **medium** (a stated invariant fails without changing
a decision on any committed artifact); **low** (tooling or harness).

## 3. Surfaces

### 3.1 Canonicalization and record ids

**Claim.** `id = SHA-256(JCS(record without id))`. Any two implementations
compute the same bytes for the same value, so the same id; any edit to a
committed record changes its id and every reference to it.

**Moves.** Find two spellings of one value that canonicalize differently
(then the same record has two ids, or a record fails its own id check
depending on which spelling a verifier saw). Find a value one
implementation canonicalizes and another refuses. Exploit key ordering
(UTF-16 versus UTF-8), string escaping, or number formatting differences.

**Enforcement.** `src/base/canonical.rs`: members sorted by UTF-16 code
units, minimal JCS escaping, ECMAScript number formatting via `ryu-js`,
integers refused outside the I-JSON safe range, doubles refused where they
would print as such integers, non-finite refused, correctly rounded parsing
(serde_json `float_roundtrip`). The Python implementation writes the same
rules from RFC 8785 independently (`bellbook_conformance.py`, `jcs` and
`_jcs_float`).

**Evidence.** Unit tests: the RFC 8785 section 3.3 worked example, the
Appendix B number cases Bellbook admits, UTF-16 key ordering (a
supplementary-plane key sorting before U+E000), control-character
escaping, the safe-range refusals on both integers and doubles, and six
spellings of one double producing one form. Every corpus case's ids are
recomputed by the Python implementation. Fuzz: `canonical_json` (never
panics; output is a fixed point; refusal is deterministic), seeded on every
push and coverage-guided weekly.

**Findings.** F1, F2, F3, F4 (section 4). All fixed in #142.

**Residual.** The number rules are now one rule at one boundary in both
implementations, but they were wrong for a month and only the fuzzer said
so. Number handling stays the place most likely to hide a divergence; the
corpus carries one float-bearing case and should gain more if any further
free-form field is ever added. Everything else on this surface is
structural and has been byte-stable across three epochs.

### 3.2 The canonical-payload rule

**Claim.** A record's `data` is exactly the JCS serialization of its
schema's payload type; a verifier decodes and re-encodes and rejects any
byte difference with `InvalidPayload`.

**Moves.** Smuggle a duplicate key, an unknown field, non-canonical member
order, whitespace, or a non-canonical number spelling into `data` so that
two verifiers with different parsers decode different values from the same
bytes.

**Enforcement.** Typed decode (unknown fields refused, enum variants
checked) followed by re-encode and byte comparison, in both
implementations. The Python side reproduces the typed decode field by
field.

**Evidence.** Every record case in the corpus passes through this check in
both implementations; the malformed battery includes duplicate top-level
fields and extra fields; `test_receipt_wire_rejects_duplicate_rule_keys`
covers the rules object. The seeded harness mutates corpus receipts
byte-wise and asserts an Invalid report always states a reason.

**Findings.** None beyond 3.1 (F1 manifested here as a false rejection).

**Residual.** None known.

### 3.3 Replay

**Claim.** `verify_log` and `validate` walk from genesis, recompute every
id, enforce gap-free logical time, pair every subject with exactly one
verdict, and re-derive every verdict under the embedded rules; a stored
verdict is compared, never trusted.

**Moves.** Edit a record's bytes. Delete, insert, or reorder records. Forge
an Accept verdict for a record the rules reject. Drop a verdict. Point a
verdict at a subject that does not exist. Replay only a suffix.

**Enforcement.** Id recomputation on every record; time must increase by
exactly one; verdict re-derivation from state built by replay; validation
always starts at genesis (receipts never carry a checkpoint).

**Evidence.** Receipt vectors `invalid-forged-verdict`,
`invalid-tampered-id`, `invalid-missing-verdict`; tests
`test_verify_log_rejects_time_gap`, `test_verify_log_rejects_missing_verdict`,
`test_forged_verdict_dangling_subject_rejected`,
`test_forged_verdict_envelope_rejected`, `test_validate_detects_tampering`,
`test_validate_always_replays_from_genesis`,
`test_generative_state_equivalence_and_replay` (incremental state equals
rebuilt state over generated logs). Fuzz: `validate` (never panics; a Clean
report lists nothing retracted or tainted).

**Findings.** None.

**Residual.** Replay proves internal consistency. A from-genesis rewrite by
the log's owner replays green by construction (SPEC section 11); the
answer is signatures for the actors that matter plus anchoring the head
attestation where the writer cannot reach, and the receipt says which
actors were pinned.

### 3.4 Governance rules

**Claim.** An accepted record was authored by a registered actor of the
right role, under an active request, with the capability and (for Ask
mode) the approval the rules require, and names the exact authority it
used.

**Moves.** A provider authoring a user's record. An unregistered actor
authoring control records. An action outside its request's scope. Reusing
an exact approval, or using one issued to another actor. Acting under a
retracted capability or approval. A Require ref to an unaccepted record.
Closing an action twice. An External action reporting a plain Result.

**Enforcement.** The per-kind rules in the verifier, each with a reason
code: `AuthorRoleInvalid`, `RequestMissing`, `CapabilityMissing`,
`CapabilityDenied`, `ApprovalMissing`, `ApprovalExpired`,
`AuthorityRefMissing`, `ActionClosed`, `ReplacementInvalid`,
`ExternalReceiptRequired`, `RefUnresolved`, `RefCrossSpace`,
`UnknownSchema`, `KindSchemaMismatch`, `EvidenceBelowThreshold`,
`InvalidPayload`, and for spec 0.3 and 0.4 kinds `SourceBindingInvalid`,
`LineageInvalid`, `PayloadRefUnresolved`, `EvaluationInvalid`,
`SelectionInvalid`, `ReaffirmationInvalid`, `ArtifactRefInvalid`,
`RequirementInvalid`. Exact approvals are single-use and actor-bound.

**Evidence.** One integration test per reason code
(`tests/integration/rejection_*.rs`), plus
`test_registered_provider_cannot_impersonate_user`,
`test_unregistered_actors_cannot_author_control_records`,
`test_exact_approval_single_use_and_actor_bound`,
`test_exact_approval_scope_must_match_action`,
`test_retracted_capability_stops_authorizing`,
`test_retracted_approval_stops_authorizing`,
`test_require_ref_must_target_accepted_state`, and the corpus's record
cases, which carry accepting and rejecting cases for every rule and are
re-derived by the Python implementation. The conformance test asserts that
every wire-expressible reason code (23 of the 26; `Refused` is a payload
value, `InvalidCheckpoint` arises only on the trusted-checkpoint path, and
`RefCrossSpace` needs a second space a receipt cannot carry, and those
three have integration tests instead) appears in a committed rejecting
case, so a rule without a vector cannot ship.

**Findings.** None.

**Residual.** Rules are agreed out of band; a receipt is only as meaningful
as the `rules_hash` it embeds, and the profiles (3.8) are what let two
parties name a rule shape they both accept.

### 3.5 Retraction, taint, standing

**Claim.** A retraction taints every record that epistemically depends on
its target (`Use`, not `Cause`), transitively and permanently; a receipt
with any taint is Tainted, never Clean; standing over the evolution graph
is replay-derived and a retracted candidate is unrestorable.

**Moves.** Retract someone else's record. Launder a retracted candidate
back into a sound line through a same-tree derivation. Reaffirm with an
actor not allowed to, or over a different objective. Hide a dependency as
`Cause` to escape the cascade.

**Enforcement.** Retraction ownership and admin allowlist; the
`Use`/`Cause` distinction is structural and recorded; standing base case
that a retracted candidate has compromised, unrestorable standing;
reaffirmation restricted to `reaffirmation_actors` and same objective.

**Evidence.** Receipt vectors `tainted-retraction`, `tainted-use-not-cause`,
`tainted-require-leg`, `tainted-require-target-rejected`, and the eleven
`standing-*` vectors (cascade, derivation, deep reaffirmation recovery,
competing reaffirmations, retracted parent and candidate unrestorable,
binding upgrade sound and compromised); tests
`test_retraction_taints_use_dependents`,
`test_retraction_does_not_taint_cause_dependents`,
`test_taint_cascades_transitively`, `test_retraction_ownership`,
`test_retraction_invalid_targets`.

**Findings.** None.

**Residual.** SPEC section 13 says it: a host that records a continuation
as a derivation escapes the cascade, and intent is not checkable. The
receipt proves the recorded structure is consistent, not that it mirrors
the process.

### 3.6 Signatures and key pinning

**Claim.** A record signed by a pinned actor was made with that actor's
private key; removing, replacing, or transplanting a signature is
detected; a record a pinned actor did not sign is rejected.

**Moves.** Strip a signature. Substitute another valid signature. Sign with
a key the rules do not pin for the author (a valid signature under the
wrong identity). Move a signature from one record to another. Replay a
signed record in another context. Present a malformed or weak key. Write
an attested evaluation without the signature that admits it.

**Enforcement.** The signing form is domain-separated
(`bellbook.record-signature.v0.4`) and excludes `id` and the signature;
the id form then includes the signature, so the id binds it: stripping or
substituting changes the id and the record is Invalid on replay, not
merely unsigned. Verification is `verify_strict` (malleable and weak
encodings rejected identically everywhere). `key_id` is self-describing
but binding is by `author_keys`: a valid signature under a key not pinned
for the author is `SignatureInvalid`; a pinned actor's unsigned record is
`SignatureMissing` regardless of kind. The attested evaluation schema is
admitted only under a pinned signature.

**Evidence.**
`test_subject_signature_removal_changes_id_and_invalidates_receipt`,
`test_valid_signature_substitution_changes_record_id`,
`test_verdict_signature_bytes_reject`, `test_signature_missing`,
`test_signature_invalid`, `test_signature_wrong_key_for_pinned_actor`,
`test_hostile_signature_key_ids`,
`test_pinned_identity_cannot_be_claimed_unsigned`; the signed-tier vectors
(12 cases carrying real Ed25519 signatures under deterministic keys, one
with a stripped signature that is Invalid with every clause failing),
which the Python implementation verifies with a different cryptographic
library; the CLI story `signed_tier_story_from_the_cli_alone` and the
Python story `test_signed_story_from_python_alone`, both of which try the
unsigned and wrong-key moves and observe the reason codes.

**Findings.** None.

**Residual.** Signatures bind authorship, not sequence: a signed record can
be omitted from a rewritten log by the owner. Anchoring covers that. Key
management is the host's. The crate ships no key generation; hosts use
their own randomness.

### 3.7 Receipt parsing, limits, and the CLI boundary

**Claim.** Arbitrary bytes never panic the validator; a document that is
not a well-formed receipt is Invalid with a stated problem; resource use is
bounded before parsing.

**Moves.** Non-JSON, truncated JSON, duplicate top-level fields, extra
fields, wrong spec version, a profile declaration on an epoch that has none,
malformed signature field types, oversized documents, record counts or ref
counts chosen to exhaust memory or time.

**Enforcement.** `ValidationLimits`, finite by default (64 MiB document,
1,000,000 records, 16 MiB payload, 4,096 refs per record; the CLI exposes
`--max-size`), checked before and during decode; strict decode of the
envelope; every failure is a report, never a panic.

**Evidence.** The 14 malformed documents of epoch 0.4 (strict decode,
duplicates, truncation, wrong version, declaration shapes, each limit
exceeded) reproduced by the Python implementation; the seeded harness over
random and mutated buffers (`validate` never panics, Invalid always carries
a reason); fuzz targets `validate` and `receipt_parse`; the CLI tests for
exit codes 0, 1, 2, 3 and for usage errors.

**Findings.** None.

**Residual.** Validation is linear in records plus hashing proportional to
content; within the default limits an adversarial receipt costs bounded
time. `unlimited()` exists and is documented as being for inputs whose
origin the caller controls.

### 3.8 Profiles

**Claim.** A receipt's declared profiles are re-evaluated, never trusted;
a declaration that names a table other than the one applied is reported as
a mismatch; a required profile is evaluated whether declared or not; every
clause fails closed.

**Moves.** Declare a profile the receipt does not meet. Declare a stale
hash. Declare a profile the validator does not know. Meet the baseline and
claim the signed tier without signatures. Build a delivery claim over a
failed evaluation with every digest consistent; reattach a passing
evaluation to another candidate.

**Enforcement.** Declarations are inputs to evaluation, not conclusions;
`declaration_matches` is reported beside the result; the exit code derives
from `met`, which requires Conformant and a matching declaration; unknown
profiles are refused at export and reported Unknown on validation.

**Evidence.** The three vector sets: every failable clause fails in its own
set (B1 through B4; D0 through D7; S0 through S3), a stale declaration in
each, the two canonical delivery forgeries rejected by both
implementations, and the CLI test that a false declaration exits 3 unasked.

**Findings.** None.

**Residual.** A profile checks what it says it checks and nothing else;
the profile documents list what each does not prescribe.

### 3.9 The log and its recovery

**Claim.** One writer at a time; a torn or partial write is detected and
the log stays readable; state and rules drift between writer and log are
refused.

**Moves.** Two writers on one log. A crash mid-append. A corrupt intent
frame. Reopening a log under different rules or with a mismatched state.

**Enforcement.** File locking (`fs4`), intent and subject framing with
recovery of every torn shape, rule and state hash checks on open.

**Evidence.** The `recovery.rs` suite (subject present with intent absent,
empty, torn, or unwritten; healthy tail with corrupt intent; truncated
frames), `test_writer_rejects_rule_drift`,
`test_writer_rejects_state_mismatch`,
`test_writer_rejects_invalid_existing_log`, the appender retry and
head-conflict tests, and `test_torn_trailing_write_then_append_stays_readable`.

**Findings.** None.

**Residual.** This surface is host-side by nature (the log is the host's
file); receipts, which are what cross a trust boundary, never carry a
checkpoint and are always replayed from genesis.

## 4. Findings log

Every finding to date, from the fuzz workflow read on 2026-09-05 and fixed
in #142. Nothing is open.

| Id | Severity | Surface | Finding | Resolution |
|---|---|---|---|---|
| F1 | high | 3.1 | serde_json's default float parser is best-effort and parsed `411E44` one ulp off the nearest double; the canonical form depended on the spelling a value arrived in, and a record carrying it failed its own payload check at commit. | `float_roundtrip` enabled (correctly rounded parsing); unit test over six spellings; both libFuzzer inputs are regression seeds. |
| F2 | high | 3.1 | The Python implementation refused every float, so a receipt with a double in `Action.params` was Clean under the reference and undecodable under the validator. | ECMAScript `Number::toString` implemented from RFC 8785 section 3.2.2.3, checked against Appendix B; corpus case `accept-action-float-params` added. |
| F3 | medium | 3.1 | Integer-valued doubles with 2^53 <= abs(f) < 1e21 print as integer literals outside the safe range, so the canonical form was not a fixed point and the implementations disagreed. | Both refuse them under the one safe-range rule; SPEC section 3 states it. |
| F4 | low | tooling | The `canonical_json` fuzz target and the seeded harness counted a refused out-of-range integer as a crash. | Refusal is the contract; both now require it to be deterministic. |

## 5. Fuzz budget at this review

Fuzz workflow run 3 on commit `4c08030` (2026-09-05): `validate`,
`receipt_parse`, and `canonical_json`, 300 seconds each, coverage-guided,
no crash and no violated invariant. Gate item 2 requires the same on the
1.0.0 release commit, with the budget stated here; a failure of the weekly
run opens an issue automatically (`fuzz.yml`), and a finding there is a
security finding per SECURITY.md.

## 6. What this review cannot claim

- **Independence of person.** The reviewer wrote most of the code and the
  Python implementation. The two implementations are independent in code
  and in the source they were written from (the specification and RFC 8785,
  not each other), which is what catches divergence; they are not
  independent in who read the specification. An external review (#75) is
  what would change that, and 1.0 ships without one.
- **No formal argument.** The invariants are tested and fuzzed, not proved.
- **Cryptographic assumptions.** SHA-256 collision resistance and Ed25519
  unforgeability are assumed; `ed25519-dalek` with `verify_strict`,
  `sha2`, `serde_json`, `ryu-js`, and `fs4` are the runtime dependencies;
  `cargo audit` runs weekly and on pull requests. No side-channel analysis
  was done; the verifier handles no secrets.
- **The SPEC section 13 boundaries stand.** Consistency, not completeness;
  integrity, not confidentiality; tamper-evident, not tamper-proof;
  lineage as recorded, not as intended.
- **Only the trust boundary was reviewed.** Host integrations, the Python
  bindings' own surface (thin wrappers over the crate), and the site were
  not.

## 7. Re-running this review

```
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
python3 conformance/python/run_conformance.py
cd fuzz && cargo +nightly fuzz run canonical_json -- -max_total_time=300   # and validate, receipt_parse
```

Or dispatch the Fuzz workflow from the Actions tab
(`.github/workflows/fuzz.yml`, "Run workflow", budget in seconds per
target) and read the run.

## 8. History

- 2026-09-05: first publication, at `4c08030`, after #142. Four findings,
  all resolved.
