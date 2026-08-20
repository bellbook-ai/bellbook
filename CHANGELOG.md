# Changelog

All notable changes to Bellbook are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Fuzzing harness over the receipt trust boundary** (#65). A fast, seeded
  harness (`tests/fuzz_trust_boundary.rs`) runs in the ordinary test suite on
  every push, asserting that `validate` never panics and that its reports,
  along with `Receipt::from_bytes` and RFC 8785 canonicalization, stay
  self-consistent for arbitrary input. A coverage-guided libFuzzer target set
  (`fuzz/`) runs weekly and on demand for deeper exploration. `SECURITY.md`
  documents both layers and the pending external-review gate. Development-only;
  the published crate API is unchanged.
- **Adoption worked examples and a best-of-N quickstart** (#66, #67, #68).
  `examples/iterative_evolution.rs` records a multi-generation
  fork-evaluate-select loop and reads the surviving lineage back;
  `examples/repair_reevaluate.rs` shows a single-candidate repair and why a
  repair *motivated by* a retracted evaluation is not tainted by it (`Cause`
  carries intent, not taint). `docs/quickstart-best-of-n.md` takes a best-of-N
  harness to a portable receipt with the CLI and the Python package side by
  side, with a committed starter `docs/quickstart/rules.json`. Docs/examples
  only; the published crate API is unchanged.

## [0.3.0] - 2026-08-20

Second public release. Implements Bellbook spec version 0.3, the evolution
epoch: three new record kinds (`Candidate`, `Evaluation`, `Selection`) that
bind Git source states, judge them, and record set-valued decisions over
them, with replay-derived lineage standing layered over the v0.2 trust
kernel, which is unchanged. Spec v0.2 stays a frozen, still-valid
compatibility epoch: its artifacts are byte-frozen, the published 0.2.0
crate remains their validator, and a CI epoch check confirms the committed
v0.2 receipts validate identically under it. This validator rejects v0.2
receipts with a clear unsupported-version report.

### Changed

- **Opened the spec v0.3 epoch** (design: `spec/v0.3-delta.md`,
  accepted RFC-0001; tracking: #19). `SPEC_VERSION` is `0.3`, the signing
  domain is `bellbook.record-signature.v0.3`, and the current test vectors
  and conformance corpus live at `spec/test-vectors-v0.3.json` and
  `spec/conformance/v0.3/`. The v0.2 artifacts are frozen in place and stay
  valid under v0.2 rules; the published 0.2.x release is their validator,
  and this validator rejects v0.2 receipts with a clear
  unsupported-version report (a corpus case pins it).

### Added

- Release epoch check (#34): a CI job installs the published 0.2.0 crate
  and replays every committed v0.2 receipt case through it, asserting the
  status, reason, record count, head and rules hashes, and retracted and
  tainted sets are identical to the recorded expectations
  (`scripts/epoch_check_v02.py`). This pins the *meaning* of the frozen
  v0.2 artifacts under the published validator, complementing the byte
  freeze in `tests/frozen_v02.rs`.
- Flagship worked example (#32): `examples/broken_benchmark.rs` runs the
  RFC-0001 §10 story end to end - a baseline chosen on a benchmark
  evaluation, a line of continuations and derivations built on it, the
  benchmark retracted when found broken, kernel taint reaching the
  Selection that used it, and the replay report's `standing` section
  showing the whole descendant line compromised at every depth while a
  repair derived from the sound baseline stays sound. Work keeps recording
  under compromise; one reaffirming Selection on a surviving evaluation
  restores the line, with the retraction and taint permanently on the
  record. It exports a receipt and validates it offline at each phase, and
  asserts the standing transitions so `cargo run --example broken_benchmark`
  is also a CI check.
- Evolution CLI (#31): the `bellbook` binary gains `candidate add`,
  `eval add`, `select`, and `lineage` subcommands over a persistent log
  (behind the `persist` feature; `validate` stays feature-independent).
  Every mutating command commits one record and prints its id; `--json`
  emits `{ id, result, reason? }` that round-trips. `candidate --upgrades`
  refuses a binding upgrade whose `--git-tree` differs from its target's,
  so a rebinding never silently changes the source identity. `lineage`
  reports a record's ancestors, children, siblings, considering and
  selecting Selections, taint, and standing. The README documents the
  single-writer recording pattern (the log takes an exclusive lock) before
  the commands.
- Conformance corpus completeness for the evolution rules (#29): with the
  per-reason-code triggering cases (#24/#25), the standing receipt cases and
  byte-for-byte `standing`-section agreement (#26), this adds the
  `max_considered` / receipt-ref-bound interplay - a comparative Selection the
  verifier accepts at `max_considered` (one evaluation per considered
  candidate), and the same Selection's ref count rejected structurally by a
  tight receipt ref budget. Both implementations agree on every case.
- Extended v0.3 test vectors (#28): the golden vectors now pin every
  evolution-kind subject shape, not just one per kind - a `manifest`
  source binding (SHA-256 object format, `commit`, `manifest_hash`), a
  `continuation` and a `derivation` candidate, `scored` and `passed`
  evaluations, and `selected`, `none`, and reaffirmation (`Replace`)
  selections - so the richer canonical forms are held to cross-implementation
  byte agreement by both the Rust and Python id recomputation. The frozen
  v0.2 vectors are unchanged.
- Three record kinds for evolution semantics: `Candidate` (binds a Git
  tree via a reported or manifest source binding), `Evaluation` (one
  criterion per record, with decode-enforced score bounds), and
  `Selection` (set-valued outcomes), with author-role rows, base evidence
  classes, strict typed payloads, vectors, corpus cases, and independent
  Python validator parity.
- Evolution lineage and selection rule battery (#24): per-kind
  `Candidate`/`Evaluation`/`Selection` verification with six new reason
  codes (`SourceBindingInvalid`, `LineageInvalid`, `PayloadRefUnresolved`,
  `EvaluationInvalid`, `SelectionInvalid`, `ReaffirmationInvalid`), shared
  payload-id resolution, source-binding well-formedness, basis obligations
  over `Cause`/`parent`, selection winner and evaluation discipline, and
  `Selection` reaffirmation via `Replace`. Adds the `min_binding`,
  `selection_requires_evaluation`, `reaffirmation_actors`, and
  `max_considered` rule knobs. Mirrored in the Python validator with a
  triggering corpus case per check.
- Selection approval binding (#25): under the `selection_requires_approval`
  knob (default false), a Selection must `Require` a valid, unconsumed
  approval whose subject hash binds the selecting author, the Replace target
  (or null), and the `SelectionData` under domain
  `bellbook.selection-approval.v0.3`. The Replace target inside the hash
  stops a fresh-decision approval from being diverted onto a reaffirmation
  with identical data. Consumption is single-use on Selection accept,
  parallel to the Action exact-approval path and never refunded. Reuses
  `ApprovalMissing`/`ApprovalExpired`; mirrored in the Python validator with
  corpus cases for the approved, missing, mismatched-actor, expired,
  already-consumed, diverted-reaffirmation, and approved-reaffirmation
  paths.
- Standing (#26): the replay report gains a `standing` section
  (`compromised` candidates, `unsound` Selections, `restorations`),
  re-derived on every validation from the accepted records at replay end as
  a pure function of the log. A retracted candidate is compromised
  unconditionally; continuation standing follows anchor soundness and the
  parent, derivation standing follows its candidate `Cause` targets, and one
  reaffirmation re-selecting a parent restores the whole descendant subtree.
  Receipts are unchanged in shape (nothing standing is embedded). Adds the
  `reject_compromised_continuation` knob (default false). Mirrored in the
  Python validator and pinned by standing receipt corpus cases (cascade,
  derivation non-cascade and cascade, deep reaffirmation recovery,
  None-reaffirmation, accepted-but-unsound-intermediate chains, competing
  reaffirmations, the unrestorable retracted-candidate and retracted-parent
  base cases, and the binding-upgrade idiom before and after retraction).
  Completes the spec 0.3 evolution rule set.
- Canonical manifest v1 (#27): `src/manifest.rs` computes a `manifest`
  binding's `manifest_hash` = SHA-256 over the JCS bytes of the manifest
  object mapping each repo-relative POSIX path to `{ mode, sha256 }`, with
  the mode rules for regular and executable files, symlinks (target string),
  and gitlinks (submodule commit OID string, sourced from the Git tree object
  so the manifest is checkout-state independent). `.git` is excluded and the
  hash is order-independent. Includes a persist-gated worktree walker that
  treats submodule roots as gitlinks. This is a recording and interop utility
  (the verifier checks binding well-formedness but never recomputes a
  manifest).
- Machine-readable conformance corpus under `spec/conformance/v0.2/`
  (record, receipt, and malformed-document cases) with a runner that
  re-derives every outcome from the stored inputs. It triggers a case for
  every verdict rejection reason the portable format can express and
  documents the three reason codes it cannot. Regenerate with
  `UPDATE_CONFORMANCE=1`.
- Independent, from-scratch Python validator under `conformance/python/`
  (not a binding over the Rust core) that reproduces the test vectors and
  the conformance corpus, confirming cross-implementation agreement on
  canonicalization, record ids, head/rules hashes, strict decoding, and
  structural log integrity. Runs in CI.
- Independent Python verdict engine (`conformance/python/bellbook_verdict.py`)
  that re-derives every conformance-corpus verdict and replays every receipt
  to the same status, reason, and retracted/tainted sets: the full per-record
  rule battery, the retraction and transitive-taint state machine, and
  whole-log replay. Completes the cross-implementation check of Bellbook's
  verification policy, not just its hashing.

## [0.2.0] - 2026-08-09

First public release. Implements Bellbook spec version 0.2, the first
published compatibility epoch.

### Added

- Twelve typed record kinds covering requests, actions, responses, results,
  authority, approvals, refusals, plans, usage, summaries, retractions, and
  deterministic verdicts.
- RFC 8785 JSON canonicalization and SHA-256 content-addressed record ids.
- Typed `Cause`, `Use`, `Require`, and `Replace` references between records.
- Deterministic record and full-log verification with gap-free logical time,
  subject/verdict pairing, verdict re-derivation, author-role enforcement,
  request lifecycle checks, and authority resolution.
- Five evidence classes with weakest-link derivation and configurable
  per-record-kind thresholds.
- Strict Ed25519 record signatures with actor key pinning and a
  version-specific signing domain.
- Append-only retractions with transitive taint through epistemic
  dependencies.
- A crash-safe, exclusively locked file writer with verified open, bounded
  loading, pair-atomic commits, recovery, deterministic batches, and
  idempotent compare-and-append.
- Portable receipts and the `bellbook validate` CLI for bounded offline
  validation from genesis.
- Trusted checkpoints for host-side replay acceleration and canonical head
  attestations for external anchoring.
- Deterministic context selection and verified state construction.
- Versioned canonical test vectors, including signed-record vectors.
- CI across Linux, macOS, and Windows, Rust 1.75 compatibility checks,
  documentation checks, scheduled RustSec scanning, and Dependabot updates.

### Security

- Record ids bind completed signatures; removing or substituting a signature
  changes the record id and every dependent reference or anchored head.
- Signature input is domain-separated as
  `bellbook.record-signature.v0.2`, preventing cross-protocol and
  cross-version replay.
- Receipt, rule, record, author, signature, reference, and payload decoding is
  strict: unknown fields, duplicate logical keys, and non-canonical payloads
  reject.
- Receipt and persistent-log input is resource-bounded before verification or
  unbounded allocation.
- Replay recomputes record ids and stored verdicts, including complete verdict
  envelope validation.
- Checkpoints cannot arrive through receipts and are accepted only through the
  explicit trusted-checkpoint API.
- Persistent commits reserve and recover the complete subject/verdict pair;
  uncertain durable writes require reopen and recovery before another commit.
- Key-pinned actors must sign every record, and actor identities are bound to
  configured roles.
- Actions name the exact capability and approval that authorized them;
  retracted authority no longer authorizes later actions.

### Known limitations

- Bellbook proves consistency of captured activity, not capture completeness.
- Bellbook provides integrity, not confidentiality; records and receipts may
  contain sensitive payloads.
- A storage owner can replace an unanchored log from genesis. Key-pinned
  signatures and externally stored head attestations limit that threat.
- Receipt status is evaluated under the embedded verifier rules. Consumers
  compare `rules_hash` against rules they trust.

See [SPEC.md](SPEC.md) for normative behavior and [SECURITY.md](SECURITY.md)
for the security model and vulnerability-reporting process.
