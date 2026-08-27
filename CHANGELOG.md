# Changelog

All notable changes to Bellbook are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-08-27

The read side. RFC-0002 names the seven questions a Bellbook log can
answer about lineage, evidence, and standing, and this release implements
the closed set - `descent`, `descendants`, `siblings`, `frontier`,
`standing`, `evidence`, `selected` - in the Rust core, on the CLI (over a
log or a receipt), in the conformance corpus, and in the independent
Python validator. No new record kinds and no spec change - the epoch
stays 0.3 - and no ranking anywhere: queries report annotated facts and
the caller decides. The PyPI package gains the same query methods
immediately after the core publish (the bindings track the published
crate, which gains the queries module at this release). Existing 0.3/0.4/0.5
receipts and rules validate identically.

### Added

- **The named query set q1-q7 in the core** (`bellbook::queries`,
  RFC-0002; #91). Seven deterministic, read-only queries over canonical
  record relationships - `descent`, `descendants`, `siblings`, `frontier`,
  `standing`, `evidence`, `selected` - derived from what replay already
  computes: never stored, never ranked, answered only over verified state
  (an unverifiable log returns `LogInvalid`, not answers). Rejected
  records are not addressable (they made no claim); every reported node
  carries its standing, taint, and retraction annotations so nothing is
  silently filtered. A closed set with fixed semantics: `selected`
  matches its objective exactly, and the general query engine remains
  gated on RFC-0001 section 15.
- **Conformance corpus query vectors and an independent query
  implementation** (#91). The corpus gains
  `spec/conformance/v0.3/query-cases.json`: cases pairing a portable
  receipt with vectors for all seven named queries, generated from and
  drift-checked against the reference by the `conformance` test, with a
  coverage assertion that every query name appears. The Python validator
  gains `bellbook_queries.py`, a from-scratch implementation of the named
  set that re-derives every vector from the stored receipt and matches
  the reference's surface JSON byte for byte.
- **CLI `bellbook query`** (#91). Run any named query from the command
  line: `bellbook query NAME [ID|OBJECTIVE] (--log DIR --rules FILE |
  --receipt FILE) [--json]`, over an open log or a portable receipt
  alike, with byte-identical `--json` output on both inputs (asserted in
  CI). An invalid log or receipt is an error, never data. The CLI suite
  also carries the RFC-0002 section 8 gate proof: the canary best-of-N
  field test rewritten against the named set, every question answered by
  `bellbook query` alone with zero hand-walking of records.

## [0.5.0] - 2026-08-27

Retraction and standing on every surface. No new record kinds and no spec
change - the epoch stays 0.3 - and the library API is unchanged. What
changes is reach: the semantics that define Bellbook (retraction,
transitive taint, standing, restoration) were previously exercisable only
from the Rust core; the CLI and the Python package can now tell the whole
story, and the story is enforced in CI on both surfaces. Existing 0.3/0.4
receipts and rules validate identically.

### Added

- **CLI `bellbook retract`** (#83). Retract a committed record from a log:
  `bellbook retract --log DIR --rules FILE --author ID --target RECORD_ID
  --reason TEXT [--json]`, with the same conventions as the other mutating
  commands (prints the committed id, exit 65 on a rejected commit). With
  #82's Python verb, the retraction story now runs from both adoption
  surfaces, and the v0.5.0 gate is enforced in CI (#87): the
  broken-benchmark story - Clean, retract, standing collapse, reaffirm,
  restoration with the receipt Tainted permanently - is replayed end to end
  by a CLI test and a Python test, plus an ownership battery (cross-author
  rejected, admin accepted, Verdict/Retraction/missing targets rejected).

- **Python `Writer.retract(author, target, reason)`** (#82). Commits a
  `Retraction` record (payload `{target_id, reason}` with the exactly-one
  `Cause` ref the verifier checks) and returns a `Commit` like the other
  verbs. Ownership is enforced by replay: the retractor must be the
  target's author or an admin retraction actor, an Executor may never
  author one, and a Verdict or Retraction cannot be retracted. On
  acceptance the receipt reports Tainted permanently; a reaffirming
  selection restores standing, never Clean. With this, the broken-benchmark
  story (retract -> taint -> reaffirm -> restore) runs end to end from
  Python alone.
- **The repair pattern documented for Python** (#85). A Derivation
  candidate's `derives_from` members may be candidates or evaluations, so a
  repair *motivated by* an evaluation names it there
  (`derives_from=[sound_parent, failing_eval]`); `Cause` carries intent,
  not taint, so retracting that evaluation later does not compromise the
  repair. Verified against the verifier and pinned by a binding test; the
  set-valued `Writer` parameters are now documented as lists.

- **Retraction-story rules knobs on both surfaces** (#84). `bellbook rules
  init` gains repeatable `--admin <id>` (populates `admin_retraction_actors`:
  actors allowed to retract records they did not author) and
  `--reaffirmer <id>` (populates `reaffirmation_actors`: when non-empty,
  restricts reaffirming selections to the listed actors); Python
  `default_rules` gains matching `admins=` and `reaffirmers=` keyword
  arguments, and `VerifierRules` gains the corresponding builder methods.
  Both surfaces refuse an admin or reaffirmer id that has no author binding,
  since such an actor could never author an accepted record. Without these,
  Executor-authored records were retractable only through a knob no adoption
  surface could set. The rules shape is unchanged - the fields existed since
  their spec epochs; only the generation surface grew.

## [0.4.0] - 2026-08-20

Adoption and hardening release. It adds no new record kinds and no spec change -
it still implements spec epoch 0.3 - and instead closes the gap between the
shipped wedge and a first successful run: the CLI now completes the
record -> receipt -> validate loop by itself (no language binding required), the
receipt trust boundary is fuzzed, and worked examples plus a best-of-N
quickstart show the three proving workloads. The published crate's API is
unchanged; existing 0.3.0 receipts and rules validate identically.

### Added

- **CLI `bellbook rules init` and `bellbook export`** (#70, #71). `rules init`
  writes a starter verifier-rules file from `--author <id>:<role>` bindings, so
  a new user no longer hand-authors one (it is feature-independent, like
  `validate`). `export` bundles a log directory into a portable receipt,
  closing the record -> receipt -> validate loop from the CLI alone; previously
  the export step required the Rust or Python API. Both were surfaced as
  adoption friction while writing the best-of-N quickstart.
- **Python `bellbook.default_rules(authors, max_context=200)`.** Builds a
  starter verifier-rules JSON string from actor-id -> role bindings - the
  Python counterpart to `bellbook rules init` - so `Writer` users need not
  hand-author a rules object.
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
