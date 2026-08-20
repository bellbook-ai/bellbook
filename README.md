# Bellbook

[![CI](https://github.com/bellbook-ai/bellbook/actions/workflows/ci.yml/badge.svg)](https://github.com/bellbook-ai/bellbook/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/bellbook.svg)](https://crates.io/crates/bellbook)
[![docs.rs](https://img.shields.io/docsrs/bellbook)](https://docs.rs/bellbook)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**A tamper-evident, replay-verifiable record of captured agent activity.**

Bellbook is a small embeddable Rust library with one durable primitive: a typed
`Record` in an append-only log. Activity the host captures is written down as
a typed entry - what was requested, what was done, what came back, what was
approved, what was refused, and the verdict on whether it followed the rules.
Modifying hash-covered record content or the committed sequence becomes
detectable. Detecting complete replacement from genesis requires an external
anchor. A verifier can replay the whole record to confirm its internal
consistency: no action without a verdict, no gaps, and no forged record ids.

In one line: it turns *"the agent says it did X"* into *"here is
tamper-evident, replay-verifiable evidence of the agent activity that was
recorded."*

As of spec v0.3, Bellbook also records how software *evolves*: `Candidate`
source states bound to a Git tree, `Evaluation`s of them, and set-valued
`Selection`s between them - so a chosen line of work carries **verifiable
candidate selection and lineage**. When an evaluation is later retracted
(say, a benchmark turns out to be broken), replay marks every candidate that
rested on it compromised, transitively at any depth, and one reaffirming
selection on surviving evidence restores the line - with the whole episode
permanently on the record. See [Recording evolution](#recording-evolution-cli)
and `cargo run --example broken_benchmark`.

One honest boundary up front: Bellbook proves **consistency, not
completeness**. It verifies that captured history is intact,
rule-conforming, and honestly graded; whether *everything* the agent did
was captured depends on how the host instruments its runtime
([SPEC §13](SPEC.md#13-known-limitations)). And it provides
**integrity, not confidentiality**: records and receipts carry full
payloads in the clear, so a receipt inherits the sensitivity of
everything committed - never put credentials in records, and treat
sharing a receipt as disclosure (see SECURITY.md).

## Where Bellbook fits

Bellbook is an evidence layer, not an identity provider or runtime
policy engine. Identity systems establish who an agent is and what
access it holds. Policy engines decide whether an action may execute.
Bellbook preserves captured requests, authority, actions, and results as a
portable receipt that another party can verify independently. The spec does
not include a record for an external policy engine's decision. Bellbook's own
`Verdict` records are its deterministic
judgment that the *ledger followed its rules*; they are never a
substitute for an external policy engine's permit/deny decision, and
the separately scoped `PolicyDecision` work is not implemented.
See [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md) for how surrounding systems
relate to Bellbook and
[docs/INTEROPERABILITY.md](docs/INTEROPERABILITY.md) for the boundary
definitions.

Not a logger, not a database, not a runtime - an evidence kernel your process
embeds.

## How it works

- **Content-addressed records.** A record's `id` is the SHA-256 of its
  RFC 8785 (JCS) canonical id form (only id excluded; a completed signature
  is included), so an
  independent implementation in any language computes identical ids
  ([test vectors](spec/test-vectors-v0.3.json)). Records reference earlier
  records by that hash through typed refs (`Cause`, `Use`, `Require`,
  `Replace`), forming a DAG. Edit any byte of history and every id and ref
  that depends on it breaks.
- **Every record is judged.** Committing a record runs a deterministic
  verifier and appends a `Verdict` (`Accept`/`Reject` + reason) immediately
  after it. Rejected records stay in the log - the log records what was
  *attempted*, not just what was allowed.
- **The whole log replays.** `verify_log` walks the log from genesis (or a
  checkpoint): recomputes every id, enforces gap-free logical time
  (`time == prev + 1`), requires every non-verdict record to be immediately
  followed by its verdict, and **re-derives every verdict** from the replay
  start onward to compare with what's stored - a forged verdict is caught,
  not trusted. (Records inside a checkpoint prefix are attested by the
  prefix hash instead of re-derivation.)
- **Governance is in-band.** Capabilities, approvals, refusals, and expiries
  are records too, so "was this action allowed at the time?" is answered by
  the log itself, deterministically. Author roles are enforced and actor
  identities are bound to roles in the rules; pin an actor's signing keys
  in `author_keys` and its records must be validly signed, so the agent
  cannot author its own approvals, even by claiming to be the user -
  that guarantee is cryptographic exactly when the claimed identity has
  pinned keys, and configuration-level otherwise. Exact approvals are
  bound to one actor's one action and are single-use, every action must
  name the exact authority that allowed it, retracted authority stops
  authorizing, and retraction itself is ownership-bound.
- **Evidence classes.** Every record carries how its content is known - an
  ordered five-class lattice, strongest to weakest: `Deterministic`
  (verifier-derived), `Verified` (a signed attestation from a key-pinned
  external party - origin verified, never the real-world effect),
  `Reported` (asserted by an external party), `Inferred` (derived by
  reasoning), `Assumed` (unverified assumption) - and derived records
  inherit the *weakest* evidence among the sources they declare
  (`Use`/`Require` refs), so evidence can never be inflated. Rules can
  set per-kind minimum-evidence thresholds.
- **Ed25519 signatures.** Records can carry a detached signature over a
  Bellbook-epoch-domain-separated, id-free signing form; the completed signature
  is then included in the final record id, so signatures and head attestations
  cannot be substituted without detection. Rules configure which kinds require
  one and which keys each actor may sign with; verification is strict and
  real, not a stub.
- **Retraction with taint.** A `Retraction` record asserts an earlier
  record's content was wrong - append-only, nothing erased. Records that
  epistemically depended on it (via `Use`/`Require` refs) are marked
  tainted; a tainted chain still replays and verifies, and the report
  surfaces exactly which claims no longer rest on anything.
- **Evolution semantics (spec v0.3).** Three more record kinds capture how
  work evolves: a `Candidate` binds a source state (a Git tree, `reported`
  or committed to a canonical `manifest`), an `Evaluation` records one
  criterion's judgment of one candidate, and a set-valued `Selection`
  chooses among considered candidates under an objective, grounded on
  evaluations. A `Replace` on a Selection reaffirms an earlier decision.
  On top of these, the replay report gains a **standing** section: a
  purely replay-derived lineage dimension that marks which candidates rest
  on decisions and states that no longer stand. When a benchmark's
  evaluations are retracted, taint reaches the selections that used them
  and standing marks the descendant line compromised at any depth; one
  reaffirming selection on surviving evidence restores it. Standing is
  re-derived by every validator like the taint set, never embedded in a
  receipt, and never merged into kernel taint or evidence
  ([SPEC §7.2](SPEC.md#72-standing); run `cargo run --example
  broken_benchmark`).
- **Honest threat model.** Tamper-*evident*, not tamper-proof: replay
  detects any interior edit to committed history, but the ledger's owner
  can rewrite the whole log from genesis. SPEC §11 states this plainly and
  defines the mitigations - key-pinned signatures and a canonical
  [head attestation](SPEC.md#111-head-attestation-format) to anchor
  externally.
- **Crash-safe, verified single writer.** `LogWriter` holds an exclusive
  file lock, refuses existing history that does not replay under its opening
  rules, rejects stale or fabricated derived state, keeps raw append and its
  time source private, and uses an intent-file protocol to restore an
  interrupted record/verdict pair exactly once. Opening and appending are
  bounded to 64 MiB by default; trusted larger logs can opt into an explicit
  higher limit.

`batch_commit` preserves the atomicity of each subject/verdict pair but is not
a transaction across the entire batch: an error on a later proposal leaves
earlier pairs durable. Integrations that retry batches should use
`checked_batch_commit` with the expected head.

## Quickstart

```rust
use bellbook::*;

let space = default_space();
// Bind actor identities to roles: every non-Verdict record needs a
// registered author (pin keys in `author_keys` to authenticate them).
let rules = VerifierRules::new(space, 200)
    .with_author_role("human", AuthorType::User)
    .with_author_role("agent", AuthorType::Provider);
let mut writer = LogWriter::open(dir, &rules)?;
let mut state = State::default();

let (id, verdict) = writer.commit(proposal, &rules, &mut state)?;
assert_eq!(verdict.result, VerdictResult::Accept);

// Replay-verify the entire log - recomputes ids, times, and every verdict.
let report = verify_log(writer.records(), &rules, None);
assert_eq!(report.result, VerdictResult::Accept);
```

Run the full working demo (commit → verify → tamper → detect):

```
cargo run --example quickstart
```

See [SPEC.md](SPEC.md) for the record model, verification rules, commit
protocol, and storage format.

## Feature flags

| Flag | Default | Effect |
|------|---------|--------|
| `persist` | on | File-backed log through the verified `LogWriter` API, with locking through `fs4` and a configurable 64 MiB default file-size bound. Raw storage mutation is internal. Disable for the pure in-memory model, verifier, and receipt validation (no file-I/O dependency). |

## Validating a receipt

A log exports as a portable, self-contained `Receipt`; anyone can verify
it offline - ids, chain, every verdict re-derived, signatures, evidence,
taint - with no Rust knowledge required. The CLI ships with the crate
(`cargo install bellbook`, or `cargo run --bin bellbook -- …` from a
checkout):

```
bellbook validate receipt.json          # human-readable report
bellbook validate receipt.json --json   # same report as JSON
```

Exit codes: `0` clean, `1` invalid, `2` valid-but-tainted. See SPEC §12
for the receipt format and the normative truth rules. Two honesty notes.
**Clean is relative to the rules embedded in the receipt** (compare the
reported `rules_hash` against a rule set you trust) - under default rules
it means "internally consistent", not "meets a shared security
baseline". And a receipt proves the recorded *process*, not source
contents: a `Candidate`'s Git OIDs are pointers the repository resolves
(under `manifest` binding a party holding the tree can recompute the hash
and bind the receipt to actual contents; under `reported` binding it is a
verifiable record of an unverified claim, and the receipt says which), and
the **lineage, standing, and taint guarantees are conditional on the
producer's recording discipline** - `basis`, `parent`, and refs are
producer claims a verifier cannot check against intent
([SPEC §13](SPEC.md#13-known-limitations)).

## Recording evolution (CLI)

The same binary records the v0.3 evolution kinds against a persistent log.
Each command commits one record and prints its id; `--json` prints
`{ id, result, reason? }` that round-trips, so pipelines can chain ids
without scraping text.

```
bellbook candidate add --log <dir> --rules <file> --author <id> \
         --git-tree <oid> [--continues <sel> --parent <cand>
                           | --derives-from <id>... | --upgrades <cand>]
bellbook eval add      --log <dir> --rules <file> --author <id> \
         --candidate <id> --criterion <s> (--passed | --failed | --score <v> --scale <n>)
bellbook select        --log <dir> --rules <file> --author <id> --objective <s> \
         --consider <id>... (--choose <id>... --uses-eval <id>... | --none) [--replaces <sel>]
bellbook lineage       --log <dir> --rules <file> <id> [--json]
```

The grammar above shows the load-bearing flags; optional ones
(`--git-commit`, `--algo`, `--manifest`, `--note`, `--procedure`,
`--uses`, `--rationale`, and `--json` on every command) are omitted for
brevity. Run `bellbook` with no arguments for the full usage.

**The log is single-writer by design.** `LogWriter` takes an exclusive
lock on the directory for the life of the process, so exactly one
recording process may hold a log at a time; a second concurrent writer
fails to open rather than corrupting the log. This is deliberate: parallel
candidate *generation* is the intended workload, parallel *recording* is
not. Generate candidates concurrently, then record them serially from one
process (a loop over the commands above, or `checked_batch_commit` for
retry-safe batches). The CLI is not a coordination layer, and `--upgrades`
refuses to record a binding upgrade whose `--git-tree` differs from its
target's, so a rebinding never silently changes the source identity.

For the evolution semantics end to end - a benchmark found broken, the
compromise it casts over a line of work, and the one-record recovery - run
the flagship worked example:

```
cargo run --example broken_benchmark
```

It records candidates, evaluations, and selections across several
generations, retracts the broken benchmark, and prints the replay report's
`standing` section changing from sound, to a compromised descendant line, to
restored (with the retraction and taint permanently on the record).

## Status

**`main` implements spec v0.3 (evolution semantics: Candidate, Evaluation,
and Selection records with replay-derived lineage standing), fully tested
but not yet published as a crate release; the last published epoch is
0.2.0, implementing spec v0.2.** SPEC.md is the authority for what v0.3
means (design notes in [`spec/v0.3-delta.md`](spec/v0.3-delta.md)); the
v0.3 milestone is tracked in issue #19. The v0.2 artifacts stay frozen and
valid under v0.2 rules forever, and the published 0.2.x release is their
validator.

It ships exactly what is implemented and tested today: the
content-addressed (JCS-canonical) record model, the deterministic verifier
with replayable `verify_log` (identity-to-role binding, authority binding
and revocation, single-use exact approvals, explicit request lifecycle,
advisory plan consistency checks), Ed25519 signatures, retraction with
taint, the v0.3 evolution kinds (Candidate / Evaluation / Selection) with
source binding, the selection and reaffirmation rule battery, and the
replay-derived standing section, derived state with incremental/full-build
equivalence, checkpoints, the crash-safe writer with idempotent
compare-and-append, and portable receipts with the offline `bellbook
validate` CLI and the `candidate`/`eval`/`select`/`lineage` recording
commands - fully tested (every rejection reason code has a triggering
test), clippy-clean, no `unsafe`, no panics in library code.

The repository also carries a language-neutral **conformance corpus**
(`spec/conformance/v0.3/`: record, malformed, receipt-replay, and standing
cases, run by `tests/conformance.rs`; the frozen `spec/conformance/v0.2/`
corpus stays valid under v0.2 rules) and an **independent Python
implementation** of the verifier (`conformance/python/`) that shares no
code with this crate, recomputes every record id, and re-derives every
verdict and standing section across the corpus, agreeing with this
reference on every case - including the deliberately malformed and forged
inputs it must reject.

Open work, **not implemented**:

1. **`bellbook-core-v1` baseline profile** - a fixed minimum rule set
   (required signatures, pinned keys, evidence thresholds) for comparing
   receipts under shared rules.
2. **`PolicyDecision` record + `bellbook-policy-enforced-v1` profile** -
   first-class capture of external policy-engine permit/deny decisions,
   kept strictly separate from Bellbook's own Verdicts, followed by a
   reference adapter for an open-source authorization engine (see
   [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md)).
3. **Profile-aware receipts** - receipts declare claimed profiles;
   the validator reports per-profile conformance instead of trusting
   the declaration.
4. **Python bindings** - PyO3/maturin wheels wrapping this same core
   (validation-first), once the current spec epoch is frozen by a release.
5. **Interop mapping** - a short document mapping Bellbook records
   outward to OpenTelemetry logs, W3C PROV, in-toto statements, and
   SCITT receipts, rather than inventing adjacent layers (the boundary
   definitions are already in
   [docs/INTEROPERABILITY.md](docs/INTEROPERABILITY.md)).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
