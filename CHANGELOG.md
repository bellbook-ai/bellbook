# Changelog

All notable changes to Bellbook are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`docs/SECURITY-REVIEW.md`**: the internal adversarial review of the
  trust boundary, gate item 1 of the 1.0 security gate. Nine surfaces
  (canonicalization and ids, the canonical-payload rule, replay, the
  governance rules, retraction and standing, signatures and key pinning,
  receipt parsing and limits, profiles, the log and its recovery), each
  with the claim, the attacker's moves, what enforces it, the named
  evidence, findings, and residual risk; the findings log (F1 through F4,
  all resolved); the fuzz budget at this review; and what the review cannot
  claim. Re-dated at the 1.0.0 release commit.
- The Fuzz workflow files a `security`-labelled issue when a target
  crashes or violates an invariant, with the run, the reproducer artifact,
  and the reproduce command, so a finding is seen where work is tracked.

### Fixed

- **Number canonicalization was not idempotent.** Found by the weekly
  libFuzzer run (2026-08-24 and 2026-08-31). serde_json's default float parser is
  best-effort and parsed `411E44` one ulp off the nearest double, so the
  canonical form of that value depended on the spelling it arrived in
  (`4.1100000000000004e+46` from `411E44`, `4.11e+46` from its own canonical
  output), and a record carrying it failed its own payload check at commit.
  Doubles reach the wire only through `Action.params`. The crate now enables
  serde_json's `float_roundtrip` feature (correctly rounded parsing); a unit
  test pins that six spellings of the value canonicalize identically, and
  both libFuzzer inputs are regression seeds in
  `tests/fuzz_trust_boundary.rs`. Any committed record whose params carried
  a double the old parser mis-rounded gets a different id under correct
  parsing; no committed vector, corpus case, or receipt did.
- **The independent Python validator refused every floating-point number**
  as "not part of the wire format", so a receipt whose `Action.params`
  carried a double was Clean under the reference and undecodable under the
  validator. It now formats finite doubles as ECMAScript `Number::toString`,
  written from RFC 8785 section 3.2.2.3 and checked against the RFC's
  examples, and the epoch 0.4 corpus gains `accept-action-float-params` so
  both implementations are held to the same bytes.
- The `canonical_json` fuzz target and the seeded harness treated a refused
  out-of-range integer as a crash. Refusal is the contract (an error, never
  silent rounding), so both now require the refusal to be deterministic
  instead.
- **Integer-valued doubles between 2^53 and 1e21 are now refused**, as the
  unsafe integers they print as. Surfaced by the seeded harness once it
  carried large exponents: `1e16` canonicalized to `10000000000000000`,
  whose re-parse is a refused integer, so the canonical form was not a
  fixed point and the reference disagreed with the independent validator
  (which already refused the literal). Both implementations now apply one
  rule at one boundary; doubles from 1e21 up print in exponent form and are
  unaffected. RFC 8785 Appendix B's `1e+20`, `9007199254740994`, and
  `999999999999999700000` cases are therefore refused by Bellbook, and
  SPEC section 3 and the canonicalization module say why.

### Changed

- **The 1.0 security gate is re-scoped** (RFC-0003 decision 10; #114, #75).
  1.0 does not ship on an external security review; it ships on an internal
  adversarial review of the trust boundary published in the repository, the
  fuzz targets clean over a stated budget on the release commit, and zero
  unresolved findings. SECURITY.md and STABILITY.md say so, and the 1.0
  release notes will. The external review stays open for when an adopter's
  dependence justifies it.

## [0.10.0] - 2026-09-05

The signed tier. No core or wire change: every record, canonical form,
signing form, schema, and verdict rule is byte-for-byte that of 0.9.0,
and core conformance and the earlier profiles' vectors are unchanged. What
is new is the third published profile, `bellbook-core-signed-v1`, the
surfaces that reach it from the CLI and Python without touching Rust, the
stability document that says what 1.0 will promise, and three small acts
from the first-party half of field test 3
(`docs/field-tests/ft3-delivery-receipt-canary.md`). This is the line the
1.0 soak runs on: 1.0.0 is the freeze, tagged after the soak and the
security review, not a feature release. The Python package gains the
signed tier's surface right after the core publish (the bindings track the
published crate).

### Added

- **The `bellbook-core-signed-v1` profile** (RFC-0003 section 4.5, SPEC
  section 12.2; #113). The signed tier above the baseline, four clauses,
  every one fail-closed: S0 the baseline is met (declared and matching, or
  evaluated as the fallback); S1 `signature_required_kinds` includes
  Candidate, Evaluation, Selection, Retraction, and Requirement; S2
  `author_keys` pins every author of an accepted record of those kinds; S3
  every evaluation an accepted `Selected` Selection uses carries
  `bellbook.evaluation.attested.v1`. A baseline-conformant receipt reaches
  the tier by adding signatures and switching evaluation schema ids; no
  payload changes shape. `--require-profile bellbook-core-signed-v1` and
  `export --profile bellbook-core-signed-v1` work on every surface. The
  clause table and hash are published in
  `spec/profiles/bellbook-core-signed-v1/profile.json`; `cases.json` beside
  it carries the tier met in five honest shapes (including a delivery claim
  judged under the signed tier and a Tainted history with a signed
  retraction), one rejecting case per clause, a stale declaration, and a
  receipt with a stripped signature (Invalid; every clause fails). Every
  record a pinned author wrote carries a real Ed25519 signature under a
  deterministic test key, which the independent Python validator verifies;
  it implements every clause from scratch and agrees on every vector.
  Profile document: `docs/profiles/bellbook-core-signed-v1.md`.
- **Signing surfaces**, so the signed tier is reachable without touching
  Rust. CLI: `rules init --signed` requires a signature on the five
  evolution kinds and `--author-key <id>:<pubkey-hex>` (repeatable) pins an
  actor's key; every recording command takes `--sign-key <file>` (the
  Ed25519 secret as 64 hex characters or 32 raw bytes) and signs the record
  before it is committed; `eval add --attested` writes
  `bellbook.evaluation.attested.v1` (refused without `--sign-key`);
  `key public --secret <file>` prints the public key to pin. Key generation
  and storage stay with the host; the CLI never prints a secret. Python:
  `default_rules(..., signed=True, author_keys={actor: [pubkey_hex]})`,
  `Writer(log_dir, rules, signers={actor: secret})` signs every record the
  listed actors write, and `evaluate(..., attested=True)` selects the
  attested schema. Both story gates record a receipt declaring all three
  profiles and assert every one met.
- **`docs/STABILITY.md`**: what 1.0 promises (spec epoch 0.4 frozen and
  forward-valid receipts; the profile triple immutable; the crate's public
  items, the CLI grammar and JSON, and the Python surface under semantic
  versioning; MSRV policy), what it does not (capture completeness,
  confidentiality, what a profile does not check, performance, internals,
  message text), the deprecation period for each surface, and the support
  policy. The 0.10.x line already behaves this way; 1.0.0 is tagged when
  the release gates hold. The public API audit that accompanies it: every
  public item of the crate is documented, nothing is deprecated, and
  `cargo semver-checks` against the published 0.9.0 (the bump treated as
  minor, 196 checks) reports no breaking change - 0.10.0 is additive over
  0.9.0.

- `conformance/python/validate_receipt.py`: the independent validator's
  one-receipt entry point for a skeptic - structural decode, replay, every
  declared profile and any `--require-profile` id, with `bellbook
  validate`'s exit codes; standard library only, and it refuses to run with
  the `bellbook` package imported.
- `bellbook validate --json` reports `met` on every profile entry, the
  field the exit code is derived from, for parity with the Python
  surface's `Report.profiles`.

### Changed

- The `delivery-receipt-v1` D2 detail line names the claim's used
  evaluations ("every used evaluation of a required requirement passed"),
  matching the clause's stated scope. Detail text only; no clause, vector,
  or hash changes.
- The profile document says what D5 does not prescribe: how
  `procedure_hash` and `input_hash` are computed is the evaluator's
  published convention, and names the simplest checkable one.

## [0.9.0] - 2026-09-05

The delivery receipt. No core or wire change: every record, canonical
form, signing form, schema, and verdict rule is byte-for-byte that of
0.8.0, and core conformance (`spec/conformance`, the 0.3 and 0.4 vector
files) is unchanged. What is new is the second published profile,
`delivery-receipt-v1`: the grammar of a delivery claim over the spec 0.4
records, with its own vector set and a fraud battery that both
implementations reject on replay, and the quickstart that takes a
delivery loop to a receipt a skeptic can check. The Python package gains
the profile's surface right after the core publish (the bindings track
the published crate).

### Added

- **The `delivery-receipt-v1` profile** (RFC-0003 sections 4.4 and 4.6,
  SPEC section 12.2; #111). The grammar of a delivery claim over the spec
  0.4 records: a claim is an accepted `Selected` Selection whose `Use`d
  extended evaluations bind to requirements of exactly one Request (the
  request is determined from the record, never declared; the latest sound
  claim per request is evaluated and earlier ones reported superseded).
  Clauses D0 through D7: a claim exists; every required requirement is
  covered by a passing, unretracted evaluation at the receipt head; no
  evaluation of a required requirement is non-passing; every evaluation
  judges the one chosen candidate with non-empty evidence that the
  candidate or an accepted Result in the thread carries; producer and
  evaluator are distinct actors; the decider binding is complete, with the
  weakest basis reported; `bellbook-core-v1` is met (declared and
  matching, or evaluated as the fallback); the claim is sound, untainted,
  and unretracted. `bellbook validate --require-profile
  delivery-receipt-v1` and `export --profile delivery-receipt-v1` work on
  every surface. The clause table and hash are published in
  `spec/profiles/delivery-receipt-v1/profile.json`; `cases.json` beside it
  is the fraud battery - four conformant shapes (baseline declared,
  baseline as the fallback, evidence bound through a Result, a superseded
  earlier claim) and one rejecting case per clause, including the
  canonical forgeries (a claim over a failed evaluation with every digest
  consistent; a passing evaluation reattached to another candidate). The
  independent Python validator implements every clause from scratch and
  agrees on every vector; the CLI story gate now exports a receipt
  declaring both profiles and asserts both are met, and the Python gate
  does the same once the bindings pin the published 0.9 crate. Core
  conformance is byte-unchanged.
- **Quickstart: a delivery receipt a skeptic can check**
  (`docs/quickstart-delivery-receipt.md`; #112). Request, requirements,
  a bound candidate, evaluations by a distinct evaluator, and the claim,
  on both surfaces; what the skeptic runs holding only the receipt; the
  fraud demonstration (a claim over an honestly recorded failed
  evaluation validates Clean and is rejected by the profile on D1 and
  D2); and how a requirement added after the claim withdraws it until
  re-claimed. RFC-0003 section 10.1 records validation criterion 2 (the
  fraud battery holds in both implementations) as met.

## [0.8.0] - 2026-09-02

Requirement binding: spec epoch 0.4, the first spec change since 0.3
(RFC-0003). A receipt can now say what was required (`Requirement`),
bind a judgment to the exact artifacts it judged (`ArtifactRef`), name
who decided and how with fail-closed outcomes (the extended
`Evaluation`), and declare the profiles it claims for every validator to
re-check. What stays valid: the record envelope, canonical form, signing
form, and every 0.3 schema are byte-for-byte those of 0.3; a 0.4
validator replays a 0.3 receipt under the 0.3 schema set and reaches the
identical decision its own epoch's validator reached (the 0.3 vectors and
corpus are byte-frozen, re-derived in CI, and replayed through the
published 0.7.0 binary); rules files from earlier versions stay valid
with their `rules_hash` unchanged and reject a `Requirement` as
`UnknownSchema` until the schema is added. The Python package gains the
0.4 surfaces immediately after the core publish (the bindings track the
published crate).

### Added

- **The `Requirement` record kind** (`bellbook.requirement.v1`, base
  evidence `Reported`; RFC-0003 section 4.1, SPEC section 2; #107). An
  addressable statement of what a Request requires, so evidence and
  evaluator decisions can bind to it by id: `{key, description, required,
  expected_evidence, provenance: user_authored | derived}`. Exactly one
  `Cause` to an accepted Request in the same thread and space; `key`
  unique among accepted, unretracted Requirements under that request
  (new reason code `RequirementInvalid`, also for an empty key or
  description or a wrong Cause shape). Provenance is bound to
  authorship: `user_authored` needs a `User` author, `derived` a
  `Provider` or `System`, else `AuthorRoleInvalid`; an `Executor` never
  authors one. Never replaced: amendment is retract-and-record, and a
  retracted Requirement releases its key. State gains the per-request key
  index (and its reverse index), so checkpoint state hashes of logs
  differ from 0.7.0's for the same records; checkpoints are host-side
  and never travel in receipts. The default `kind_schema_map` (and
  `rules init`) now carries the schema; rules from earlier versions stay
  valid and reject a Requirement as `UnknownSchema` until the schema is
  added.
- **The extended `Evaluation`: `bellbook.evaluation.v2` and
  `bellbook.evaluation.attested.v1`** (RFC-0003 section 4.3, SPEC section
  2; #89). `bellbook.evaluation.v1` is frozen as it was; the extended
  shape is a new schema name because it adds required fields and a
  vocabulary. It carries the v1 judgment plus `evaluator: DeciderBinding
  {id, version, procedure_hash, input_hash}` (who decided, with what
  exact procedure, over what input - the one vocabulary a future
  `PolicyDecision` reuses), `basis: recomputed | declared` (declared,
  never inferred), `evidence: [ArtifactRef]` (what was judged), and
  `requirements: [RecordId]` (accepted Requirements it speaks to, each
  mirrored by a `Use` ref so a retracted requirement taints the
  evaluations that judged against it). Outcomes are fail-closed: `passed
  | failed | scored | blocked | insufficient | stale | not_run`, and only
  `passed` passes. Binding failures, an unordered `requirements` list, or
  an empty `evaluator.id` reject with `EvaluationInvalid`; malformed
  evidence with `ArtifactRefInvalid`. The attested schema has base
  evidence `Verified` and must carry a signature from an author with
  pinned keys, exactly like `result.external_receipt.v1`: a signature
  never promotes a class, the schema does. Selections and the named
  query set accept either shape; `evidence` reports the fail-closed
  outcome labels.
- **First-class artifact identity: `ArtifactRef`** (RFC-0003 section
  4.2, SPEC section 2; #108). `{scheme, digest, name}`: a scheme token, a
  lowercase-hex content digest of the length the scheme dictates
  (registered: `git-tree-sha1`, `git-tree-sha256`, `manifest-v1`,
  `git-archive-tar-v1`, `oci-image-manifest`, `sha256-bytes`; an
  unregistered scheme is accepted under a generic 20..=64-byte rule), and
  an optional label that is never identity. `Candidate` and `Result`
  payloads gain an optional `artifacts` list, strictly sorted and
  deduplicated; a malformed entry or an unordered list rejects with the
  new reason code `ArtifactRefInvalid`. The field is additive and absent
  from the canonical form when unset, so every 0.3 payload keeps its
  bytes and id. Vectors pin the new canonical forms; the corpus carries
  accepting and rejecting cases for both kinds; the independent Python
  validator implements the rule from scratch.
- **Receipt profile declarations** (RFC-0003 section 4.5, SPEC section
  12; #10). The receipt envelope gains `profiles: [ProfileRef {id,
  version, hash}]`, the profiles the producer claims, omitted from the
  wire form when empty so an undeclared receipt is byte-identical to
  before. A declaration is never trusted: every validator evaluates each
  declared profile itself, unasked, and each `ProfileResult` now reports
  `declared` and `declaration_matches` (whether the declared version and
  hash name the clause table that was evaluated; `None` for an undeclared
  or unknown profile). `validate_with_profiles` evaluates declared
  profiles first, then the required ids the receipt did not declare;
  `ProfileResult::met` is Conformant plus a matching declaration when
  declared. `Receipt::with_declared_profiles` and `bellbook export
  --profile ID` declare; `bellbook validate` exits 3 when any declared or
  required profile is not met, including a declaration whose hash or
  version is not the profile the binary evaluated. Structural rules: a
  receipt of an epoch before 0.4 carrying a declaration, an empty id, or a
  repeated id is Invalid before replay (malformed corpus cases). The
  profile vectors now pin every reported profile per case, with
  declaration cases for a matching, stale-hash, wrong-version, unknown,
  and false claim; the Python validator mirrors the decoding rule and
  evaluates declarations from scratch.
- **CLI surfaces for the 0.4 kinds** (#110). `bellbook request add`
  (a user-role author's objective; requirements bind to it) and
  `bellbook requirement add` (`--request`, `--key`, `--description`,
  `--optional`, `--expected-evidence`, `--provenance` defaulting from the
  author's role and refused when the role cannot carry it). `candidate
  add` and `eval add` take `--artifact <scheme>:<digest>[:<name>]`
  (repeatable), checked against the artifact rule and canonically ordered
  before the write. `eval add` records the extended evaluation when
  `--evaluator` and `--basis recomputed|declared` are given, with
  `--evaluator-version`, `--procedure-hash`, `--input-hash`,
  `--requirement` (repeatable, each mirrored by a `Use` ref), and the
  fail-closed outcomes `--blocked`, `--insufficient`, `--stale`,
  `--not-run`; without them it writes the v1 shape as before. The named
  query set's `Node` gains `artifacts` and `requirements`, present only
  where a record binds them, on every surface (the query vectors gain a
  bound line and the Python validator reproduces the annotations). A CLI
  story test drives request, requirements, a bound candidate, bound
  evaluations, a selection, a declaring export, validation, the query
  surface, and the taint a retracted requirement spreads.

### Changed

- **Opened the spec 0.4 epoch** (#109). `SPEC_VERSION` is `0.4`; the
  current test vectors and conformance corpus live at
  `spec/test-vectors-v0.4.json` and `spec/conformance/v0.4/`. Epoch 0.4
  adds to 0.3 without changing anything 0.3 defined: the record envelope,
  canonical form, signing form, and the fifteen 0.3 schemas are
  byte-for-byte those of 0.3, so the signing domain stays
  `bellbook.record-signature.v0.3`.
- **The validator dispatches on the receipt's `spec_version`.** A 0.3
  receipt replays under the 0.3 schema set and reaches the identical
  decision its own epoch's validator reached; a 0.4 receipt replays under
  the full set; any other version is a structural `Invalid` naming the
  supported versions. The 0.3 vectors and corpus are byte-frozen
  (`tests/frozen_v03.rs`), every stored 0.3 outcome re-derives under the
  0.4 validator (`tests/epoch_v03.rs`), and a new `epoch-v03` CI job
  replays the 0.3 receipts through the published 0.7.0 binary
  (`scripts/epoch_check.py`, which now serves both frozen epochs). The
  independent Python validator accepts both epochs and runs both corpora.
- Receipts exported by this version declare `spec_version` `0.4`; the
  committed example receipt and the `bellbook-core-v1` profile vectors
  are regenerated accordingly (the profile's clause table and hash are
  unchanged).

## [0.7.0] - 2026-09-02

Profiles foundation. RFC-0003 (accepted 2026-09-02) sets the sequence
from a Clean receipt to a checkable delivery claim, and this release
ships its first step: the `bellbook-core-v1` baseline profile, the
content-addressed agreement two parties name so their receipts are
comparable. A profile is a report alongside the verdict, never a change
to it. No record or receipt wire change - the spec epoch stays 0.3 and
the 0.3 corpus is byte-unchanged - and existing 0.3-0.6 receipts and
rules validate identically. The Python package gains the profile check
and baseline-default rules immediately after the core publish (the
bindings track the published crate).

### Added

- **The `bellbook-core-v1` baseline profile** (RFC-0003 section 4.5,
  SPEC section 12.2; #6). A Clean receipt is Clean under its own embedded
  rules; two organizations could not compare receipts without first
  agreeing what those rules must look like. This profile is that
  agreement, kept small and unsigned: six clauses over the rule shape
  (B1 the receipt is not Invalid; B2 author roles are registered; B3
  evidence thresholds for Candidate, Evaluation, and Selection are
  present and no weaker than the schema base class; B4 a bounded context
  size is declared; B5 retraction and reaffirmation authority are
  reported; B6 the binding mode of every accepted Candidate is
  reported). The clause table is content-addressed - `sha256` over its
  RFC 8785 canonical form - and published with the hash in
  `spec/profiles/bellbook-core-v1/profile.json`; seven vectors in
  `cases.json` pair receipts with the exact result each must yield, with
  a rejecting vector for every failable clause, generated from and
  drift-checked against the reference by `tests/profile_vectors.rs`.
  Profile conformance is a report alongside the verdict: it never
  changes `status` or `reason` and is never a verdict reason.
- **`validate_with_profiles`** in the core and `--require-profile ID`
  (repeatable) on `bellbook validate`. `Report` gains a `profiles` field
  (empty unless requested; reports written before this field parse
  unchanged) carrying id, hash, status (`Conformant`, `NonConformant`,
  or `Unknown` for an id the validator does not know), and per-clause
  results with a detail string. New exit code `3`: the receipt validates
  but a required profile is not met (an unknown profile counts as not
  met). `bellbook::profiles` exposes the clause table, the hash, and the
  evaluator.
- **Independent profile evaluation** in the Python validator
  (`conformance/python/bellbook_profiles.py`): every clause implemented
  from scratch, the profile hash recomputed from the published table,
  and every vector in `cases.json` re-derived and compared.
- **`VerifierRules::with_evidence_threshold` and
  `with_baseline_thresholds`** builders. The baseline thresholds are
  Candidate `Reported`, Evaluation `Reported`, Selection `Inferred` -
  exactly the schema base classes, so they admit every record the
  schemas admit today and reject only assumption-class evolution
  records.

### Changed

- **`bellbook rules init` emits the baseline evidence thresholds** so a
  generated rule set conforms to `bellbook-core-v1` out of the box. Rules
  generated by earlier versions stay valid and keep their `rules_hash`;
  they are NonConformant under the baseline until the three thresholds
  are added (which changes the hash, as any rules change does). The
  quickstart's `rules.json` is updated accordingly. The Python
  `default_rules(...)` helper gains the same defaults with the bindings
  release that follows the core publish.

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
