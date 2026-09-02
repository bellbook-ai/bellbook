# Bellbook specification

**Spec version: 0.3 (first published as `bellbook` 0.3.0; also implemented by
0.4.0 and later).** The previous epoch
is 0.2; its artifacts remain valid under v0.2 rules forever, and the
published 0.2.x release is their validator (§14). This document is
versioned independently of the `bellbook` crate; the crate's CHANGELOG
states which spec version each release implements (see §14). The v0.3
design notes are in [`spec/v0.3-delta.md`](spec/v0.3-delta.md); this
document is the normative description of what the implementation does.

This document is **normative**: conformance is defined by this
specification, not by any implementation. Where the reference
implementation or its tests disagree with this document, that is an
implementation bug (or, if the document is wrong, a spec bug to be fixed
by a documented spec change) - implementations never redefine meaning.
Please file an issue for any divergence found.

## 1. Model

Bellbook has one durable primitive: a typed **Record** in an append-only
**Log**. A single-writer **commit protocol** appends each record together with
a deterministically derived **Verdict**. A **Verifier** can replay any log
from genesis (or from a **Checkpoint**) and confirm every rule below. Derived
**State** is a pure fold over accepted records and is reproducible by anyone
holding the log.

Trust boundary: everything *proposing* records (LLMs, tools, humans, the host
runtime) is untrusted. Truth is only what committed to the log and what the
verifier derives from it.

## 2. Records

```
Record {
  id:       Hash256   // SHA-256 of the canonical form (see §3)
  space:    Hash256   // trust domain; refs never cross spaces
  thread:   Hash256   // conversation/work grouping
  time:     u64       // logical counter, strictly time == prev + 1
  author:   { id, type, signature? }
  kind:     Kind
  schema:   Hash256   // SHA-256(utf8(schema name)), e.g. "bellbook.request.v1"
  data:     bytes     // JSON payload for the schema
  refs:     [ { type, target: RecordId } ]  // sorted, deduped
  evidence: Deterministic | Verified | Reported | Inferred | Assumed
}
```

**Kinds:** `Request`, `Action`, `Response`, `Result`, `Summary`, `Approval`,
`Capability`, `Usage`, `Refusal`, `Verdict`, `Plan`, `Retraction`,
`Candidate`, `Evaluation`, `Selection`.

**Author types:** `User`, `Provider` (LLM), `System`, `Executor` (tool),
`Verifier` (verdicts only).

**Normative kind-to-author-type table.** The verifier enforces which
author types may produce each kind; a violation rejects with
`AuthorRoleInvalid`. Signatures cannot substitute for this check: a
validly signed actor could still declare a forbidden author type or emit
a forbidden kind.

| Kind | Allowed author types |
|------|----------------------|
| `Request` | `User` |
| `Action`, `Response`, `Summary`, `Plan` | `Provider` |
| `Result` | `Executor` |
| `Approval` | `User` |
| `Capability` | `User`, `System` |
| `Usage` | `Provider`, `System` |
| `Refusal` | `User`, `System` |
| `Retraction` | `User`, `Provider`, `System` |
| `Verdict` | `Verifier` |
| `Candidate` | `User`, `Provider`, `Executor`, `System` |
| `Evaluation` | `User`, `Provider`, `Executor`, `System` |
| `Selection` | `User`, `Provider`, `System` |

Rationale: authority-granting and authority-exercising roles must never
coincide. Capabilities and approvals come from the human principal (or,
for capabilities, deployment configuration), never from the governed
agent or its executor; results come only from the executor that ran the
tool; retraction is open to every accountable party (an agent retracting
its own wrong claim is behavior the model rewards) but never to the
`Executor` or `Verifier`, whose records are attestations that others
retract. Candidates and evaluations are things any accountable actor may
honestly report producing or observing; selections are decisions, so
`Executor`, the role that performs work, may not author them. One
consequence, stated because recovery flows depend on it:
Executor-authored evaluations are retractable only through
`admin_retraction_actors`. Hosts that want evaluation retraction without
administrative override author evaluations as `Provider` or `System`; a
deployment decision, not an accident.

**Identity-to-role binding.** The declared `author.type` is
adversary-controlled - a governed agent could simply *claim* `User` on an
Approval - so the table alone prevents accidents, not impersonation.
`VerifierRules::author_roles` binds actor ids to roles: a registered
actor's records must declare exactly the registered role, and for
**every kind except `Verdict`** the author MUST be registered
(`AuthorRoleInvalid` otherwise) - an unregistered actor claiming `User`
could otherwise close requests with Refusals, inject Summaries into
context, skew Usage feedback, or retract records. `Verdict` stays on
its deterministic special path.
Combined with `author_keys` (§3.2), the identity itself becomes
cryptographic: a pinned actor's records must be validly signed under a
pinned key (unsigned records claiming that identity reject with
`SignatureMissing`), the key proves who signed, and `author_roles`
proves what that identity is allowed to be. A pinned Provider key
signing an Approval that declares `User` rejects. Without pinned keys,
role registration binds the id to a role but does not authenticate who
supplied the id - pin keys for every authority-bearing actor in
production.

**Retraction ownership.** A `Retraction` is valid only when its author is
the target's author, or when the retractor is listed in
`VerifierRules::admin_retraction_actors` (an explicit administrative
override, e.g. the human principal). One actor declaring another's
record wrong is contrary evidence or a `Refusal` - never a retraction,
which has operational teeth (§7.1).

**Ref types:**
- `Cause` - this record exists because of the target (Result → Action,
  Verdict → subject, delegated Request → parent).
- `Use` - the target's content was used as input. A `Use` ref may name a
  rejected, retracted, or tainted record (an actor may genuinely have
  consumed bad input), but such a target contributes floor evidence
  (`Assumed`) to derivation (§7).
- `Require` - the target must be accepted state for this record to be valid
  (Action → Capability/Approval). Enforced generically for every kind: a
  `Require` ref whose target is rejected, retracted, or tainted rejects
  the record with `RefUnresolved`.
- `Replace` - this record supersedes the target. The target is never deleted;
  it enters `state.replaced_records`. Only `Summary`, `Capability`,
  `Approval`, `Plan`, and `Selection` records may be replaced, and only by a
  record of the same kind with a compatible payload (a `Selection` Replace is
  a *reaffirmation*, §7.1).

Payload structs for every kind live in `src/record/payloads.rs`; frozen
schema-name constants in `src/base/schema.rs`.

**Evolution kinds (spec 0.3).** Three kinds record how autonomously
produced software states are proposed, judged, and chosen:

- `Candidate` (`bellbook.candidate.v1`): `{ source: SourceBinding, basis:
  root | continuation | derivation, parent: Option<RecordId>, note:
  Option<String> }`. `SourceBinding` is `{ git: { algo: sha1 | sha256,
  tree, commit? }, manifest_hash: Option<Hash256>, binding: reported |
  manifest }`: identity binds to the Git **tree** (two commits with the
  same tree are the same software state); `commit` is provenance, never
  identity. A `reported` binding proves the claim was recorded, not that
  the OIDs match any contents; a `manifest` binding additionally commits
  to the canonical manifest of the tree and is the authoritative identity
  when both are present.
- `Evaluation` (`bellbook.evaluation.v1`): `{ candidate: RecordId,
  criterion: String (non-empty), procedure: Option<String>, outcome:
  passed | failed | scored { value, scale } }`. Exactly one criterion per
  record: retraction is record-granular, so per-metric evaluations let one
  broken metric be retracted without erasing the others. `value` is
  bounded to the I-JSON safe range and `scale` to 0 through 12, enforced
  at decode (`InvalidPayload`).
- `Selection` (`bellbook.selection.v1`): `{ objective: String (non-empty),
  considered: [RecordId], outcome: selected { candidates: [RecordId] } |
  none, rationale: Option<String> }`. Set-valued: one survivor for
  best-of-N or a repair accept, several for population evolution.

**Canonical manifest v1.** A `manifest` binding's `manifest_hash` is
`SHA-256` over the JCS bytes of a canonical manifest: a JSON object mapping
each repo-relative POSIX path to `{ "mode": <string>, "sha256": <64-hex> }`.
Modes are `100644` and `100755` (the `sha256` is over the file bytes as
materialized, with no EOL or attribute normalization), `120000` (symlink;
over the target string), and `160000` (gitlink; over the submodule commit
OID as a lowercase-hex ASCII string with no trailing newline, sourced from
the Git tree object and never worktree state, so initialized and
uninitialized submodule checkouts of the same tree yield the same manifest -
a gitlink commits to the pointer only, never to submodule contents).
Directories are implicit and empty directories are unrepresented; `.git` is
excluded. The manifest object is never stored or embedded; only the hash
rides in the payload. This makes `manifest_hash` algorithm-independent (the
same for a SHA-1 and a SHA-256 Git object format, submodules aside), and it
is the authoritative identity when it and the tree OID disagree - a
disagreement is detectable only by materializing the tree and recomputing,
the same boundary §7 draws for `Verified`. The verifier never recomputes a
manifest (§13); a party holding the tree does, via
[`manifest_hash`](src/manifest.rs).

The evolution rules ([`spec/v0.3-delta.md`](spec/v0.3-delta.md)) are
implemented: lineage, selection, reaffirmation, and Selection
approval-binding (D3, D4, D5) in §4.1 and §7.1, and standing (D6, D7) in
§7.2 and §12. The canonical manifest (D2) is computed by
[`src/manifest.rs`](src/manifest.rs).

## 3. Identity and hashing

- Canonical id form = the record with only `id` omitted, serialized as
  **RFC 8785 (JCS)** canonical JSON: object members sorted by the UTF-16 code
  units of their names, no whitespace, minimal JCS string escaping, and
  ECMAScript number formatting. A completed `author.signature` is included;
  for unsigned records the absent signature field is omitted, preserving one
  canonical unsigned form.
  `id = SHA-256(canonical id form)`. An independent JCS implementation in any
  language computes byte-identical canonical forms and therefore identical
  ids.
- Integers must stay within the I-JSON safe range (|n| ≤ 2^53 − 1); the
  serializer errors rather than lose precision. Hash-valued fields
  serialize as JSON arrays of 32 byte values; payload `data` serializes as
  a JSON array of byte values.
- **Canonical payloads:** a record's `data` MUST be exactly the JCS
  canonical serialization of its schema's payload type. The verifier
  decodes the payload and re-encodes it canonically; any byte difference
  rejects with `InvalidPayload`. This uniformly rejects duplicate keys,
  unknown fields, non-canonical member order, whitespace, and
  non-canonical number spellings - so two conforming verifiers can never
  reach different verdicts through permissive-parsing differences.
- Refs are sorted by (ref-type ordinal, target bytes) and deduplicated
  **before** hashing.
- Schema ids are `SHA-256(utf8(name))` of frozen names, e.g.
  `bellbook.request.v1`.

Because ids are content addresses and refs point at ids, the log is a DAG in
which any mutation of history invalidates every dependent record.

### 3.1 Test vectors

[`spec/test-vectors-v0.4.json`](spec/test-vectors-v0.4.json) contains one
record of every kind from a fixed unsigned scripted log (the frozen v0.3
and v0.2 vectors remain at
[`spec/test-vectors-v0.3.json`](spec/test-vectors-v0.3.json) and
[`spec/test-vectors-v0.2.json`](spec/test-vectors-v0.2.json)): the record's exact
canonical id form (the JCS bytes fed to SHA-256, with `id` omitted and the
absent signature field omitted) and the resulting id, plus the UTF-8 names the
space/thread/scope hashes derive from. It also contains a deterministic signed
Request with its secret-key seed, public key, signing form, signature, completed
canonical id form, and final id, plus a valid alternate-key signature and id.
The substitution case demonstrates that changing signers changes identity;
substituting only the key on the original envelope fails verification. A
third-party implementation conformance-tests canonicalization, signing, strict
verification, and hashing without running Rust. The vectors are regenerated
only on an intentional format change (a new spec version); the crate's test
suite fails if the implementation drifts from the committed vectors.

### 3.2 Signatures

Records may carry a detached **Ed25519** (RFC 8032) signature in
`author.signature`:

- The signature covers the canonical, domain-separated **signing form**:
  `{"domain":"bellbook.record-signature.v0.3","record":<record form>}`,
  where `<record form>` is the record with `id` and `author.signature`
  omitted and the whole envelope is serialized as JCS. The explicit protocol
  and spec-epoch domain prevents a signature made for another protocol or
  Bellbook epoch from being replayed as a v0.3 record. After signing, the
  record id is computed from the canonical id form (§3), which includes the completed
  signature. This avoids a circular dependency while ensuring signature
  removal or substitution changes the record id and every dependent ref and
  head attestation.
- `signature.key_id` is the signer's public key as exactly 64 lowercase
  hex characters (self-describing - a verifier needs no side channel to
  check integrity). `signature.sig` is the 64 signature bytes. Lowercase
  is the only accepted spelling: uppercase or non-hex `key_id` content is
  `SignatureInvalid`, so conforming verifiers agree byte-for-byte on what
  verifies.
- Verification is **strict** (`verify_strict` semantics: non-canonical
  point encodings and weak keys are rejected), so conforming
  implementations agree on the same accept/reject boundary.
- Which kinds *require* a signature is rules-configurable
  (`signature_required_kinds`; empty by default; must not include
  `Verdict` - verdicts are materialized unsigned by the commit protocol).
  **In addition, a key-pinned actor's records always require a
  signature**, regardless of kind: an actor id is just a string anyone
  can write, so an unsigned record claiming a pinned identity would
  bypass exactly the authentication pinning exists to provide. A
  required-but-absent signature rejects with `SignatureMissing`. Any
  *present* signature, required or not, must verify - else
  `SignatureInvalid`.
- Key→identity binding: `author_keys` maps an actor id to the set of
  public keys it may sign with. For listed actors, a signature under any
  other key is `SignatureInvalid`. Unlisted actors may sign with any key
  (the signature then proves integrity and key possession, not identity).
  Key generation, storage, and rotation are host concerns. Pair with
  `author_roles` (§2) to bind the identity to a role: the key proves who
  signed, the role registration proves what that identity may author.

Why Ed25519: deterministic signatures (no nonce-reuse catastrophes),
small keys and signatures (32/64 bytes), fast verification, ubiquitous
library support in every ecosystem a third-party verifier would be
written in, and standard in the transparency-log ecosystems external
anchoring targets (§11.1).

## 4. Verification

### 4.1 verify_record

`verify_record(record, prior, rules, state) -> VerdictData` deterministically
judges one record against the committed prefix. Checks include: id
recomputation, space match, schema→kind consistency against the frozen map,
author role against the normative table (§2), ref ordering (refs must be
strictly sorted by (ref-type ordinal, target) and
deduplicated, so equal content always yields equal ids),
ref resolution (targets must exist, in the same space), replacement validity,
evidence must equal the derived evidence (§7), canonical payload
round-trip (§3), and per-kind rules:

- an `Action` must name an active `Request` **in whose scope it
  operates** (`ActionData.scope == RequestData.scope` - a capability
  held for another scope must not let a provider serve a request with
  out-of-scope actions) and resolve a non-retracted,
  non-tainted `Capability` (`Auto`, or `Ask` plus an unexpired,
  non-retracted `Approval` - exact, class, or wildcard, in that
  priority), **and must carry `Require` refs naming the exact capability
  and (for Ask) the exact approval that authorize it** - so the audit
  graph shows which authority allowed each action, and retracting that
  authority taints the action (`AuthorityRefMissing` otherwise). The
  exact-approval target is `SHA-256(canonical((action_author_id,
  ActionData)))` - it binds the acting author together with the action
  content, so one actor's approval never authorizes another actor's
  byte-identical action - the matched approval's `actor_id` must equal
  the acting author and its declared `scope` must equal the action's
  scope (an approval must not visibly claim one scope while authorizing
  another through its hash), and **exact approvals are single-use**: an accepted
  action consumes the approval (it leaves `valid_approvals`), so
  repeating the identical action needs a fresh approval. Class approvals
  stay reusable - that is their explicit purpose;
- a `Result` must close an open `Action` with a matching exec-mode
  schema; an external result must additionally be signed by an author
  with pinned keys (§7);
- a `Response`'s `turn_index` must equal the count of previously accepted
  responses for its request (gap-free, in order), and
  `closes_request = true` is only valid when the request has no open
  actions **and no running plan** (a plan must reach Completed or
  Abandoned first - a final response must not silently strand in-flight
  work);
- an `Approval` must set exactly one of `target_action`/`action_class`,
  and the exact form must declare its subject `actor_id`;
- a `Summary` must carry at least one `Use` ref to its sources (a claim
  with no sources is unfounded, and sources are epistemic dependence);
- a `Usage` record's payload `actor` must equal its envelope author, and
  its consuming record must be an accepted Result/Refusal in the same
  thread;
- `Plan` task graphs must be acyclic, `inputs_from`/`depends_on` must
  name real tasks, and a task's `result_record_id` - allowed only on
  `Done`/`Failed` tasks - must resolve to an accepted `Result` whose
  action belongs to the plan's request. **Plans are advisory
  orchestration metadata, not compliance proof**: `result_record_id` is
  a *related result* (supporting evidence), not task-to-proof binding -
  there is no task id in `ActionData`, so the verifier cannot bind a
  specific task to a specific action, and it does not check task/result
  status agreement or citation uniqueness. The checks above keep plans
  internally consistent and their citations real; they do not make a
  Completed plan a proof object;
- a `Request`'s parentage is unambiguous: `parent_request_id: None`
  means zero Request `Cause` refs, and a declared parent means exactly
  one `Cause` ref naming exactly that parent - contradictory delegation
  graphs (undeclared, surplus, or mismatched parents) reject;
- a `Retraction` must Cause-ref an accepted record that is neither a
  `Verdict` nor another `Retraction`, and its author must own the target
  or be a configured administrator (§2, §7.1).

The evolution kinds (spec 0.3) add the lineage and selection battery.
Three payload fields (`CandidateData.parent`, each `SelectionData.considered`
member, and `EvaluationData.candidate`) are **payload ids, not refs**; each
must resolve, in the same space, to a previously accepted `Candidate`, else
`PayloadRefUnresolved`. Retracted or tainted targets still resolve: those
conditions surface through refs, evidence, and standing, never through
payload lookup.

- a `Candidate`'s `source` must be well-formed (`tree`, and `commit` when
  present, lowercase hex of the length its `algo` dictates - 40 for `sha1`,
  64 for `sha256` - and `manifest_hash` present exactly when
  `binding == Manifest`), else `SourceBindingInvalid`. Its `basis`
  obligations must hold, including acceptance of every `Cause` target at
  commit position: `Root` allows at most one `Cause`, targeting an accepted
  `Request`, and no `parent`; `Continuation` requires exactly one `Cause` to
  an accepted `Selection` whose outcome is `Selected`, with `parent` naming a
  member of that selected set; `Derivation` requires one or more `Cause`
  refs, each an accepted `Candidate` or `Evaluation` (never a `Selection`),
  and no `parent`. Violations reject with `LineageInvalid`. `Continuation`
  uses `Cause`, not `Require`, deliberately: a candidate's evidence reflects
  its own content and a tainted history must never block recording ongoing
  work; the lineage consequence of the anchor's health is carried by
  standing (§7.2);
- an `Evaluation` must `Use` the record named in its `candidate` field (the
  epistemic subject edge, so a retracted candidate taints its evaluations),
  else `EvaluationInvalid`; `criterion` non-empty and `outcome` within the
  §2 bounds are enforced by the canonical payload decode (`InvalidPayload`);
- a `Selection`'s `considered` must be non-empty, unique, and no longer than
  `max_considered`. When the outcome is `Selected`, its `candidates` must be
  non-empty, unique, a subset of `considered`, and named by `Require` refs;
  the `Require` targets must be exactly the selected set plus, when the rules
  demand it, the one authority approval below (no other `Require` targets);
  each winner must meet `min_binding`; and when `selection_requires_evaluation`
  (default true) at least one **accepted** `Evaluation` must be `Use`d. Every
  `Use`d accepted `Evaluation`'s `candidate` must appear in `considered`.
  Only accepted evaluations count: `Use`-ing a rejected Evaluation is legal
  (it degrades the Selection's evidence like any `Use` of bad content) but a
  repudiated judgment is not evaluation evidence. A `None` decision
  carries no candidate `Require` refs. Violations reject with
  `SelectionInvalid`. The winner `Require` refs also give commit-time teeth
  under the generic rule: a Selection whose winner is retracted or tainted at
  commit position rejects with `RefUnresolved`;
- a `Selection` carrying a `Replace` ref is a **reaffirmation** (§7.1): the
  target must be a `Selection` with the same `objective`, and when
  `reaffirmation_actors` is configured the author must be listed. Violations
  reject with `ReaffirmationInvalid`.

When `selection_requires_approval` is set, a `Selection` must additionally
`Require` a valid, unconsumed approval whose **subject hash** is

```
SHA-256(canonical((
  "bellbook.selection-approval.v0.3",   // domain
  selection_author_id,
  replace_target_id_or_null,            // the Replace target when present, else null
  SelectionData
)))
```

This parallels the Action exact-approval binding (which has no domain
prefix): the matched approval's declared `actor_id` must equal the selecting
author, it must be unexpired, and an accepted Selection consumes it
single-use, through a consumption step parallel to the Action path (a later
`Replace` of the consuming Selection never refunds it, matching v0.2, where
no code path un-consumes). The Replace target is inside the hash so an
approval granted for a fresh decision cannot be diverted onto a reaffirmation
with identical `SelectionData`: approving a decision and approving the
*restoration of a compromised line* are different acts. A missing or
unusable approval rejects with `ApprovalMissing`; an expired one with
`ApprovalExpired`.

`VerdictData { result: Accept | Reject, reason: Option<ReasonCode> }` with
reason codes:

`UnknownSchema`, `KindSchemaMismatch`, `SignatureMissing`, `SignatureInvalid`,
`RefUnresolved`, `RefCrossSpace`, `RequestMissing`, `CapabilityMissing`,
`CapabilityDenied`, `ApprovalMissing`, `ApprovalExpired`, `ActionClosed`,
`ReplacementInvalid`, `ExternalReceiptRequired`, `EvidenceBelowThreshold`,
`Refused`, `InvalidPayload`, `InvalidCheckpoint`, `AuthorRoleInvalid`,
`AuthorityRefMissing`, `SourceBindingInvalid`, `LineageInvalid`,
`PayloadRefUnresolved`, `EvaluationInvalid`, `SelectionInvalid`,
`ReaffirmationInvalid`.

Signature checks follow §3.2: `SignatureMissing` for a required-but-absent
signature, `SignatureInvalid` for any present signature that fails strict
Ed25519 verification or was made with a key not pinned for its actor.

**Selection rule knobs** (`VerifierRules`, spec 0.3): `min_binding`
(default `Reported`, i.e. no constraint) is the minimum source binding a
Selection's winners must carry; `Manifest` rejects a selection over
merely reported bindings with `SelectionInvalid`. `selection_requires_evaluation`
(default true) requires a `Selected` Selection to `Use` at least one
`Evaluation`. `reaffirmation_actors` (default empty) is an identity
allowlist for reaffirming Selections; empty means the Selection
author-role row alone governs. `max_considered` (default 4096) bounds a
Selection's `considered` list; because `considered` members carry no refs,
this bound is independent of `max_refs_per_record` (`ValidationLimits`,
§12), and a
comparative Selection that `Use`s one Evaluation per considered candidate
is still bounded by the receipt ref limit. `selection_requires_approval`
(default false) requires every Selection to carry the bound approval above.
`reject_compromised_continuation` (default false) rejects, with
`LineageInvalid`, a `Continuation` whose anchor Selection is unsound
(retracted or tainted) at its commit position; by default such a
continuation commits and is born standing-compromised (§7.2).

### 4.2 verify_log

`verify_log(records, rules, checkpoint?) -> LogVerdict` replays a whole log:

1. If a checkpoint is given, every field is validated (`InvalidCheckpoint`
   on any mismatch) **before anything else, including the empty-log
   case**: `log_length` must fit the actual log, so a records slice
   shorter than the checkpoint's coverage (including an empty slice,
   i.e. attested history was deleted) rejects; `log_hash` must
   equal the recomputed `SHA-256(concat(ids))` over the prefix; the boundary
   must not split a subject/verdict pair; and `last_time`,
   `last_record_id`, and `state_hash` must agree with the verified prefix
   and the state rebuilt from it.
2. Enforce strictly gap-free logical time: `records[i].time ==
   records[i-1].time + 1`, and the first record of a non-empty log at
   `time == 1` unconditionally. A checkpoint covering an empty prefix
   grants nothing: replay starts at genesis and the genesis-time rule
   applies.
3. Recompute every record's `id` from the replay start point onward.
4. From the replay start point onward, require every non-verdict record
   to be **immediately followed** by its verdict, and verify the verdict
   record's own envelope in full - a
   forged log can put anything in a verdict record: id recomputes;
   verdict schema and `Verifier` author type; **no signature** (verdicts
   are deterministic verifier output with no external signer, so every
   conforming implementation must materialize the same unsigned envelope;
   a present signature rejects, and would be included in the id);
   space equals the verifier's space; evidence is `Deterministic`;
   payload decodes as `VerdictData`;
   exactly one ref, a `Cause` edge to a resolving prior non-verdict
   subject in the same space and thread (an unresolved subject rejects
   with `RefUnresolved`, never passes); at most one verdict per subject.
5. **Re-derive each verdict** with `verify_record` against the replayed state
   and compare with the stored verdict - stored verdicts after the replay
   start are checked, never trusted. Records inside a checkpoint prefix are
   attested by the prefix hash rather than re-derived; because checkpoints
   must align to pair boundaries, every verdict after the replay start is
   always re-derived.
6. Fold accepted records into `State` as it goes.

## 5. Commit protocol and crash recovery

`LogWriter::open` takes an exclusive file lock (`.lock`), replay-verifies
the complete prefix under the supplied rules, recovers an interrupted tail,
re-verifies the result, and restores a private time counter. Raw storage and
intent machinery are not public APIs: callers receive read-only record access
through the locked writer, while durable writes go through `LogWriter`.
`LogWriter::open` rejects a file larger than 64 MiB before reading it and
enforces the same bound before append. Each commit reserves capacity for its
complete subject/verdict pair before either frame is written;
`open_with_max_bytes` lets a host opt a trusted larger log into an explicit
limit.

`commit(proposal, rules, state)` first requires the rules to match those used
at open and the supplied derived state to equal the state rebuilt from the
current log; `RulesMismatch` or `StateMismatch` is returned before any
write. It then:

1. Derive evidence from the proposal's schema and its refs' evidence (§7).
2. Without advancing logical time, materialize the complete pair: assign the
   next two times, sort/dedup refs, attach the optional writer-produced
   signature over the signing form, compute the final subject `id`, run
   `verify_record` against the prior prefix, and materialize its deterministic
   verdict (`Cause` → subject).
3. Preflight serialization and reserve file capacity for **both** frames.
4. Write intent file (`.intent`, `written: false`), fsync.
5. Append the subject record, fsync; update intent to `written: true`.
6. Append the already-derived verdict record, fsync.
7. Clear the intent file and apply subject + verdict to in-memory `State`.
8. Publish the two consumed logical times only after the durable pair and
   state fold succeed.

Any error before the durable phase leaves the handle reusable and consumes no
logical time. Once the intent is durable, an error makes that handle return
`RecoveryRequired` on all later write attempts; the caller must drop and reopen
it so open-time recovery can inspect and repair the tail.

Recovery on open occurs only after the complete prefix has replayed
successfully: **the log tail is the final recovery authority, never the
intent file.** A commit appends the fsynced subject first and its
verdict second, so the only interrupted-commit signature is a trailing
non-verdict record; whenever the final complete record is not a Verdict,
its verdict is recomputed and appended - regardless of whether `.intent`
is present, absent, empty, or torn (a crash can leave any of those, and
none may change the outcome). The intent file is a crash-marker only and
is cleared after recovery. Intent updates are atomic and durable
(temp-file write, fsync, rename, directory fsync where the platform
supports it), so a crash mid-update leaves the old intent or the new
one - never a truncated file. A torn trailing frame in the log file
(from a crash mid-append) is truncated away on open, so subsequent
appends continue from the last complete record. Frames are refused
before they can overflow the u32 length prefix (`RecordTooLarge`), and
frame-boundary arithmetic is checked so hostile lengths cannot overflow a
platform `usize`.

`batch_commit` orders proposals by the SHA-256 of their canonical form before
committing, so batch commit order is deterministic and independent of caller
order. It commits those pairs sequentially: every subject/verdict pair has the
failure-atomic guarantee above, but the batch as a whole is not transactional.
If a later pair errors, earlier pairs remain durable. Hosts that may retry use
the compare-and-append contract below rather than blindly retrying
`batch_commit`.

### 5.1 Appender contract: idempotent compare-and-append

Serious hosts crash-retry, and duplicates in an append-only ledger are
permanent pollution - so appends MUST be idempotent. The contract:

- The appender supplies the **expected parent head** - the id of the last
  record the batch was built against (all zeros for an empty log).
- If the log is at that head, the batch commits normally.
- If the identical batch - recognized by content, in deterministic batch
  order - already landed immediately after the expected head, the call is
  a **success no-op returning the same resulting head** (and the same
  per-record verdicts, read back from the log) as the original append,
  even if unrelated records were appended afterwards. A crash mid-batch
  leaves a batch prefix landed; a retry recognizes the prefix and commits
  only the remainder, converging on the same head.
- Anything else - the log moved to a different head with records that are
  not this batch, or an unknown expected head - is a **conflict**
  (`HeadConflict`), never a duplicate append. The appender then rebuilds
  its batch against the current head.

The library affordance is `LogWriter::checked_batch_commit(expected_head,
proposals, rules, state)` with `LogWriter::head()` as the token source.
A retry must resend the identical batch. The caller's `state` must
reflect the current log (rebuild via `build_state_unchecked` after
reopening); the writer checks exact equality before both normal and no-op
appends, and remains bound to the rules used at open.

## 6. Storage format (`persist` feature)

`records.log` is a flat file of length-prefixed frames: `u32` big-endian
length followed by the record's canonical JSON. Sidecar files: `.lock`
(exclusive writer lock), `.intent` (commit intent). The full log is held in
memory with an id → position index; `scan(from, to)` returns records by
logical-time range.

## 7. Evidence

Evidence is a five-class ordered lattice describing how a record's content
is known, strongest → weakest:

| Class | ≈ | Meaning |
|-------|---|---------|
| `Deterministic` | proven | Derived by the verifier itself (Verdict records). |
| `Verified` | attested | A signed attestation from a key-bound external party (see below - what is verified is the attestation's origin, never the real-world effect). |
| `Reported` | - | An external party (user, provider, executor, host) asserted it. |
| `Inferred` | - | Derived by reasoning from other records. |
| `Assumed` | - | Proceeded on an unverified assumption. |

Base evidence by schema - every frozen schema is classified explicitly (an
exhaustive mapping; adding a schema requires classifying it):

- `bellbook.verdict.v1` → `Deterministic`
- `bellbook.result.external_receipt.v1` → `Verified`
- `bellbook.request.v1`, `bellbook.action.v1`, `bellbook.response.v1`,
  `bellbook.result.v1`, `bellbook.result.effect_confirmation.v1`,
  `bellbook.capability.v1`, `bellbook.approval.v1`, `bellbook.refusal.v1`,
  `bellbook.usage.v1`, `bellbook.candidate.v1`, `bellbook.evaluation.v1`
  → `Reported`
- `bellbook.summary.v1`, `bellbook.plan.v1`, `bellbook.selection.v1`
  → `Inferred`

A candidate's binding and an evaluation's outcome are host-asserted; a
selection is a judgment derived by reasoning. Under these bases, and
because a Selection `Use`s its evaluations and `Require`s its winners
while continuation edges are `Cause`, evaluations derive at most
`Reported`, selections at most `Inferred`, and evidence does not compound
across generations.

No core schema has base `Assumed`; it is the floor, reserved for
host-declared assumptions and for evidence degradation. Unknown schemas
(rejected with `UnknownSchema` regardless) map to `Assumed`, never to a
stronger class. `bellbook.result.effect_confirmation.v1` is deliberately
`Reported`, not `Verified`: it asserts an observation the verifier cannot
check, which is exactly the Reported class.

**What `Verified` means for external results.** The
`bellbook.result.external_receipt.v1` schema earns its `Verified` base
only because the verifier enforces that such a record is a **signed
attestation from a key-bound executor**: it must carry an Ed25519
signature (verified strictly, §3.2) and its author must have pinned keys
in `author_keys` - otherwise it rejects (`SignatureMissing` /
`SignatureInvalid`). What is verified is that the named executor really
produced this attestation about this action - never that the claimed
real-world effect held, which no log-level verifier can check.
Verification of receipt *content* against external systems (issuers,
transparency logs, in-toto/SCITT-style statements) is a host or profile
concern layered on the `output` payload.

Effective (derived) evidence = weakest of (base, evidence of every record
referenced by a **`Use` or `Require`** ref), where a rejected, retracted,
or tainted target contributes the floor (`Assumed`) - depending on
invalid or withdrawn content is an unverified assumption. `Cause` and
`Replace` refs
are provenance, not epistemic dependence: exactly as they do not
propagate taint (§7.1), they do not affect derivation - a Result exists
*because of* its Action and truthfully reports what the tool returned
without resting on the action's claim. The verifier rejects records whose
stored evidence differs from the derived value, so evidence can never be
inflated: a summary over reported inputs is at best `Inferred`; anything
resting on an `Assumed` input is `Assumed`.

**Evidence thresholds.** `VerifierRules::evidence_thresholds` maps a Kind
to a minimum evidence strength. A record whose derived evidence is weaker
than the threshold configured for its kind is rejected with
`EvidenceBelowThreshold`. Policies like "the highest-confidence claims may
only rest on proven/observed inputs" are expressed as a threshold (e.g.
`Summary → Verified`), not as special-case rules. No thresholds are
configured by default.

### 7.1 Retraction and taint

A `Retraction` (`bellbook.retraction.v1`) asserts that an accepted
record's content was **wrong, and nothing replaces it**. This is a
distinct kind rather than a payload on the `Replace` machinery - a
deliberate design decision: `Replace` expresses *supersession* (a
same-kind record with a compatible payload identity takes over the slot,
and only `Summary`/`Capability`/`Approval`/`Plan` are replaceable), so it
cannot express negation-without-successor, and it cannot target a
`Result` at all - the paradigm retraction case.

Rules:

- A Retraction carries `RetractionData { target_id, reason }` and exactly
  one `Cause` ref to `target_id`. The target must be an accepted record in
  the same space (any thread); it may be of any kind except `Verdict`
  (the verifier's own deterministic output is not retractable - dispute
  the *subject*, not the judgment) and `Retraction` (retraction is not
  un-assertable; contrary evidence is a new record, not an undo).
- Retraction is **append-only**: nothing is edited or deleted. The target
  stays in the log; its id enters `state.retracted_records`.
- **Taint** propagates forward through the DAG to dependents via `Use`
  and `Require` refs, transitively. `Cause` refs do **not** propagate
  taint: causation is provenance, not epistemic dependence - a `Result`
  exists because of its `Action` and truthfully reports what the tool
  returned even if the action's stated intent proves wrong; a record that
  *rests on* another's content must say so with a `Use` (or `Require`)
  ref. `Replace` refs likewise do not propagate (the replacement stands
  on its own content).
- Taint is implemented **on the evidence-derivation engine**: for records
  committed after the retraction, a `Use`/`Require` ref to a retracted or
  tainted record contributes the floor class (`Assumed`) to weakest-link
  derivation - taint *is* evidence degradation. Records committed before
  the retraction have immutable stored evidence, so they are surfaced via
  `state.tainted_records` instead (maintained through the reverse
  epistemic-dependence index `state.epistemic_dependents`).
- **Replay of a tainted chain still passes.** Taint marks claims
  unreliable; it never makes honest history unverifiable. `verify_log`'s
  report carries `retracted_records` and `tainted_records` (populated on
  Accept), so a consumer distinguishes three outcomes: *clean* (Accept,
  empty sets), *tainted* (Accept, non-empty sets), *invalid* (Reject).
- **Retracted authority is deactivated operationally, not just marked.**
  Retracting a `Capability` or `Approval` removes it from the active
  authority maps, and the verifier additionally refuses to let a
  retracted or tainted authority record authorize a new `Action` - a
  grant whose content was asserted wrong must stop granting, so
  governance state and epistemic state always agree. (Planned
  supersession is still `Replace`; expiry is still expiry - retraction is
  the "this was wrong" path.) For non-authority kinds, retraction leaves
  operational slots (open actions etc.) untouched: it is an epistemic
  marker, and closing an open action is what `Result`/`Refusal` are for.
  Retracted records are excluded from context selection (§9); tainted
  records are not.

Worked example: an `Action` runs, its `Result` reports success, and a
`Summary` is committed with a `Use` ref to that result ("the change is
deployed and working"). Later the real-world outcome contradicts the
result - the change was reverted. The host appends a `Retraction`
targeting the result. The result's id enters `retracted_records`; the
summary, reached through the `Use` edge, enters `tainted_records`. The
log still replays Accept - the history of what happened is intact - but
any consumer of the report knows the summary's claim no longer rests on
anything. A later summary that tried to `Use` the retracted result would
derive `Assumed` evidence and could be rejected outright by an evidence
threshold.

**Reaffirmation (spec 0.3).** A `Selection` may `Replace` a prior
`Selection` under the **same `objective`** (the objective string is the
compatibility key, so hosts treat objectives as identifiers, not prose).
This is a new decision over the same objective on evidence that currently
stands: all the ordinary Replace semantics apply (at most one `Replace`
ref, a same-kind accepted target, the target enters `replaced_records` and
leaves context construction, no taint or evidence effect, and several
records may `Replace` one target). It is append-only in the same sense as
retraction: the earlier Selection and any retraction on its line stay
permanently in the log. Reaffirmation exists to restore standing for a
line whose anchor was later compromised; that restoration is a replay-time
report dimension (§7.2). The verifier rule here is the objective-match and,
when configured, the `reaffirmation_actors` allowlist; the restoration
consequence is derived at replay end.

### 7.2 Standing

**Standing** answers, for each candidate: does its membership in a chosen
line still rest on states and decisions that stand? It is derived at replay
end, from accepted records only, as a pure function of the log - exactly as
deterministic and forgery-resistant as the taint sets, because a validator
re-derives it. It is **not** kernel taint: it does not affect evidence
derivation, does not gate commits by default, and is reported alongside
taint, never merged with it.

A `Selection` is **unsound** at replay end iff it is retracted or tainted.
(A rejected Selection can never be an anchor: the `LineageInvalid` rule
requires every `Cause` target of a Candidate to be accepted at commit, and
acceptance is permanent, so an anchor becomes unsound only later, via
retraction or taint.)

**Anchor soundness** for a continuation candidate C with `Cause` to
Selection S and `parent` P: S itself is sound, or some accepted, sound
Selection S2 exists with a `Replace` chain to S (one or more hops, every
intermediate accepted) whose selected set contains P. Any sound replacement
suffices (an existential over the fixed replay-end set, so the result is
deterministic and order-independent). Intermediates need only be accepted,
not sound.

**Standing recursion** (well-founded; all edges point to earlier records):

- A **retracted Candidate is compromised, unconditionally and
  unrestorably**; no anchor, parent, or reaffirmation rule applies to it. A
  state asserted wrong has no legitimate membership in any line, and without
  this base case a same-tree derivation of a retracted candidate would
  re-enter the line with sound standing.
- A `Root` candidate (not retracted) is sound.
- A `Continuation` candidate (not retracted) is sound iff its anchor is
  sound and its parent's standing is sound.
- A `Derivation` candidate (not retracted) is sound iff every `Cause`d
  Candidate has sound standing; Evaluation targets carry no standing, so a
  derivation with only Evaluation targets is sound.

Whenever any candidate is compromised, some record is necessarily retracted
or tainted, so the report status is already `Tainted` under the unchanged
v0.2 status mapping; standing only adds which lineage is affected and what
restored it. Standing does not reject new continuations of an unsound
Selection by default; they commit and are born compromised (a ledger that
cannot record ongoing work stops being a ledger, and rejection would create
the perverse incentive to mislabel continuations as derivations). Rules MAY
opt into commit-time strictness with `reject_compromised_continuation`.

**Reachability pre-commitment.** `parent`, each `considered` member, and
`EvaluationData.candidate` are edges a ref-walking tool cannot see.
Reachability over the evolution kinds is therefore **payload-aware**: any
future garbage collection, synchronization, or checkpoint tooling MUST treat
these payload ids as reachability edges, or it would silently sever the
standing spine. This is recorded now, before any such tooling exists, so no
later stage inherits ref-only reachability as a hidden default.

## 8. State

`State` is a pure fold over (record, verdict) pairs - rejected records change
nothing. It tracks accepted ids, active requests, open actions and their
per-request counts, active capabilities/approvals/summaries/plans, replaced
records, usage counts, and the epistemic sets from §7.1: retracted record
ids, tainted record ids, and the reverse `Use`/`Require` dependence index
that lets a late retraction taint dependents committed before it. Invariant: incrementally applying each pair
(`apply_record`) yields a `State` identical to rebuilding from scratch
(`build_state_unchecked`) for any log.

`State` serializes to valid JSON (and canonicalizes under JCS): maps whose
keys are not strings - tuple and hash keys - serialize as sorted sequences
of `[key, value]` pairs.

Request lifecycle: a request leaves `active_requests` only on an
**explicit terminal event** - a `Response` with `closes_request = true`
(valid only when the request has no open actions) or a `Refusal`
targeting the request itself. Completion is never inferred from a
transient zero count of open actions: sequential workflows (action →
result → next action) and plan updates on the same request remain valid
until the request is explicitly closed.

State also tracks the per-request accepted-response count
(`response_turns`, backing the turn-ordering rule) and reverse indexes
from capability/approval record ids to their lookup keys
(`capability_index`, `exact_approval_index`, `class_approval_index`), so
a retraction deactivates authority in O(log n) without scanning.

## 9. Context

`build_context(records, state, rules, thread)` deterministically selects the
working set shown to an untrusted proposer: accepted, non-replaced,
non-retracted, **non-tainted**, non-verdict records of one thread, newest
first (ties broken by id), capped at `rules.max_context_records`, plus
usage-feedback counts for the selected records. Retracted records are
excluded because their content was asserted wrong; tainted records
(unreliable, resting on retracted content) are excluded **by default** -
the safe behavior is not opt-in. A host that wants them anyway uses
`build_context_with(..., ContextPolicy::IncludeTainted)`, and the
returned `Context::tainted_records` identifies which selected records
are tainted so they can be labeled.

## 10. Checkpoints

`Checkpoint { log_length, last_time, last_record_id, state_hash, log_hash }`
where `log_hash = SHA-256(concat(record ids))` and `state_hash =
SHA-256(canonical(State))`. `verify_log` can start from a checkpoint after
validating all five fields against the actual prefix (§4.2 step 1);
checkpoint boundaries must align to subject/verdict pairs. Checkpoint
validation precedes every other check: presenting fewer records than the
checkpoint covers - including none at all - rejects with
`InvalidCheckpoint`, so a retained checkpoint detects deletion or
truncation of the history it attests. A checkpoint over an empty prefix
accelerates nothing and exempts nothing (§4.2 step 2).

**Checkpoint trust.** A checkpoint skips verdict re-derivation and
per-kind rule checks for its prefix - that is the acceleration. Prefix
record ids are still recomputed (content-binding), but forged verdicts
inside the prefix are *attested by the checkpoint, not detected*. The
**only** source of checkpoint trust is a prior successful replay
verification of the prefix under the exact same rules. The API enforces
this with an opaque `TrustedCheckpoint` type that `verify_log` requires:
it cannot be deserialized from the wire and is produced either by
`TrustedCheckpoint::from_verified_log` (runs full verification, succeeds
only on Accept) or by the explicit, greppable
`TrustedCheckpoint::assume_verified` assertion (for re-hydrating a
checkpoint that an earlier verification produced and that was stored
where the ledger's writer cannot rewrite). The checkpoint is bound to the
rules it was verified under; a rules mismatch rejects with
`InvalidCheckpoint`.

External anchoring (§11.1) is **not** a trust path. An anchored
attestation proves particular bytes existed at a point in time and were
not subsequently changed - it says nothing about whether those bytes
ever passed verification, and an attacker can anchor a forged history.
Anchoring protects an *already-verified* checkpoint against later
rewriting; it never substitutes for verification. A checkpoint supplied
by the same untrusted party as the records proves nothing, which is why
receipts carry none (§12).

## 11. Threat model

Bellbook is **tamper-evident, not tamper-proof**, and this section states
plainly where the line sits. Overselling tamper-evidence would get the
format copied badly; an integrator has to know exactly what a green
replay does and does not prove.

**What replay verification detects.** Any *interior* edit to committed
history - modifying a record's bytes, deleting or inserting a record,
reordering, forging or altering a verdict - breaks id recomputation,
gap-free logical time, subject/verdict pairing, or verdict re-derivation,
and the log rejects. Content addressing makes every dependent ref break
too.

**What it does not stop.** The ledger's *owner* - anyone with write access
to the storage and no external constraints - can discard the entire log
and rewrite history from genesis: re-propose whatever records they like,
re-run the commit protocol, and produce a fully self-consistent forgery
that replays green. Replay proves internal consistency, not provenance.
Two further honest limits:

- A verifier and producer must agree on `VerifierRules` out of band; a
  verdict re-derivation is only meaningful under the rules the producer
  committed under.
- Acceptance is not truth. An accepted record proves the claim was made,
  in order, under the governance rules - the evidence lattice (§7) is what
  grades how much the *content* can be trusted.

**Mitigations** (integration guidance, deliberately not library code):

1. **Signatures (§3.2).** Pin actors' keys in `author_keys` and require
   signatures for the kinds that matter. A from-genesis rewrite then
   cannot re-forge those actors' records without their private keys.
   Signatures bind authorship, not sequence - combine with anchoring.
2. **External anchoring.** Periodically store the head attestation
   (§11.1) somewhere the ledger's writer cannot rewrite: the host's own
   database, a transparency log, a timestamping service, or simply a
   counterparty's records. A rewrite-from-genesis (or truncation to an
   old prefix) then diverges from the anchored head. Anchoring cadence
   bounds the exposure window: history older than the last anchor is
   bound; unanchored recent history is not.

### 11.1 Head attestation format

The thing an integrator anchors is a fixed, minimal, JCS-canonical
structure, so independent anchoring implementations stay interoperable -
any witness receives exactly these bytes:

```
HeadAttestation {
  head_hash:    Hash256  // SHA-256(concat(record ids)), whole log -
                         // the same computation as Checkpoint.log_hash
  record_count: u64      // records covered (subjects and verdicts)
  spec_version: string   // e.g. "0.3"
  timestamp:    string   // canonical RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`), host-supplied wall-clock time
}
```

The Rust API represents the wire string as `CanonicalUtcTimestamp`; both
construction and deserialization reject every other spelling or an invalid
calendar value. Canonical bytes = RFC 8785 serialization of the structure
(fields in JCS key order: `head_hash`, `record_count`, `spec_version`,
`timestamp`).
To audit against an anchor, recompute `head_hash` over the log prefix of
`record_count` records and byte-compare. An anchor attests *existence
and immutability* of those bytes - it never attests that they were
verified, and it is never a substitute for replay verification or a
source of checkpoint trust (§10). Witness services, transports,
and anchor storage are host concerns; this spec defines only the format.

## 12. Receipts

A **Receipt** is the portable form of a ledger: a self-contained bundle a
third party validates offline, without trusting the producer.

```
Receipt {
  spec_version: string          // e.g. "0.3"
  rules:        VerifierRules   // what the log was committed under
  records:      [Record]        // full sequence from genesis
}
```

A receipt deliberately carries **no checkpoint**: checkpoint trust must
come from outside the artifact being validated (§10), and a checkpoint
inside an untrusted receipt would let the producer attest their own
forged prefix. `validate(bytes) -> Report` therefore always replays from
genesis, re-deriving everything from the receipt's own bytes: record ids
(JCS canonicalization + SHA-256), gap-free logical time, subject/verdict
pairing with full verdict re-derivation, signature verification, evidence
derivation, and taint status. The `Report` carries
a three-way status - **Clean** (verified, no retracted/tainted claims),
**Tainted** (verified history containing retracted or tainted claims,
each listed by id), **Invalid** (unparseable, unsupported spec version,
or failed replay) - plus the recomputed `head_hash` (compare against an
externally anchored head attestation, §11.1) and `rules_hash` (compare
against rules agreed out of band: acceptance is always relative to the
embedded rules, and a validator cannot know whether those rules are the
ones the parties intended).

The `Report` also carries a **`standing`** section (§7.2), re-derived on
every validation exactly like the retracted and tainted sets; the receipt
embeds nothing standing, so there is nothing to forge. Its content:
`compromised` (the standing-compromised Candidate ids), `unsound` (the
unsound Selection ids), and `restorations` (for each unsound Selection with
at least one sound replacement chain, the set of sound replacing Selection
ids). Sets are id-byte-ordered like the existing report sets, and
`restorations` encodes as pairs sorted by key id with each value set
id-byte-ordered, so conforming implementations produce byte-identical
sections. A validator that derives a different `standing` section from the
same records is nonconforming, which the conformance corpus detects the same
way it detects taint disagreement.

Receipt decoding is strict for this version. Unknown fields in the
receipt, rule document, record envelope, author, signature, ref, or typed
payload are structural failures, as are duplicate logical keys in rule
maps and pair-encoded maps. This prevents extension-looking data that the
validator did not actually enforce and gives every conforming validator
one interpretation of the same wire document. Future extensions require
a new spec or schema version rather than silently ignored fields.

**"Clean" is relative to the embedded rules.** Under default rules no
signatures are required and no evidence thresholds are set, so Clean
means "this history is internally consistent under the rules it names" -
not "this meets a shared security baseline". Receipts are comparable
across organizations only when the parties compare `rules_hash` against
an agreed rule set, or name a profile (§12.2): the `bellbook-core-v1`
baseline is that agreement, evaluated on request as a report alongside
the verdict, not a change to this spec version.

Validation is resource-bounded: `validate` applies default
`ValidationLimits` (64 MiB receipt bytes - the same default as the CLI,
so parsing an adversarial receipt cannot demand gigabytes of memory
before per-record limits are reached - plus record count, per-record
payload bytes, and refs per record), and
`validate_with_limits` lets callers tighten, raise, or lift them. Limit
violations are structural failures (Invalid), reported before any
verification work. Deriving state from an untrusted log goes through
`verify_and_build_state` (verification first, state only on Accept);
`build_state_unchecked` trusts stored verdicts and is only for logs that
already passed replay.

The reference CLI wraps this for auditors with no Rust knowledge:
`bellbook validate <file>` prints the human-readable report;
`--json` prints the same report as JSON; `--max-size <bytes>` bounds the
file size before it is read (default 64 MiB, `0` = unlimited) - the CLI
is the trust boundary for untrusted receipts, so the bound lives there.
Exit codes: 0 clean, 1 invalid, 2 valid-but-tainted.

### 12.1 Future profile design principles (non-normative)

Future receipt profiles should prevent silence from being mistaken for
evidence. In particular, a profile that introduces required claims or
verification attempts should define explicit representations for
conflicting evidence, checks that did not run or failed open, and values
that were not measured. The current core has no `Inconclusive` result,
Requirement record, or verification-attempt record, so these principles
are intentionally not part of core conformance.

Existing core mechanisms still preserve useful facts without erasure:
refusals record work that was not performed, rejected records remain in
the log, evidence classes distinguish asserted or inferred content from
verified content, and retractions mark claims that later proved wrong.
They do not, by themselves, implement a complete truth-reporting profile.

### 12.2 Profiles

A **profile** is a separately versioned document with a stable id, a
canonical hash of its normative clauses, and a predicate over the embedded
rules, the records, and the validation report. A validator evaluates a
profile on request and reports **Conformant**, **NonConformant** (naming
the failing clauses), or **Unknown**; profile conformance is a report
alongside the verdict and is never a verdict reason. Profile documents
live under `docs/profiles/` and their vectors under `spec/profiles/`,
separate from the core conformance corpus so that no profile can
destabilize it.

Earlier drafts of this section sketched a "task receipt profile" the core
could not express - there was no Requirement record, no structured
evaluator decision, and artifact identity would have been parsed out of an
opaque `output` string - and the sketch was removed rather than promise
what could not be checked. [RFC-0003](docs/rfcs/0003-requirement-binding.md)
(accepted 2026-09-02) restores it as checkable design, in this sequence:

- **`bellbook-core-v1`** (crate 0.7.0, this epoch, validator-side only): the
  content-addressed baseline fixing what Clean, Tainted, and Invalid mean
  under a declared rule shape, with no signature requirement.
- **Spec epoch 0.4** (crate 0.8.0): the `Requirement` record, first-class
  artifact identity (`ArtifactRef`), the extended `Evaluation` with the
  shared decider-binding vocabulary, the attested evaluation schema, and
  receipt profile declarations (`profiles: [ProfileRef]`).
- **`delivery-receipt-v1`** (crate 0.9.0): the grammar of a delivery claim
  - requirement, evidence, evaluator decision, artifact identity,
  capability profile - with its own fraud-rejection vectors.
- **`bellbook-core-signed-v1`** (crate 1.0.0): the signed tier above the
  baseline.

The baseline is implemented: `bellbook validate --require-profile
bellbook-core-v1` evaluates it, the clause table and its hash are
published in `spec/profiles/bellbook-core-v1/profile.json` with vectors
in `cases.json` beside it, and the profile document is
[docs/profiles/bellbook-core-v1.md](docs/profiles/bellbook-core-v1.md).
Nothing else in this list is implemented until the release named beside
it.

### 12.3 Conformance

An implementation may claim **Bellbook conformance for a given spec
version** iff it (a) passes that version's published test vectors (§3.1)
and (b) implements the normative schemas and verification rules in that
version, including the strict receipt decoding requirements above.
There is no badge program and no registry - the claim is defined so that
it can be checked, disputed, and falsified by anyone holding the vectors.

Beyond the per-kind hashing vectors, `spec/conformance/<version>/`
publishes a machine-readable **conformance corpus**: accept and reject
cases that pair a portable input (records and rules, or a raw receipt
document) with the expected verdict, receipt status, reason code, and
derived-state hashes. It covers author-role binding, the signature
matrix, capability and approval resolution (including expiry and
single-use exact approvals), retraction taint (which follows `Use` and
`Require` refs but not `Cause`), validation-limit failures, and at least
one triggering case for every verdict rejection reason the portable format
can express. A conformant validator re-derives each stored outcome from the
stored input. The corpus README documents the wire encoding and the three
reason codes (`Refused`, `InvalidCheckpoint`, `RefCrossSpace`) that the
single-space, checkpoint-free receipt format cannot express and that the
reference implementation's own test suite exercises instead.

### 12.4 Read-side queries (the named set)

Implementations may expose the **named query set** of
[RFC-0002](docs/rfcs/0002-read-side-queries.md): seven deterministic,
read-only queries over canonical record relationships - `descent`,
`descendants`, `siblings`, `frontier`, `standing`, `evidence`,
`selected` - answerable identically over a verified log or a receipt.
The set is closed and its semantics are fixed. Queries derive from what
replay already computes (never stored, never ranked), answer only over
verified state (an input that does not verify is an error, not answers),
address only accepted records (a rejected record made no claim), and
annotate every reported record with its standing, taint, and retraction
status rather than filtering anything silently. `selected` matches its
objective exactly; there are no patterns, predicates, or composition
(RFC-0002 section 7). The set reaches records through the relationships a
decision creates: an accepted Evaluation that no Selection ever `Use`d
grounded no decision, so it is not part of any line's evidence and the
named set does not surface it - such a record is reachable only by
enumerating the log directly.

The queries are surface, not wire format: they change no record, schema,
or receipt byte, and carry no spec-version implications. Their authority
chain is RFC-0002 (semantics and edge cases), this section (existence
and boundaries), and the corpus's `query-cases.json` (executable
answers: each vector pairs a receipt and a query with the exact surface
JSON the query must return, and every name appears at least once). An
implementation claiming the read-side surface re-derives each stored
answer from the stored receipt, as the independent validator in
`conformance/python/` does.

## 13. Known limitations

- **Integrity, not confidentiality.** Records and receipts carry full
  payloads in the clear (prompts, responses, action parameters, tool
  output); content addressing and signatures prove integrity and origin,
  never secrecy. A receipt inherits the sensitivity of everything
  committed to the log, and sharing one is disclosure. Hosts MUST NOT
  place credentials or secrets in record payloads, SHOULD redact or
  minimize sensitive content before commit, and own encryption, access
  control, and retention. Selective disclosure (e.g. commitment-based
  attachments revealing hashes instead of content) is future work.
- **Bellbook proves consistency, not completeness.** The untrusted host
  controls what gets captured: an action can be omitted before anything
  reaches the log, and a perfectly Clean receipt can therefore be an
  internally consistent *subset* of what actually happened. What replay
  proves is that the captured history is tamper-evident, rule-conforming,
  and honestly graded - capture completeness depends on how the
  integration instruments its runtime, which is outside this spec.
  (External anchoring, §11.1, bounds *when* history could have been
  edited; it cannot conjure records that were never written.)
- **A receipt carries no source contents.** A `Candidate`'s Git OIDs are
  pointers whose resolution requires the repository; the receipt proves the
  recorded process (which candidates, evaluations, and selections existed,
  under what objective, and what is retracted, tainted, or
  standing-compromised), not the bytes of any tree. Under `manifest`
  binding a party holding the tree can recompute `manifest_hash` and bind
  the receipt to actual contents; under `reported` binding they hold a
  verifiable record of an unverified claim, and the receipt says which,
  explicitly.
- **Lineage, standing, and taint are conditional on the producer's
  recording discipline.** A candidate's `basis`, `parent`, and choice of
  refs are producer claims. A host that records what is really a
  continuation as a derivation escapes the standing cascade, and no
  verifier can detect that, because intent is not checkable. Bellbook proves
  the recorded structure is internally consistent under its rules; it does
  not prove the structure faithfully mirrors the development process. A
  receipt consumer trusts the embedded `rules_hash` *and* the producer's
  recording conventions - this is the "consistency, not completeness"
  boundary above, extended one level to the lineage graph. Standing is a
  replay-derived advisory over that recorded structure, reported alongside
  kernel taint and never merged into it: it never gates a commit by default
  and never changes a record's evidence.
- Author identity is cryptographically bound only for actors pinned in
  `author_keys` on records that carry signatures; unsigned records (and
  unpinned actors) remain claims. Key management and rotation are host
  concerns.
- Verdicts inside a checkpoint prefix are attested by the checkpoint
  rather than re-derived (ids are recomputed; all checkpoint fields are
  validated). Checkpoint trust is the caller's responsibility (§10);
  receipts never carry one.
- The in-memory log index assumes logs fit comfortably in RAM.
  `LogWriter::open` and appends use a 64 MiB default file bound, configurable
  through `open_with_max_bytes`; passing `u64::MAX` is only for trusted
  storage. Receipts carry the full record sequence, so the same general bound
  applies to validation. Validation cost is linear in the number of records plus
  hashing proportional to total content size: ref resolution, subject
  lookup, and duplicate-verdict detection go through an id index built
  during replay, never per-lookup scans of the prefix. `ValidationLimits`
  (finite by default; `unlimited()` opts out) bounds the input a
  validator will accept at all.

## 14. Spec versioning and backward validity

This specification carries its own version, independent of the crate
version; the crate's CHANGELOG states which spec version each release
implements.

- **Backward validity guarantee:** a ledger or receipt that is valid under
  spec vN remains verifiable under vN's rules forever. Verifiers keep vN
  rule-sets, keyed by the schema version they find in the records or the
  receipt; a newer spec version never invalidates an existing artifact.
- Payload schema names (`bellbook.<kind>.v1`) version payload *shapes*;
  the record envelope, evidence classes, and canonicalization are governed
  by the spec version, which portable artifacts (receipts, head
  attestations) carry explicitly. Hosts embedding raw logs pin the crate
  version, whose CHANGELOG names the spec version it implements.
- Spec 0.4 is the third and current compatibility epoch, opened by
  [RFC-0003](docs/rfcs/0003-requirement-binding.md) and first released in
  crate 0.8.0. It adds to 0.3 without changing anything 0.3 defined: the
  record envelope, canonicalization, id form, signing form, and the
  fifteen 0.3 schemas are byte-for-byte those of 0.3, so the signing
  domain stays `bellbook.record-signature.v0.3` (the domain names the
  signing form, which last changed in 0.3; a 0.3 signature must keep
  verifying). A 0.4 validator **dispatches on the receipt's
  `spec_version`**: a 0.3 receipt replays under the 0.3 schema set (a
  schema introduced by 0.4 rejects as `UnknownSchema` there, even if the
  embedded rules map it) and reaches the identical decision its own
  epoch's validator reached; a 0.4 receipt replays under the full set. An
  unsupported version is a structural `Invalid` with a clear report.
  Three gates hold this: the 0.3 vectors and corpus are byte-frozen
  (`tests/frozen_v03.rs`), every stored 0.3 outcome re-derives under the
  0.4 validator (`tests/epoch_v03.rs`), and CI replays the 0.3 receipts
  through the published 0.7.0 binary (`scripts/epoch_check.py`).
- Spec 0.3 is the second compatibility epoch, first released in crate
  0.3.0 and implemented through crate 0.7.0: fifteen kinds, signing
  domain `bellbook.record-signature.v0.3`, vectors at
  `spec/test-vectors-v0.3.json` and corpus at `spec/conformance/v0.3/`,
  both frozen. A v0.3 validator rejects a v0.2 receipt as `Invalid` with
  a clear unsupported-version report; v0.2 artifacts remain valid under
  v0.2 rules, whose validator is the pinned, published 0.2.x release.
- Spec 0.2 is the first published compatibility epoch. The backward-validity
  guarantee starts with artifacts produced under this version.
