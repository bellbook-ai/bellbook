# RFC-0003: Requirement binding, artifact identity, and the delivery-receipt profile

**Status:** Draft (2026-08-28). This document specifies the design for the
v0.7.0, v0.8.0, and v0.9.0 milestones (tracking: #106, #6, #107, #108, #89,
#10, #109, #110, #111, #112, #113). It proposes the **first spec change
since epoch 0.3**: one new record kind, one new shared type, additive
fields on three existing payloads, and a receipt-envelope field, landing
together as spec epoch 0.4 in v0.8.0. Everything else here is profile and
validator work with no wire change. Where this design and SPEC.md differ
about the present, SPEC.md is authoritative.

**Scope anchor:** SPEC §12.2 deliberately removed a sketched "task receipt
profile" from the normative spec because the core could not express it -
there was no Requirement record, no structured evaluator decision, and
artifact identity would have been parsed out of an opaque string. This RFC
fills exactly that gap and nothing wider: it gives a delivery claim the
shape requirement -> evidence -> evaluator decision -> artifact identity ->
capability profile, and makes the claim checkable by a party who trusts
none of the actors that produced it.

**Gate honesty (drift control):** this work sat in the Gated milestone
under RFC-0001 §15. The signal that moves it is a committed adopter with a
concrete artifact to emit. That adopter is connected to this project, so it
does **not** satisfy §15 criterion 1 ("no connection to this project") and
reaches criterion 5 only after its cutover validates receipts inside its own
loop. Under VISION's build-ahead note, accepting this RFC is therefore the
explicit, recorded decision to set the gate aside for one cluster - the
requirement-binding and profile primitives named here - and no other.
Native storage, distribution, the runtime, the general query engine, #9,
#11, and #12 remain gated on independent adoption. Wire formats never build
ahead of their gates; this RFC is the gate record for the one wire change it
proposes.

---

## 1. Summary

A portable **delivery receipt**: a Bellbook receipt carrying a claim that
every required requirement of a request was met by bound evidence, judged
by an evaluator distinct from the producer, over an exactly identified
artifact, under a named capability profile - and a validator, including an
independent one sharing no code with the reference, that rejects the claim
on replay when any of that does not hold. Three primitives make it
expressible (`Requirement`, `ArtifactRef`, an extended `Evaluation`), one
mechanism makes it comparable (profiles), and one profile makes it a
delivery receipt (`delivery-receipt-v1`). No scoring, thresholds, or domain
logic enters the core or the profile; the profile defines the grammar of a
claim, and an agent that has never heard of any particular adopter can emit
and check one.

## 2. Motivation

Two sources of evidence, both first-party or first-party-adjacent, and
neither speculative.

**The project's own field tests.** Field test 1 (2026-08-26) recorded an
evaluation faithfully but could not say what actually ran: `Evaluation`
carries a free-form `procedure` string, which is narrative, not evidence
(#89). A verifier could confirm the evaluation was recorded and by whom,
not that two receipts' "unit-tests" mean the same check. Field test 2
(2026-08-28, `docs/field-tests/ft2-read-side.md`) confirmed the read side
answers every lineage question but surfaced that an evaluation no selection
used is unreachable - evidence that grounds no decision has no place in
the record's story. Both point the same way: evidence needs binding, and
decisions need a shape.

**A committed adopter's delivery receipts.** The adopter emits its own
stopgap receipt format today, precisely because Bellbook cannot express
the claim it needs a skeptic to check. Its inputs (held privately; nothing
in them is reproduced here) established six constraints that a neutral
design must satisfy, and that a naive design would miss:

1. Decisions may be **unsigned yet content-addressed and independently
   recomputable**. That combination must be first-class, distinct from
   signed attestation, with a promotion path to signed that reshapes
   nothing.
2. **Decision strength is not uniform.** Some evaluators recompute every
   fact they judge from the bound evidence; some check facts as declared
   by the producer. A record that presents both as one uniform verdict
   hides exactly what a skeptic needs.
3. **Some requirements are informational.** They belong in the record but
   do not count toward the claim.
4. **The outcome space is richer than pass/fail.** A missing prerequisite
   yields a complete but non-passing decision; so do stale or insufficient
   evidence. Every one of these must be distinguishable, and none may
   certify - fail-closed.
5. **Identity digests must be replay-stable.** An artifact's identity
   excludes recording timestamps and other non-semantic fields, so two
   replays converge on the same reference.
6. **Provenance is not structure.** Whether a requirement was confirmed by
   a person or derived by an agent is a separate axis from what the
   requirement is.

The principles the adopter states publicly - producer and evaluator must be
distinct actors; a verifier recomputes rather than trusts; a green build is
not evidence; receipts are content-addressed and re-checkable; fail-closed
- are Bellbook's own principles restated. The fit is not a coincidence and
not a favor: the substrate was designed for this class of claim, and this
is the first concrete instance of it.

## 3. Design constraints

- **C1: neutral grammar, no domain content.** The profile defines the
  shape of a delivery claim. Requirement keys, criteria, evaluator
  identities, artifact schemes, and capability profile ids are strings the
  adopter supplies; the core validates form, never meaning. There is no
  ranking, scoring, or threshold anywhere in core or profile (VISION design
  rule 2).
- **C2: the kernel `Verdict` is never an evaluator's judgment.** An
  evaluator's decision is domain evidence - `Reported`, or `Verified` when
  attested by a pinned key - and lives in an `Evaluation`. The verifier's
  `Verdict` remains the deterministic judgment that a record follows the
  ledger's rules (docs/INTEROPERABILITY.md). The two never share a record.
- **C3: replay decides, not cryptography alone.** The claim invariants are
  semantic checks the validator re-derives from the records. A forgery
  that keeps every hash consistent still fails, because the check is over
  content, not over digests. Digests bind; replay judges.
- **C4: cross-implementation testable.** Every new rule and every profile
  clause has corpus vectors; the independent Python validator implements
  them from scratch and must agree byte-for-decision.
- **C5: profiles are separate documents with separate vectors.** A profile
  cannot destabilize core conformance: its vectors live apart, its
  conformance is a report alongside the verdict, never a verdict reason.
- **C6: additive and canonical.** New payload fields are required in the
  new epoch (empty permitted), never optional-absent, so canonical bytes
  stay unambiguous. Records of an earlier epoch validate under that
  epoch's rules; a validator dispatches on the receipt's `spec_version`.
- **C7: no new evidence class.** The five-class lattice (SPEC §7) is
  unchanged. Promotion from `Reported` to `Verified` uses the existing
  attested-schema pattern (`bellbook.result.external_receipt.v1`): a schema
  whose base class is `Verified` and whose signature and key binding the
  verifier enforces.

## 4. Design

### 4.1 The `Requirement` record (spec 0.4, #107)

A statement of what a request requires, addressable by id so evidence and
decisions can bind to it.

```
Kind::Requirement, schema bellbook.requirement.v1, base evidence Reported

RequirementData {
  key:               String       // non-empty; unique among accepted
                                  // Requirements under the same Request
  description:       String       // non-empty
  required:          bool         // false = informational: recorded, but
                                  // not counted toward any claim
  expected_evidence: Option<String>
  provenance:        Provenance   // user_authored | derived
}
```

Rules:

- Exactly one `Cause` ref, to an accepted `Request` in the same thread.
  The requirement belongs to that request.
- A duplicate `key` under the same request is rejected
  (`RequirementInvalid`), as are an empty key or description.
- **Provenance is bound to authorship.** `user_authored` requires an author
  of type `User`; `derived` requires `Provider` or `System`. An `Executor`
  never authors a Requirement. "Confirmed by a person" is thereby a
  replay-verifiable fact about who wrote the record, not a flag anyone can
  set (draft decision, open question Q1).
- Amendment is append-only: a wrong requirement is retracted and a new one
  recorded; `Replace` is not accepted on Requirements in v1 (Q5).

### 4.2 First-class artifact identity: `ArtifactRef` (spec 0.4, #108)

```
ArtifactRef {
  scheme: String          // non-empty token: [a-z0-9][a-z0-9.-]*
  digest: String          // lowercase hex; even length; 20..=64 bytes
  name:   Option<String>
}
```

- **Scheme-tagged.** Registered schemes and their fixed digest lengths:
  `git-tree-sha1` (20 bytes), `git-tree-sha256` (32), `manifest-v1`
  (Bellbook's canonical manifest, SPEC §5.1, 32), `git-archive-tar-v1`
  (SHA-256 over an archive of a tree, 32), `oci-image-manifest` (32),
  `sha256-bytes` (32). Unknown schemes are accepted by the core with the
  generic length rule; profiles may restrict to registered ones. The
  canonical manifest is one scheme among several, not the only one.
- **Replay-stable.** A digest identifies content, never a recording; a
  scheme whose input includes timestamps or run identifiers is not a valid
  scheme.
- Carried as `artifacts: Vec<ArtifactRef>` on `Candidate` (produced or
  bound artifacts beyond the source binding), `Result` (produced artifacts
  and evidence bundles), and as `evidence: Vec<ArtifactRef>` on
  `Evaluation` (what was judged). Each vector is sorted and deduplicated
  by `(scheme, digest, name)`; malformed entries are rejected
  (`ArtifactRefInvalid`).
- `Candidate.source` is unchanged; `artifacts` adds to it.

### 4.3 The extended `Evaluation` and the decider-binding vocabulary (spec 0.4, #89)

`EvaluationData` gains, in addition to `candidate`, `criterion`,
`procedure`, and `outcome`:

```
evaluator:    DeciderBinding
basis:        Basis                 // recomputed | declared
evidence:     Vec<ArtifactRef>      // what was judged
requirements: Vec<RecordId>         // Requirements this evaluation speaks
                                    // to; sorted, deduplicated; each
                                    // mirrored by a Use ref

DeciderBinding {
  id:             String            // stable evaluator identity, non-empty
  version:        Option<String>
  procedure_hash: Option<Hash256>   // the exact procedure that ran
  input_hash:     Option<Hash256>   // the normalized input it judged
}
```

- **One vocabulary, defined once.** `DeciderBinding` is the shared shape
  for "who decided, with what procedure, over what input". `Evaluation`
  uses it now; the gated `PolicyDecision` (#9) reuses it when unlocked,
  instead of the parallel `engine_id` / `policy_set_hash` /
  `evaluation_input_hash` fields sketched there. #89's warning against a
  parallel vocabulary is honored by construction.
- **Basis is declared, never inferred.** `recomputed` means the evaluator
  re-derived the facts it judged from the bound evidence; `declared` means
  it checked facts as recorded. The record states which; a profile reports
  the weakest basis in a claim rather than hiding it.
- **Outcome vocabulary, fail-closed.** `EvaluationOutcome` gains
  `blocked`, `insufficient`, `stale`, and `not_run` alongside `passed`,
  `failed`, and `scored`. Only `passed` is a passing outcome. A complete
  decision that could not run to a pass is recorded as exactly what it is,
  never as a pass and never omitted.
- Each `requirements` entry must resolve to an accepted `Requirement`; it
  is mirrored by a `Use` ref, so a retracted requirement taints the
  evaluations that judged against it, as `Use` semantics already provide.
  Binding failures reject with the existing `EvaluationInvalid`.
- `procedure` (narrative) stays; `procedure_hash` is the binding.

**The attested schema.** `bellbook.evaluation.attested.v1` carries the same
payload with base evidence `Verified`; the verifier requires a signature by
a key pinned for the author in `author_keys`, exactly as it does for
`result.external_receipt.v1`. An unsigned evaluation and its attested
counterpart differ in schema id and nothing else, which is the promotion
path constraint 1 asked for.

### 4.4 The claim is a Selection

No new claim kind. A delivery claim is an accepted `Selection` with outcome
`Selected` whose `Use`d evaluations bind to requirements. The claim's
request is determined, not declared: it is the single `Request` that every
requirement referenced by the claim's evaluations belongs to. A claim whose
evaluations span two requests, or none, is not a delivery claim.

### 4.5 Profiles: the mechanism and its tiers (#6, #10, #113)

A **profile** is a separately versioned document with a stable id
(`NAME-vN`), a canonical hash of its normative clause table, and a
predicate over `(rules, records, report)`. The validator evaluates a
profile on request and reports **Conformant**, **NonConformant** (with the
failing clauses), or **Unknown** (the id is not known to this validator).
Profile conformance is a report alongside the validation verdict; it never
changes the verdict and is never a verdict reason code (C5).

- **v0.7.0 - the predicate, validator-side.** `bellbook validate
  --require-profile ID` and `bellbook.validate(data, require_profile=ID)`
  evaluate a profile over a receipt with **no receipt change**.
- **v0.8.0 - declarations.** The receipt envelope gains
  `profiles: [ProfileRef { id, hash }]` (additive; strict decoding makes
  this epoch-bound, hence 0.4). The validator evaluates every declared
  profile and reports each; a declared but unknown profile is reported
  `Unknown`, never an error.

**`bellbook-core-v1` - the content-addressed baseline (v0.7.0).** Small by
design (#6). Its value is that two parties naming it agree on what Clean,
Tainted, and Invalid mean and under which rule shape:

- B1: the receipt validates Clean or Tainted; Invalid never conforms.
- B2: `author_roles` is non-empty and every accepted record's author is
  registered (replay guarantees the second half; the clause states it for
  consumers).
- B3: `evidence_thresholds` carries entries for `Candidate`, `Evaluation`,
  and `Selection`, each no weaker than the schema base class (`Reported`,
  `Reported`, `Inferred`): the rules cannot admit assumption-class
  evolution records.
- B4: `max_context_records` is declared within `1..=100_000`.
- B5: retraction and reaffirmation authority are readable from the rules
  (`admin_retraction_actors`, `reaffirmation_actors`), so a consumer knows
  who could have retracted or restored.

No signature requirement. Not every adopter signs from day one, and a
baseline nobody can meet compares nothing.

**`bellbook-core-signed-v1` - the signed tier (v1.0.0, #113).** Everything
in the baseline, plus:

- S1: `signature_required_kinds` includes `Candidate`, `Evaluation`,
  `Selection`, `Retraction`, and `Requirement`.
- S2: `author_keys` pins every actor that authored one of those kinds.
- S3: every evaluation a claim rests on uses the attested schema.

A baseline-conformant receipt reaches the signed tier by adding signatures
and switching evaluation schemas; no payload changes shape.

### 4.6 `delivery-receipt-v1` (v0.9.0, #111)

The profile that makes a receipt a delivery receipt. Over a claim (4.4):

- D1 **Coverage.** Every accepted `Requirement` with `required: true` under
  the claim's request has at least one evaluation among the claim's `Use`d
  evaluations that references it and has outcome `passed`.
- D2 **Truthful completion.** No evaluation among the claim's `Use`d
  evaluations that references a required requirement has an outcome other
  than `passed`. A claim over a non-passing evaluation is rejected on
  replay, whatever its hashes say (C3).
- D3 **Binding equality.** Every evaluation the claim uses judges the
  claimed candidate (`candidate` equals the chosen candidate), and its
  `evidence` set is non-empty. Every `Result` the evaluations' evidence
  references carries the same artifact set. A claim rebound to a different
  candidate fails here.
- D4 **Separation.** The author of every evaluation the claim uses is a
  different actor from the author of the claimed candidate (producer and
  evaluator are distinct; Q4 covers the selector).
- D5 **Decider binding present.** Every evaluation the claim uses carries
  `evaluator.id`, `evaluator.procedure_hash`, and `evaluator.input_hash`,
  and a declared `basis`. The report names the weakest basis in the claim.
- D6 **Capability profile named.** The receipt declares (0.8) or is
  evaluated against (0.7 fallback) `bellbook-core-v1` or a stronger tier,
  and conforms to it.
- D7 **Standing.** The claim's Selection is sound and untainted at the
  receipt head. A retracted evaluation under the claim makes the claim
  NonConformant, as the standing section already records.

Its vectors are its own (`spec/profiles/delivery-receipt-v1/`): conformant
claims, and one rejecting case per clause - the fraud battery, including
the canonical forgery of flipping one bound evaluation to non-passing while
keeping every digest consistent (D2), and reattaching a genuine passing
claim to another candidate (D3).

### 4.7 Evidence classes

Unchanged (C7). `Requirement` is `Reported`. `Evaluation` stays `Reported`;
`Evaluation` (attested) is `Verified`. `Selection` stays `Inferred`: a
claim is a judgment derived by reasoning, and the lattice says so. What a
profile adds is not a stronger class but a checked shape.

### 4.8 Verifier rules and reason codes

Two new reason codes: `RequirementInvalid` and `ArtifactRefInvalid`. Every
other new failure maps to an existing code (`EvaluationInvalid` for decider
binding, basis, and requirement-ref failures; `AuthorRoleInvalid` for the
provenance-authorship rule; the existing signature codes for the attested
schema). Every new code and every new rule has at least one triggering
corpus case (#109).

### 4.9 Epoch 0.4

`SPEC_VERSION` moves to `0.4`. The 0.3 epoch is frozen: its corpus and
vectors are byte-unchanged, stay green under 0.3 rules in CI, and every
0.3 receipt validates identically under a 0.4 validator, which dispatches
on `spec_version` (C6). Epoch 0.2 already has this treatment.

## 5. Surfaces

- **Rust:** the new kind, type, and fields in `bellbook::record`; profile
  evaluation in `bellbook::profiles`; `validate` reports per-profile.
- **CLI (#110, #10):** `bellbook requirement add`; `--artifact SCHEME:DIGEST`
  on `candidate add` and `eval add`; `--requirement`, `--evaluator`,
  `--evaluator-version`, `--procedure-hash`, `--input-hash`, `--basis`, and
  the fail-closed outcomes on `eval add`; `bellbook validate
  --require-profile ID`.
- **Python:** `Writer.requirement(...)`; `artifacts=`, `requirements=`,
  `evaluator=`, `basis=`, and the outcome keywords on `evaluate`;
  `bellbook.validate(data, require_profile=...)` and `Report.profiles`.

Surface parity is a release rule: nothing ships core-only.

## 6. Conformance

- Epoch 0.4 test vectors and corpus (#109), with the independent Python
  validator extended from scratch and agreeing byte-for-decision.
- Profile vectors under `spec/profiles/NAME/`, separate from core
  conformance; the Python validator implements every profile clause.
- The corpus test asserts every reason code and every profile clause has
  at least one triggering case.

## 7. Non-goals (binding for v0.7 through v0.9)

No scoring, thresholds, or ranking in core or profile. No requirement
hierarchy, dependency graph, or lifecycle beyond append-and-retract. No
waivers: a waiver never becomes a pass, so it has no record shape here. No
signature requirement in the baseline. No `PolicyDecision` (#9), reference
adapter (#11), or selective disclosure (#12): each stays gated on
independent adoption. No cross-receipt claims. Nothing that re-opens
RFC-0001 §15 for the storage, distribution, runtime, or engine stages.

## 8. Validation and falsification criteria (pre-registered)

Recorded before implementation. Evaluation window: 90 days from shipping
v0.9.0.

**Validation - the design is the right shape if at least 2 hold:**
1. A committed adopter emits a real delivery receipt through the published
   0.9.0 surfaces, replacing its own format, and the independent Python
   validator confirms it holding nothing but the receipt and the
   content-addressed artifacts (field test 3, #112).
2. The fraud battery holds in both implementations: every clause D1-D7
   has a rejecting vector, and the canonical forgeries (D2, D3) are
   rejected on replay by the reference and the independent validator.
3. A party outside both projects verifies a delivery receipt, or asks a
   question about one - which simultaneously progresses RFC-0001 §15.

**Falsification - the shape missed if both hold:**
1. The adopter still needs a private side channel for facts the profile
   cannot express, after cutover, and
2. no party outside both projects engages a delivery receipt during the
   window.

**Decision rule:** falsified means `delivery-receipt-v2` is designed before
1.0 is declared; 1.0 does not ship on a profile that missed. Either way the
gated stages stay gated.

## 9. Sequencing

| Release | Spec epoch | Delivers |
|---|---|---|
| v0.7.0 | 0.3 | This RFC accepted; `bellbook-core-v1`; validator-side `--require-profile`; VISION and SPEC §12.2 reconciled |
| v0.8.0 | **0.4** | `Requirement`, `ArtifactRef`, extended `Evaluation`, attested schema, receipt `profiles`; corpus and validator parity; surfaces |
| v0.9.0 | 0.4 | `delivery-receipt-v1` with its fraud battery; quickstart; field test 3 (cutover) |
| v1.0.0 | 0.4 | `bellbook-core-signed-v1`; soak; security review; freeze |

## 10. Open questions (to be resolved at acceptance)

- **Q1 - provenance bound to authorship.** Proposed: yes (4.1). It makes
  "confirmed by a person" a replay-checked fact. The alternative - a free
  flag - is weaker and easier.
- **Q2 - fold `PolicyDecision` (#9) into epoch 0.4 to avoid a later epoch?**
  Proposed: no. It has no adopter; bundling unrequested wire into an
  epoch is the speculation the gates exist to prevent. The shared
  `DeciderBinding` keeps the door open at no cost.
- **Q3 - baseline strictness on candidate binding.** Proposed: the
  baseline reports the binding mode (`Manifest` vs `Reported`) and
  requires neither; `delivery-receipt-v1` D3 requires a non-empty artifact
  set but not a specific scheme.
- **Q4 - separation scope.** Proposed: producer and evaluator must
  differ (D4); the selector (claim author) is unconstrained in v1. A
  three-party rule can be a signed-tier clause later.
- **Q5 - requirement amendment.** Proposed: retract and re-record; no
  `Replace` on Requirements in v1.
