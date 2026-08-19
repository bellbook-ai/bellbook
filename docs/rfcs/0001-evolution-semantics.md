# RFC-0001: Software-evolution semantics (spec v0.3)

**Status:** Draft, revision 2 — incorporates the adversarial review of
revision 1 (set-valued selection; reaffirmation; binding-authority,
discipline, and concurrency honesty). Nothing in this RFC is implemented;
nothing in it changes spec v0.2 or the published crate. The goal is to make
the object semantics and invariants precise enough to implement without
re-litigating them mid-build. Kind names and field spellings are tentative
until accepted.

**Scope anchor:** the wedge defined in [VISION.md](../VISION.md#next--v03-the-wedge-under-design):
*verifiable candidate selection and lineage for autonomous coding agents*,
on top of Git, reusing the v0.2 trust kernel unchanged.

---

## 1. Summary

Spec v0.3 adds three typed record kinds — `Candidate`, `Evaluation`,
`Selection` — to the existing twelve. The record remains the only primitive.
Lineage is derived from existing typed refs (`Cause`, `Use`, `Require`),
never stored as a parallel structure. Source identity binds to Git (tree
OID), with an optional Bellbook-computed manifest hash for stronger binding.
Selections are **set-valued** (they may select one candidate or several), so
best-of-N, population/beam evolution, and single-candidate repair share one
vocabulary. Retraction and transitive taint apply through one carefully
chosen rule — continuation requires its Selection — so a retracted evaluation
taints the entire descendant line it selected; a **forward-only
reaffirmation** mechanism lets a superseding Selection restore a line's
standing without retroactively erasing taint.

## 2. Motivation

Autonomous coding systems already run this loop today:

```
state → generate candidate(s) → evaluate → select (or repair and re-evaluate) → continue
```

Git can store the file contents at each step but has no native representation
of the loop itself: which candidates were considered, under what objective,
on what evidence, why some were selected, and what the surviving lineage
therefore rests on. That knowledge lives in throwaway branches and harness
logs, unverifiable after the fact.

v0.2 already provides the hard part — content-addressed records, deterministic
re-derivable verdicts, an evidence lattice that cannot be inflated,
signatures with key pinning, retraction with transitive taint, and portable
offline-verifiable receipts. v0.3 adds the missing vocabulary on top of that
kernel, and nothing else.

## 3. Design constraints

C1. **One primitive.** No new storage objects. `Candidate`, `Evaluation`,
    `Selection` are record kinds; a "software state" is a *pattern*: a
    Candidate plus the records that reference it.

C2. **Workload generality.** The semantics must serve, without privileging
    any of them:
    (a) best-of-N — fork N candidates, evaluate, select one;
    (b) iterative / population evolution (autoresearch) — generations of
        candidates, top-k survivors as parents of the next generation,
        abandoned lines;
    (c) single-candidate development — one candidate, evaluation fails,
        repair produces a successor candidate, re-evaluate, accept.
    Consequences: selections operate over candidate sets of size **≥ 1** and
    may select **≥ 1** survivors; repair is an ordinary candidate-to-candidate
    derivation; there is **no** `Generation`, `Tournament`, or `Repair`
    object — all such structure is derivable (§8).

C3. **Kernel unchanged.** The evidence lattice, verdict machinery, signature
    scheme, retraction/taint engine, and receipt model of v0.2 are reused,
    not modified. v0.3 defines how the new kinds *participate* in them.

C4. **Git is the substrate, not the model.** v0.3 reads Git object ids and
    optionally walks a worktree to compute a manifest. It performs no other
    Git operations: no materialization, no remotes, no history rewriting.

C5. **No agent cognition.** Objectives, criteria, and rationales are bounded
    strings supplied by the host. Bellbook records them; it never interprets
    them. Structured context objects are VISION-scope, not v0.3.

## 4. New record kinds

All three kinds are ordinary records: content-addressed via JCS + SHA-256,
subject to author-role rules, signable, judged by an immediate deterministic
Verdict, and referenced through typed refs. Numbers in payloads are integers
only, per the v0.2 wire format.

### 4.1 `Candidate`

Asserts that a specific source state exists as a candidate in some line of
development.

```jsonc
{
  "source": {
    "git": {
      "algo": "sha1",              // "sha1" | "sha256" (repo object format)
      "tree": "<40- or 64-hex>",   // REQUIRED: content identity
      "commit": "<40- or 64-hex>"  // OPTIONAL: provenance only, never identity
    },
    "manifest_hash": "<64-hex>",   // OPTIONAL: Bellbook canonical manifest (§5)
    "binding": "reported"          // "reported" | "manifest"
  },
  "basis": "root",                 // "root" | "continuation" | "derivation"
  "parent": "<record id>",         // REQUIRED iff basis == "continuation":
                                   //   the selected candidate this continues from
  "note": "<bounded string>"       // OPTIONAL: free-form label
}
```

**Basis semantics and required refs:**

| basis          | meaning                                        | ref obligations |
|----------------|------------------------------------------------|-----------------|
| `root`         | starts a line (imported / initial state)       | MAY `Cause` a Request; no `parent` |
| `continuation` | continues from a selected state                | MUST `Require` exactly one `Selection` whose outcome is `selected`, and `parent` MUST name a member of that Selection's selected set |
| `derivation`   | derived from sibling material (repair, mutation)| MUST `Cause` ≥ 1 record, each of kind `Candidate` or `Evaluation`; no `parent` |

The `continuation`/`derivation` distinction is the taint boundary and is the
most consequential rule in this RFC; rationale in §6. The `parent` field is
descriptive lineage (which selected state this builds on); the *epistemic*
dependency is the `Require` on the Selection.

### 4.2 `Evaluation`

A judgment about exactly one candidate under an explicit criterion.

```jsonc
{
  "candidate": "<record id>",      // REQUIRED: the subject
  "criterion": "<bounded string>", // REQUIRED, non-empty (e.g. "unit-tests")
  "procedure": "<bounded string>", // OPTIONAL: how it was run (command, harness, version)
  "outcome": {
    "status": "passed",            // "passed" | "failed" | "scored"
    "value": 930,                  // REQUIRED iff status == "scored"; integer
    "scale": 3                     // REQUIRED iff status == "scored"; value/10^scale
  }
}
```

**Ref obligations:** MUST `Use` the record named in `candidate`; MAY `Use`
additional evidence records (e.g. Results, Usage, traces). The subject
dependency is `Use`, not `Cause`, because the evaluation's content
epistemically rests on the candidate binding: if the candidate is retracted,
every evaluation of it is correctly tainted.

Evidence class follows the unchanged v0.2 lattice: a harness reporting its
own results is at most `Reported`; a signed attestation from a key-pinned
external party is `Verified`; `Deterministic` remains reserved for
verifier-derived records. Bellbook never computes or re-runs an evaluation
(C5); it records and grades how the result is known.

### 4.3 `Selection`

A recorded decision over a set of candidates under an objective. Selections
are **set-valued**: the outcome names the surviving candidates — one for
best-of-N or a repair accept, several for population/beam evolution where the
top-k jointly become parents of the next generation. A single decision that
keeps k survivors is one record, not k fragmented ones.

```jsonc
{
  "objective": "<bounded string>",   // REQUIRED, non-empty
  "considered": ["<id>", "..."],     // REQUIRED: ≥ 1, unique, all Candidate ids
  "outcome": {
    "decision": "selected",          // "selected" | "none"
    "candidates": ["<id>", "..."]    // REQUIRED iff selected: ≥ 1, unique, ⊆ considered
  },
  "rationale": "<bounded string>"    // OPTIONAL
}
```

**Ref obligations:**

- If `decision == "selected"`: MUST `Require` exactly the members of
  `outcome.candidates` (each of which MUST appear in `considered`).
- MUST `Use` ≥ 1 `Evaluation` (default rules; a rules knob MAY relax this,
  see §9), and the `candidate` of every `Use`d Evaluation MUST appear in
  `considered`.
- `decision == "none"` records that no candidate was acceptable under the
  objective — a legal, meaningful outcome (pruning, backtracking). It carries
  no `Require`.
- A Selection MAY carry a `Replace` ref to a prior Selection: this is
  **reaffirmation** (§6.1). If present, the `Replace` target MUST be a
  Selection.

Losing candidates are listed in `considered` (descriptive) but not referenced
via `Use`/`Require`; the decision's *epistemic* premises are the evaluations
it declares it `Use`d. A comparative selection naturally `Use`s the losers'
evaluations too, and taint then flows through those evaluations — the host
controls comparative-vs-threshold semantics through what it declares, not
through special kinds.

A Selection with `considered` of size 1 and a selected set of size 1 is the
formal version of "accept this state under this objective" — the
single-candidate workflow's terminal step (C2c). Authority composes
unchanged: rules may demand that Selections be authored by a given role,
carry an exact approval, or meet evidence thresholds, using existing v0.2
machinery.

## 5. Source binding model

Identity binds to the **Git tree**, not the commit: two commits with the same
tree are the same software state. The commit OID, when present, is
provenance.

Two binding modes, distinguished explicitly in the payload:

- **`reported`** — the host asserts the Git OIDs. Cheap (no I/O). Bellbook
  proves the *claim was recorded*, not that the OIDs match any file contents.
  Inherits Git's hash properties (SHA-1 for classic repos).
- **`manifest`** — `manifest_hash` is additionally present: a SHA-256 over
  the Bellbook canonical manifest of the materialized tree (§5.1), computed
  by the recording process. Costs one worktree walk; upgrades the receipt to
  a content commitment independent of Git's hash algorithm: anyone holding
  the tree can recompute the manifest and compare.

**Authority on disagreement.** Nothing inside a record can prove that
`manifest_hash` and `git.tree` describe the same contents; a false record can
carry a tree OID and a manifest that disagree. When both are present, the
**manifest is the authoritative identity commitment** and the tree OID is an
interoperability pointer; a disagreement makes the record a false claim,
detectable only by materializing the tree and recomputing the manifest —
the same boundary v0.2 draws for `Verified` evidence ("origin verified,
never the real-world effect"). SPEC v0.3 §13 must state this.

**Adoption reality, stated in advance.** The manifest walk is O(worktree) per
candidate. High-N workloads will predictably use `reported` for the
population, which means their receipts commit to claims about SHA-1 hashes,
not to contents. That is acceptable and must be said plainly, not
discovered. The intended pattern is cheap `reported` bindings for the
population and strong binding for the states that matter (the selected
survivors); since a record's binding is immutable, how a survivor's binding
gets upgraded (e.g. a manifest-bound re-record of the same tree that the
Selection then `Require`s) is open question §16.6.

**Deliberate refinement of an earlier framing:** binding strength is carried
by the explicit `binding` field plus a per-kind rules threshold
(`min_binding`, §9) — *not* by overloading the evidence-class definitions,
whose v0.2 meanings stay fixed. The evidence class continues to grade how the
record's content is known, and the two mechanisms compose. Rules like "any
candidate a Selection `Require`s must have `manifest` binding" become
expressible without touching the lattice.

### 5.1 Canonical manifest v1 (proposal)

A JCS-canonicalized JSON object mapping repo-relative POSIX paths (sorted by
JCS rules) to entries:

```jsonc
{ "<path>": { "mode": "100644", "sha256": "<64-hex of file bytes>" }, ... }
```

- Modes: `100644`, `100755`, `120000` (symlink; `sha256` is over the target
  string). Directories are implicit; empty directories are unrepresented.
- `.git` is excluded. Bytes are hashed as materialized on disk — no EOL or
  attribute normalization.
- `manifest_hash` = SHA-256 over the JCS bytes of that object.
- Submodules: **out of scope for v1** (open question §16).

## 6. Reference and taint semantics

v0.2's rule is preserved exactly: **taint follows `Use` and `Require`, never
`Cause`** (this is an existing corpus case). v0.3 adds one principle for
choosing between them:

> **Artifacts descend by `Cause`; judgments and standing depend by
> `Use`/`Require`.**

Applied:

- An **Evaluation** `Use`s its candidate → retracting a candidate taints its
  evaluations. Correct: the judgments were about content whose binding no
  longer stands.
- A **Selection** `Use`s the evaluations it relied on and `Require`s its
  selected candidates → retracting a relied-on evaluation, or any selected
  candidate, taints the selection. Correct: the decision's premises are gone.
- A **continuation Candidate** `Require`s its Selection → a tainted selection
  taints every candidate that continued from it, and (via their evaluations
  and subsequent selections) the entire descendant line. This is the rule
  that makes the flagship scenario (§10) true, and it is epistemically
  honest: a continuation's claim is not "these files exist" but "this is the
  chosen line's successor" — standing that genuinely rests on the decision.
- A **derivation Candidate** (repair, mutation) `Cause`s its origins → taint
  does *not* flow. Correct: if the failing evaluation that motivated a repair
  is later retracted, the repaired artifact is not thereby wrong; only its
  motivation evaporated. Retraction poisons conclusions, not code.

Two acknowledged consequences, both deliberate:

1. **The cascade can be over-broad.** A Selection may be over-determined
   (the survivors stand on four evaluations even after a fifth is
   retracted), and taint through a multi-winner Selection reaches *all* its
   continuation lines even if only one winner's premises collapsed. Taint
   means "rests on something retracted," never "is wrong" — the recovery
   path is reaffirmation (§6.1), not weaker taint.
2. **This asymmetry — continuation `Require`s, derivation `Cause`s — is the
   single most consequential decision in this RFC** and should be challenged
   hardest in review.

### 6.1 Reaffirmation: forward-only taint recovery

Without a recovery mechanism, one retracted evaluation permanently taints an
entire active line, and the only exit is re-recording the chain. Large,
mostly-recoverable cascades would teach users to ignore taint — destroying
the flagship capability through alarm fatigue. v0.3 therefore defines
**reaffirmation**:

- A new Selection S′ MAY carry a `Replace` ref to a prior Selection S
  (typically tainted, not necessarily). S′ is an ordinary Selection in every
  respect: its own `considered`, its own `Use`d evaluations (the surviving
  and/or newly produced evidence), its own selected set, the full rules
  battery, and whatever role/approval requirements the rules impose on
  Selections — rules MAY impose *stricter* requirements when `Replace` is
  present (knob: `reaffirmation_roles`).
- **Effect is forward-only.** Continuations recorded after S′ `Require` S′
  and are untainted. Records that `Require`d S remain tainted — taint is
  never retroactively cleared. The replay report SHOULD annotate such
  records as *superseded* (tainted via S, where S is `Replace`d by S′), so a
  consumer can distinguish "rests on retracted evidence, standing restored
  downstream" from "rests on retracted evidence, abandoned." Exact report
  shape is open question §16.7.
- **Retroactive clearing is explicitly rejected.** If a later record could
  un-taint earlier ones, a producer could launder history: retract
  inconvenient evidence, reaffirm, and present a clean receipt. Taint must
  be monotone with respect to committed history; recovery happens only by
  extending history, in the open, with the reaffirmation itself on the
  record.
- **Last resort:** a host abandoning a long-tainted line entirely may start
  a new `root` candidate with a provenance `note`. This deliberately severs
  verifiable lineage continuity, and the receipt shows the break — that is
  the honest cost of a re-baseline.

## 7. Derived lineage

No lineage is stored. Defined queries over the ref graph:

- **line of descent**: from any Candidate, follow its `Require`d Selection
  and `parent` field (continuations) and `Cause` edges (derivations) back to
  a `root`.
- **siblings / a "generation"**: candidates sharing the same `Require`d
  Selection (continuations) or the same `Cause` targets (derivations).
- **frontier**: candidates that are not in any Selection's `considered`, plus
  selected candidates with no continuation yet.
- **standing**: for any record, its taint status plus any superseding
  reaffirmation chain (§6.1).

These are traversals the CLI exposes (§12); a general query engine is a
non-goal (§14).

## 8. Workload walkthroughs (generality check, C2)

**Best-of-N.** Selection S₀ selects state A. N candidates, each
`basis: continuation`, `parent: A`, `Require` S₀. Each gets one or more
Evaluations. One Selection considers all N, `Use`s their evaluations, selects
one. Continue.

**Population / beam evolution (autoresearch).** A Selection selects the
top-k survivors {A, B} in one record. Generation k+1 candidates each name
`parent: A` or `parent: B` and `Require` that Selection. Mutations *within*
a generation are `basis: derivation` candidates `Cause`-ing a sibling.
Abandoned lines simply have no continuation; recorded pruning is a Selection
with `decision: none` over the line's frontier. If an evaluation behind the
top-k decision is later retracted, the Selection and both lines taint; a
reaffirmation S′ (`Replace` → S) re-selecting {A} on surviving evidence
restores forward standing for A's line while B's line remains visibly
tainted-and-not-reaffirmed. No new kinds needed.

**Single-candidate repair.** C₁ (`root` or `continuation`) → Evaluation E₁
fails → C₂ `basis: derivation`, `Cause` [C₁, E₁] → Evaluation E₂ passes →
Selection with `considered: [C₂]` (or `[C₁, C₂]` if the host wants the
comparison on record), `Use` [E₂ (, E₁)], selecting [C₂]. The accept step is
the same object best-of-N uses; nothing is privileged.

## 9. Verifier rules (additions to the per-record battery)

All existing v0.2 checks (author roles, identity-to-role binding, signatures,
canonical payloads with typed decode, evidence thresholds, retraction
ownership) apply to the new kinds unchanged. New checks, each with a distinct
rejection reason code and a triggering corpus case:

**Candidate**
- V3-C1: `source.git.tree` present, hex, length matching `algo`.
- V3-C2: `binding == "manifest"` ⇒ `manifest_hash` present (64-hex);
  `binding == "reported"` ⇒ `manifest_hash` absent.
- V3-C3: basis/ref obligations of §4.1 hold (continuation ⇒ exactly one
  `Require`d Selection with outcome `selected`; derivation ⇒ ≥ 1 `Cause` of
  allowed kinds; root ⇒ no `Require`).
- V3-C4: a `Require`d Selection must not be retracted at commit time
  (retracted authority stops authorizing — same principle as v0.2 capability
  revocation).
- V3-C5: `parent` present iff `basis == "continuation"`, and it names a
  member of the `Require`d Selection's selected set.

**Evaluation**
- V3-E1: `candidate` names an existing Candidate record and is matched by a
  `Use` ref.
- V3-E2: `criterion` non-empty; `outcome` well-formed per status
  (`scored` ⇔ `value` and `scale` present).

**Selection**
- V3-S1: `considered` non-empty, unique, all existing Candidate ids.
- V3-S2: `decision == "selected"` ⇒ `outcome.candidates` non-empty, unique,
  ⊆ `considered`, and the record `Require`s exactly those candidates;
  `decision == "none"` ⇒ no `Require`.
- V3-S3: every `Use`d Evaluation's `candidate` ∈ `considered`.
- V3-S4 (default rules; knob `selection_requires_evaluation = true`): ≥ 1
  `Use`d Evaluation when `decision == "selected"`.
- V3-S5: a `Replace` ref on a Selection, if present, targets a Selection;
  rules knob `reaffirmation_roles` MAY restrict which authors may reaffirm.

**New rules knobs**
- `min_binding` per referencing context (e.g. Selections may only `Require`
  candidates with `manifest` binding).
- `selection_requires_evaluation` (default true).
- `reaffirmation_roles` (default: same as Selection authorship).
- Per-kind evidence thresholds and author-role bindings apply to the three
  kinds exactly as to existing kinds.

## 10. Retraction and the flagship scenario

The demonstration this release is built around:

> A benchmark harness is discovered to be broken. Its Evaluations are
> retracted. Every Selection that `Use`d them is tainted; every continuation
> Candidate that `Require`d those Selections is tainted; their Evaluations
> and every subsequent Selection and continuation are tainted transitively.
> One retraction, and the receipt now shows exactly which surviving lineage
> still rests on untainted evidence — and which "best" states were chosen on
> evidence that no longer stands. Repairs and mutations motivated by the
> broken evaluations remain untainted: their motivation vanished, their
> content did not. The team then re-runs the surviving evaluations and
> records a reaffirming Selection (§6.1): forward standing is restored, on
> the record, without erasing what happened.

Taint here means "rests on retracted evidence," never "the code is wrong" —
and the reaffirmation step is part of the demo precisely so the cascade
reads as actionable state, not as a permanent alarm. This requires zero new
taint machinery — only the ref discipline of §6 — and is the capability that
distinguishes Bellbook from experiment trackers and Git workflows alike. It
ships as a worked example plus corpus receipt cases covering: the full
cascade, the derivation non-cascade, the reaffirmation recovery, and a
forged "un-tainted" receipt that replay rejects.

## 11. Receipt boundary

A v0.3 receipt proves the recorded **process**: which candidates were
recorded, what was claimed about them, which evidence and evaluations existed,
what was selected under what objective, what is retracted, tainted, or
superseded, and that none of it was altered after the fact. It does **not**
contain source contents; Git OIDs are pointers whose resolution requires the
repository. With `manifest` binding, a party holding the tree can
independently recompute `manifest_hash` and bind the receipt to actual
contents; with `reported` binding they hold a verifiable record of an
unverified claim — and the receipt says which, explicitly.

One further boundary, stated with the same bluntness: **the lineage and taint
guarantees are conditional on the producer's recording discipline.** `basis`,
`parent`, and the choice of refs are producer claims; a host that records
continuations as derivations escapes the cascade, and no verifier can detect
that, because intent is not checkable. Bellbook proves the recorded structure
is internally consistent under its rules — it does not prove the structure
faithfully mirrors the development process. A receipt consumer trusts the
embedded `rules_hash` *and* the producer's recording conventions. This is
v0.2's "consistency, not completeness" boundary extended one level, and it
must appear in SPEC v0.3 §13 verbatim in spirit.

## 12. CLI surface (the wedge's adoption surface)

Thin wrappers over the crate; JSON in/out; every command prints the committed
record id; harnesses in any language integrate by shelling out.

```
bellbook candidate add  --git-tree <oid> [--git-commit <oid>] [--algo sha1|sha256]
                        [--manifest <path-to-worktree>]        # computes manifest binding
                        [--continues <selection-id> --parent <candidate-id>
                         | --derives-from <id> ...]
                        [--note <s>]
bellbook eval add       --candidate <id> --criterion <s>
                        (--passed | --failed | --score <value> --scale <n>)
                        [--procedure <s>] [--uses <id> ...]
bellbook select         --objective <s> --consider <id> ...
                        (--choose <id> ... | --none)
                        [--replaces <selection-id>]            # reaffirmation
                        --uses-eval <id> ... [--rationale <s>]
bellbook lineage        <id> [--json]      # descent, siblings, taint + superseded status
bellbook validate       <receipt>          # unchanged from v0.2
```

**Concurrency guidance (normative for the docs, not the verifier):** the
persistent log is deliberately single-writer (`LogWriter` holds an exclusive
lock, exactly as in v0.2). Parallel candidate *generation* is the workload;
parallel *recording* is not the mechanism. Hosts generate candidates
concurrently and record them serially afterward — one process, in a batch
(`checked_batch_commit` for retry-safe batches) or a loop. The CLI is not a
coordination layer, and integration docs must say so before integrators
discover the lock by contention.

Signing, roles, and receipt export use existing mechanisms. Python bindings
remain out of scope (README open-work list); the independent Python validator
is updated in lockstep via the corpus, as now.

## 13. Compatibility and conformance plan

- v0.3 is a new compatibility epoch: twelve kinds become fifteen; signing
  domain becomes `bellbook.record-signature.v0.3`; v0.2 logs and receipts
  remain valid under v0.2 rules (no migration of committed history).
- Test vectors regenerated and extended per new kind, including signed
  vectors.
- Conformance corpus extended with positive and adversarial cases per new
  invariant in §9 (each rejection reason code gets a triggering case), plus
  the §10 receipt cases (cascade, non-cascade, reaffirmation, forged
  un-taint).
- The Python validator implements the three kinds and the taint flows
  independently, and the corpus gate in CI holds both implementations to
  byte-for-decision agreement — same discipline that caught real bugs in the
  v0.2 cycle.

## 14. Non-goals (binding for v0.3)

No ranking or scoring computation; no evaluation execution; no general query
engine (lineage traversal only — but see §15's read-side signal, which is the
designated trigger for revisiting this); no Git plumbing beyond reading OIDs
and the optional manifest walk; no materialization; no remotes or sync; no
native source storage; no structured ContextObject system; no `Generation`,
`Tournament`, or `Repair` kinds; no agent-cognition vocabulary of any sort.
Each of these is either VISION-scope (gated) or belongs to host systems
permanently.

## 15. Validation and falsification criteria (pre-registered)

Recorded before implementation so the outcome cannot be rationalized later.
Evaluation window: **90 days from shipping v0.3 + the flagship example**.

**Validation — proceed to the next VISION gate only if ≥ 2 hold:**
1. At least one harness integration authored by someone with no connection to
   this project, in actual use.
2. Receipts generated by ≥ 3 external users or organizations (observed via
   issues, discussions, or shared receipts — not download counts).
3. Inbound issues or PRs that engage the *semantics* (binding modes, taint
   flows, selection invariants) — people argue about semantics they use.
4. The flagship broken-benchmark scenario independently reproduced or cited
   by an external party.
5. **Read-side usage**: at least one integration that *queries* — lineage
   traversal, taint/superseded status, or receipt validation inside its own
   loop — rather than only writing records. This signal specifically gates
   the VISION query-surface stage: write-side adoption justifies more
   recording semantics; only read-side adoption justifies a query engine.

**Falsification — the thesis fails at this layer if both hold:**
1. Direct exposure to ≥ 5 teams running best-of-N or iterative-evolution
   workflows yields zero adoption, with the stated reason being that ad-hoc
   eval JSON plus branch conventions are sufficient.
2. Any integrations that do exist use Bellbook as write-only logging — no
   receipt validation, no taint queries, no selection semantics — for the
   full window.

**Decision rule:** if falsified, VISION stages 1–4 stay parked indefinitely;
native storage would not have changed the answer. If neither validated nor
falsified, extend once by 90 days with a written note on what changed;
no second extension without new evidence.

## 16. Open questions for review

1. **Score representation** — is `{value, scale}` integer fixed-point
   sufficient, or do hosts need multi-metric outcomes per Evaluation (vs. one
   Evaluation per metric, the current proposal)?
2. **Comparative evaluations** — pairwise judgments ("A preferred over B",
   Elo-style) currently have no direct form; they must be encoded as unary
   evaluations. Is a two-subject Evaluation variant warranted, or is unary
   encoding acceptable for the wedge?
3. **Manifest v1** — submodules; whether `mode` belongs in v1 or only
   `sha256`; large-file cost and whether a size bound is needed.
4. **Allowed `Cause` targets for `derivation`** — currently Candidate and
   Evaluation; should Requests and Results be admitted?
5. **SHA-256 Git repositories** — `algo` field is included; is dual-hash
   (tree in both algorithms) worth supporting for migration-era repos?
6. **Late binding upgrade** — a record's binding is immutable; the intended
   pattern (reported for the population, manifest for survivors) needs a
   defined idiom, e.g. a manifest-bound re-record of the same tree that the
   Selection `Require`s instead of the reported one. Does that re-record need
   its own basis/ref rule?
7. **Superseded-annotation shape** — how the replay report expresses
   "tainted via S, S `Replace`d by S′" (§6.1); field naming and whether
   supersession chains longer than one hop are flattened.
8. **V3-C4 timing** — "Selection not retracted at commit time" mirrors
   capability revocation; confirm the same replay semantics (validity judged
   at commit position, taint judged at replay end) reads correctly for
   selections.
9. **`considered` size bound** — population workloads may list thousands of
   ids per Selection; should rules impose a per-record bound consistent with
   the existing resource bounds?
