# RFC-0001: Software-evolution semantics (spec v0.3)

**Status:** Draft, revision 4. Revision 2 folded in the first adversarial
review (set-valued selection; reaffirmation). Revision 3 responded to a
second, code-verified audit — its central change: **lineage standing is a
replay-derived dimension computed over `Cause` edges, not a use of kernel
taint via `Require`.** Revision 4 folds in a third, maximum-depth audit that
verified revision 3's kernel claims against the v0.2 source and closed the
gaps it found: `Cause` targets of Candidates must be accepted (the
rejected-anchor hole), standing lives in the replay report only (receipts
embed nothing derived), the standing section's content is now normative,
reaffirmation's default trust posture is stated bluntly with an
identity-binding knob, and the retracted-parent unrestorability asymmetry is
documented. Nothing in this RFC is implemented; nothing in it changes spec
v0.2 or the published crate. Kind names and field spellings are tentative
until accepted.

**Scope anchor:** the wedge defined in [VISION.md](../VISION.md#next--v03-the-wedge-under-design):
*verifiable candidate selection and lineage for autonomous coding agents*,
on top of Git, reusing the v0.2 trust kernel unchanged.

---

## 1. Summary

Spec v0.3 adds three typed record kinds — `Candidate`, `Evaluation`,
`Selection` — to the existing twelve. The record remains the only primitive.
Lineage is derived from refs and payload fields, never stored as a parallel
structure. Source identity binds to Git (tree OID), with an optional
Bellbook-computed manifest hash for stronger binding. Selections are
**set-valued** (one survivor or several).

Dependency semantics are split to match what they mean:

- **Knowledge** flows through `Use`/`Require` exactly as in v0.2:
  evaluations epistemically depend on their candidates; selections
  epistemically depend on the evaluations they relied on and the candidates
  they selected. Kernel evidence derivation and taint apply here, unchanged.
- **Standing** — "is this state a legitimate member of a chosen line?" — is
  a **new, replay-derived dimension** computed over lineage `Cause` edges:
  continuation anchors (with `parent`) and derivation edges to candidates.
  It is deterministic, derived identically by every validator, and
  forgery-proof for the same reason taint is: replay re-derives it. It does
  not touch evidence derivation, does not freeze appends, and — when the
  compromise stems from decisions that no longer stand, not from a retracted
  state itself (§6.3) — is restorable by a single on-record reaffirmation.

This split is the revision-3 correction of revision 2's central defect:
overloading `Require` for lineage bought kernel taint at the cost of
evidence collapse and frozen lines. Standing gives the flagship guarantee —
*one retraction visibly compromises the entire selected descendant line* —
without either side effect, and makes recovery a one-record act at any
depth.

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

C3. **Kernel engines unchanged; extension is additive.** Canonicalization,
    content addressing, the signature scheme, evidence derivation, taint
    propagation, and the receipt replay structure are reused exactly as
    they are — never modified, never scoped, never special-cased. What v0.3
    adds sits beside them: three kinds with author-role rows and base
    evidence classes (the same registration every kind has), new per-kind
    verifier checks, two entries on the existing `Replace` kind whitelist
    with a Selection compatibility rule, and one new *derived* replay output
    (standing, §6.2). Anything that would require changing how an existing
    v0.2 record verifies is out of scope by definition.

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

### 4.0 Registration: author roles and base evidence classes

v0.2 normatively requires every kind to have an allowed-author-type row and
every schema to have a base evidence class; leaving either undefined lets
conforming implementations diverge. v0.3 registers:

| Kind        | Allowed author types              | Base evidence class |
|-------------|-----------------------------------|---------------------|
| `Candidate` | User, Provider, Executor, System  | `Reported`          |
| `Evaluation`| User, Provider, Executor, System  | `Reported`          |
| `Selection` | User, Provider, System            | `Inferred`          |

Rationale. Candidates and evaluations are things any actor may honestly
report producing or observing; rules narrow this per deployment. Selections
are decisions, so `Executor` — the role that performs work — may not author
them. Base classes are conservative: a candidate's binding and an
evaluation's outcome are host-asserted (`Reported`); a selection is a
judgment derived by reasoning (`Inferred`). Stored evidence can never exceed
the derived minimum over base and `Use`/`Require` targets, so under this
table: evaluations are at most `Reported`, selections at most `Inferred`,
and per-kind thresholds at those levels are meaningful — their real teeth is
that any retracted or tainted dependency drags the derived class to the
`Assumed` floor and below threshold. Whether a key-pinned externally signed
evaluation can be granted a `Verified` pathway is deliberately **not**
claimed here (revision 2 overclaimed it); it is open question §16.8, to be
settled against v0.2's actual `Verified` mechanism.

One consequence for retraction, stated now because the flagship (§10)
depends on it: v0.2 permits `Retraction` records to be authored only by
User, Provider, or System, and a record may be retracted only by its author
or a configured `admin_retraction_actors` entry. **Executor-authored
evaluations are therefore admin-retractable only.** Hosts that want the
broken-benchmark recovery story must either author evaluations as Provider
or System, or configure admin retraction. The RFC makes this a documented
deployment decision, not an accident.

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

**Basis semantics and ref obligations:**

| basis          | meaning                                         | ref obligations |
|----------------|-------------------------------------------------|-----------------|
| `root`         | starts a line (imported / initial state)        | at most one `Cause`, targeting an accepted Request; no other `Cause` targets; no `parent` |
| `continuation` | continues from a selected state                 | MUST `Cause` exactly one record: an **accepted** `Selection` whose outcome is `selected`; `parent` MUST name a member of that Selection's selected set |
| `derivation`   | derived from sibling material (repair, mutation)| MUST `Cause` ≥ 1 record, each an **accepted** `Candidate` or `Evaluation`; no `parent` |

Acceptance of every `Cause` target is checked at the candidate's commit
position and, because acceptance is permanent in v0.2, holds forever after.
This closes what the third audit named the *rejected-anchor hole*: without
it, a continuation could anchor to a rejected Selection and yield a
`Clean` receipt with a compromised lineage, and derivation standing would be
undefined over rejected targets.

Continuation uses `Cause`, **not** `Require` — this is the revision-3
change. `Cause` carries neither evidence derivation nor kernel taint, so a
candidate's evidence class reflects how *its own content* is known, and a
tainted history never blocks the recording of ongoing work (the log records
what was attempted). The lineage consequence of the Selection's health is
carried by **standing** (§6.2), which is derived from exactly these edges.
The `parent` field is the specific selected state this candidate builds on;
payload-id resolution rules for it are in §9 (V3-C5).

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
dependency is `Use` — genuinely epistemic — because the evaluation's content
rests on the candidate's binding: if the candidate is retracted, every
evaluation of it is correctly tainted and its derived evidence falls to the
`Assumed` floor. This is kernel machinery doing exactly what it was built
for, and it is kept.

### 4.3 `Selection`

A recorded decision over a set of candidates under an objective. Selections
are **set-valued**: the outcome names the surviving candidates — one for
best-of-N or a repair accept, several for population/beam evolution where the
top-k jointly become parents of the next generation. A single decision that
keeps k survivors is one record, not k fragmented ones.

```jsonc
{
  "objective": "<bounded string>",   // REQUIRED, non-empty
  "considered": ["<id>", "..."],     // REQUIRED: ≥ 1, unique Candidate ids (resolution: §9 V3-S1)
  "outcome": {
    "decision": "selected",          // "selected" | "none"
    "candidates": ["<id>", "..."]    // REQUIRED iff selected: ≥ 1, unique, ⊆ considered
  },
  "rationale": "<bounded string>"    // OPTIONAL
}
```

**Ref obligations:**

- If `decision == "selected"`: MUST `Require` every member of
  `outcome.candidates`. These `Require` refs are epistemically honest (the
  decision's validity rests on the winners' integrity) and give commit-time
  teeth for free under unchanged kernel rules: a Selection whose winner is
  retracted or tainted at its commit position is rejected outright.
- Additional `Require` refs are permitted **only** for authority records
  (Capability/Approval) demanded by the rules — see "Authority" below. No
  other `Require` targets are allowed (V3-S2).
- MUST `Use` ≥ 1 `Evaluation` when `decision == "selected"` (rules knob
  `selection_requires_evaluation`, default true; a `none` decision has no
  evaluation obligation). The `candidate` of every `Use`d Evaluation MUST
  appear in `considered`. This is the single normative statement of the
  evaluation obligation; §12's CLI grammar mirrors it.
- `decision == "none"` records that no candidate was acceptable under the
  objective — a legal, meaningful outcome (pruning, backtracking). It carries
  no candidate `Require`s.
- A Selection MAY carry one `Replace` ref targeting a prior Selection: this
  is **reaffirmation** (§6.3), subject to the compatibility rule in V3-S5.

**Authority.** Revision 2 claimed authority "composes unchanged"; that was
wrong — v0.2's exact-approval machinery is Action-specific (its approval
hash binds the action author and `ActionData`). v0.3 therefore defines the
analogous binding for selections: when rules require an approval for
Selections, the approval's subject hash is
`SHA-256(canonical((selection_author_id, SelectionData)))` in a
selection-specific domain, the approving record is referenced by `Require`,
and single-use consumption follows the existing approval rules. This is new,
explicitly specified machinery modeled on the Action path — not a claim
that the Action path already covers it.

Losing candidates are listed in `considered` (descriptive) but not referenced
via `Use`/`Require`; the decision's *epistemic* premises are the evaluations
it declares it `Use`d. A comparative selection naturally `Use`s the losers'
evaluations too. A Selection with `considered` of size 1 and a selected set
of size 1 is the formal "accept this state under this objective" — the
single-candidate workflow's terminal step (C2c).

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

**Binding strength and the lattice.** Binding strength is carried by the
explicit `binding` field plus a per-kind rules threshold (`min_binding`,
§9) — *not* by overloading the evidence-class definitions, whose v0.2
meanings stay fixed. Rules like "any candidate a Selection `Require`s must
have `manifest` binding" are expressible without touching the lattice.

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

## 6. Knowledge, taint, and standing

### 6.1 Knowledge: unchanged kernel semantics

v0.2's rules apply verbatim. Evidence derivation: a record's stored evidence
must equal the weakest of its base class and the evidence of every
`Use`/`Require` target, with rejected/retracted/tainted targets contributing
the `Assumed` floor. Taint: propagates transitively through `Use` and
`Require`, never `Cause`; a record that `Use`s a tainted record commits but
is tainted; a record that `Require`s a tainted or retracted record is
rejected. Under §4's ref discipline this yields, per generation:
evaluations ≤ `Reported`, selections ≤ `Inferred` — and, because
continuation edges are `Cause`, **evidence does not compound across
generations**: each candidate's class reflects its own binding, each
evaluation its own grounding. (Revision 2's design collapsed all lineages to
a fixed point within one generation and made threshold rules unusable; this
is the fix.)

### 6.2 Standing: a derived lineage dimension

**Definition.** Standing answers: *does this candidate's membership in a
chosen line still rest on decisions that stand?* It is computed at replay
end, from accepted records only, as a pure function of the log — exactly as
deterministic and forgery-resistant as the taint set, because a validator
re-derives it. It is **not** kernel taint: it does not affect evidence, does
not gate commits by default, and is reported alongside taint, never merged
with it.

Let a Selection S be **unsound** at replay end iff S is retracted or
tainted. (A rejected Selection can never be an anchor: V3-C3 requires every
`Cause` target of a Candidate to be accepted at commit, and acceptance is
permanent — so an anchor can become unsound only *after* the fact, via
retraction or taint.) Define **anchor soundness** for a continuation
candidate C with `Cause` → S and `parent` = P:

- S itself is sound, **or**
- some accepted, sound Selection S′ exists with a `Replace` chain leading to
  S (one or more hops, every intermediate accepted) whose selected set
  contains P. If multiple replacements of S exist, **any** sound one
  suffices (deterministic: existential over the fixed replay-end set).
  Intermediates need only be *accepted*, not sound — requiring soundness
  would recreate a frozen-chain pathology while granting nothing, since a
  host can always `Replace` S directly (multiple replacements of one target
  are legal in v0.2); a corpus case pins this reading.

Then standing is derived recursively (well-founded: all edges point to
earlier records):

- `root` candidate: **sound**.
- `continuation` candidate: **sound** iff its anchor is sound **and**
  standing(P) is sound; otherwise **compromised**.
- `derivation` candidate: **sound** iff every `Cause`d Candidate has sound
  standing (evaluation targets carry no standing); a derivation with only
  Evaluation targets is **sound**.

**Where standing lives: the replay report only.** A v0.2 receipt embeds
nothing derived — it is `{spec_version, rules, records}`, and the
retracted/tainted sets exist only in the validator's report, re-derived on
every validation. Standing follows the same discipline exactly: the
**report** gains a `standing` section; receipts are unchanged in shape, and
there is no embedded standing for anyone to forge — a validator that derives
a different standing set from the same records is simply nonconforming,
which the corpus detects the same way it detects taint disagreement.

**Normative content of the `standing` section** (field names are open
question §16.7; the content is not):

- `compromised`: the set of standing-compromised Candidate ids;
- `unsound`: the set of unsound Selection ids;
- `restorations`: for each unsound Selection that has at least one sound
  replacement chain, the set of sound replacing Selection ids.

All three are pure functions of the accepted records at replay end, with
canonical (logical-time) ordering for output. Restored lines are visible as:
their candidates absent from `compromised`, their anchor present in
`unsound`, and the restoring Selection listed in `restorations` — closing
the gap between this section and §7/§10's restoration queries.

Whenever `compromised` is non-empty, the responsible anchor is necessarily
retracted or tainted (rejected anchors are impossible per V3-C3, and
acceptance is permanent), so the report's overall status is already
`Tainted` under unchanged v0.2 status rules — v0.2 reports `Tainted`
whenever either the retracted or the tainted set is non-empty. Standing adds
*which lineage* is affected and *what restored it*; it never manufactures a
status v0.2 would not report. Two independent implementations must derive
identical standing sections; corpus receipt cases pin the expected values
(§13).

**What standing deliberately does not do.** It does not reject new
continuations of an unsound Selection — they commit and are born
compromised, because a ledger that cannot record ongoing work stops being a
ledger (and produces the perverse incentive to mislabel continuations as
derivations). Rules MAY opt into commit-time strictness
(`reject_compromised_continuation`, default false).

### 6.3 Reaffirmation: one-record recovery, at any depth

A Selection S′ carrying `Replace` → S is a **reaffirmation**: a new decision
over the same objective, on evidence that currently stands. Requirements
(V3-S5): the target is a Selection in the same space with the same
`objective`; rules MAY restrict reaffirmation authorship
(`reaffirmation_actors`: an explicit allowlist of actor *identities*; when
unset, the Selection author-role row applies).

Because standing (not kernel taint) carries lineage consequence, S′ is
committable **at any depth**: its `Require`d winners are ordinary untainted
candidates, its `Use`d evaluations are ordinary untainted evaluations (a
candidate is never kernel-tainted by its line's compromise), so nothing
blocks the append. One committed reaffirmation whose selected set contains
the relevant parents restores standing for the entire descendant subtree at
the next replay — zero re-recording. (Revision 2's design required
re-recording every intervening generation because `Require`-of-tainted is a
hard rejection; this is the fix.)

Honesty properties, unchanged from revision 2 and now structurally
guaranteed:

- **Forward-only, laundering-proof.** The retraction, the tainted Selection,
  and the reaffirmation all remain permanently in the log and the receipt;
  standing is a derived judgment *over* them, never an edit *of* them. A
  consumer always sees that the line was compromised and exactly what
  restored it. Kernel taint is never cleared, retroactively or otherwise.
- **Degenerate reaffirmations are inert.** A reaffirmation with
  `decision: "none"` (recorded abandonment: "we reviewed; nothing stands")
  restores no standing — the §6.2 walk requires the parent in a *selected*
  set. Competing reaffirmations with different selected sets each restore
  exactly the parents they name; the walk's existential rule keeps the
  result deterministic and order-independent.
- **Replacement side effects are v0.2's.** A `Replace`d Selection leaves
  context construction, as any replaced record does today; the RFC adds no
  new Replace semantics beyond the whitelist entries and the compatibility
  rule. Consequently, replacing a *sound* Selection is legal (V3-S5 does not
  require the target to be unsound — a state-dependent Replace rule would be
  new machinery): standing is unaffected (soundness is never revoked by
  replacement), but the target still leaves context construction. Hosts
  should not `Replace` healthy Selections casually; this side effect is
  documented rather than forbidden.
- **Retracted parents are unrestorable — by design.** Reaffirmation
  recovers from retracted or tainted *decisions*. If a selected *candidate*
  is itself retracted ("the state was wrong," not "the decision no longer
  stands"), no reaffirmation can restore its descendants: any restoring
  Selection must `Require` that candidate, and `Require`-of-retracted is a
  hard rejection. The only path forward is a new `root` — the graver claim
  gets the graver consequence, and the flagship's recovery story is
  explicitly conditional on *what* was retracted. Corpus cases cover both
  (§13).
- **The default trust posture, stated bluntly.** Under default rules,
  restoration is producible in **two records** by any actor in the Selection
  author-role row: one self-authored Evaluation of the old parent, one
  reaffirming Selection. Restoration is therefore *ownership-unbound* while
  retraction is *ownership-bound* (only a record's author or a configured
  admin may retract). Everything stays visible — the junk evaluation, the
  reaffirmation, and their authors are permanently on the record, and a
  consumer can judge the restoring evidence for itself — but deployments
  that need restoration to be as guarded as compromise MUST set
  `reaffirmation_actors` and/or require approvals on Selections (§4.3).
  The default favors recordability; the knobs supply the guarantees.
- **Last resort.** A host abandoning a line entirely may start a new `root`
  candidate with a provenance `note`; the receipt shows the break in
  verifiable lineage. That is the honest cost of a re-baseline.

## 7. Derived lineage

No lineage is stored. Defined queries over refs and payload fields:

- **line of descent**: from any Candidate, follow its continuation edge
  (`Cause`d Selection + `parent`) and derivation `Cause` edges back to a
  `root`.
- **siblings / a "generation"**: candidates sharing the same `Cause`d
  Selection (continuations) or the same `Cause` targets (derivations).
- **frontier**: candidates that appear in no Selection's `considered`, plus
  selected candidates with no continuation yet.
- **standing**: per §6.2, including which reaffirmation (if any) restored a
  line.

These are traversals the CLI exposes (§12); a general query engine is a
non-goal (§14).

## 8. Workload walkthroughs (generality check, C2)

**Best-of-N.** Selection S₀ selects state A. N candidates, each
`basis: continuation`, `parent: A`, `Cause` S₀. Each gets one or more
Evaluations. One Selection considers all N, `Use`s their evaluations,
`Require`s and selects one. Continue.

**Population / beam evolution (autoresearch).** A Selection selects the
top-k survivors {A, B} in one record. Generation k+1 candidates each name
`parent: A` or `parent: B` and `Cause` that Selection. Mutations *within*
a generation are `basis: derivation` candidates `Cause`-ing a sibling.
Abandoned lines simply have no continuation; recorded pruning is a Selection
with `decision: none` over the line's frontier.

**Deep-taint recovery (the case revision 2 could not handle).** At
generation 5, the harness discovers the generation-2 benchmark was broken and
retracts its Evaluations. Kernel taint reaches exactly the generation-2
Selection (it `Use`d them). Standing marks generations 3–5 compromised.
Work continues uninterrupted (new continuations commit, born compromised).
The team re-runs the surviving generation-2 evaluations, commits **one**
reaffirming Selection (`Replace` → S₂) re-selecting the same parents on that
evidence — and at the next replay the entire descendant subtree's standing
is sound again, with the whole episode (retraction, taint, compromise,
reaffirmation) permanently on the record.

**Single-candidate repair.** C₁ (`root` or `continuation`) → Evaluation E₁
fails → C₂ `basis: derivation`, `Cause` [C₁, E₁] → Evaluation E₂ passes →
Selection with `considered: [C₂]` (or `[C₁, C₂]` if the host wants the
comparison on record), `Use` [E₂ (, E₁)], `Require`-ing and selecting [C₂].
The accept step is the same object best-of-N uses; nothing is privileged.

## 9. Verifier rules (additions to the per-record battery)

All existing v0.2 checks (author roles per §4.0's table, identity-to-role
binding, signatures, canonical payloads with typed decode, evidence
derivation and thresholds, taint, retraction ownership) apply to the new
kinds unchanged. New checks, each with a distinct rejection reason code and
a triggering corpus case:

**Payload-id resolution (shared rule).** `parent`, every member of
`considered`, and `Evaluation.candidate` are payload ids, not refs; v0.2's
ref battery never touches them. v0.3 defines: each MUST resolve, in the same
space, to a previously **accepted** `Candidate` record (retracted or tainted
targets resolve — those conditions surface through evidence/taint on refs
and through standing, not through payload lookup). Unresolvable,
cross-space, or wrong-kind payload ids reject.

**Candidate**
- V3-C1: `source.git.tree` present, hex, length matching `algo`.
- V3-C2: `binding == "manifest"` ⇒ `manifest_hash` present (64-hex);
  `binding == "reported"` ⇒ `manifest_hash` absent.
- V3-C3: basis/ref obligations of §4.1 hold, **including acceptance of every
  `Cause` target at commit position**: continuation ⇒ exactly one `Cause`,
  targeting an *accepted* Selection with `decision == "selected"`;
  derivation ⇒ ≥ 1 `Cause`, each an *accepted* `Candidate` or `Evaluation`,
  none a `Selection`; root ⇒ at most one `Cause`, targeting an *accepted*
  Request, and no other `Cause` targets. (Closes the rejected-anchor hole,
  §4.1/§6.2.)
- V3-C5: `parent` present iff `basis == "continuation"`; resolves per the
  shared rule; and names a member of the `Cause`d Selection's selected set.

(Revision 2's V3-C4 — rejecting continuation of a retracted Selection — is
**removed**: with `Cause` edges the generic kernel rules do not apply, and
its consequence is now correctly carried by standing (§6.2), with the
optional `reject_compromised_continuation` knob for hosts that want
commit-time strictness.)

**Evaluation**
- V3-E1: `candidate` names an accepted Candidate (shared rule) and is
  matched by a `Use` ref.
- V3-E2: `criterion` non-empty; `outcome` well-formed per status
  (`scored` ⇔ `value` and `scale` present).

**Selection**
- V3-S1: `considered` non-empty, unique, each member resolving per the
  shared rule.
- V3-S2: `decision == "selected"` ⇒ `outcome.candidates` non-empty, unique,
  ⊆ `considered`, each `Require`d; every `Require` target is either a
  selected candidate or an authority record (Capability/Approval) demanded
  by the rules; `decision == "none"` ⇒ no candidate `Require`s.
- V3-S3: every `Use`d Evaluation's `candidate` ∈ `considered`.
- V3-S4 (knob `selection_requires_evaluation`, default true): ≥ 1 `Use`d
  Evaluation when `decision == "selected"`.
- V3-S5: at most one `Replace` ref (v0.2 rule); if present, the target is a
  Selection, same space, same `objective`; author satisfies
  `reaffirmation_actors` when set.

**New rules knobs**
- `min_binding` per referencing context (e.g. Selections may only `Require`
  candidates with `manifest` binding).
- `selection_requires_evaluation` (default true).
- `reaffirmation_actors` (identity allowlist; unset ⇒ the Selection
  author-role row alone governs — see §6.3's trust-posture statement).
- `reject_compromised_continuation` (default false; §6.2).
- Per-kind evidence thresholds and author-role bindings apply to the three
  kinds exactly as to existing kinds, using §4.0's registrations.

**Spec-level changes beyond the battery** (still additive, per C3): the
`Replace` kind whitelist gains `Selection` (carrier) / `Selection` (target)
with the V3-S5 compatibility rule; the **replay report** gains the
`standing` section (§6.2 — receipts embed nothing derived, unchanged from
v0.2); SPEC v0.3 defines the selection approval-binding hash (§4.3
"Authority") with its own domain string.

**Reachability pre-commitment (for VISION stages, decided now while it is
cheap):** `parent`, `considered`, and `Evaluation.candidate` are edges that
ref-walking tools cannot see. SPEC v0.3 therefore states normatively that
**reachability over v0.3 kinds is payload-aware** — any future garbage
collection, synchronization, or checkpoint tooling MUST treat these payload
ids as reachability edges, or it would silently sever the standing spine.
This is recorded in the spec now, before any such tooling exists, so no
later stage can inherit ref-only reachability as a hidden default.

## 10. Retraction and the flagship scenario

The demonstration this release is built around:

> A benchmark harness is discovered to be broken. Its Evaluations — authored
> by the Provider (or admin-retractable by configuration; §4.0) — are
> retracted. Kernel taint reaches every Selection that `Use`d them, exactly
> as v0.2 defines. The `standing` section of the replay report now shows
> every descendant candidate of those Selections as compromised,
> transitively, at any depth. Repairs and mutations merely *motivated* by
> the broken evaluations remain sound — a derivation is compromised only
> when a **candidate** it derives from is compromised; evaluation
> motivations alone never compromise. Work never stops:
> the line keeps recording, visibly compromised. The team re-runs the
> surviving evaluations and commits one reaffirming Selection; the next
> replay shows the line's standing restored — with the retraction, the
> taint, the compromise, and the recovery all permanently, verifiably on
> the record.

Standing means "rests on decisions that no longer stand," never "the code is
wrong" — and the one-record recovery is part of the demo precisely so the
cascade reads as actionable state, not a permanent alarm or a frozen ledger.
It ships as a worked example plus corpus receipt cases covering: the full
compromise cascade, the derivation non-cascade (evaluation-only motivation)
and the derivation cascade (compromised-candidate derivation), deep
reaffirmation recovery, a `none`-decision reaffirmation restoring nothing,
competing reaffirmations, a replacement chain through an accepted-but-unsound
intermediate, the retracted-parent unrestorable case, and expected-standing
agreement cases that pin the report's `standing` section byte-for-decision —
the same mechanism that already enforces taint agreement between the two
implementations.

## 11. Receipt boundary

A v0.3 receipt proves the recorded **process**: which candidates were
recorded, what was claimed about them, which evidence and evaluations
existed, what was selected under what objective, what is retracted, tainted,
or standing-compromised and what restored it (all re-derived by the
validator from the records — never embedded in the receipt), and that none
of it was altered after the fact. It does **not** contain source contents; Git OIDs
are pointers whose resolution requires the repository. With `manifest`
binding, a party holding the tree can independently recompute
`manifest_hash` and bind the receipt to actual contents; with `reported`
binding they hold a verifiable record of an unverified claim — and the
receipt says which, explicitly.

One further boundary, stated with the same bluntness: **the lineage,
standing, and taint guarantees are conditional on the producer's recording
discipline.** `basis`, `parent`, and the choice of refs are producer claims;
a host that records continuations as derivations escapes the standing
cascade, and no verifier can detect that, because intent is not checkable.
Bellbook proves the recorded structure is internally consistent under its
rules — it does not prove the structure faithfully mirrors the development
process. A receipt consumer trusts the embedded `rules_hash` *and* the
producer's recording conventions. This is v0.2's "consistency, not
completeness" boundary extended one level, and it must appear in SPEC v0.3
§13 verbatim in spirit.

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
                        (--choose <id> ... --uses-eval <id> ...   # evals required with --choose
                         | --none)                               # no evals required with --none
                        [--replaces <selection-id>]              # reaffirmation
                        [--rationale <s>]
bellbook lineage        <id> [--json]      # descent, siblings, taint + standing
bellbook validate       <receipt>          # v0.2 semantics + the standing section
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
  the §10 receipt cases and standing-derivation cases (two implementations
  must produce identical standing sections).
- **v0.2 corpus backfill (independent of v0.3):** the audit found that no
  existing corpus case exercises the `Require` leg of taint propagation,
  though SPEC.md claims that coverage. A small v0.2-scope corpus addition
  should close that gap regardless of this RFC's fate.
- The Python validator implements the three kinds, the standing derivation,
  and the Replace extension independently, and the corpus gate in CI holds
  both implementations to byte-for-decision agreement — same discipline that
  caught real bugs in the v0.2 cycle and in revisions 1–2 of this RFC.

## 14. Non-goals (binding for v0.3)

No ranking or scoring computation; no evaluation execution; no general query
engine (lineage traversal only — but see §15's read-side signal, which is the
designated trigger for revisiting this); no Git plumbing beyond reading OIDs
and the optional manifest walk; no materialization; no remotes or sync; no
native source storage; no structured ContextObject system; no `Generation`,
`Tournament`, or `Repair` kinds; no agent-cognition vocabulary of any sort;
no retroactive clearing of kernel taint under any mechanism. Each of these
is either VISION-scope (gated) or excluded permanently.

## 15. Validation and falsification criteria (pre-registered)

Recorded before implementation so the outcome cannot be rationalized later.
Evaluation window: **90 days from shipping v0.3 + the flagship example**.

**Validation — proceed to the next VISION gate only if ≥ 2 hold:**
1. At least one harness integration authored by someone with no connection to
   this project, in actual use.
2. Receipts generated by ≥ 3 external users or organizations (observed via
   issues, discussions, or shared receipts — not download counts).
3. Inbound issues or PRs that engage the *semantics* (binding modes, standing
   and taint flows, selection invariants) — people argue about semantics they
   use.
4. The flagship broken-benchmark scenario independently reproduced or cited
   by an external party.
5. **Read-side usage**: at least one integration that *queries* — lineage
   traversal, standing/taint status, or receipt validation inside its own
   loop — rather than only writing records. This signal specifically gates
   the VISION query-surface stage: write-side adoption justifies more
   recording semantics; only read-side adoption justifies a query engine.

**Falsification — the thesis fails at this layer if both hold:**
1. Direct exposure to ≥ 5 teams running best-of-N or iterative-evolution
   workflows yields zero adoption, with the stated reason being that ad-hoc
   eval JSON plus branch conventions are sufficient.
2. Any integrations that do exist use Bellbook as write-only logging — no
   receipt validation, no standing or taint queries, no selection semantics —
   for the full window.

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
7. **Standing report naming** — exact field names and serialization order
   for the `standing` section. Its *content* is normative in §6.2
   (`compromised` candidates, `unsound` selections, `restorations` per
   anchor); only the naming and presentation remain open.
8. **`Verified` pathway for evaluations** — under §4.0's base classes,
   evaluations top out at `Reported`. Whether and how a key-pinned external
   attestor's evaluation can reach `Verified` must be settled against
   v0.2's actual `Verified` mechanism (schema base vs. signature-conditioned
   grants) — deliberately unresolved here rather than overclaimed.
9. **`considered` size bound** — population workloads may list thousands of
   ids per Selection; should rules impose a per-record bound consistent with
   the existing resource bounds?
10. **Selection approval-binding domain** — final form of the
    selection-approval hash domain string and its interaction with
    single-use consumption when a Selection is later `Replace`d.
