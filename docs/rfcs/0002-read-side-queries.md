# RFC-0002: Read-side queries over lineage and evidence

**Status:** Accepted (revision 2, 2026-08-27). This document specifies the
design for the v0.6.0 milestone (tracking: #91, #90). It makes **no spec
change**: no new record kinds, no wire-format change, and no spec-version
bump; the spec epoch stays 0.3. Where this design and SPEC.md differ about
the present, SPEC.md is authoritative.

**Scope anchor:** the read side of the current layer. RFC-0001 §7 already
*defines* lineage as derived queries over canonical record relationships,
and the CLI already exposes one of them (`bellbook lineage`). This RFC
completes that named set and gives it surface parity (Rust, Python, CLI;
over a log or a receipt) - the read-side counterpart of what v0.5.0 did for
the write side.

**Gate honesty (drift control):** RFC-0001 §14 declares "no general query
engine" a binding non-goal, and §15 criterion 5 pre-registers *external
read-side adoption* as the only trigger for the VISION query-engine stage.
This RFC does **not** propose that stage, and does not touch that gate: the
general engine (query languages, composition, payload predicates, indexes)
remains gated on §15's signal. What it proposes is a **closed, named query
set** with fixed semantics - the completion of RFC-0001 §7's own list. The
design is advanced ahead of the §15 window on first-party field evidence,
under VISION's build-ahead note; accepting this RFC is the explicit,
recorded decision to implement the named set and nothing beyond it.

---

## 1. Summary

Seven named, deterministic, read-only queries over canonical record
relationships, answerable identically from Rust, Python, and the CLI, over
a live log or a portable receipt. All of them derive from what replay
already computes; none of them store anything, rank anything, or interpret
payloads beyond the spec's own fields.

## 2. Motivation

A field test (2026-08-26: a real best-of-N over eightbells-canary Git
trees, followed by the retraction story) surfaced the asymmetry. The write
side has full surface parity since 0.5.0. On the read side, every real
question required hand-walking `records()` and parsing payload JSON from
Python; the CLI has `lineage` but receipts and Python have nothing. The
questions asked in practice were concrete and few:

- what is the line of descent, and what happened to it?
- which sound, selected candidates stand under this objective?
- what evidence does the survivor's line rest on?
- how do the siblings of a generation compare?

Three generations were enough to make each of these painful. The need is
not speculative and not external: it is the project's own field tests. That
is exactly the evidence class VISION's build-ahead note admits for *design*
work, and exactly not the evidence class RFC-0001 §15 requires for the
*engine* stage; hence the shape of this RFC.

## 3. Design constraints

- **C1: derived, never stored.** No new state, no indexes, no
  materialization. Lineage remains derived from canonical relationships
  (RFC-0001 §7); a query is a pure function of `(records, rules)`.
- **C2: deterministic and cross-implementation testable.** The same
  `(records, rules, query, args)` yields the same answer on every surface
  and in both implementations (Rust core and the independent Python
  validator). The conformance corpus gains query vectors.
- **C3: no ranking, no scoring.** Bellbook records the consequences of
  intelligence, not its architecture (VISION design rule 2). There is
  deliberately no "best descendant" query: Bellbook returns the *sound,
  selected* candidates and their evidence; the caller ranks. Naming a
  winner is the harness's job and stays out of the core forever.
- **C4: log and receipt parity.** Every query runs over an open log or a
  portable receipt, after verification. Queries never run on an unverified
  receipt: an Invalid receipt returns the validation error, not answers.
- **C5: closed set.** The queries are enumerated here with fixed semantics.
  Anything parameterized beyond the named arguments - payload predicates,
  pattern matching, composition - is the gated engine and out of scope.

## 4. The named query set (v1)

All queries operate on the replayed state of an accepted record sequence.
Ids are record ids; "sound" and "compromised" are the standing dimension of
RFC-0001 §6.2 exactly, never recomputed differently.

- **q1 `descent(candidate)`** - the line of descent from a candidate back
  to its root: continuation edges (`Cause`d Selection plus `parent`) and
  derivation `Cause` edges, each node annotated with kind, standing, and
  taint. The existing `bellbook lineage` view, normalized.
- **q2 `descendants(record)`** - the forward closure: every candidate
  whose descent passes through the given record, annotated as q1.
- **q3 `siblings(candidate)`** - the generation: candidates sharing the
  same `Cause`d Selection (continuations) or the same `Cause` target set
  (derivations), per RFC-0001 §7.
- **q4 `frontier()`** - candidates appearing in no Selection's
  `considered`, plus selected candidates with no continuation yet, per
  RFC-0001 §7.
- **q5 `standing(id)`** - `sound` | `compromised` | `unsound`, with the
  restoring reaffirmation ids when a restoration applies. Today partially
  visible via the report's standing section; q5 makes it addressable per
  record.
- **q6 `evidence(id)`** - for a Selection: the evaluations it `Use`d, with
  their outcomes and current standing. For a Candidate: the same,
  transitively along its descent - "what does this line rest on", the exact
  question the field test hand-walked.
- **q7 `selected(objective)`** - the accepted Selections whose `objective`
  equals the given string exactly (no patterns - patterns are engine
  territory), with their chosen candidates, each annotated with standing
  and the q6 evidence set.

Each query's full input/output shape, error behavior, and edge cases
(rejected records, retracted targets, empty logs) are specified before
implementation in this document's acceptance revision; the JSON shapes are
shared verbatim across all three surfaces so answers are diffable.

## 5. Surfaces

- **Rust:** a `queries` module over `(&[Record], &VerifierRules)`; the CLI
  and the binding are thin callers, per the v0.5.0 precedent.
- **Python:** methods on `Receipt` and `Writer` returning plain
  dicts/lists with the shared JSON shapes.
- **CLI:** `bellbook query q-name [args] (--log DIR --rules FILE | --receipt FILE)`
  emitting the shared JSON (human-readable rendering as `lineage` does
  today). `bellbook lineage` remains as the q1 convenience.

## 6. Conformance

The corpus gains query vectors: `(case, query, args) -> expected answer`.
The Rust runner asserts them; the independent Python validator implements
the same named set and asserts the same vectors. Two implementations,
byte-for-decision agreement, as with verdicts - determinism is a claim only
until it is cross-checked.

## 7. Non-goals (binding for v0.6)

No query language or composition; no predicates over payload fields beyond
the named arguments; no pattern or substring matching on objectives; no
ranking or scoring of any kind; no indexes or persisted derived state; no
cross-receipt joins; no remote or streaming queries. The general query
engine remains gated on RFC-0001 §15 criterion 5 (external read-side
adoption), and nothing in this RFC re-opens that decision.

## 8. Validation and falsification criteria (pre-registered)

Recorded before implementation. Evaluation window: 90 days from shipping
v0.6.0.

**Validation - the named set is the right shape if at least 2 hold:**
1. Re-running the project's own field tests (the canary best-of-N and the
   retraction story) requires **zero** hand-walking of `records()`: every
   question maps to a named query. Measured by rewriting the field-test
   scripts against the query set.
2. External read-side usage of any named query (an integration, issue, or
   discussion exercising them) - which would *simultaneously* progress
   RFC-0001 §15 criterion 5.
3. An external request for a query outside the named set - demand evidence
   for the gated engine, to be recorded against §15, not quietly absorbed
   into this set.

**Falsification - the shape missed if both hold:**
1. The rewritten field tests still need hand-walking (the set answers the
   wrong questions), and
2. no external signal engages the read side during the window.

**Decision rule:** falsified means the named set is revised before any
further read-side work, and the engine stage remains untouched either way -
it opens only on RFC-0001 §15's own terms.

### 8.1 Evaluation log

- **2026-08-28 - validation criterion 1 met.** The canary best-of-N field
  test was re-run against the published 0.6.0 artifacts (the CLI over an
  exported receipt and the Python query methods over the live writer), with
  the retraction story and the tie-break pattern included. Every field-test
  question mapped to a named query; hand-walks of `records()`: zero. Answers
  were byte-identical across the two surfaces. Recorded in
  [`docs/field-tests/ft2-read-side.md`](../field-tests/ft2-read-side.md). Two
  frictions surfaced (foreign-receipt entry-point enumeration; unused
  evaluations not being query-reachable); neither justified new
  implementation - the first waits on external demand under criterion 3, the
  second is documented as a boundary in SPEC §12.4. Criteria 2 and 3
  (external signals) remain open for the window.

## 9. Resolved design decisions (at acceptance, 2026-08-27)

1. **Frontier scope: the whole log (or receipt).** q4 takes no scoping
   argument in v1. The definition is over canonical relationships only, so
   it does not bake in the writer's current single-thread behavior; a
   scoped variant would be a new named query, not a parameter.
2. **Evidence transitivity: unbounded, documented.** q6 on a candidate
   walks the full descent. Lines are bounded in practice by
   `max_context_records` and receipt limits; no depth argument in v1 (an
   argument would be the first step toward parameterized queries, which
   are engine territory). The docs state the full-descent behavior
   plainly.
3. **Semantics live in this RFC plus a short SPEC section plus corpus
   vectors.** Two implementations must agree byte-for-decision, so the
   named set's shapes are pinned the same way verdicts are: SPEC documents
   the set briefly and points here; the corpus carries the answers.
4. **#90 (tie-break evidence) resolves as the documentation pattern.**
   The discriminating fact between two passing candidates is recorded as
   an Evaluation under its own criterion (e.g. `completeness`), so the
   selection's `uses_eval` genuinely discriminates and q6/q7 surface it.
   No payload change. #90 closes when the pattern lands in the docs
   during v0.6.0 implementation.
