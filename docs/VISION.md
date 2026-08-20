# Bellbook Vision

**Status: long-term direction, not current scope.** This document describes
where Bellbook is headed if, and only if, each stage earns the next one.
Nothing in it changes what Bellbook is today. SPEC.md (normative), the
README, and the published crate describe the shipped system; this document
describes a direction. Where this document disagrees with them about the
present, they are right: SPEC.md first, per the repository's own normativity
rule.

## North star

> Bellbook is the version-control system for code that evolves autonomously.

Git was built around humans changing files. Autonomous coding systems change
the assumptions underneath that model: they generate, execute, evaluate,
compare, reject, repair, and evolve many software variants without a human
inspecting each intermediate change. Infrastructure built for human
branching can scale to more agents; it cannot naturally represent what those
agents are actually doing.

## Core thesis

Git treats a version primarily as a snapshot of source code. Bellbook treats
a version as a **software state**: the source *and what is known about it*,
meaning its lineage, the claims made about it, the evidence behind those
claims, the evaluations performed on it, and the provenance of all of the
above, bound together tamper-evidently, so that another party can verify the
history of a piece of autonomously produced software without trusting the
system that produced it.

That second half is not decoration. When no human witnessed the intermediate
states, a verifiable record of how software came to be becomes critical.
Without one, downstream systems must trust the producer's account of its own
evolution.

## The missing semantics

Human version control developed around branch, change, review, merge.
Autonomous development adds a second fundamental pattern:

```
state -> fork N candidates -> modify independently -> evaluate -> rank -> select -> continue
```

Merge remains necessary, but it does not define this pattern. Many candidate
states are explored, evaluated, and discarded without ever merging. Today
that entire process (which candidates were considered, what evidence was
gathered, why one was selected, what lineage the survivor carries) has no
native, verifiable representation anywhere. It lives in throwaway branches,
harness logs, and JSON files.

The concepts Bellbook adds are therefore:

```
Candidate    a software/source state proposed as a possible continuation of one or more prior states
Evaluation   an assessment of a candidate against an explicit criterion
Selection    a recorded choice among one or more candidates, grounded in referenced evaluations
Lineage      the ancestry and decision history derived from canonical record relationships
```

together with the trust machinery those records need: content-addressing,
deterministic verdicts, evidence classes that cannot be inflated,
signatures, retraction, and transitive taint. That trust machinery is not
future work: it is the shipped v0.2 kernel, independently reimplemented and
held to byte-for-decision agreement by a conformance corpus.

## Sequencing: how we get there without pretending we are there

The architectural principle for the road itself:

> **Bellbook defines the missing semantics of autonomous software evolution.
> Git can be the initial storage implementation underneath those semantics.**

### v0.2 (shipped): the evidence kernel

An embeddable evidence kernel: typed, content-addressed records in an
append-only log; deterministic re-derivable verdicts; the five-class
evidence lattice with weakest-link derivation; Ed25519 signatures with key
pinning; retraction with transitive taint; portable offline-verifiable
receipts; a language-neutral conformance corpus with an independent second
implementation. This is the trust pillar of everything below, and it exists.

### Now: v0.3 (shipped): the wedge

**Verifiable candidate selection and lineage for autonomous coding agents**,
built on top of Git, not instead of it:

- Git remains the source storage substrate. A candidate binds a Git tree
  (identity) and optionally a commit (provenance).
- `Candidate`, `Evaluation`, and `Selection` are typed record kinds; the
  record remains the only primitive; lineage is derived from canonical
  record relationships, never materialized as a separate structure.
- The existing kernel supplies evidence, signatures, retraction, taint, and
  receipts unchanged.
- The proving workloads are best-of-N candidate selection,
  autoresearch-style iterative evolution, and single-candidate
  repair-and-reevaluate loops. The semantics must serve all three without
  privileging any.

The design is specified in [RFC-0001](rfcs/0001-evolution-semantics.md)
(accepted), including pre-registered validation and falsification criteria,
and was first released as `bellbook` 0.3.0. The question the wedge now exists to
answer, honestly:

> Do autonomous coding systems need a native, verifiable way to represent
> candidate states, evaluation evidence, selection decisions, and trusted
> lineage?

If the answer is no, nothing further below gets built. Rebuilding Git would
not have changed that answer.

### Later: gated on wedge adoption, in rough order of earned need

Each of these is deliberately **not** part of v0.3 and begins only after the
wedge shows real external adoption (the criteria are in RFC-0001):

1. **Query surface**: lineage and evidence queries beyond simple traversal
   ("find the best verified descendant of S under objective X").
2. **Native source storage**: content-addressed blob/tree storage with
   structural sharing, making the filesystem an execution projection of
   Bellbook state and Git an interoperability surface rather than the
   substrate.
3. **Distribution**: remotes, incremental sync, reachability, policy-driven
   garbage collection for repositories with very large numbers of ephemeral
   machine-generated states.
4. **Runtime and control plane**: materialization, sandboxed execution,
   deployment and observation of states without loss of identity or
   lineage; hosted repositories and governance.

The long-term shape, if every gate is passed: one substrate where autonomous
software is versioned, evaluated, run, observed, and continuously evolved,
with the same state identity throughout its lifecycle.

## Design rules

Every proposed Bellbook feature must pass:

1. *Does this represent or preserve a fundamental property of autonomous
   software evolution that belongs at Bellbook's current layer?* If the
   capability belongs to a later layer of the vision, it must wait until that
   layer's adoption gate has been earned.
2. *Bellbook must never need to understand how an agent thinks in order to
   understand what happened to the software.* No prompts, planners, tasks,
   repair strategies, models, or conversations in the core. Bellbook
   versions the consequences of intelligence, not its architecture.
3. *Claims must never be broader than guarantees.* Consistency is not
   completeness; integrity is not confidentiality; tamper-evident is not
   tamper-proof. Every layer states its boundary the way SPEC.md §13 does
   today.

## What Bellbook is not, at any stage

Bellbook does not contain agent planners, prompt storage, model routing,
task scheduling, repair strategies, ranking or scoring logic, or product UX
for any particular autonomous development system. Any coding agent,
autoresearch system, or future architecture not yet invented should be able
to read and write Bellbook state on equal terms. That independence is what
would make Bellbook infrastructure rather than a component of one product.
