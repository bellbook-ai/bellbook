# Interoperability boundaries

This document defines the boundary between four responsibilities that
are frequently conflated, and states which one Bellbook owns. The core
crate stays vendor-neutral; named products appear only in
[ECOSYSTEM.md](ECOSYSTEM.md) with explicit status labels.

## The four responsibilities

**Identity** establishes who an agent is, who owns it, and what access
it holds. Bellbook consumes identity: actor ids appear as `author.id`
(use stable, URI-shaped ids, not display names), roles are bound via
`VerifierRules::author_roles`, and identities become cryptographic when
their signing keys are pinned in `author_keys`. Bellbook never mints,
stores, or lifecycle-manages identities.

**Runtime authorization** decides whether a specific action may execute,
at the moment it is attempted. Bellbook captures authorization evidence:
capabilities, approvals, and (planned) external `PolicyDecision`
records. Bellbook's in-band capability/approval machinery is a
deterministic *record* of authority, useful on its own for simple
deployments; it is not a general policy engine and does not compete with
one.

**Telemetry** transports and aggregates execution events for
observability. Telemetry pipelines are a transport with their own trust
model; Bellbook is a system of record with replay verification. The two
can carry the same events: record ids and thread ids make good
correlation attributes.

**Evidence** is Bellbook's layer: an append-only, content-addressed,
replay-verifiable ledger whose receipts a third party can validate
offline without trusting the producer.

## Verdict is not a policy decision

A Bellbook `Verdict` is the deterministic verifier's judgment that a
record conforms to the ledger's rules: ids recompute, authority was
recorded and referenced, evidence derives correctly. It says nothing
about whether an external policy engine permitted the action. These two
judgments must never be conflated:

- A `Verdict` is `Deterministic` evidence because any verifier
  re-derives it from the log alone.
- An external engine's permit/deny is, at best, `Verified` evidence
  (a signed decision from a key-pinned engine or adapter) and otherwise
  `Reported` (the host relayed it). It is never `Deterministic` merely
  because the engine describes itself as deterministic: Bellbook can
  prove who reported the decision, not that the engine evaluated its
  policy correctly, unless the policy bundle, normalized input, and a
  compatible evaluator are all available for re-evaluation.

The planned `PolicyDecision` record (see the roadmap issues) makes this
distinction first-class: it binds an action id, an outcome
(permit/deny/not-applicable/indeterminate/error), an enforce/observe
mode, a stable engine identifier, the evaluated policy-bundle hash, and
the normalized-input hash - so a receipt can show *which* policy, over
*which* input, produced *which* decision, without Bellbook vouching for
the engine's internals.

## Profiles carry the guarantees

Base Bellbook stays usable without any policy engine. Stronger claims
come from separately versioned profiles:

- `bellbook-core-v1` (shipped): the content-addressed baseline - a fixed
  rule shape (registered roles, evidence thresholds no weaker than the
  schema base classes, a bounded context) under which Clean, Tainted, and
  Invalid mean the same thing to two organizations. It requires no
  signatures; the signed tier is a separate profile,
  `bellbook-core-signed-v1` (planned).
- `bellbook-policy-enforced-v1` (planned): proves runtime policy
  decisions were captured and respected (every external action carries
  exactly one accepted, key-pinned, single-use decision;
  deny/error/indeterminate closes through a Refusal; decisions and
  results are independently authored).

From spec 0.4 a receipt declares the profiles it claims, and every
validator evaluates each declaration itself and reports the result beside
the verdict - a declaration is a claim to check, never something to
trust.

## Standards mapping

The deeper outward mapping (OpenTelemetry log model, W3C PROV, in-toto
statements, SCITT receipts for anchoring) has its own document:
[STANDARDS.md](STANDARDS.md). The short version: Bellbook specializes in
agent governance and replay verification, and maps outward to established
standards rather than growing competing layers.
