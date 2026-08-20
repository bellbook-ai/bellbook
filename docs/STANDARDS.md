# Standards mapping

How a Bellbook ledger exchanges data with four adjacent standards -
OpenTelemetry Logs, W3C PROV, in-toto, and SCITT - without adding record
kinds, runtime dependencies, or any claim of an implemented integration.

This is a mapping for interchange, not an adapter. Bellbook stays the
verification source for its own receipts: every mapping below is a lossy
*projection outward* (telemetry and provenance formats carry a shadow of the
ledger for transport, indexing, or description) or an *anchoring inward* (a
transparency service stores evidence that a head attestation existed). None of
them verify a Bellbook receipt; only replay does (§12). The boundary framing
these mappings assume is in [INTEROPERABILITY.md](INTEROPERABILITY.md); named
products live in [ECOSYSTEM.md](ECOSYSTEM.md).

The record model referenced throughout (`Record`, its `kind`, `author`,
`evidence`, typed `refs`, and the `HeadAttestation`) is defined in
[SPEC.md](../SPEC.md) §2 and §11.1.

## OpenTelemetry Logs

Telemetry pipelines transport and index events; they are a transport with their
own trust model, not a system of record. A Bellbook log projects cleanly onto
the OpenTelemetry log data model for observability, with record id and thread
id as the correlation keys.

| Bellbook | OpenTelemetry Logs |
|----------|--------------------|
| one record (subject or verdict) | one `LogRecord` |
| `thread` | correlation attribute (trace-like grouping) |
| `id` | unique event-id attribute; the target of `refs` from other events |
| `kind` | attribute |
| `author.id`, `author.type` | attributes |
| `evidence` class | attribute |
| `time` (logical counter) | attribute - **not** `Timestamp` (a record carries no wall-clock; the host supplies ingestion time) |
| `data` payload | `LogRecord` `Body` |
| `Cause` / `Use` / `Require` / `Replace` refs | attributes naming target ids (causal links) |
| `Verdict` record | its own `LogRecord` - never a `SeverityText`/status field |

Boundary: a `Verdict` is the deterministic verifier's judgment (§4), not a log
severity, and it re-derives only inside Bellbook. Telemetry can carry the same
events for search and dashboards; it cannot stand in for validation.

## W3C PROV

PROV is an interchange vocabulary for provenance. A receipt maps onto it so
provenance tools can render lineage, with the understanding that a PROV export
is a lossy view: it drops the evidence lattice, the re-derivable verdicts, and
the standing section.

| Bellbook | W3C PROV |
|----------|----------|
| a record | `prov:Entity` (immutable, content-addressed) |
| the act that produced a record (running an `Action`, making a `Selection`) | `prov:Activity` |
| `author` `{id, type}` | `prov:Agent`; record `prov:wasAttributedTo` it |
| `Provider` acting under a `User`'s request | `prov:actedOnBehalfOf` (delegation) |
| `Cause` ref (Result -> Action, Verdict -> subject) | `prov:wasGeneratedBy` / `prov:wasDerivedFrom` |
| `Use` ref | `prov:used` |
| `Require` ref | `prov:used` on a precondition entity (semantics are stricter - see below) |
| `Replace` ref | `prov:wasRevisionOf` |
| `Retraction` | `prov:wasInvalidatedBy` |
| Candidate continuation / derivation | `prov:wasDerivedFrom` |

Boundary: PROV records that a relationship exists; it does not enforce one. A
`Require` ref is a validity precondition - a record whose required target is
rejected, retracted, or tainted is itself rejected (§2) - whereas `prov:used`
carries no such rule. Standing (§7.2), taint, and the evidence class have no
PROV equivalent and are lost in export. Bellbook stays the place those facts are
computed.

## in-toto

An in-toto Statement (ITE-6: `_type`, `subject`, `predicateType`, `predicate`)
describes what was built or tested. Bellbook carries such a Statement as the
`output` of an external-receipt `Result` (`bellbook.result.external_receipt.v1`,
base evidence `Verified` when the executor's key is pinned). The two layers are
complementary and stay in their lanes.

| Bellbook | in-toto |
|----------|---------|
| external `Result` `output` | the serialized in-toto Statement |
| the `Result`'s key-pinned `author` (Executor) | the Statement's functionary (signer) |
| the `Action` the Result closes (`Cause` ref) | the step whose evidence the Statement is |
| a `Candidate`'s `manifest_hash` / Git tree | the Statement `subject` digest it concerns |

Boundary: Bellbook does not parse or evaluate the in-toto layout or verify the
predicate's truth; it binds a *reported* Statement to an action, an author, and
a place in the replay-verifiable chain (so the Statement inherits taint and
retraction if its supports do). Verifying the Statement itself is the in-toto
verifier's job. A Candidate's manifest binding and an in-toto subject digest
both commit to content, from opposite directions: the manifest binding lets a
holder recompute the identity (§2), the Statement carries a signed claim about
it.

## SCITT

SCITT (Supply Chain Integrity, Transparency, and Trust) is a transparency
service: it registers a signed statement on an append-only log and returns a
receipt proving the statement existed there at a time. It is an *anchoring
target* for Bellbook's head attestation, exactly the role §11.1 leaves to the
host.

| Bellbook | SCITT |
|----------|-------|
| `HeadAttestation` (JCS bytes, §11.1) | the signed statement that is registered |
| `head_hash` + `record_count` | identifies the exact log prefix anchored |
| the SCITT transparency receipt | external anchoring evidence, stored out of band |
| validation's recomputed `head_hash` | audited by byte-comparing against the anchored attestation |

Boundary: a transparency receipt attests *existence and immutability* of those
bytes at a time - never that the log was verified, and never as a source of
checkpoint trust (§10, §11.1). Anchoring is not validation: an auditor still
recomputes `head_hash` over `record_count` records and replays from genesis.
Bellbook defines only the attestation format; the witness, transport, and anchor
storage are host concerns.

## What this document does not claim

It defines no new record kinds, adds no runtime dependency, ships no adapter, and
makes no compatibility or certification claim about any named product. Each
mapping is a description of how data can move across a boundary while Bellbook
remains the source of replay-verifiable evidence for its receipts.
