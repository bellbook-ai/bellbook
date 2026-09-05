# bellbook-core-signed-v1

**The signed tier above the baseline.** Version 1. Specified by
[RFC-0003](../rfcs/0003-requirement-binding.md) section 4.5; mechanism in
[SPEC](../../SPEC.md) section 12.2. Clause table and hash published in
[`spec/profiles/bellbook-core-signed-v1/profile.json`](../../spec/profiles/bellbook-core-signed-v1/profile.json);
vectors in `cases.json` beside it.

[`bellbook-core-v1`](bellbook-core-v1.md) requires no signatures, so that a
baseline exists which every adopter can meet. It therefore proves the
evolution record *consistent*, not *authenticated*: an actor id is a
string anyone can write, and under baseline rules an unsigned Candidate
claiming to be the producer's is accepted as the producer's. The signed
tier is what a consumer names when that is not enough. It asks three
things of the rules and the record, all checkable from the receipt alone:
signatures are required on every evolution kind, every actor who authored
one has pinned keys (so a signature binds a key to an identity rather than
to whatever key it happens to carry), and every evaluation a selection
rests on carries the attested schema, whose `Verified` base class the
verifier admits only under a pinned signature.

A baseline-conformant receipt reaches this tier by adding signatures and
switching evaluation schema ids. No payload changes shape.

## What conformance means

- **Conformant** - every clause below held. A consumer may conclude, on
  top of everything the baseline guarantees: every accepted Candidate,
  Evaluation, Selection, Retraction, and Requirement was signed by a key
  the rules pin to its author (replay verified each signature, else the
  receipt would be Invalid), and every evaluation a selection uses is an
  attestation from a key-bound party, not a reported opinion.
- **NonConformant** - at least one clause failed; the report names it and
  what it saw (the missing kinds, the unpinned authors, the unattested
  evaluations). The verdict is unchanged.
- **Unknown** - the validator does not know the profile id.

Profile conformance is a report alongside the verdict. It never changes
`status` or `reason` and is never a verdict reason code.

## Clauses

The normative statements are the ones in `profile.json`; the hash commits
to them. Restated with what each clause judges:

| Clause | Statement | Judges |
|---|---|---|
| **S0** | The receipt conforms to `bellbook-core-v1`, and if it declares that profile the declaration names the evaluated table. | The baseline, declared or evaluated as the fallback, exactly as `delivery-receipt-v1` D6 does. An Invalid receipt fails every clause. |
| **S1** | `signature_required_kinds` includes Candidate, Evaluation, Selection, Retraction, and Requirement. | The rules. This is about the rule shape, not this log's luck: a log where every record happens to be signed still fails if the rules would have accepted an unsigned one. |
| **S2** | `author_keys` pins every actor that authored an accepted Candidate, Evaluation, Selection, Retraction, or Requirement. | The records against the rules. An unlisted actor may sign with any key and the signature still verifies; only pinning binds the key to the identity. |
| **S3** | Every evaluation `Use`d by an accepted Selection with outcome `Selected` carries the schema `bellbook.evaluation.attested.v1`. | The evaluations selections rest on. A signature never promotes an evidence class; the schema does, and the verifier admits the attested schema only under a pinned signature. Evaluations no selection uses may carry any schema. |

Every clause is fail-closed. S0 through S3 all fail on an Invalid receipt;
a Tainted receipt can still conform (the baseline admits Tainted, and a
signed Retraction is exactly the kind of record this tier wants
authenticated).

## Meeting the signed tier

Three changes to a baseline setup, none of which reshapes a payload:

1. **Rules.** Add the five kinds to `signature_required_kinds` and pin each
   actor's Ed25519 public key in `author_keys`. A pinned actor's records
   always require a signature that verifies against one of its keys,
   whatever the kind.
2. **Signing.** Every writer that acts as one of those actors signs what it
   commits. The signature covers the domain-separated canonical signing
   form and is bound into the record id, so a stripped or transplanted
   signature is an Invalid receipt, not a NonConformant one.
3. **Attested evaluations.** Evaluators write `bellbook.evaluation.attested.v1`
   instead of `bellbook.evaluation.v2`. Same payload; the schema id is the
   only difference, and the verifier rejects an attested record whose
   author has no pinned keys or whose signature is absent.

Changing the rules changes `rules_hash`: a receipt exported under baseline
rules stays valid under them and stays NonConformant here.

From the CLI, with one secret per actor (any 32 random bytes, kept by the
host; `openssl rand -hex 32 > agent.hex` is enough):

```sh
bellbook key public --secret agent.hex          # the hex to pin
bellbook rules init --author human:user --author agent:provider --author evaluator:provider \
  --signed --author-key human:HUMAN_PUB --author-key agent:AGENT_PUB \
  --author-key evaluator:EVALUATOR_PUB --out rules.json
bellbook candidate add ... --author agent --sign-key agent.hex
bellbook eval add ... --author evaluator --evaluator harness --basis recomputed \
  --attested --sign-key evaluator.hex
bellbook select ... --author agent --sign-key agent.hex
bellbook export --profile bellbook-core-v1 bellbook-core-signed-v1 delivery-receipt-v1 --out receipt.json
```

From Python:

```python
rules = bellbook.default_rules({"human": "user", "agent": "provider", "evaluator": "provider"},
                               signed=True,
                               author_keys={"human": [HUMAN_PUB], "agent": [AGENT_PUB],
                                            "evaluator": [EVALUATOR_PUB]})
w = bellbook.Writer("./log", rules, signers={"human": HUMAN_SECRET, "agent": AGENT_SECRET,
                                             "evaluator": EVALUATOR_SECRET})
e = w.evaluate(author="evaluator", ..., evaluator="harness", basis="recomputed", attested=True)
```

The writer signs every record a listed actor writes; an unsigned record by
a pinned actor is rejected by the verifier as `SignatureMissing`, and a
record signed with a key the rules do not pin for its author as
`SignatureInvalid`. Both are durable rejected records, not errors.

## Declaring

```sh
bellbook export --log ./log --rules rules.json \
  --profile bellbook-core-v1 bellbook-core-signed-v1 --out receipt.json
```

The declaration is never trusted: every validator evaluates the tier from
its own clause table and reports whether the declared version and hash name
that table. A stale or altered hash is reported with `declaration_matches:
false` and the profile does not count as met.

## Checking

```sh
bellbook validate receipt.json --require-profile bellbook-core-signed-v1
# exit 0 Clean and every profile met; 2 Tainted and met;
# 3 validates but a declared or required profile is not met; 1 Invalid
```

```python
report = bellbook.validate(data, require_profile="bellbook-core-signed-v1")
p = report.profiles[0]
p["status"], p["met"], [c["id"] for c in p["clauses"] if not c["passed"]]
```

`delivery-receipt-v1` D6 accepts the baseline "or a stronger tier": a
receipt declaring all three profiles is a delivery claim whose every
evaluation is an authenticated attestation. The vectors carry that case.

The independent validator under `conformance/python/` implements every
clause from scratch, verifies every Ed25519 signature the vectors carry,
and must agree with the reference on every vector in `cases.json`.

## The vectors

`cases.json` pairs each receipt with its validation status and every
profile result: the tier met in five honest shapes (baseline declared,
baseline as the fallback, a delivery claim judged under the signed tier, a
Tainted history with a signed retraction, an unused unattested
evaluation), one rejecting case per clause (a baseline that fails B3; rules
that leave two kinds unsigned; a producer who signs with an unpinned key; a
claim resting on signed-but-unattested `evaluation.v2`; a claim resting on
`evaluation.v1`), a stale declaration, and a receipt whose Candidate
signature was stripped after export (Invalid; every clause fails). Every
record a pinned author wrote carries a real signature under a
deterministic test key.

## Hash

`sha256` over the RFC 8785 canonical form of the clause table in
`profile.json`. Printed by the validator with every result so a consumer
can confirm which revision of this profile was applied. Any change to a
clause statement is a new version with a new hash.
