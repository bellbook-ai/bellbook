# bellbook-core-v1

**The content-addressed baseline profile.** Version 1. Specified by
[RFC-0003](../rfcs/0003-requirement-binding.md) section 4.5; mechanism in
[SPEC](../../SPEC.md) section 12.2. Clause table and hash published in
[`spec/profiles/bellbook-core-v1/profile.json`](../../spec/profiles/bellbook-core-v1/profile.json);
vectors in `cases.json` beside it.

A Clean receipt under default rules means the captured history is
internally consistent under *its own* embedded rules. Two organizations
cannot compare Clean receipts without first agreeing what those rules must
look like. This profile is that agreement, kept deliberately small: when two
parties both name `bellbook-core-v1`, they agree on the rule shape below and
on what Clean, Tainted, and Invalid mean under it. It requires no
signatures - not every adopter signs from day one, and a baseline nobody can
meet compares nothing. The signed tier is a separate profile,
`bellbook-core-signed-v1`.

## What conformance means

- **Conformant** - every clause below held. A consumer may conclude: the
  history replayed under a rule set that registers every author's role,
  admits no evolution record weaker than its schema base class, and declares
  a bounded context; and the consumer can read from the rules who could
  have retracted or restored anything.
- **NonConformant** - at least one clause failed; the report names it. The
  verdict is unchanged: a NonConformant receipt may still be Clean under its
  own rules. It is simply not comparable under this profile.
- **Unknown** - the validator does not know the profile id.

Profile conformance is a report alongside the verdict. It never changes
`status` or `reason` and is never a verdict reason code.

## Clauses

The normative statements are the ones in `profile.json`; the hash commits
to them. Restated with what each clause judges:

| Clause | Statement | Judges |
|---|---|---|
| **B1** | The receipt validates Clean or Tainted; an Invalid receipt never conforms. | `Report.status` |
| **B2** | `author_roles` is non-empty, and every accepted record's author is registered in it. | The rules; replay guarantees the second half (`AuthorRoleInvalid`) |
| **B3** | `evidence_thresholds` carries entries for Candidate, Evaluation, and Selection, each no weaker than the schema base class (Reported, Reported, Inferred). | The rules; "no weaker" means at least as strict as the base class |
| **B4** | `max_context_records` is declared within `1..=100000`. | The rules |
| **B5** | Retraction and reaffirmation authority are readable from the rules: `admin_retraction_actors` and `reaffirmation_actors` are reported. | Always holds; the value is the reported detail |
| **B6** | The source binding mode of every accepted Candidate (Manifest or Reported) is reported; neither is required. | Always holds; the value is the reported detail |

B5 and B6 are reporting clauses: they exist so a consumer reading the
profile result sees the facts a comparison needs, not so a receipt can fail
them.

## Meeting the baseline

`bellbook rules init` and `bellbook.default_rules(...)` emit the B3
thresholds by default, so a generated rule set conforms out of the box. A
rule set written before 0.7.0, or by hand, adds:

```json
"evidence_thresholds": {"Candidate": "Reported", "Evaluation": "Reported", "Selection": "Inferred"}
```

Changing the rules changes `rules_hash`: a receipt already exported under
the old rules stays valid under them and stays NonConformant here. That is
correct - the baseline is a statement about the rules a history was
committed under, not something applied afterwards.

## Checking

```sh
bellbook validate receipt.json --require-profile bellbook-core-v1
# exit 0 Clean and conformant; 2 Tainted and conformant;
# 3 validates but does not conform (or unknown profile); 1 Invalid
```

```python
report = bellbook.validate(data, require_profile="bellbook-core-v1")
report.profiles[0]["status"]          # "Conformant" | "NonConformant" | "Unknown"
report.profiles[0]["clauses"]         # [{"id": "B1", "passed": True, "detail": ...}, ...]
```

The independent validator under `conformance/python/` implements every
clause from scratch and must agree with the reference on every vector in
`cases.json`, recomputing the profile hash from the published clause table.

## Hash

`sha256` over the RFC 8785 canonical form of the clause table in
`profile.json`. Printed by the validator with every result so a consumer
can confirm which revision of this profile was applied. Any change to a
clause statement is a new version with a new hash.
