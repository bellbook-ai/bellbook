# Stability

What Bellbook 1.0 promises, what it does not, and how anything that is
promised can change. This document is normative for the project's own
releases; SPEC.md stays the authority for what a record or receipt means.

1.0 is a promise, not a feature. A trust root earns the label by surviving
use and review, so 1.0.0 is tagged only after the gates in the release
issue hold: an adopter in production on the 0.x line for a 30-day soak with
no breaking change needed, spec epoch 0.4 unchanged through it, the trust
boundary reviewed as SECURITY.md gates it (an internal adversarial review
published in this repository, the coverage-guided fuzz targets clean over a
stated budget on the release commit, no unresolved finding), and the public
surface below audited. 1.0 does not ship on an external security review,
and its release notes will say so: nothing outside the project depends on
Bellbook enough yet to justify one, and Bellbook does not claim assurance it
has not earned. Until then this document describes what 1.0 *will* promise,
and the 0.10.x line already behaves this way.

## Versioning

Releases follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
over the surfaces listed in "What is covered". From 1.0.0:

- **Patch** (1.0.x): fixes that change no covered surface and no decision
  any conforming validator reaches on any valid input.
- **Minor** (1.x.0): additive changes only. New functions, types, record
  kinds, schemas, profiles, CLI commands and flags, Python parameters,
  reason codes, and JSON fields. Nothing covered is removed, renamed,
  retyped, or given a different meaning.
- **Major** (2.0.0): anything else. A spec epoch that changes the meaning
  of an existing record, a removed or renamed public item, a CLI flag that
  stops being accepted, an exit code that changes meaning.

Before 1.0.0 (the 0.x line), minor releases may break, as they have; the
CHANGELOG names every such change under "Changed" or "Removed".

## What is covered

### The wire format (SPEC.md)

- **Spec epoch 0.4 is frozen.** The record envelope, RFC 8785 canonical
  form, record id derivation, signing form and domain string, every schema
  the epoch names, the receipt document, and the verdict rules are fixed.
  A 1.x validator reaches, for every 0.3 and 0.4 receipt, the identical
  decision (status, reason, retracted and tainted sets, standing) that the
  epoch's own validator reached. This is enforced by the byte-frozen
  vectors and conformance corpora under `spec/`, re-derived in CI on every
  commit, and by replaying frozen receipts through published binaries.
- **Receipts are forward-valid.** A receipt produced by any 1.x release
  validates under every later 1.y release with the same decision.
- **New epochs are additive.** A later epoch (0.5 and beyond, or whatever
  the numbering becomes) may add record kinds, schemas, and receipt fields.
  It never changes what an existing epoch's record means, and validators
  keep every earlier epoch's schema set. An epoch that could not keep this
  promise would be a major release.
- **Reason codes** are stable identifiers. New codes may be added (minor);
  no existing code is removed or reassigned. A validator never reaches a
  new code on an input a previous validator accepted.

### Profiles (SPEC.md section 12.2)

A profile is identified by `(id, version, clause-table hash)`. That triple
is immutable: any change to a clause statement is a new version with a new
hash, published beside the old one, and the old version keeps evaluating
exactly as it did. The clause *semantics* behind a published table are
fixed by its vectors; a change in what a clause accepts on an existing
vector is a defect, fixed as a patch, never a reinterpretation. New
profiles are minor.

### The Rust crate

Every `pub` item reachable from the `bellbook` crate root and its `pub mod`
paths is covered: names, signatures, field sets, enum variants, trait
impls, and documented behavior. All of them are documented (`missing_docs`
is denied in CI). Behavior that the documentation calls out as
unspecified, or that is reachable only through `unsafe` or private paths,
is not covered.

- **MSRV** is 1.75 and is checked in CI. Raising it is a minor change,
  announced in the CHANGELOG.
- **Features**: the `persist` feature (on by default) gates the writer and
  the CLI's recording commands. Removing a feature or changing a default is
  major.
- **Dependencies** are not part of the surface, except that the crate's
  public types never expose a third-party type without a documented reason.

### The CLI (`bellbook`)

Command names, flag names and their accepted values, positional arguments,
exit codes, and the shape of `--json` output are covered. Human-readable
output (the non-JSON text) is not: it may be reworded in any release. New
commands, flags, and JSON fields are minor; consumers of `--json` must
ignore fields they do not know.

### The Python package (`bellbook` on PyPI)

Public functions, classes, methods, their positional and keyword
parameters, return shapes (including the dict keys of `Report.profiles`
and the query surfaces), and exception types are covered. New keyword
parameters with defaults and new dict keys are minor. The package tracks
the published crate: its version is the crate version it pins.

### The independent Python validator (`conformance/python/`)

Covered as a *checkable claim*, not as a library: it agrees with the
reference on every published vector and corpus case, and
`validate_receipt.py` reports what `bellbook validate` reports with the
same exit codes. Its module and function names are not covered.

## What is not covered

- **Completeness of capture.** Bellbook proves recorded history is
  consistent and honestly graded, never that everything the agent did was
  recorded (SPEC.md section 13).
- **Confidentiality.** Payloads are in the clear by design.
- **Anything a profile does not check.** A conformant `delivery-receipt-v1`
  receipt proves the recorded process, not that the evaluator was
  competent or the requirements were the right ones.
- **Performance.** No throughput, latency, or size figure is a promise;
  the validation limits are, and they are documented.
- **Internal module layout** below the documented paths, private items, and
  the text of error and detail messages.
- **The site, the articles, and the field-test reports.** Evidence and
  explanation, not interfaces.

## Deprecation

Nothing covered is removed without a deprecation period.

1. A deprecated Rust item carries `#[deprecated(since, note)]` naming its
   replacement for at least one minor release before a major removes it.
2. A deprecated CLI flag or command keeps working and prints a one-line
   notice to stderr naming its replacement for at least one minor release.
   Its `--json` output does not change.
3. A deprecated Python parameter keeps working and emits a
   `DeprecationWarning` naming its replacement for at least one minor
   release.
4. Spec epochs are never deprecated: a validator keeps every epoch it ever
   supported.
5. Profiles are never deprecated: an old version keeps evaluating. The
   profile document may say a newer version exists.

Every deprecation and removal is listed in the CHANGELOG under
"Deprecated" or "Removed" with the release it takes effect in.

## Support

- The latest minor release receives fixes. A security fix to the
  verification path is released as a patch on the latest minor and noted
  in the CHANGELOG and the security advisory, with the affected range.
- Published 0.x releases stay on the registries and keep validating the
  epochs they implement; they receive no further changes.
- Reports of a decision the two implementations disagree on, or of a
  frozen vector that no longer re-derives, are treated as defects of the
  highest priority: they are the promise this document makes.

## How this document changes

A change that narrows a promise is a major release. A change that widens
one, or clarifies wording without changing what holds, is recorded in the
CHANGELOG and may land in any release.
