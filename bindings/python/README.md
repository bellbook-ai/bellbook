# bellbook (Python)

Python bindings for [Bellbook](https://github.com/bellbook-ai/bellbook):
validate tamper-evident, replay-verifiable records of agent activity offline,
from Python.

This is a thin [PyO3](https://pyo3.rs) wrapper over the Rust `bellbook`
crate, which stays the single source of truth for canonicalization,
verification, and the conformance vectors. It is **not** a reimplementation.
(The independent from-scratch validator under `conformance/python/` in the
repository is a separate thing: a deliberate second implementation that exists
to cross-check the specification.)

## Status

Validation (with the `bellbook-core-v1` baseline and `delivery-receipt-v1`
profile checks), reading,
writing, and the read-side query set (issue #13, RFC-0002, RFC-0003).

## Validate

`validate(bytes) -> Report` reaches the same Clean / Tainted / Invalid
decision as the `bellbook validate` CLI, over the same core.

```python
import bellbook

report = bellbook.validate(open("receipt.json", "rb").read())

print(report.status)          # "clean" | "tainted" | "invalid"
print(report.spec_version)    # "0.3"
print(report.record_count)
print(report.head_hash)       # lowercase hex; compare against an anchored head
print(report.rules_hash)      # compare against rules you trust
print(report.retracted, report.tainted)
print(report.standing)        # {"compromised": [...], "unsound": [...], "restorations": {...}}
print(report)                 # the full human-readable report (same as the CLI)
```

Validation never raises for a bad receipt: an unparseable or failing receipt
returns a `Report` with `status == "invalid"` and a `problem` or `reason`
set. As with the CLI, **Clean is relative to the rules embedded in the
receipt** - compare `rules_hash` against a rule set you trust, or name the
shared baseline:

```python
report = bellbook.validate(data, require_profile="bellbook-core-v1")
p = report.profiles[0]
print(p["status"])            # "Conformant" | "NonConformant" | "Unknown"
print(p["hash"])              # hex of the profile's clause-table hash
for c in p["clauses"]:        # [{"id": "B1", "passed": True, "detail": "..."}, ...]
    print(c["id"], c["passed"], c["detail"])
```

`require_profile` takes one id or a list; results land in `report.profiles`
in request order, and an unknown id is reported as `"Unknown"`, not raised.
A receipt that declares profiles (spec 0.4, `Writer.receipt(profiles=...)`)
needs no `require_profile`: every declared profile is evaluated unasked and
comes first, with `p["declared"]`, `p["declaration_matches"]` (whether the
declared version and hash name the clause table that was evaluated; `None`
for an undeclared or unknown profile), and `p["met"]` (Conformant and, if
declared, matching). A declaration is never trusted. A profile result is a
report alongside the verdict: it never changes `status` or `reason`. The
profiles themselves are documented in
[docs/profiles/bellbook-core-v1.md](../../docs/profiles/bellbook-core-v1.md)
and
[docs/profiles/delivery-receipt-v1.md](../../docs/profiles/delivery-receipt-v1.md);
`require_profile="delivery-receipt-v1"` reports the eight delivery clauses
D0 through D7, and the
[delivery-receipt quickstart](../../docs/quickstart-delivery-receipt.md)
walks the whole flow from Python.

## Read

`read(bytes) -> Receipt` parses a receipt for inspection. Reading does not
verify - call `validate` for the decision.

```python
import json

receipt = bellbook.read(open("receipt.json", "rb").read())

print(receipt.spec_version, len(receipt))
for r in receipt.records:
    print(r.kind, r.time, r.author_id, r.author_type, r.evidence)
    for ref in r.refs:
        print("  ", ref["type"], "->", ref["target"])
    payload = json.loads(r.payload_json)
```

A `Record` exposes `id`, `kind`, `time`, `author_id`, `author_type`,
`signed`, `evidence`, `schema`, `refs`, and `payload_json`. The enum-valued
fields (`kind`, `author_type`, `evidence`, and each ref's `type`) are the
record's Rust variant names, e.g. `"Candidate"`, `"Provider"`, `"Reported"`,
`"Use"`. `read` raises `ValueError` on bytes that are not a parseable
receipt.

## Write

`Writer(log_dir, rules)` records evolution to a persistent, single-writer log.
It holds the same exclusive lock and runs the same replay-on-commit the Rust
`LogWriter` does. `rules` is a JSON string: the verifier rules the log is
committed under, the same object a receipt embeds under `rules`.

`default_rules(authors, max_context=200, admins=None, reaffirmers=None)` builds
that string for you - the Python counterpart to `bellbook rules init` - so you
never hand-author a rules object. `authors` maps an actor id to a role (`user`,
`provider`, `system`, `executor`, or `verifier`, case-insensitive). `admins`
lists actors allowed to retract records they did not author; `reaffirmers`,
when given, restricts reaffirming selections to the listed actors. Both must
also appear in `authors`. Like `rules init`, the result carries the
`bellbook-core-v1` baseline evidence thresholds, so a log committed under it
conforms to the baseline profile out of the box:

```python
import bellbook

rules_json = bellbook.default_rules({"agent": "provider", "evaluator": "provider"})
w = bellbook.Writer("./mylog", rules_json)

c0 = w.candidate(author="agent", git_tree="a1b2...")            # a Root candidate
e0 = w.evaluate(author="agent", candidate=c0.id, criterion="builds", passed=True)
s0 = w.select(author="agent", objective="ship it",
              consider=[c0.id], choose=[c0.id], uses_eval=[e0.id])

print(c0.id, c0.accepted, c0.reason)   # each commit returns a Commit

# Export and verify in the same process:
report = bellbook.validate(w.receipt())
assert report.status == "clean"
```

Each of `request`, `requirement`, `candidate`, `evaluate`, `select`, and
`retract` commits one record
and returns a `Commit` (`id`, `accepted`, `result`, `reason`). A record is durably committed
whether accepted or rejected - a rejected record is evidence a proposal was
refused - so `accepted` may be `False` without an exception. Statically-knowable
payload violations (an unregistered author, a score scale above 12, an upgrade
whose tree differs from its target) raise `ValueError` before anything is
written.

- `candidate(author, git_tree, *, git_commit=None, algo="sha1", note=None,
  continues=None, parent=None, derives_from=None, upgrades=None, manifest=None)`
  - basis is exactly one of `continues` (with `parent`), `derives_from` (a
    **list** of record ids), or `upgrades`; omit all three for a Root.
    `manifest` (a directory path) binds the source by a canonical manifest
    hash instead of a reported tree. A `derives_from` member may be a
    candidate or an evaluation: a repair *motivated by* an evaluation names
    it there alongside the candidate it derives from
    (`derives_from=[sound_parent.id, failing_eval.id]`), and because `Cause`
    carries intent, not taint, retracting that evaluation later does not
    taint the repair.
  `artifacts` (spec 0.4) binds artifact identities: a list of
  `"scheme:digest[:name]"` strings or `{"scheme", "digest", "name"?}` dicts
  (registered schemes: `git-tree-sha1`, `git-tree-sha256`, `manifest-v1`,
  `git-archive-tar-v1`, `oci-image-manifest`, `sha256-bytes`), checked and
  canonically ordered before the write.
- `evaluate(author, candidate, criterion, *, passed=False, failed=False,
  score=None, scale=None, procedure=None, uses=None, blocked=False,
  insufficient=False, stale=False, not_run=False, evaluator=None,
  evaluator_version=None, procedure_hash=None, input_hash=None, basis=None,
  requirements=None, artifacts=None)` - exactly one outcome: `passed`,
  `failed`, a `score` (with `scale`, a decimal exponent 0-12), or one of the
  spec 0.4 fail-closed outcomes (only `passed` passes). With `evaluator` and
  `basis` (`"recomputed"` or `"declared"`; never inferred) the extended
  evaluation is written: who decided with what procedure over what input,
  the `artifacts` judged, and the accepted Requirement ids it speaks to
  (`requirements`, each also a `Use` ref, so a retracted requirement taints
  the evaluations that judged against it). Any of those without both
  `evaluator` and `basis` raises `ValueError`; without them the v1 shape is
  written.
- `select(author, objective, consider, *, choose=None, uses_eval=None,
  none=False, replaces=None, rationale=None)` - exactly one of `choose` (with
  `uses_eval`) or `none=True`; `replaces` reaffirms a prior selection.
  `consider`, `choose`, and `uses_eval` are **lists** of record ids.
- `request(author, objective)` (spec 0.4) - what a person asked for; the
  author must have the `user` role. Requirements bind to it.
- `requirement(author, request, key, description, *, required=True,
  expected_evidence=None, provenance=None)` (spec 0.4) - an addressable
  statement of what the request requires. `key` must be unique among the
  request's accepted, unretracted requirements (a duplicate commits as a
  rejected record with `RequirementInvalid`; retract-and-record releases
  it). `provenance` is `"user_authored"` or `"derived"`, defaults from the
  author's role (user -> user_authored, provider or system -> derived), and
  a value the role cannot carry raises `ValueError` before the write.
- `receipt(profiles=None)` - `profiles=["bellbook-core-v1",
  "delivery-receipt-v1"]` declares the profiles the receipt claims (spec
  0.4). A declaration is never trusted:
  every validator evaluates it unasked and reports `declared`,
  `declaration_matches`, and `met` beside the result.

```python
req = w.request(author="human", objective="ship the bound build")
r1 = w.requirement(author="human", request=req.id, key="R1", description="unit tests pass")
c0 = w.candidate(author="agent", git_tree=tree, artifacts=[f"git-tree-sha1:{tree}:src"])
e0 = w.evaluate(author="evaluator", candidate=c0.id, criterion="unit-tests", passed=True,
                evaluator="test-harness", basis="recomputed",
                requirements=[r1.id], artifacts=[f"git-tree-sha1:{tree}"])
report = bellbook.validate(w.receipt(profiles=["bellbook-core-v1"]))
report.profiles[0]["met"]     # True: Conformant, and the declaration matches
```

## Retract

`retract(author, target, reason)` asserts a committed record's content is
wrong. The target stays in the log; its id enters the retracted set, its
epistemic dependents become tainted, and the receipt reports **Tainted** from
then on - permanently. A later reaffirming selection (one that `replaces` the
unsound one on surviving evidence) restores the line's *standing*, but never
turns the receipt Clean again: the episode is part of history, and that is the
point.

```python
r = w.retract(author="evaluator", target=e0.id,
              reason="benchmark harness measured the wrong thing")
assert r.accepted
assert bellbook.validate(w.receipt()).status == "tainted"
```

Retraction is ownership-bound (SPEC section 2): it is accepted only when
`author` is the target's author, or is listed in the rules'
`admin_retraction_actors` (set via `default_rules(..., admins=[...])`). An
Executor may never author a retraction, so Executor-authored records are
retractable only through an admin actor. A Verdict or a Retraction cannot be
retracted. As with the other verbs, a rejected retraction is still durably
committed with `accepted == False` and the verifier's reason.

The writer is deliberately single-writer (SPEC 5.1): it holds an exclusive lock
for the log directory, so a second `Writer` on the same directory raises. Other
useful members: `w.head` (current head, hex), `w.records` (the committed
records, as `Record`s), `len(w)`, and `w.receipt()` (portable receipt bytes).

## Query

The RFC-0002 named query set - seven deterministic, read-only questions over
lineage, evidence, and standing - is available as methods on both `Writer`
(over the live log) and the `Receipt` returned by `read` (over an exported
receipt). Both return plain dicts/lists in the exact surface JSON shapes the
Rust core and the `bellbook query` CLI emit, so answers are diffable across
surfaces.

```python
w.selected("best-of-n")   # selections under that exact objective, with
                          # chosen candidates and their evidence
w.descent(c.id)           # the line of descent back to its roots
w.descendants(c.id)       # everything downstream, in log order
w.siblings(c.id)          # the candidate's generation
w.frontier()              # unconsidered candidates + winners not continued
w.standing(s.id)          # standing, taint, retraction, restorations
w.evidence(c.id)          # what a selection or a whole line rests on

r = bellbook.read(w.receipt())
assert r.frontier() == w.frontier()   # same answers over the receipt
```

Queries answer only over verified state: a log or receipt that does not
verify raises `ValueError` instead of answering, as do a missing or rejected
id and a kind mismatch. Nothing is ranked and nothing is silently filtered -
every reported node carries its standing, taint, and retraction annotations,
and the reader decides.

## Build from source

```
pip install maturin
maturin develop            # build and install into the current venv
pytest bindings/python/tests
```

Prebuilt wheels (Linux, macOS, Windows) are published to PyPI, so
`pip install bellbook` needs no Rust toolchain; the steps above are for local
development against the working tree.

Licensed under MIT OR Apache-2.0.
