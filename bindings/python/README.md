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

Validation (with the `bellbook-core-v1` baseline profile check), reading,
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
A profile result is a report alongside the verdict: it never changes
`status` or `reason`. The profile itself is documented in
[docs/profiles/bellbook-core-v1.md](../../docs/profiles/bellbook-core-v1.md).

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

Each of `candidate`, `evaluate`, `select`, and `retract` commits one record
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
- `evaluate(author, candidate, criterion, *, passed=False, failed=False,
  score=None, scale=None, procedure=None, uses=None)` - exactly one of
  `passed`, `failed`, or a `score` (with `scale`, a decimal exponent 0-12).
- `select(author, objective, consider, *, choose=None, uses_eval=None,
  none=False, replaces=None, rationale=None)` - exactly one of `choose` (with
  `uses_eval`) or `none=True`; `replaces` reaffirms a prior selection.
  `consider`, `choose`, and `uses_eval` are **lists** of record ids.

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
