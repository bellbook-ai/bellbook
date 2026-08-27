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

Validation, reading, and writing (issue #13).

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
receipt** - compare `rules_hash` against a rule set you trust.

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
also appear in `authors`:

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

Each of `candidate`, `evaluate`, and `select` commits one record and returns a
`Commit` (`id`, `accepted`, `result`, `reason`). A record is durably committed
whether accepted or rejected - a rejected record is evidence a proposal was
refused - so `accepted` may be `False` without an exception. Statically-knowable
payload violations (an unregistered author, a score scale above 12, an upgrade
whose tree differs from its target) raise `ValueError` before anything is
written.

- `candidate(author, git_tree, *, git_commit=None, algo="sha1", note=None,
  continues=None, parent=None, derives_from=None, upgrades=None, manifest=None)`
  - basis is exactly one of `continues` (with `parent`), `derives_from`, or
    `upgrades`; omit all three for a Root. `manifest` (a directory path) binds
    the source by a canonical manifest hash instead of a reported tree.
- `evaluate(author, candidate, criterion, *, passed=False, failed=False,
  score=None, scale=None, procedure=None, uses=None)` - exactly one of
  `passed`, `failed`, or a `score` (with `scale`, a decimal exponent 0-12).
- `select(author, objective, consider, *, choose=None, uses_eval=None,
  none=False, replaces=None, rationale=None)` - exactly one of `choose` (with
  `uses_eval`) or `none=True`; `replaces` reaffirms a prior selection.

The writer is deliberately single-writer (SPEC 5.1): it holds an exclusive lock
for the log directory, so a second `Writer` on the same directory raises. Other
useful members: `w.head` (current head, hex), `w.records` (the committed
records, as `Record`s), `len(w)`, and `w.receipt()` (portable receipt bytes).

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
