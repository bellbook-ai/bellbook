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

Validation and reading. The writer API lands in a later stage (issue #13).

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

## Build from source

```
pip install maturin
maturin develop            # build and install into the current venv
pytest bindings/python/tests
```

Wheels are built and published in CI (later stages); this is for local
development.

Licensed under MIT OR Apache-2.0.
