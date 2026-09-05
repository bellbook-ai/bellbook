# Quickstart: a delivery receipt a skeptic can check

You deliver work: an agent produces a change, checks run, someone decides
it is done. This takes you from that loop to a **delivery receipt** - a
portable, self-contained record that says *requirement R was met by evidence
E, judged by evaluator V, over artifact A, under capability profile L* - and
that a skeptic verifies offline, holding nothing from you but the receipt
and the content-addressed artifacts.

Two surfaces, same core: the **Python package** (`pip install bellbook`) and
the **`bellbook` CLI** (`cargo install bellbook`). Both need 0.9.0 or later
for the delivery profile. Pick one.

## What you record

| In your loop | Bellbook record |
| --- | --- |
| what the person asked for | `Request` |
| each thing it requires, and who said so | `Requirement` |
| the change, bound to the artifacts it produced | `Candidate` (with `artifacts`) |
| a check of one requirement over those artifacts, by a named evaluator | `Evaluation` (extended: evaluator, basis, evidence, requirements) |
| "this candidate is delivered, on these checks" | `Selection` - the claim |

A claim is not a new record. It is an accepted `Selection` whose evaluations
bind to the request's requirements. The profile `delivery-receipt-v1` reads
the claim off the record and checks eight clauses, D0 through D7
([the profile document](profiles/delivery-receipt-v1.md) lists them). Every
clause is fail-closed: a claim that cannot be checked does not conform.

## The one prerequisite: a rules file

A delivery receipt needs three roles: a **user** who asks and states
requirements, a **provider** who produces, and a second provider who
evaluates. Producer and evaluator must be different actors (clause D4), so
name both.

```sh
bellbook rules init --author human:user --author agent:provider \
                    --author evaluator:provider --out rules.json
```

From Python you can skip the file: `bellbook.default_rules({"human": "user",
"agent": "provider", "evaluator": "provider"})`. Either way the rules carry
the `bellbook-core-v1` baseline thresholds, which clause D6 requires.

## Python

```python
import bellbook

rules = bellbook.default_rules({"human": "user", "agent": "provider", "evaluator": "provider"})
w = bellbook.Writer("./mylog", rules)

TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"        # the candidate's git tree
PROC = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # hash of the harness that ran
INPUT = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"  # hash of what it ran over

# 1. what was asked, and what it requires
req = w.request(author="human", objective="add hours support to format_duration")
r1 = w.requirement(author="human", request=req.id, key="R1",
                   description="the unit tests pass on the delivered tree")
r2 = w.requirement(author="agent", request=req.id, key="R2", required=False,
                   description="lint is clean", expected_evidence="lint log")

# 2. the change, bound to the artifact it produced
c0 = w.candidate(author="agent", git_tree=TREE, artifacts=[f"git-tree-sha1:{TREE}:src"])

# 3. the checks: who decided, how, over what, against which requirement
e1 = w.evaluate(author="evaluator", candidate=c0.id, criterion="unit-tests", passed=True,
                evaluator="pytest-harness", evaluator_version="1.4.0",
                basis="recomputed", procedure_hash=PROC, input_hash=INPUT,
                requirements=[r1.id], artifacts=[f"git-tree-sha1:{TREE}"])
e2 = w.evaluate(author="evaluator", candidate=c0.id, criterion="lint", not_run=True,
                evaluator="linter", basis="declared",
                procedure_hash=PROC, input_hash=INPUT,
                requirements=[r2.id], artifacts=[f"git-tree-sha1:{TREE}"])

# 4. the claim
s0 = w.select(author="agent", objective="deliver", consider=[c0.id], choose=[c0.id],
              uses_eval=[e1.id, e2.id])
for c in (req, r1, r2, c0, e1, e2, s0):
    assert c.accepted, c.reason

# 5. export a receipt that declares what it claims, and check it
receipt = w.receipt(profiles=["bellbook-core-v1", "delivery-receipt-v1"])
report = bellbook.validate(receipt)
assert report.status == "clean"
for p in report.profiles:
    print(p["id"], p["status"], "met" if p["met"] else "NOT MET")
open("receipt.json", "wb").write(receipt)
```

The `not_run` lint evaluation is allowed because `R2` is informational
(`required=False`). Had it been required, the claim would fail clauses D1
and D2: only `passed` passes, and a check that did not run is recorded as
exactly that, never as a pass.

## CLI

```sh
RULES=rules.json
LOG=./mylog
TREE=4b825dc642cb6eb9a060e54bf8d69288fbee4904
PROC=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
INPUT=2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

req=$(bellbook request add --log $LOG --rules $RULES --author human \
        --objective "add hours support to format_duration" --json | jq -r .id)
r1=$(bellbook requirement add --log $LOG --rules $RULES --author human --request $req \
        --key R1 --description "the unit tests pass on the delivered tree" --json | jq -r .id)
r2=$(bellbook requirement add --log $LOG --rules $RULES --author agent --request $req \
        --key R2 --description "lint is clean" --optional --expected-evidence "lint log" \
        --json | jq -r .id)

c0=$(bellbook candidate add --log $LOG --rules $RULES --author agent \
        --git-tree $TREE --artifact git-tree-sha1:$TREE:src --json | jq -r .id)

e1=$(bellbook eval add --log $LOG --rules $RULES --author evaluator --candidate $c0 \
        --criterion unit-tests --passed --evaluator pytest-harness --evaluator-version 1.4.0 \
        --basis recomputed --procedure-hash $PROC --input-hash $INPUT \
        --requirement $r1 --artifact git-tree-sha1:$TREE --json | jq -r .id)
e2=$(bellbook eval add --log $LOG --rules $RULES --author evaluator --candidate $c0 \
        --criterion lint --not-run --evaluator linter --basis declared \
        --procedure-hash $PROC --input-hash $INPUT \
        --requirement $r2 --artifact git-tree-sha1:$TREE --json | jq -r .id)

s0=$(bellbook select --log $LOG --rules $RULES --author agent --objective deliver \
        --consider $c0 --choose $c0 --uses-eval $e1 $e2 --json | jq -r .id)

bellbook export --log $LOG --rules $RULES \
  --profile bellbook-core-v1 delivery-receipt-v1 --out receipt.json
bellbook validate receipt.json          # -> CLEAN, both profiles CONFORMANT, exit 0
```

`--provenance` is not needed: a requirement's provenance is bound to its
author's role. `human` is a user, so `R1` is `user_authored`; `agent` is a
provider, so `R2` is `derived`. Stating a provenance the role cannot carry
is refused before anything is written.

## What the skeptic does

The skeptic holds `receipt.json` and nothing else from you:

```sh
bellbook validate receipt.json
# exit 0 Clean and every declared profile met
# exit 3 valid receipt, but a declared or required profile is not met
# exit 2 Tainted; exit 1 Invalid
bellbook validate receipt.json --json | jq -c '.profiles[] | {id, status, declared, declaration_matches}'
bellbook query selected deliver --receipt receipt.json     # the claim, its candidate, its evidence
```

```python
report = bellbook.validate(open("receipt.json", "rb").read())
p = next(p for p in report.profiles if p["id"] == "delivery-receipt-v1")
print(p["status"], [c["id"] for c in p["clauses"] if not c["passed"]])
```

If the receipt did not declare the profile, `--require-profile
delivery-receipt-v1` (or `require_profile=...`) evaluates it anyway. A
declaration is a claim the validator re-checks, never something it trusts:
a declared hash that is not the published table's is reported as a mismatch
and the profile counts as not met.

The independent Python validator under `conformance/python/` implements
every clause from scratch and reaches the same result, so the skeptic need
not trust the reference implementation either.

## The fraud demonstration

Every id in a receipt is a content address and every ref names one, so you
cannot edit a recorded evaluation without breaking the record: change one
byte of `e1`'s payload and the receipt is Invalid before any profile runs.
The forgery that matters is the one where every hash *is* consistent - the
harness genuinely failed, and the log honestly says so, but the claim is
made anyway. Record it and watch the claim rejected on replay:

```python
w = bellbook.Writer("./forged", rules)
req = w.request(author="human", objective="add hours support")
r1 = w.requirement(author="human", request=req.id, key="R1", description="unit tests pass")
c0 = w.candidate(author="agent", git_tree=TREE, artifacts=[f"git-tree-sha1:{TREE}"])
bad = w.evaluate(author="evaluator", candidate=c0.id, criterion="unit-tests", failed=True,
                 evaluator="pytest-harness", basis="recomputed",
                 procedure_hash=PROC, input_hash=INPUT,
                 requirements=[r1.id], artifacts=[f"git-tree-sha1:{TREE}"])
claim = w.select(author="agent", objective="deliver", consider=[c0.id], choose=[c0.id],
                 uses_eval=[bad.id])
assert claim.accepted                     # the core accepts the record: it is valid history

report = bellbook.validate(w.receipt(profiles=["delivery-receipt-v1"]))
print(report.status)                      # "clean": the history is consistent
p = report.profiles[0]
print(p["status"])                        # "NonConformant": it is not a delivery
print([c["id"] for c in p["clauses"] if not c["passed"]])   # ["D1", "D2"]
```

The receipt is Clean and the claim is rejected. That is the point of a
profile: the core proves the history is what it says; the profile judges
whether what it says amounts to a delivery. The same happens when a genuine
passing evaluation of one candidate is reattached to a claim for another
(D3), when the producer evaluates its own work (D4), when an evaluator names
no procedure or input (D5), or when the evaluation the claim rests on is
later retracted (D7). Each is a vector in
`spec/profiles/delivery-receipt-v1/cases.json`, reproduced by both
implementations.

## Requirements change; so does the claim

A requirement is amended by retract-and-record, and coverage is judged at
the receipt head. Add a required requirement after the claim and the claim
stops conforming until it is re-made:

```python
r3 = w.requirement(author="human", request=req.id, key="R3",
                   description="the changelog names the new behavior")
report = bellbook.validate(w.receipt(profiles=["delivery-receipt-v1"]))
# D1 fails: "uncovered R3". Evaluate R3 and record a new selection over e1, e2, e3.
```

Retract a requirement and every evaluation that judged against it is
tainted; the receipt reports Tainted from then on, permanently, and the
claim's standing (D7) says so.

## What a conformant delivery receipt means (and does not)

It means every required requirement of the request was judged passed by an
evaluator distinct from the producer, with a procedure and input binding,
over evidence the record itself carries for the claimed candidate; that the
receipt meets the baseline capability profile; and that the claim stands at
the receipt head. It does **not** mean the evaluator was competent, that the
procedure hash names a good procedure, or that the requirements were the
right ones - those are facts the record binds so a skeptic can go and check
them, not facts Bellbook judges. And it proves the recorded process, not
source contents: `git-tree-sha1:...` is a pointer the repository resolves
(SPEC section 13).

## Next

- [`docs/profiles/delivery-receipt-v1.md`](profiles/delivery-receipt-v1.md):
  the clauses, the fraud battery, the hash.
- [`docs/quickstart-best-of-n.md`](quickstart-best-of-n.md): the evolution
  loop this claim sits on top of - candidates, evaluations, selections,
  retraction, and repair.
- [RFC-0003](rfcs/0003-requirement-binding.md): why the claim is a
  Selection, why provenance is bound to authorship, and what would falsify
  the design.
