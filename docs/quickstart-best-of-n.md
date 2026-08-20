# Quickstart: a verifiable receipt from a best-of-N harness

You already run a best-of-N loop: generate a few candidate changes, score
them, keep the winner. This takes you from that loop to a **portable receipt** -
a self-contained proof another party can verify offline, without trusting your
harness - in a few minutes.

Two surfaces, same core: the **Python package** (`pip install bellbook`) and
the **`bellbook` CLI** (`cargo install bellbook`). Pick one.

## What you record

Three record kinds map onto a best-of-N loop directly:

| Your loop | Bellbook record |
| --- | --- |
| a candidate change (a Git tree) | `Candidate` |
| a score/pass for one candidate under one metric | `Evaluation` |
| "we kept candidate B, over A and C, on these scores" | `Selection` |

The decision stays yours - Bellbook records *what* was considered, the
evaluation evidence, and *which* you chose. It never ranks or scores for you.

## The one prerequisite: a rules file

Verification is relative to a **rules** object - the trust policy (which actor
ids may author, minimum evidence, and so on). It is embedded in every receipt,
so a verifier re-derives every decision against it. Generate a starter with
`rules init`, binding each actor id to a role
(`user|provider|system|executor|verifier`):

```sh
bellbook rules init --author agent:provider --author evaluator:provider --out rules.json
```

That is the one file both surfaces below load. (A ready-made
[`docs/quickstart/rules.json`](quickstart/rules.json) is also committed if you
prefer to copy one; from Python you can skip the file entirely with
`bellbook.default_rules(...)`, shown below.)

## Python

```python
import bellbook

# build the rules inline (no file needed), or: rules = open("rules.json").read()
rules = bellbook.default_rules({"agent": "provider", "evaluator": "provider"})
w = bellbook.Writer("./mylog", rules)

# best-of-N: three candidates, one evaluation each
cands, evals = [], []
for git_tree, score in [("a1b2...", 40), ("c3d4...", 90), ("e5f6...", 65)]:
    c = w.candidate(author="agent", git_tree=git_tree)
    e = w.evaluate(author="evaluator", candidate=c.id, criterion="fitness",
                   score=score, scale=0)
    cands.append(c.id); evals.append(e.id)

# your harness picks the winner; Bellbook records the choice and its evidence
winner = cands[1]
w.select(author="agent", objective="best-of-n",
         consider=cands, choose=[winner], uses_eval=evals)

# export a receipt and verify it, all in one process
report = bellbook.validate(w.receipt())
assert report.status == "clean"
print(report)                       # the full offline report

open("receipt.json", "wb").write(w.receipt())   # hand this to anyone
```

`w.receipt()` is the portable bundle. `bellbook.validate(bytes)` re-derives
every id, verdict, and the standing section from scratch - the same decision
the CLI reaches.

## CLI

The CLI records to a log directory. Each mutating command prints the committed
record id (use `--json` to capture it).

```sh
RULES=rules.json
LOG=./mylog

c0=$(bellbook candidate add --log $LOG --rules $RULES --author agent \
       --git-tree a1b2... --json | jq -r .id)
c1=$(bellbook candidate add --log $LOG --rules $RULES --author agent \
       --git-tree c3d4... --json | jq -r .id)

e0=$(bellbook eval add --log $LOG --rules $RULES --author evaluator \
       --candidate $c0 --criterion fitness --score 40 --scale 0 --json | jq -r .id)
e1=$(bellbook eval add --log $LOG --rules $RULES --author evaluator \
       --candidate $c1 --criterion fitness --score 90 --scale 0 --json | jq -r .id)

# choose the winner; name the evaluations the choice rests on
bellbook select --log $LOG --rules $RULES --author agent --objective best-of-n \
  --consider $c0 $c1 --choose $c1 --uses-eval $e0 $e1

# inspect a candidate's descent, siblings, taint, and standing
bellbook lineage --log $LOG --rules $RULES $c1
```

Export the log as a portable receipt and validate it - the whole
record -> receipt -> validate loop stays in the CLI, no binding required:

```sh
bellbook export --log $LOG --rules $RULES --out receipt.json
bellbook validate receipt.json          # -> CLEAN
```

## What Clean means (and does not)

A **Clean** receipt means the recorded history is internally consistent under
its embedded rules, and nothing is retracted or tainted. It does **not** mean
the candidate is good, the benchmark was right, or that every decision was
recorded - Bellbook proves consistency, not completeness (SPEC.md §13). Compare
`rules_hash` against a rule set you trust before relying on a receipt from
someone else.

## Next

- `cargo run --example iterative_evolution` - the multi-generation loop.
- `cargo run --example repair_reevaluate` - a single-candidate repair, and why
  a repair *motivated by* a broken evaluation is not tainted by it.
- `cargo run --example broken_benchmark` - a broken benchmark, the compromise
  it casts, and one-record recovery.
