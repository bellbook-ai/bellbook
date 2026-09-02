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
s = w.select(author="agent", objective="best-of-n",
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
s0=$(bellbook select --log $LOG --rules $RULES --author agent --objective best-of-n \
       --consider $c0 $c1 --choose $c1 --uses-eval $e0 $e1 --json | jq -r .id)

# inspect a candidate's descent, siblings, taint, and standing
bellbook lineage --log $LOG --rules $RULES $c1
```

Export the log as a portable receipt and validate it - the whole
record -> receipt -> validate loop stays in the CLI, no binding required:

```sh
bellbook export --log $LOG --rules $RULES --out receipt.json
bellbook validate receipt.json          # -> CLEAN
```

## Phase 2: the benchmark was broken

A Clean receipt is where most tools stop. Bellbook's value begins after
that: suppose you discover the fitness harness was measuring the wrong
thing. The evaluation your winning selection rests on is wrong, and the
record has to absorb that honestly. Its author retracts it:

```python
r = w.retract(author="evaluator", target=evals[1],
              reason="fitness harness measured the wrong thing")
assert r.accepted

report = bellbook.validate(w.receipt())
print(report.status)                 # "tainted"
print(report.retracted)              # the retracted evaluation
print(report.standing["unsound"])    # the selection that rested on it
```

Or from the CLI:

```sh
bellbook retract --log $LOG --rules $RULES --author evaluator \
  --target $e1 --reason "fitness harness measured the wrong thing"

bellbook export --log $LOG --rules $RULES --out receipt.json
bellbook validate receipt.json          # -> TAINTED, exit 2
```

Retraction is ownership-bound: `evaluator` may retract its own evaluation.
Retracting someone else's record requires an admin retraction actor
(`rules init --admin <id>`, or `default_rules(..., admins=[...])`).

Recovery is one selection. Re-evaluate on something you still trust, then
reaffirm the choice, naming the selection it replaces:

```python
e_new = w.evaluate(author="evaluator", candidate=winner,
                   criterion="manual-review", passed=True)
s_new = w.select(author="agent", objective="best-of-n",
                 consider=cands, choose=[winner], uses_eval=[e_new.id],
                 replaces=s.id)

report = bellbook.validate(w.receipt())
print(report.status)                     # still "tainted" - permanently
print(report.standing["restorations"])   # {unsound id: [reaffirming id]}
```

```sh
e2=$(bellbook eval add --log $LOG --rules $RULES --author evaluator \
       --candidate $c1 --criterion manual-review --passed --json | jq -r .id)
bellbook select --log $LOG --rules $RULES --author agent --objective best-of-n \
  --consider $c0 $c1 --choose $c1 --uses-eval $e2 --replaces $s0

bellbook export --log $LOG --rules $RULES --out receipt.json
bellbook validate receipt.json   # still TAINTED; the report shows the restoration
```

**Restoration restores standing, not Clean.** The receipt stays Tainted
(exit code 2) permanently, because the retraction is part of history. What
changes is the standing section: the line is recorded as restored, with the
whole episode - the break, the taint, and the repair - on the record. That
is not a limitation; it is the point. A record that could quietly return to
Clean after a retraction would be a record you could not trust.

## Tie-breaks: when two candidates pass, record why one won

Rewind to the selection at the start: suppose `c0` and `c1` had both
*passed* the only criterion and you chose `c1`. If the reason lives only
in the selection's free-text `rationale`, the record shows a valid
choice whose stated evidence does not distinguish the winner - a
verifier sees two green candidates and a coin flip. The discriminating
fact deserves to be evidence, not prose: record it as its own
Evaluation under its own criterion, and make the selection use it.

```python
# both c0 and c1 passed "unit-tests"; c1 also covers the edge cases
e_tb = w.evaluate(author="evaluator", candidate=cands[1],
                  criterion="completeness", passed=True)
s = w.select(author="agent", objective="best-of-n",
             consider=cands, choose=[cands[1]],
             uses_eval=[evals[1], e_tb.id],
             rationale="both green; c1 also covers the edge cases")
```

```sh
etb=$(bellbook eval add --log $LOG --rules $RULES --author evaluator \
        --candidate $c1 --criterion completeness --passed --json | jq -r .id)
bellbook select --log $LOG --rules $RULES --author agent --objective best-of-n \
  --consider $c0 $c1 --choose $c1 --uses-eval $e1 $etb
```

Now the tie-break is queryable evidence. Ask the record why the winner
won, or what any descendant of the winner rests on, and the
`completeness` evaluation is in the answer:

```sh
bellbook query selected best-of-n --log $LOG --rules $RULES
bellbook query evidence $c1 --log $LOG --rules $RULES
```

`rationale` stays what it is - a recorded statement, useful to humans,
verified by no one. Bellbook records consequences, not scoring logic, so
there is no first-class ranking field and no rule forcing chosen
candidates to be evidence-distinguishable from rejected ones; the
pattern above is the supported way to make a tie-break hold up under
verification. `bellbook query NAME [ID|OBJECTIVE] (--log DIR --rules
FILE | --receipt FILE)` runs any of the seven named read-side queries
(RFC-0002) the same way over a live log or an exported receipt.

## What Clean means (and does not)

A **Clean** receipt means the recorded history is internally consistent under
its embedded rules, and nothing is retracted or tainted. It does **not** mean
the candidate is good, the benchmark was right, or that every decision was
recorded - Bellbook proves consistency, not completeness (SPEC.md §13). Compare
`rules_hash` against a rule set you trust before relying on a receipt from
someone else, or ask for the shared baseline: `bellbook validate receipt.json
--require-profile bellbook-core-v1` reports whether the embedded rules have
the [`bellbook-core-v1`](profiles/bellbook-core-v1.md) shape (the rules
generated above do), alongside the verdict and without changing it.

## Next

- `cargo run --example iterative_evolution` - the multi-generation loop.
- `cargo run --example repair_reevaluate` - a single-candidate repair, and why
  a repair *motivated by* a broken evaluation is not tainted by it.
- `cargo run --example broken_benchmark` - a broken benchmark, the compromise
  it casts, and one-record recovery.
