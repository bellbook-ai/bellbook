# Field test 2 - the read side on published 0.6.0

**Date:** 2026-08-28.
**Subject:** the RFC-0002 named query set, exercised in the field.
**Artifacts under test:** the published releases only - `bellbook` 0.6.0 from
crates.io (`cargo install bellbook@0.6.0`) and the 0.6.0 wheel from PyPI. No
working-tree build.
**Records:** [RFC-0002](../rfcs/0002-read-side-queries.md) section 8,
validation criterion 1.

## Why

Field test 1 (2026-08-26) ran a best-of-N over the `eightbells-canary`
repository and found that the write side held, but reading the log back meant
walking `records()` by hand: "which candidate won and on what evidence" and
"what does this line rest on" had no answer short of chasing refs into
payloads. That gap motivated RFC-0002, whose section 8 pre-registered the
success criterion: **re-running the field test must require zero hand-walking
of `records()`.** This is that re-run, against the shipped artifacts rather
than a working tree.

## What was actually run

Task: add hours support to the canary's `format_duration(ms)`. Three real
implementations were written as real Git commits over the canary baseline
(tree `8cbb7d5...`):

- **cand-a** - naive hours, drops seconds above an hour. Its own test suite
  passes.
- **cand-b** - full `h/m/s` with new tests. Passes.
- **cand-c** - hours with a wrong divisor (`// 360000`). Its own suite
  genuinely fails: `format_duration(3600000)` returns `"10h 0m"`.

Every recorded evaluation is a real measurement, not a hand-set label:

- `unit-tests`: `pytest` run in each candidate tree (a, b pass; c fails).
- `completeness`: `format_duration(3725000) == "1h 2m 5s"` - the real
  discriminating fact between the two passing candidates (a fails: `"1h 2m"`;
  b passes). This is the tie-break-as-evidence pattern the
  [best-of-N quickstart](../quickstart-best-of-n.md) documents.
- a wall-clock `benchmark` on the baseline (200k timed calls) that
  deliberately timed only the sub-second path - the flaw discovered and
  retracted in phase 3.

The recorded story (30 records, driven entirely through the published Python
wheel): baseline adopted on the benchmark; three continuations of the adopted
line; the unit-test and completeness evaluations; selection of cand-b on
`unit-tests` + `completeness`; retraction of the benchmark; re-evaluation and
a reaffirming selection of the baseline. The exported receipt validates
**Tainted** (30/30 checked) under both `bellbook validate` and
`bellbook.validate` - correct and permanent, by design.

## The battery: every field-test question, queries only

Each answer was produced twice and compared as parsed JSON: the Python query
methods over the live `Writer`, and the published `bellbook query` CLI over
the exported receipt.

| Question (from field test 1) | Query | Answer |
|---|---|---|
| Which candidate won, on what evidence? | `selected "adopt-hours"` | cand-b; `unit-tests: passed` + `completeness: passed` |
| The winner's line of descent? | `descent` | anchor Selection (unsound) via continuation-anchor, then baseline via parent |
| What does the line rest on? | `evidence` | the anchor's evidence: the wall-clock benchmark, **annotated retracted** |
| Standing of the adoption after retraction + repair? | `standing` | unsound, tainted, restorations = [reaffirming selection] |
| What is still open? | `frontier` | cand-b: `selected-no-continuation` |
| The winner's generation? | `siblings` | cand-a, cand-c |
| Everything downstream of the baseline? | `descendants` | a, b, c - all sound after the repair |

**Hand-walks of `records()` required: 0.** RFC-0002 section 8 validation
criterion 1 is met in the field, not only in CI.

**Cross-surface agreement held in the field:** all seven answers were
byte-identical between the Python-over-writer surface and the CLI-over-receipt
surface.

Field test 1's number-one friction - retraction unreachable from the CLI and
Python - is confirmed resolved: the retraction phase ran entirely through the
published wheel (shipped in 0.5.0).

## Frictions surfaced (with the decision on each)

- **F1 - no entry-point enumeration on a foreign receipt.** `selected`
  requires the exact objective string. A reader holding someone else's
  receipt with no out-of-band knowledge can reach `frontier()` (no argument)
  but cannot ask "what objectives or selections exist here?" without walking
  records. First-party observation only; acting on it now would be inventing
  demand the gate exists to require. If an external reader asks for it, that
  is RFC-0001 section 15 / RFC-0002 criterion-3 evidence, recorded there. A
  cheap non-engine shape, if warranted, is a listing form of `selected` (all
  selections grouped by objective) - still a closed named query, not a
  predicate language.
- **F2 - evaluations no selection used are not query-reachable.** `evidence`
  surfaces the evaluations a selection `Use`d, along a candidate's descent;
  an evaluation that grounded no accepted selection is reachable only through
  `records()`. This did not bite here (every evaluation was used or
  replaced), and is arguably correct - evidence that grounded no decision is
  not part of any line's story - so it is documented as a boundary of the
  named set (SPEC section 12.4) rather than changed.

Nothing else. Recording, the tie-break, retraction, repair, export,
validation, and all seven queries worked first try against the published
artifacts, with no workaround anywhere.

## Verdict

The named set is the right shape for this workload. Criterion 1 of the
pre-registered evaluation is met; criteria 2 and 3 (external signals) remain
open for the 90-day window. Neither friction justifies new implementation:
F1 waits for an external ask, F2 is a boundary note. No v0.7 scope emerges
from this test - which, per the sequencing in [VISION.md](../VISION.md),
means the wedge is complete as specified and the next lever is adoption, not
code.
