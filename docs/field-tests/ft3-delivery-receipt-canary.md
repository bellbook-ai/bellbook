# Field test 3a - a delivery receipt on published 0.9.0, first-party

**Date:** 2026-09-05.
**Subject:** the `delivery-receipt-v1` profile (RFC-0003 sections 4.4 and
4.6), exercised in the field: a real change, real measurements, a delivery
claim, and a skeptic who holds nothing but the receipt, the artifacts it
names, and the public repository.
**Artifacts under test:** the published releases only - `bellbook` 0.9.0 from
crates.io (`cargo install bellbook@0.9.0`) for the skeptic's CLI, the 0.9.0
wheel from PyPI for the producer's recording, and the independent Python
validator with the published profile tables taken from the repository at tag
`v0.9.0`. No working-tree build anywhere.
**Records:** RFC-0003 section 8. This is the first-party half of field test 3
(#135). It does **not** satisfy validation criterion 1, which needs a
committed adopter replacing its own delivery format; that half is the
cutover, recorded separately when it runs. What this half establishes is
that the shipped surfaces carry a real delivery end to end and that the
skeptic's position is tenable.

## Why

0.9.0 published the grammar of a delivery claim and a fraud battery that
both implementations reject (criterion 2, recorded in RFC-0003 section
10.1). A vector set proves the clauses; it does not prove that a producer
can record a real delivery through the published wheel without workarounds,
or that a skeptic can check one from outside. Field tests 1 and 2 answered
the same question for the write side and the read side. This run answers it
for the delivery claim, and rehearses the exact procedure the adopter
cutover will follow.

## What was actually run

Task: add hours support to `format_duration(ms)` in the `eightbells-canary`
repository, over the baseline both earlier field tests used (commit
`1024049`, tree `8cbb7d5...`). The canary's current head has since been
reduced to a README and a workflow, so the work ran on that historical
baseline in a clone; every candidate is a real Git commit over it.

Three actors, one rules file: `human` (user role) asks and states
requirements; `agent` (provider) writes the code; `harness` (provider) judges
it. Producer and evaluator are distinct authors, which is what D4 checks.

The request and its requirements, all recorded through the wheel:

| Key | Author | Provenance (bound by role) | Required | Statement |
|---|---|---|---|---|
| R1 | human | user_authored | yes | the repository's own test suite passes on the delivered tree |
| R2 | human | user_authored | yes | `format_duration(3725000) == "1h 2m 5s"`, `3600000 -> "1h 0m 0s"`, `7322000 -> "2h 2m 2s"`; minutes formatting unchanged |
| R3 | agent | derived | no | every module byte-compiles with warnings as errors |

Two candidates, both real commits:

- **cand-a** - naive hours: `"1h 2m"`, drops the seconds. Its own test
  suite passes.
- **cand-b** - full `h/m/s`, three new tests, derived from cand-a.

Each candidate binds two artifact identities: `git-tree-sha1:<tree>:src`
(the Git tree of the commit) and `sha256-bytes:<digest>:src.tar` (a
deterministic `git archive` of the same commit, fixed mtime). The tarball
is what the skeptic is handed; the tree id is what a skeptic with the
repository can resolve.

The evaluator is three stdlib-only procedures, run for real, with the
outcome taken from the exit code and nothing else:

| Criterion | Procedure | Requirement | cand-a | cand-b |
|---|---|---|---|---|
| unit-tests | `run_tests.sh` (extract the tarball, `pytest -q`) | R1 | passed | passed |
| completeness | `check_completeness.py` (import the module, check the three values) | R2 | **failed** | passed |
| compile-check | `compile_check.sh` (`python -W error -m compileall`) | R3 | passed | passed |

Every evaluation carries the full decider binding: `evaluator.id` names the
procedure, `procedure_hash` is the SHA-256 of the procedure's own bytes,
`input_hash` is the SHA-256 of the tarball it ran over, `basis` is
`recomputed`, and `evidence` cites both artifact identities of the candidate
judged. cand-a's failed completeness check is on the record, honestly, as
`failed`.

The claim: one Selection with objective `deliver`, considering both
candidates, choosing cand-b, using cand-b's three evaluations. The receipt
was exported declaring both profiles. 26 records.

Recorded through the wheel and validated there first:

```
records: 26  status: clean
bellbook-core-v1      Conformant  declared  met
delivery-receipt-v1   Conformant  declared  met
  D0 ok  claim 1633dcc5b328 for request 926574099a94
  D1 ok  2 required requirement(s) covered
  D2 ok  every required-bound evaluation passed
  D3 ok  3 evaluation(s) bound to the chosen candidate, evidence on the record
  D4 ok  producer "agent", every evaluator distinct
  D5 ok  weakest basis recomputed
  D6 ok  bellbook-core-v1: Conformant (declared, declaration matches)
  D7 ok  sound, untainted
```

## What the skeptic did

The skeptic's directory held four things: `receipt.json`, `src.tar` (the
candidate tarball), the three harness scripts, and the public repository's
`conformance/python/` and `spec/profiles/` at tag `v0.9.0`. Nothing else
from the producer. The check ran under the system Python with the
`bellbook` package deliberately absent from the import path, so that the
independent validator's independence was a fact of the run and not a claim.

| Check | Result |
|---|---|
| `bellbook validate receipt.json` (published CLI; declared profiles evaluated unasked) | Clean, both profiles Conformant, declaration matches, exit 0 |
| `bellbook validate receipt.json --require-profile delivery-receipt-v1` | exit 0 (already declared; evaluated once) |
| Independent validator: structural decode, replay, both profiles | StructurallyValid; Clean; both profiles met |
| Independent validator agrees with the CLI JSON clause by clause (id, status, declared, declaration_matches, hash, every clause flag) | yes, both profiles |
| `sha256(src.tar)` equals the chosen candidate's `sha256-bytes` artifact | yes |
| Git tree id recomputed from the tarball alone (`git init; git add -A; git write-tree`) equals the candidate's `git-tree-sha1` | yes, `f009dd26...` |
| For each of the three used evaluations: a procedure on hand whose SHA-256 equals `procedure_hash`; `input_hash` equals `sha256(src.tar)`; evidence cites the tarball | yes, yes, yes (x3) |
| Re-running each procedure over the tarball reproduces the recorded outcome | yes (x3): the `recomputed` basis is not a word, it re-computes |
| `bellbook query selected deliver --receipt receipt.json` | the claim, the chosen candidate with both artifacts, the three evaluations with their requirements |

Twenty-two checks, all holding, from outside.

## The hostile half

A skeptic whose checks cannot fail has learned nothing. Three attacks, each
against the published artifacts:

- **T1 - the wrong artifact.** The skeptic is handed cand-a's tarball as
  `src.tar` with the honest receipt. Nine checks fail at once: the tarball
  digest, the recomputed tree id, every `input_hash` and every evidence
  citation, and the completeness procedure re-run fails where the receipt
  says passed. The receipt is fine; the artifact is not what it claims to be,
  and the receipt is what says so.
- **T2 - the forgery that matters.** A second log where the producer claims
  cand-a, using its genuinely passing unit-test evaluation and its genuinely
  failing completeness evaluation, every digest consistent. The wheel, the
  CLI, and the independent validator all say the same thing: receipt
  **Clean**, `bellbook-core-v1` Conformant, `delivery-receipt-v1`
  **NonConformant on exactly D1 and D2**. CLI exit 3. The history is true
  and it is not a delivery.
- **T3 - the edit.** Take that forged receipt and change the one string
  `"failed"` to `"passed"` in the completeness evaluation's payload, leaving
  every id and hash as recorded. CLI: **Invalid**, reason `InvalidPayload`,
  exit 1. Independent validator: structural check rejects it ("record id
  does not match recomputation"); its replay, run anyway, reaches the same
  `Invalid` / `InvalidPayload`. Both surfaces refuse before any profile
  runs.

## Frictions surfaced (with the decision on each)

- **F1 - no one-receipt entry point in the independent validator.** The
  skeptic had to write about twenty lines of glue to point
  `conformance/python` at a single receipt (decode, replay, load the profile
  tables, evaluate declared and required profiles, print). The adopter
  cutover's skeptic will hit the same wall. **Act:** add a small
  `validate_receipt.py` entry point to the conformance package that takes a
  receipt path and optional `--require-profile` ids and reports status,
  reason, and per-clause profile results with the CLI's exit codes.
- **F2 - `bellbook validate --json` has no `met` per profile.** The Python
  surface reports `met`; the CLI JSON reports `status`, `declared`, and
  `declaration_matches` and leaves the skeptic to combine them. **Act:**
  additive `met` field in the CLI JSON, for parity with `Report.profiles`.
- **F3 - D2's detail line reads wider than the clause.** "every
  required-bound evaluation passed" can be read as covering every evaluation
  on the record, while the clause is scoped, correctly, to the evaluations
  the claim uses: cand-a's failed completeness evaluation sits on this record
  and the claim over cand-b conforms. The published table states the scope;
  the detail string does not. **Act:** reword the detail to name the used
  evaluations. No semantic change.
- **F4 - `input_hash` and the evidence digest coincide here, and nothing
  says they should.** The harness hashed the tarball it ran over, which is
  also the evidence artifact, so the skeptic could check `input_hash`
  against something it held. When a procedure's input is not exactly one
  artifact (a tree plus a config, an environment), `input_hash` is the
  evaluator's own convention and the skeptic can only check it if the
  convention is published. **Boundary:** the profile requires the binding to
  be present (D5) and cannot require a particular convention; the
  delivery-receipt document should say that an evaluator wanting a checkable
  `input_hash` publishes how it is computed, and that hashing exactly the
  cited evidence is the simplest such convention.
- **F5 - an edited record reads as `InvalidPayload`.** The reference names
  an id-recomputation mismatch `InvalidPayload`; the independent validator's
  structural pre-check names the same fact in words and its replay agrees on
  the code. Both are Invalid, both refuse before profiles run, and the corpus
  holds them to the same decision. **Document:** the reason vocabulary folds
  "content does not match its id" into "payload invalid". A dedicated code
  would be a wire vocabulary change with no decision behind it; not
  warranted.
- **F6 - the test bed moved.** The public canary's head was reduced to a
  README and a workflow after field test 2, so this run worked on the
  historical baseline in a clone, and the tree ids it binds resolve in the
  public repository's history rather than at its head. **Document:** the
  content addresses are unaffected; a skeptic with the repository resolves
  `f009dd26...` from the tarball alone, as shown above, and would resolve it
  from the repository only if the commits were pushed. First-party
  observation about the test bed, not about Bellbook.

Nothing else. Recording through the wheel (request, three requirements,
two bound candidates, six extended evaluations, the claim), export declaring
both profiles, validation on three surfaces, both profiles, the query, and
the skeptic's recomputation of every digest and every outcome worked first
try against the published artifacts, with no workaround anywhere.

## Verdict

The delivery claim is recordable and checkable in the field through the
published 0.9.0 surfaces, by a skeptic holding nothing from the producer but
the receipt and the artifacts it names. The two forgeries the profile was
designed against are rejected by all three surfaces, identically, and an
artifact swap is caught by the receipt's own bindings. Three frictions are
small enough to act on now (F1, F2, F3) and change no semantics; F4 is a
documentation boundary; F5 and F6 are observations.

RFC-0003 criterion 1 stays open: this run has no adopter and replaces no
format. It has, however, produced the adopter's procedure. The cutover
(#135) follows exactly the steps above with the adopter's own request,
requirements, artifacts, and evaluators, and a skeptic who was not in the
room.
