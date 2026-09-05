# delivery-receipt-v1

**The delivery-claim profile.** Version 1. Specified by
[RFC-0003](../rfcs/0003-requirement-binding.md) sections 4.4 and 4.6;
mechanism in [SPEC](../../SPEC.md) section 12.2. Clause table and hash
published in
[`spec/profiles/delivery-receipt-v1/profile.json`](../../spec/profiles/delivery-receipt-v1/profile.json);
vectors in `cases.json` beside it.

A receipt that conforms to this profile carries a checkable delivery claim:
requirement R was met by evidence E, judged by evaluator V, over artifact A,
under capability profile L. A skeptic who trusts none of the parties can
verify it holding nothing but the receipt and the content-addressed
artifacts. The profile defines the grammar of that claim and nothing else:
no domain scoring, no thresholds, no ranking, and no knowledge of any
particular adopter.

## The claim

There is no claim record. A delivery claim is an accepted `Selection` with
outcome `Selected` whose `Use`d evaluations (extended evaluations,
`bellbook.evaluation.v2` or the attested schema) bind to requirements of
exactly one `Request`. The claim's request is determined from the record,
never declared: it is the single request every requirement referenced by the
claim's evaluations belongs to. A selection whose evaluations span two
requests, or bind to none, is not a delivery claim. When several accepted
selections qualify for one request, the latest sound one is evaluated and
the earlier ones are reported superseded.

## What conformance means

- **Conformant** - every clause below held for every evaluated claim. A
  consumer may conclude: every required requirement of the request was
  judged passed by a named evaluator, with a procedure and input binding,
  over evidence the record itself carries for the claimed candidate; the
  producer did not judge its own work; the receipt meets the baseline
  capability profile; and the claim stands at the receipt head.
- **NonConformant** - at least one clause failed; the report names it and
  says why per claim. The verdict is unchanged: a NonConformant receipt may
  still be Clean. It is not a delivery receipt.
- **Unknown** - the validator does not know the profile id.

Profile conformance is a report alongside the verdict. It never changes
`status` or `reason` and is never a verdict reason code.

## Clauses

The normative statements are the ones in `profile.json`; the hash commits
to them. Restated with what each clause judges and how it fails:

| Clause | Statement | Fails when |
|---|---|---|
| **D0** | At least one delivery claim exists: an accepted Selection with outcome Selected whose Used evaluations bind to requirements of exactly one Request. For each request the latest sound claim is evaluated; earlier ones are reported superseded. | No selection binds to requirements (a best-of-N receipt is not a delivery receipt). Every other clause then reports "no claim to evaluate". |
| **D1** | Every accepted, unretracted Requirement with required true under the claim's request, as of the receipt head, has at least one evaluation among the claim's Used evaluations that references it with outcome passed. | A required requirement has no passing, unretracted evaluation in the claim, including one recorded after the claim was made (coverage is judged at the head). |
| **D2** | No evaluation among the claim's Used evaluations that references a required requirement has an outcome other than passed. | The claim carries a failed, blocked, insufficient, stale, not-run, or scored evaluation of a required requirement. Fail-closed: only `passed` passes, and a claim cannot keep the passing judgment and carry the failing one along. |
| **D3** | The claim chooses exactly one candidate; every evaluation it uses judges that candidate, carries a non-empty evidence set, and every evidence reference appears in the candidate's artifacts or in the artifacts of an accepted Result in the same thread. | The claim chooses several candidates; an evaluation judged another candidate (the rebinding fraud); an evaluation has no evidence; or evidence is cited that nothing on the record carries. |
| **D4** | The author of every evaluation the claim uses is a different actor from the author of the claimed candidate. | The producer judged its own work. |
| **D5** | Every evaluation the claim uses carries evaluator.id, evaluator.procedure_hash, evaluator.input_hash, and a declared basis; the weakest basis in the claim is reported. | An evaluation lacks the procedure or input binding, or is a v1 evaluation with no decider binding at all. The detail names the weakest basis (`declared` when any evaluation is declared, else `recomputed`). |
| **D6** | The receipt conforms to bellbook-core-v1 (or a stronger tier), and if it declares that profile the declaration names the evaluated table. | The baseline is NonConformant, or its declaration carries a stale or altered version or hash. When the receipt does not declare the baseline it is evaluated as the fallback. |
| **D7** | The claim's Selection is sound, untainted, and unretracted at the receipt head. | An evaluation the claim rests on was retracted (the selection is unsound and tainted), or the selection itself was retracted. |

Evidence references are compared by scheme and digest; the optional name is
never identity. `required: false` requirements are informational: an
evaluation of one may carry any outcome and they never count for D1 or D2.

D5 requires the decider binding to be present; it does not, and cannot,
prescribe how `procedure_hash` and `input_hash` are computed. Those are the
evaluator's conventions, and a skeptic can check them only if the evaluator
publishes them. The simplest checkable convention, and the one the field
test used, is `procedure_hash` = SHA-256 of the procedure's own bytes and
`input_hash` = SHA-256 of exactly the evidence the evaluation cites, so
that a skeptic holding the evidence and the procedure can recompute both
and re-run the procedure. An evaluator whose input is wider than the cited
evidence (a tree plus a configuration, an environment) should say what the
hash covers.

## The fraud battery

The vectors in `cases.json` pair each honest shape with the ways a claim
can lie while every id and digest stays consistent and the log replays
Clean:

- the canonical forgery: a claim over a failed evaluation of a required
  requirement (D1 and D2);
- a genuine passing evaluation of one candidate reattached to a claim for
  another (D3);
- evidence cited that neither the candidate nor any accepted Result carries,
  and an evaluation with no evidence at all (D3);
- the producer judging its own candidate (D4);
- an evaluator without a procedure or input binding (D5);
- rules that do not meet the baseline, and a stale baseline declaration (D6);
- a retracted evaluation under the claim (D7);
- a required requirement added after the claim (D1);
- a receipt with no delivery claim at all (D0).

The conformant vectors cover the baseline declared and evaluated as the
fallback, evidence bound through an accepted Result rather than the
candidate, and a superseded earlier claim. The independent validator under
`conformance/python/` implements every clause from scratch and must agree
with the reference on every vector.

## Making a claim

```sh
bellbook request add     --author human --objective "ship the bound build"
bellbook requirement add --author human --request REQ --key R1 --description "unit tests pass"
bellbook candidate add   --author agent --git-tree TREE --artifact git-tree-sha1:TREE:src
bellbook eval add        --author evaluator --candidate CAND --criterion unit-tests --passed \
                         --evaluator test-harness --basis recomputed \
                         --procedure-hash PROC --input-hash INPUT \
                         --requirement R1_ID --artifact git-tree-sha1:TREE
bellbook select          --author agent --objective ship --consider CAND --choose CAND --uses-eval EVAL
bellbook export          --profile bellbook-core-v1 delivery-receipt-v1 --out receipt.json
bellbook validate receipt.json
# exit 0: Clean, both declared profiles met; 3: validates but a claim clause failed
```

```python
report = bellbook.validate(data, require_profile="delivery-receipt-v1")
p = report.profiles[0]
p["status"], p["met"]                  # "Conformant", True
[c["id"] for c in p["clauses"] if not c["passed"]]   # the failing clauses, if any
```

## Hash

`sha256` over the RFC 8785 canonical form of the clause table in
`profile.json`. Printed by the validator with every result so a consumer
can confirm which revision of this profile was applied. Any change to a
clause statement is a new version with a new hash.
