"""The v0.5.0 gate, Python half: the broken-benchmark story end to end.

Behavioral equivalence with examples/broken_benchmark.rs - the same status
transitions and standing sets, not byte-identical logs. Build a line resting
on a benchmark evaluation, retract it, watch the whole descendant line go
compromised while a repair deriving from the sound baseline stays sound,
reaffirm on fresh evidence, and watch standing restore while the receipt
stays Tainted permanently.
"""

import json
import os

import pytest

import bellbook


def test_broken_benchmark_story_runs_from_python_alone(tmp_path):
    rules = bellbook.default_rules({"agent": "provider", "evaluator": "provider"})
    w = bellbook.Writer(os.path.join(str(tmp_path), "log"), rules)

    # Phase 1: the line is built, all sound.
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    bench = w.evaluate(
        author="evaluator", candidate=c0.id, criterion="benchmark", passed=True
    )
    s0 = w.select(
        author="agent",
        objective="ship",
        consider=[c0.id],
        choose=[c0.id],
        uses_eval=[bench.id],
    )
    c1 = w.candidate(
        author="agent", git_tree="b" * 40, continues=s0.id, parent=c0.id
    )
    c2 = w.candidate(author="agent", git_tree="c" * 40, derives_from=[c1.id])
    c3 = w.candidate(author="agent", git_tree="d" * 40, derives_from=[c2.id])
    # The repair: derives from the sound baseline, motivated by the benchmark.
    c4 = w.candidate(
        author="agent", git_tree="e" * 40, derives_from=[c0.id, bench.id]
    )
    for commit in (c0, bench, s0, c1, c2, c3, c4):
        assert commit.accepted, commit.reason

    report = bellbook.validate(w.receipt())
    assert report.status == "clean"
    assert report.standing == {"compromised": [], "unsound": [], "restorations": {}}

    # Phase 2: the benchmark harness was broken; its author retracts it.
    r = w.retract(
        author="evaluator", target=bench.id, reason="harness measured the wrong thing"
    )
    assert r.accepted, r.reason

    report = bellbook.validate(w.receipt())
    assert report.status == "tainted"
    assert report.retracted == [bench.id]
    assert report.tainted == [s0.id]
    # The whole line resting on the unsound selection is compromised, at any
    # depth; the repair deriving from the sound baseline is not.
    assert set(report.standing["compromised"]) == {c1.id, c2.id, c3.id}
    assert report.standing["unsound"] == [s0.id]
    assert c4.id not in report.standing["compromised"]

    # Phase 3: reaffirm on fresh evidence.
    review = w.evaluate(
        author="evaluator", candidate=c0.id, criterion="manual-review", passed=True
    )
    s1 = w.select(
        author="agent",
        objective="ship",
        consider=[c0.id],
        choose=[c0.id],
        uses_eval=[review.id],
        replaces=s0.id,
    )
    assert s1.accepted, s1.reason

    report = bellbook.validate(w.receipt())
    # Tainted permanently: the retraction is history, not an erasure.
    assert report.status == "tainted"
    assert report.retracted == [bench.id]
    # But standing is restored: nothing compromised, the restoration recorded.
    assert report.standing["compromised"] == []
    assert report.standing["restorations"] == {s0.id: [s1.id]}

def test_requirement_binding_story_from_python_alone(tmp_path):
    """The v0.8.0 gate, Python half (spec 0.4): request, requirements, a
    candidate bound to artifacts, extended evaluations bound to the
    requirements, a selection, a receipt that declares the baseline profile,
    validated Clean and Conformant with the declaration checked unasked; the
    query surface shows the bindings; then the taint a retracted requirement
    spreads. Behavioral equivalence with the CLI story in tests/cli.rs."""
    tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    rules = bellbook.default_rules(
        {"human": "user", "agent": "provider", "evaluator": "provider"}
    )
    w = bellbook.Writer(os.path.join(str(tmp_path), "log"), rules)

    req = w.request(author="human", objective="ship the bound build")
    r1 = w.requirement(
        author="human", request=req.id, key="R1", description="unit tests pass"
    )
    # A provider-authored requirement defaults to derived provenance.
    r2 = w.requirement(
        author="agent",
        request=req.id,
        key="R2",
        description="lint is clean",
        required=False,
        expected_evidence="lint log",
    )
    c0 = w.candidate(
        author="agent",
        git_tree=tree,
        artifacts=[f"sha256-bytes:{digest}:dist.tar", {"scheme": "git-tree-sha1", "digest": tree, "name": "src"}],
    )
    e0 = w.evaluate(
        author="evaluator",
        candidate=c0.id,
        criterion="unit-tests",
        passed=True,
        evaluator="test-harness",
        evaluator_version="1.4.0",
        basis="recomputed",
        procedure_hash=digest,
        requirements=[r1.id],
        artifacts=[f"git-tree-sha1:{tree}"],
    )
    # A fail-closed outcome is recorded as exactly what it is.
    e1 = w.evaluate(
        author="evaluator",
        candidate=c0.id,
        criterion="lint",
        not_run=True,
        evaluator="linter",
        basis="declared",
        requirements=[r2.id],
    )
    s0 = w.select(
        author="agent",
        objective="ship",
        consider=[c0.id],
        choose=[c0.id],
        uses_eval=[e0.id, e1.id],
    )
    for commit in (req, r1, r2, c0, e0, e1, s0):
        assert commit.accepted, commit.reason

    receipt = w.receipt(profiles=["bellbook-core-v1"])
    report = bellbook.validate(receipt)
    assert report.status == "clean", report.problem or report.reason
    assert report.record_count == 14
    (p,) = report.profiles
    assert p["id"] == "bellbook-core-v1"
    assert p["status"] == "Conformant"
    assert p["declared"] is True
    assert p["declaration_matches"] is True
    assert p["met"] is True
    # Requiring the declared profile evaluates it once, as declared.
    again = bellbook.validate(receipt, require_profile="bellbook-core-v1")
    assert [q["id"] for q in again.profiles] == ["bellbook-core-v1"]

    # The payloads round-trip the new fields.
    parsed = bellbook.read(receipt)
    by_id = {r.id: r for r in parsed.records}
    assert json.loads(by_id[r1.id].payload_json)["provenance"] == "user_authored"
    assert json.loads(by_id[r2.id].payload_json)["provenance"] == "derived"
    assert json.loads(by_id[r2.id].payload_json)["required"] is False
    e0_payload = json.loads(by_id[e0.id].payload_json)
    assert e0_payload["evaluator"]["id"] == "test-harness"
    assert e0_payload["basis"] == "recomputed"
    assert e0_payload["evidence"][0]["scheme"] == "git-tree-sha1"
    assert json.loads(by_id[e1.id].payload_json)["outcome"] == "not_run"
    c0_payload = json.loads(by_id[c0.id].payload_json)
    assert [a["scheme"] for a in c0_payload["artifacts"]] == ["git-tree-sha1", "sha256-bytes"]

    # The query surface reports the bindings, over the log and the receipt.
    for surface in (w, parsed):
        sel = surface.selected("ship")["selections"][0]
        assert sel["selection"]["id"] == s0.id
        chosen = sel["chosen"][0]
        assert chosen["id"] == c0.id
        assert [a["scheme"] for a in chosen["artifacts"]] == ["git-tree-sha1", "sha256-bytes"]
        assert "requirements" not in chosen
        ev = sel["evidence"]
        assert [e["outcome"] for e in ev] == ["passed", "not_run"]
        assert ev[0]["node"]["requirements"] == [r1.id]
        assert ev[0]["node"]["artifacts"][0]["digest"] == tree
        assert ev[1]["node"]["requirements"] == [r2.id]
        assert "artifacts" not in ev[1]["node"]

    # Retracting the requirement taints the evaluation that judged against
    # it and the selection that rested on that evaluation.
    r = w.retract(author="human", target=r1.id, reason="the requirement was misstated")
    assert r.accepted, r.reason
    report = bellbook.validate(w.receipt())
    assert report.status == "tainted"
    assert report.retracted == [r1.id]
    assert e0.id in report.tainted and s0.id in report.tainted
    assert e1.id not in report.tainted


def test_requirement_and_extended_evaluate_refuse_what_the_verifier_would(tmp_path):
    rules = bellbook.default_rules(
        {"human": "user", "agent": "provider", "evaluator": "provider"}
    )
    w = bellbook.Writer(os.path.join(str(tmp_path), "log"), rules)
    req = w.request(author="human", objective="ship")
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    before = len(w)

    # Provenance is bound to the role: refused before the write.
    with pytest.raises(ValueError, match="bound to the author's role"):
        w.requirement(
            author="agent", request=req.id, key="R1", description="d", provenance="user_authored"
        )
    # The request must be an accepted Request.
    with pytest.raises(ValueError, match="not an accepted Request"):
        w.requirement(author="human", request=c0.id, key="R1", description="d")
    # Malformed artifacts never reach the log.
    with pytest.raises(ValueError, match="invalid artifact"):
        w.candidate(author="agent", git_tree="b" * 40, artifacts=["git-tree-sha1:abc"])
    with pytest.raises(ValueError, match="strings or dicts"):
        w.candidate(author="agent", git_tree="b" * 40, artifacts=[7])
    # Extended fields need the decider binding; basis is never inferred.
    with pytest.raises(ValueError, match="requires both evaluator and basis"):
        w.evaluate(author="evaluator", candidate=c0.id, criterion="c", blocked=True)
    with pytest.raises(ValueError, match="requires both evaluator and basis"):
        w.evaluate(author="evaluator", candidate=c0.id, criterion="c", passed=True, evaluator="h")
    with pytest.raises(ValueError, match="invalid basis"):
        w.evaluate(
            author="evaluator", candidate=c0.id, criterion="c", passed=True, evaluator="h", basis="guessed"
        )
    with pytest.raises(ValueError, match="exactly one of"):
        w.evaluate(author="evaluator", candidate=c0.id, criterion="c", passed=True, stale=True)
    with pytest.raises(ValueError, match="not an accepted Requirement"):
        w.evaluate(
            author="evaluator",
            candidate=c0.id,
            criterion="c",
            passed=True,
            evaluator="h",
            basis="declared",
            requirements=[c0.id],
        )
    with pytest.raises(ValueError, match="unknown profile"):
        w.receipt(profiles=["made-up-v1"])
    assert len(w) == before  # nothing written by any refusal

    # A duplicate key is a verifier rule: a durable rejected record.
    ok = w.requirement(author="human", request=req.id, key="R1", description="d")
    assert ok.accepted, ok.reason
    dup = w.requirement(author="agent", request=req.id, key="R1", description="again")
    assert not dup.accepted and dup.reason == "RequirementInvalid"
