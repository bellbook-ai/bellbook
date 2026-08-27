"""The v0.5.0 gate, Python half: the broken-benchmark story end to end.

Behavioral equivalence with examples/broken_benchmark.rs - the same status
transitions and standing sets, not byte-identical logs. Build a line resting
on a benchmark evaluation, retract it, watch the whole descendant line go
compromised while a repair deriving from the sound baseline stays sound,
reaffirm on fresh evidence, and watch standing restore while the receipt
stays Tainted permanently.
"""

import os

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