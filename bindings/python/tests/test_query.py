"""The RFC-0002 named query set from Python, on `Writer` and `Receipt` alike.

Seven deterministic, read-only queries - descent, descendants, siblings,
frontier, standing, evidence, selected - returning the shared surface JSON
shapes as plain dicts/lists, identical to what the Rust core and the CLI
emit. Queries run only over verified state: an input that does not verify
raises ValueError, as do a missing or rejected id and a kind mismatch.
"""

import pytest

import bellbook


def _writer(tmp_path, name="log"):
    rules = bellbook.default_rules(
        {"agent": "provider", "evaluator": "provider", "human": "user"}
    )
    return bellbook.Writer(str(tmp_path / name), rules)


def _story(w):
    """The field-test story: adopt a baseline on a benchmark, run a
    best-of-N round over its continuation, retract the benchmark, repair."""
    c0 = w.candidate(author="agent", git_tree="a" * 40).id
    bench = w.evaluate(
        author="evaluator", candidate=c0, criterion="benchmark", passed=True
    ).id
    s0 = w.select(
        author="agent",
        objective="adopt-baseline",
        consider=[c0],
        choose=[c0],
        uses_eval=[bench],
    ).id
    c1 = w.candidate(
        author="agent", git_tree="b" * 40, continues=s0, parent=c0
    ).id
    c2 = w.candidate(author="agent", git_tree="c" * 40, derives_from=[c1]).id
    c3 = w.candidate(author="agent", git_tree="d" * 40, derives_from=[c1]).id
    e2 = w.evaluate(
        author="evaluator", candidate=c2, criterion="unit-tests", passed=True
    ).id
    w.evaluate(author="evaluator", candidate=c3, criterion="unit-tests", failed=True)
    s1 = w.select(
        author="agent",
        objective="adopt",
        consider=[c2, c3],
        choose=[c2],
        uses_eval=[e2],
    ).id
    r = w.retract(author="evaluator", target=bench, reason="harness was broken")
    assert r.accepted, r.reason
    review = w.evaluate(
        author="evaluator", candidate=c0, criterion="benchmark-v2", passed=True
    ).id
    s2 = w.select(
        author="agent",
        objective="adopt-baseline",
        consider=[c0],
        choose=[c0],
        uses_eval=[review],
        replaces=s0,
    ).id
    return dict(c0=c0, bench=bench, s0=s0, c1=c1, c2=c2, c3=c3, s1=s1, s2=s2)


def test_the_named_set_answers_the_field_test(tmp_path):
    w = _writer(tmp_path)
    ids = _story(w)

    # q7: which candidate won the round, on what evidence.
    sel = w.selected("adopt")
    assert [s["selection"]["id"] for s in sel["selections"]] == [ids["s1"]]
    assert [c["id"] for c in sel["selections"][0]["chosen"]] == [ids["c2"]]
    assert sel["selections"][0]["evidence"][0]["criterion"] == "unit-tests"
    assert sel["selections"][0]["evidence"][0]["outcome"] == "passed"

    # q1: the winner's full line of descent.
    d = w.descent(ids["c2"])
    assert [(s["node"]["id"], s["via"]) for s in d["line"]] == [
        (ids["c1"], "derivation"),
        (ids["s0"], "continuation-anchor"),
        (ids["c0"], "parent"),
    ]

    # q6: what the line rests on - the retracted benchmark surfaces.
    ev = w.evidence(ids["c2"])
    assert [se["selection"]["id"] for se in ev["rests_on"]] == [ids["s0"]]
    entry = ev["rests_on"][0]["evidence"][0]
    assert entry["node"]["id"] == ids["bench"]
    assert entry["node"]["retracted"] is True
    assert entry["criterion"] == "benchmark"

    # q5: the anchor Selection is unsound and tainted; the re-adoption is a
    # restoration on the record, not an erasure.
    st = w.standing(ids["s0"])
    assert st["node"]["standing"] == "unsound"
    assert st["node"]["tainted"] is True
    assert st["restorations"] == [ids["s2"]]

    # q4: the continuation was never considered; the round's winner has no
    # continuation yet.
    fr = w.frontier()
    assert [(e["node"]["id"], e["reason"]) for e in fr["frontier"]] == [
        (ids["c1"], "unconsidered"),
        (ids["c2"], "selected-no-continuation"),
    ]

    # q3: the winner's generation.
    sib = w.siblings(ids["c2"])
    assert [n["id"] for n in sib["siblings"]] == [ids["c3"]]

    # q2: everything downstream of the baseline.
    de = w.descendants(ids["c0"])
    assert {n["id"] for n in de["descendants"]} == {ids["c1"], ids["c2"], ids["c3"]}


def test_receipt_and_writer_answers_are_identical(tmp_path):
    # The shared-shape claim (RFC-0002 C4): the same query over the live
    # writer and over its exported receipt returns equal Python objects.
    w = _writer(tmp_path)
    ids = _story(w)
    r = bellbook.read(w.receipt())

    assert r.descent(ids["c2"]) == w.descent(ids["c2"])
    assert r.descendants(ids["c0"]) == w.descendants(ids["c0"])
    assert r.siblings(ids["c2"]) == w.siblings(ids["c2"])
    assert r.frontier() == w.frontier()
    assert r.standing(ids["s0"]) == w.standing(ids["s0"])
    assert r.evidence(ids["c2"]) == w.evidence(ids["c2"])
    assert r.selected("adopt") == w.selected("adopt")


def test_query_errors_are_specific(tmp_path):
    w = _writer(tmp_path)
    ids = _story(w)

    # A rejected record is durably committed but not addressable.
    rejected = w.retract(author="agent", target=ids["bench"], reason="not mine")
    assert not rejected.accepted
    with pytest.raises(ValueError, match="rejected at commit"):
        w.standing(rejected.id)

    # Kind mismatch: descent addresses candidates only.
    with pytest.raises(ValueError, match="not a Candidate"):
        w.descent(ids["bench"])

    # Not found, and a malformed id.
    with pytest.raises(ValueError, match="not found"):
        w.descent("f" * 64)
    with pytest.raises(ValueError, match="invalid record id"):
        w.descent("zzzz")


def test_exact_objective_no_patterns(tmp_path):
    w = _writer(tmp_path)
    _story(w)
    assert w.selected("adopt-")["selections"] == []
    assert w.selected("adopt*")["selections"] == []
