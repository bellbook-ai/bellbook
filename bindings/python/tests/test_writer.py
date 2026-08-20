"""Stage 4: record evolution to a log from Python, then verify it.

These tests drive the whole loop in one process: open a Writer, commit a
candidate / evaluation / selection, export the receipt, and feed it straight
back to `validate` and `read`. What the writer records must be exactly what the
verifier accepts.
"""

import json
import pathlib

import pytest

import bellbook

ROOT = pathlib.Path(__file__).resolve().parents[3]
V03 = ROOT / "spec" / "conformance" / "v0.3" / "receipt-cases.json"


def _rules() -> str:
    """The verifier rules a v0.3 corpus receipt was committed under, as JSON.
    Its `author_roles` binds `agent` to Provider, which these tests author as."""
    corpus = json.loads(V03.read_text())
    return json.dumps(corpus["cases"][0]["receipt"]["rules"])


def _writer(tmp_path) -> "bellbook.Writer":
    return bellbook.Writer(str(tmp_path / "log"), _rules())


def test_write_then_validate_is_clean(tmp_path):
    """A Root candidate, an evaluation, and a selection over it: the exported
    receipt validates Clean, and the writer's own records survive replay."""
    w = _writer(tmp_path)

    c0 = w.candidate(author="agent", git_tree="a" * 40)
    assert c0.accepted, c0.reason
    assert c0.result == "accept"
    assert len(c0.id) == 64 and c0.id == c0.id.lower()

    e0 = w.evaluate(author="agent", candidate=c0.id, criterion="builds", passed=True)
    assert e0.accepted, e0.reason

    s0 = w.select(
        author="agent",
        objective="ship it",
        consider=[c0.id],
        choose=[c0.id],
        uses_eval=[e0.id],
    )
    assert s0.accepted, s0.reason

    # Every commit paired a subject with a verdict: 3 subjects -> 6 records.
    assert len(w) == 6
    # The head is the last committed record (the selection's verdict), so it has
    # advanced off the empty-log all-zero head.
    assert w.head != "0" * 64

    receipt = w.receipt()
    report = bellbook.validate(receipt)
    assert report.status == "clean", report.problem or report.reason
    assert report.record_count == 6

    # The same receipt reads back with the evolution kinds present.
    parsed = bellbook.read(receipt)
    kinds = {r.kind for r in parsed.records}
    assert {"Candidate", "Evaluation", "Selection", "Verdict"} <= kinds


def test_continuation_and_derivation_basis(tmp_path):
    """A continuation names its parent and Causes the prior selection; a
    derivation Causes its sources. Both must be accepted."""
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    e0 = w.evaluate(author="agent", candidate=c0.id, criterion="ok", passed=True)
    s0 = w.select(
        author="agent",
        objective="pick",
        consider=[c0.id],
        choose=[c0.id],
        uses_eval=[e0.id],
    )

    c1 = w.candidate(
        author="agent", git_tree="b" * 40, continues=s0.id, parent=c0.id
    )
    assert c1.accepted, c1.reason

    c2 = w.candidate(author="agent", git_tree="c" * 40, derives_from=[c0.id, c1.id])
    assert c2.accepted, c2.reason

    assert bellbook.validate(w.receipt()).status == "clean"


def test_upgrade_requires_same_tree(tmp_path):
    """A binding upgrade must carry the target candidate's tree; a different
    tree is refused before anything is written."""
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    before = len(w)

    with pytest.raises(ValueError, match="differs from the target"):
        w.candidate(author="agent", git_tree="f" * 40, upgrades=c0.id)
    assert len(w) == before  # nothing committed

    up = w.candidate(author="agent", git_tree="a" * 40, upgrades=c0.id)
    assert up.accepted, up.reason
    assert bellbook.validate(w.receipt()).status == "clean"


def test_basis_flags_are_mutually_exclusive(tmp_path):
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    with pytest.raises(ValueError, match="mutually exclusive"):
        w.candidate(
            author="agent",
            git_tree="b" * 40,
            derives_from=[c0.id],
            upgrades=c0.id,
        )


def test_parent_only_with_continues(tmp_path):
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    with pytest.raises(ValueError, match="parent is only valid with continues"):
        w.candidate(author="agent", git_tree="b" * 40, parent=c0.id)


def test_evaluate_outcome_is_exclusive(tmp_path):
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    with pytest.raises(ValueError, match="exactly one of passed"):
        w.evaluate(author="agent", candidate=c0.id, criterion="x", passed=True, failed=True)
    with pytest.raises(ValueError, match="exactly one of passed"):
        w.evaluate(author="agent", candidate=c0.id, criterion="x")


def test_scored_evaluation_needs_scale(tmp_path):
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    with pytest.raises(ValueError, match="scale"):
        w.evaluate(author="agent", candidate=c0.id, criterion="perf", score=8)
    ok = w.evaluate(author="agent", candidate=c0.id, criterion="perf", score=8, scale=10)
    assert ok.accepted, ok.reason


def test_score_out_of_range_is_caught_before_commit(tmp_path):
    """`scale` is a decimal exponent bounded at 12. A scale above it is a
    payload violation the round-trip catches as a ValueError; nothing is
    written (no durable rejected record with an opaque reason)."""
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    before = len(w)
    with pytest.raises(ValueError, match="invalid payload"):
        w.evaluate(author="agent", candidate=c0.id, criterion="perf", score=8, scale=13)
    assert len(w) == before


def test_select_choose_or_none(tmp_path):
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    e0 = w.evaluate(author="agent", candidate=c0.id, criterion="ok", passed=True)
    # neither
    with pytest.raises(ValueError, match="choose or none"):
        w.select(author="agent", objective="o", consider=[c0.id])
    # both
    with pytest.raises(ValueError, match="choose or none"):
        w.select(
            author="agent",
            objective="o",
            consider=[c0.id],
            choose=[c0.id],
            uses_eval=[e0.id],
            none=True,
        )
    # a none-selection is valid on its own
    s = w.select(author="agent", objective="o", consider=[c0.id], none=True)
    assert s.accepted, s.reason


def test_reaffirmation_replaces_prior_selection(tmp_path):
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    e0 = w.evaluate(author="agent", candidate=c0.id, criterion="ok", passed=True)
    s0 = w.select(
        author="agent",
        objective="pick",
        consider=[c0.id],
        choose=[c0.id],
        uses_eval=[e0.id],
    )
    e1 = w.evaluate(author="agent", candidate=c0.id, criterion="recheck", passed=True)
    s1 = w.select(
        author="agent",
        objective="pick",
        consider=[c0.id],
        choose=[c0.id],
        uses_eval=[e1.id],
        replaces=s0.id,
    )
    assert s1.accepted, s1.reason
    assert bellbook.validate(w.receipt()).status == "clean"


def test_rejected_record_is_durable_and_writer_continues(tmp_path):
    """A rejected proposal is still committed (durable evidence of a refusal):
    `accepted` is False, no exception, and the writer's state stays consistent
    so the next valid commit still goes through."""
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    before = len(w)

    # An evaluation whose candidate ref resolves to nothing is rejected by
    # replay (RefUnresolved), not caught pre-commit.
    rej = w.evaluate(author="agent", candidate="b" * 64, criterion="x", passed=True)
    assert not rej.accepted
    assert rej.result == "reject"
    assert rej.reason  # a reason code is set
    assert len(w) == before + 2  # subject + verdict still appended

    # State survived the rejection: a subsequent valid commit is accepted.
    e0 = w.evaluate(author="agent", candidate=c0.id, criterion="ok", passed=True)
    assert e0.accepted, e0.reason

    # A durable rejected record is refused history, not retraction: still valid.
    assert bellbook.validate(w.receipt()).status in {"clean", "tainted"}


def test_unregistered_author_is_refused(tmp_path):
    w = _writer(tmp_path)
    with pytest.raises(ValueError, match="not registered"):
        w.candidate(author="nobody", git_tree="a" * 40)


def test_reopen_sees_prior_records(tmp_path):
    """Closing and reopening the log rebuilds verified state; new commits
    continue the same chain."""
    log = str(tmp_path / "log")
    rules = _rules()

    w1 = bellbook.Writer(log, rules)
    c0 = w1.candidate(author="agent", git_tree="a" * 40)
    head1 = w1.head
    n1 = len(w1)
    del w1  # release the exclusive lock

    w2 = bellbook.Writer(log, rules)
    assert len(w2) == n1
    assert w2.head == head1
    e0 = w2.evaluate(author="agent", candidate=c0.id, criterion="ok", passed=True)
    assert e0.accepted, e0.reason
    assert bellbook.validate(w2.receipt()).status == "clean"


def test_second_writer_is_locked_out(tmp_path):
    log = str(tmp_path / "log")
    rules = _rules()
    w1 = bellbook.Writer(log, rules)
    w1.candidate(author="agent", git_tree="a" * 40)
    with pytest.raises(RuntimeError):
        bellbook.Writer(log, rules)  # exclusive lock still held by w1


def test_bad_rules_json_raises(tmp_path):
    with pytest.raises(ValueError, match="invalid rules JSON"):
        bellbook.Writer(str(tmp_path / "log"), "{ not json")
