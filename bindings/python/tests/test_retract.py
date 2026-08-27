"""`Writer.retract` - the retraction half of the model, from Python.

Retraction asserts a committed record's content is wrong: the target stays in
the log, its id enters the retracted set, dependents become tainted, and the
receipt reports Tainted permanently. Ownership is enforced by replay: the
retractor must be the target's author or an admin retraction actor, and an
Executor may never author one.
"""

import pytest

import bellbook


def _writer(tmp_path, name="log", **kwargs):
    rules = bellbook.default_rules(
        {"agent": "provider", "evaluator": "provider", "human": "user"}, **kwargs
    )
    return bellbook.Writer(str(tmp_path / name), rules)


def _line(w):
    """One candidate, one passing evaluation, one selection resting on it."""
    c = w.candidate(author="agent", git_tree="a" * 40)
    e = w.evaluate(author="evaluator", candidate=c.id, criterion="fitness", passed=True)
    s = w.select(
        author="agent",
        objective="best-of-n",
        consider=[c.id],
        choose=[c.id],
        uses_eval=[e.id],
    )
    assert s.accepted, s.reason
    return c, e, s


def test_retract_turns_the_receipt_tainted_permanently(tmp_path):
    w = _writer(tmp_path)
    c, e, s = _line(w)
    assert bellbook.validate(w.receipt()).status == "clean"

    r = w.retract(author="evaluator", target=e.id, reason="benchmark was broken")
    assert r.accepted, r.reason

    report = bellbook.validate(w.receipt())
    assert report.status == "tainted"
    assert report.retracted == [e.id]
    # The selection Used the retracted evaluation, so kernel taint reaches it.
    assert report.tainted == [s.id]
    # Standing: the unsound selection is named, nothing restored yet.
    assert s.id in report.standing["unsound"]
    assert report.standing["restorations"] == {}


def test_cross_author_retraction_is_rejected(tmp_path):
    # Ownership: an actor may not retract someone else's record unless it is
    # an admin retraction actor. The rejected record is still committed.
    w = _writer(tmp_path)
    c, e, s = _line(w)
    r = w.retract(author="agent", target=e.id, reason="not mine to retract")
    assert not r.accepted
    assert r.reason == "AuthorRoleInvalid"
    # The receipt stays clean: a rejected retraction retracts nothing.
    assert bellbook.validate(w.receipt()).status == "clean"


def test_admin_actor_may_retract_across_authors(tmp_path):
    # The same cross-author retraction is accepted once the retractor is
    # listed in admin_retraction_actors (default_rules admins=).
    w = _writer(tmp_path, admins=["human"])
    c, e, s = _line(w)
    r = w.retract(author="human", target=e.id, reason="admin override")
    assert r.accepted, r.reason
    assert bellbook.validate(w.receipt()).status == "tainted"


def test_retracting_a_retraction_or_missing_target_is_rejected(tmp_path):
    w = _writer(tmp_path)
    c, e, s = _line(w)
    r1 = w.retract(author="evaluator", target=e.id, reason="broken")
    assert r1.accepted

    # A retraction cannot be retracted (that would un-assert wrongness).
    r2 = w.retract(author="evaluator", target=r1.id, reason="undo")
    assert not r2.accepted

    # A target that is not in the log resolves nowhere.
    r3 = w.retract(author="evaluator", target="f" * 64, reason="ghost")
    assert not r3.accepted

    # A second retraction of the same target is valid (the record stays
    # retracted; asserting wrongness twice is redundant, not contradictory).
    r4 = w.retract(author="evaluator", target=e.id, reason="again")
    assert r4.accepted


def test_reaffirmation_restores_standing_but_not_clean(tmp_path):
    # The full story: retract the evidence, watch the line go unsound, then
    # reaffirm on fresh evidence. Standing is restored; Clean never returns.
    w = _writer(tmp_path)
    c, e, s = _line(w)
    w.retract(author="evaluator", target=e.id, reason="benchmark was broken")

    e2 = w.evaluate(
        author="evaluator", candidate=c.id, criterion="manual-review", passed=True
    )
    s2 = w.select(
        author="agent",
        objective="best-of-n",
        consider=[c.id],
        choose=[c.id],
        uses_eval=[e2.id],
        replaces=s.id,
    )
    assert s2.accepted, s2.reason

    report = bellbook.validate(w.receipt())
    # Tainted forever: the retraction is part of history.
    assert report.status == "tainted"
    # But the standing section records the restoration.
    assert report.standing["restorations"] == {s.id: [s2.id]}


def test_repair_motivated_by_a_retracted_evaluation_stays_sound(tmp_path):
    # The repair pattern (#85): a candidate may name the evaluation that
    # motivated it in derives_from, alongside the candidate it derives from.
    # Cause carries intent, not taint, so retracting that evaluation later
    # does not compromise the repair.
    w = _writer(tmp_path)
    c0 = w.candidate(author="agent", git_tree="a" * 40)
    e0 = w.evaluate(
        author="evaluator", candidate=c0.id, criterion="fitness", failed=True
    )
    repair = w.candidate(
        author="agent", git_tree="b" * 40, derives_from=[c0.id, e0.id]
    )
    assert repair.accepted, repair.reason

    r = w.retract(author="evaluator", target=e0.id, reason="the check was wrong")
    assert r.accepted

    report = bellbook.validate(w.receipt())
    assert report.status == "tainted"
    assert report.retracted == [e0.id]
    # The repair is not tainted and its standing is not compromised.
    assert repair.id not in report.tainted
    assert repair.id not in report.standing["compromised"]