"""`default_rules` builds a rules JSON string usable directly by Writer -
the Python counterpart to `bellbook rules init`, removing the need to
hand-author a rules object."""

import json

import pytest

import bellbook


def test_default_rules_drives_the_writer(tmp_path):
    rules = bellbook.default_rules({"agent": "provider", "evaluator": "provider"})
    # It is a JSON string with the requested author-role bindings.
    parsed = json.loads(rules)
    assert parsed["author_roles"] == {"agent": "Provider", "evaluator": "Provider"}

    # And it works end to end: open a Writer with it and produce a Clean receipt.
    w = bellbook.Writer(str(tmp_path / "log"), rules)
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
    assert bellbook.validate(w.receipt()).status == "clean"


def test_default_rules_roles_are_case_insensitive():
    a = json.loads(bellbook.default_rules({"agent": "Provider"}))
    b = json.loads(bellbook.default_rules({"agent": "provider"}))
    assert a["author_roles"] == b["author_roles"] == {"agent": "Provider"}


def test_default_rules_max_context():
    rules = json.loads(bellbook.default_rules({"agent": "provider"}, max_context=42))
    assert rules["max_context_records"] == 42


def test_default_rules_rejects_bad_role():
    with pytest.raises(ValueError, match="invalid role"):
        bellbook.default_rules({"agent": "wizard"})


def test_default_rules_rejects_empty():
    with pytest.raises(ValueError, match="at least one"):
        bellbook.default_rules({})


def test_default_rules_binds_admins_and_reaffirmers():
    rules = json.loads(
        bellbook.default_rules(
            {"agent": "provider", "human": "user"},
            admins=["human"],
            reaffirmers=["human"],
        )
    )
    assert rules["admin_retraction_actors"] == ["human"]
    assert rules["reaffirmation_actors"] == ["human"]

    # The knobs are opt-in: omitted, both sets stay empty.
    bare = json.loads(bellbook.default_rules({"agent": "provider"}))
    assert bare["admin_retraction_actors"] == []
    assert bare["reaffirmation_actors"] == []


def test_default_rules_rejects_admin_without_author_binding():
    # An admin with no role binding could never author an accepted record,
    # so listing it would be a silent no-op; it must be refused instead.
    with pytest.raises(ValueError, match="no author binding"):
        bellbook.default_rules({"agent": "provider"}, admins=["ghost"])
    with pytest.raises(ValueError, match="no author binding"):
        bellbook.default_rules({"agent": "provider"}, reaffirmers=["ghost"])
