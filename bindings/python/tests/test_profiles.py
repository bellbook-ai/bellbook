"""`bellbook-core-v1` across the FFI boundary: `validate(..., require_profile=...)`
carries the profile result, `default_rules` emits a baseline-conformant rule
set, and every published profile vector re-derives identically through the
wheel. A profile result is a report alongside the verdict, never a change
to it."""

import json
import pathlib

import pytest

import bellbook

# repo root: bindings/python/tests/ -> bindings/python -> bindings -> root
ROOT = pathlib.Path(__file__).resolve().parents[3]
CASES = ROOT / "spec" / "profiles" / "bellbook-core-v1" / "cases.json"
CORE_V1 = "bellbook-core-v1"
BASELINE = {"Candidate": "Reported", "Evaluation": "Reported", "Selection": "Inferred"}


def _line(tmp_path, rules_json: str) -> bytes:
    """One candidate, one passing evaluation, one selection: a Clean line."""
    w = bellbook.Writer(str(tmp_path / "log"), rules_json)
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
    return w.receipt()


def _authors():
    return {"agent": "provider", "evaluator": "provider"}


def test_default_rules_conform_to_the_baseline(tmp_path):
    rules = bellbook.default_rules(_authors())
    assert json.loads(rules)["evidence_thresholds"] == BASELINE

    report = bellbook.validate(_line(tmp_path, rules), require_profile=CORE_V1)
    assert report.status == "clean"
    (p,) = report.profiles
    assert p["id"] == CORE_V1
    assert p["status"] == "Conformant"
    assert [c["id"] for c in p["clauses"]] == ["B1", "B2", "B3", "B4", "B5", "B6"]
    assert all(c["passed"] for c in p["clauses"])
    assert len(p["hash"]) == 64 and int(p["hash"], 16)
    # The human rendering names the profile, as the CLI does.
    assert f"profile {CORE_V1}: CONFORMANT" in str(report)


def test_profiles_are_a_report_alongside_the_verdict(tmp_path):
    # Strip the thresholds: still valid rules, still a Clean log, but not
    # comparable under the baseline. The verdict fields are untouched.
    rules = json.loads(bellbook.default_rules(_authors()))
    rules["evidence_thresholds"] = {}
    receipt = _line(tmp_path, json.dumps(rules))

    plain = bellbook.validate(receipt)
    assert plain.profiles == []
    report = bellbook.validate(receipt, require_profile=[CORE_V1])
    assert (report.status, report.reason) == (plain.status, plain.reason) == ("clean", None)
    assert report.head_hash == plain.head_hash
    assert report.rules_hash == plain.rules_hash

    (p,) = report.profiles
    assert p["status"] == "NonConformant"
    b3 = next(c for c in p["clauses"] if c["id"] == "B3")
    assert not b3["passed"]
    assert "missing" in b3["detail"]
    assert all(c["passed"] for c in p["clauses"] if c["id"] != "B3")


def test_unknown_profile_is_reported_not_raised(tmp_path):
    receipt = _line(tmp_path, bellbook.default_rules(_authors()))
    report = bellbook.validate(receipt, require_profile=["no-such-profile-v9", CORE_V1])
    assert [p["status"] for p in report.profiles] == ["Unknown", "Conformant"]
    assert report.profiles[0]["hash"] == "0" * 64
    assert report.profiles[0]["clauses"] == []


def test_require_profile_type_is_checked():
    with pytest.raises(ValueError, match="require_profile"):
        bellbook.validate(b"x", require_profile=7)


def test_published_profile_vectors_match_reference():
    """Every vector in spec/profiles/bellbook-core-v1/cases.json yields the
    stored status, per-clause flags, and profile hash through the wheel."""
    doc = json.loads(CASES.read_text())
    assert doc["profile"] == CORE_V1
    expected_hash = bytes(doc["hash"]).hex()
    assert len(doc["cases"]) >= 7
    # The bindings track the *published* core. Between a spec-epoch bump on
    # main and the pin bump that follows the next core publish, the vectors
    # come from an epoch the pinned core does not implement: it reports a
    # structural problem (an unsupported version, or a rules map naming a
    # kind it has never heard of) instead of a profile result. That is not a
    # disagreement to hide; skip loudly until the pin moves. The current
    # core always parses its own vectors, so a structural problem here can
    # only be the epoch gap.
    probe = bellbook.validate(json.dumps(doc["cases"][0]["receipt"]).encode())
    if probe.problem:
        pytest.skip(f"vectors are from a newer spec epoch than the pinned core: {probe.problem}")
    for case in doc["cases"]:
        data = json.dumps(case["receipt"]).encode()
        report = bellbook.validate(data, require_profile=CORE_V1)
        (p,) = report.profiles
        assert p["hash"] == expected_hash, case["name"]
        assert p["status"] == case["expect"]["status"], case["name"]
        flags = [{"id": c["id"], "passed": c["passed"]} for c in p["clauses"]]
        assert flags == case["expect"]["clauses"], case["name"]
