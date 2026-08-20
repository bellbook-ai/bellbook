"""Stage 1 parity test: the Python wheel reaches the same decision as the
Rust reference on every committed receipt case.

The bindings wrap the same core, so this is not re-testing the verifier; it
confirms the FFI surface faithfully carries status, reason, counts, hashes,
and the standing section across the boundary.
"""

import json
import pathlib

import bellbook

# repo root: bindings/python/tests/ -> bindings/python -> bindings -> root
ROOT = pathlib.Path(__file__).resolve().parents[3]
V03 = ROOT / "spec" / "conformance" / "v0.3" / "receipt-cases.json"
V02 = ROOT / "spec" / "conformance" / "v0.2" / "receipt-cases.json"


def _validate_receipt(receipt: dict) -> "bellbook.Report":
    return bellbook.validate(json.dumps(receipt).encode())


def test_v03_receipts_match_reference():
    corpus = json.loads(V03.read_text())
    assert corpus["spec_version"] == "0.3"
    for case in corpus["cases"]:
        report = _validate_receipt(case["receipt"])
        expect = case["expect"]
        assert report.status == expect["status"].lower(), case["name"]
        assert report.record_count == expect["record_count"], case["name"]
        assert report.head_hash == bytes(expect["head_hash"]).hex(), case["name"]
        assert report.rules_hash == bytes(expect["rules_hash"]).hex(), case["name"]
        assert report.retracted == [bytes(i).hex() for i in expect["retracted"]], case["name"]
        assert report.tainted == [bytes(i).hex() for i in expect["tainted"]], case["name"]


def test_standing_section_crosses_the_boundary():
    """At least one v0.3 receipt case carries a non-empty standing section;
    confirm it is exposed as a dict with the three keys."""
    corpus = json.loads(V03.read_text())
    saw_standing = False
    for case in corpus["cases"]:
        report = _validate_receipt(case["receipt"])
        standing = report.standing
        assert set(standing.keys()) == {"compromised", "unsound", "restorations"}
        if standing["compromised"] or standing["unsound"] or standing["restorations"]:
            saw_standing = True
    assert saw_standing, "expected at least one receipt case with standing content"


def test_v02_receipt_is_rejected_as_wrong_epoch():
    """The current core rejects a v0.2 receipt with a clear version problem."""
    corpus = json.loads(V02.read_text())
    report = _validate_receipt(corpus["cases"][0]["receipt"])
    assert report.status == "invalid"
    assert report.problem is not None
    assert "spec version" in report.problem.lower()


def test_garbage_is_invalid_not_an_exception():
    report = bellbook.validate(b"not a receipt")
    assert report.status == "invalid"
    assert not report.is_clean
