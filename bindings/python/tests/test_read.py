"""Stage 2: parse a receipt and inspect its records from Python."""

import json
import pathlib

import pytest

import bellbook

ROOT = pathlib.Path(__file__).resolve().parents[3]
V03 = ROOT / "spec" / "conformance" / "v0.3" / "receipt-cases.json"


def _first_receipt() -> bytes:
    corpus = json.loads(V03.read_text())
    return json.dumps(corpus["cases"][0]["receipt"]).encode()


def test_read_exposes_records():
    receipt = bellbook.read(_first_receipt())
    assert receipt.spec_version == "0.3"
    records = receipt.records
    assert len(records) == len(receipt)
    assert len(records) > 0

    r = records[0]
    # id and schema are 32-byte lowercase hex.
    assert len(r.id) == 64 and r.id == r.id.lower()
    assert len(r.schema) == 64
    assert r.time == 1  # genesis is time 1
    assert isinstance(r.kind, str) and r.kind
    assert isinstance(r.author_id, str)
    assert r.author_type in {"User", "Provider", "System", "Executor", "Verifier"}
    # The payload round-trips through json.
    assert isinstance(json.loads(r.payload_json), (dict, list))


def test_records_pair_with_verdicts():
    """Every subject record is followed by a Verdict, so a receipt over N
    subjects has 2N records and exactly N verdicts."""
    receipt = bellbook.read(_first_receipt())
    kinds = [r.kind for r in receipt.records]
    verdicts = [k for k in kinds if k == "Verdict"]
    assert verdicts, "expected Verdict records"
    assert len(kinds) == 2 * len(verdicts)


def test_refs_are_typed_and_hex():
    receipt = bellbook.read(_first_receipt())
    for r in receipt.records:
        for ref in r.refs:
            assert set(ref.keys()) == {"type", "target"}
            assert ref["type"] in {"Cause", "Use", "Require", "Replace"}
            assert len(ref["target"]) == 64


def test_evolution_kinds_present_in_v03_evolution_receipt():
    """Find a receipt case that contains the evolution kinds and confirm they
    are surfaced."""
    corpus = json.loads(V03.read_text())
    seen = set()
    for case in corpus["cases"]:
        receipt = bellbook.read(json.dumps(case["receipt"]).encode())
        seen.update(r.kind for r in receipt.records)
    for kind in ("Candidate", "Evaluation", "Selection"):
        assert kind in seen, kind


def test_read_rejects_garbage():
    with pytest.raises(ValueError):
        bellbook.read(b"not a receipt")
