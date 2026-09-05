"""Signing from Python: `default_rules(signed=..., author_keys=...)` shapes
the rules for the signed tier, `Writer(signers=...)` signs every record a
listed actor writes, and `evaluate(attested=True)` selects the attested
schema. The negative branches are the verifier's, reached through the
bindings: an unsigned record by a pinned actor, a record signed with a key
the rules do not pin for its author, and an attested evaluation from an
actor with no signer (refused before the write)."""

import hashlib
import json
import os

import pytest

import bellbook

# Deterministic test secrets; the matching public keys are pinned in the
# rules. Any 32 bytes are a valid Ed25519 secret.
HUMAN = "15" * 32
AGENT = "16" * 32
EVALUATOR = "17" * 32
# Public keys derived by the reference (`Ed25519Signer::public_key_hex`) for
# the secrets above; pinned as the CLI story pins them.
HUMAN_PUB = "d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da"
TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
DIGEST = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
FIVE = {"Candidate", "Evaluation", "Selection", "Retraction", "Requirement"}


def _signed_rules(tmp_path, pubs: dict) -> str:
    return bellbook.default_rules(
        {"human": "user", "agent": "provider", "evaluator": "provider"},
        signed=True,
        author_keys={who: [pub] for who, pub in pubs.items()},
    )


def _pubs(tmp_path) -> dict:
    out = {}
    for who, secret in (("human", HUMAN), ("agent", AGENT), ("evaluator", EVALUATOR)):
        rules = bellbook.default_rules({"agent": "provider"})
        w = bellbook.Writer(os.path.join(str(tmp_path), f"probe-{who}"), rules, signers={"agent": secret})
        c = w.candidate(author="agent", git_tree=TREE)
        assert c.accepted
        # The receipt's wire form carries the key id the signature names.
        receipt = json.loads(w.receipt())
        rec = next(r for r in receipt["records"] if bytes(r["id"]).hex() == c.id)
        out[who] = rec["author"]["signature"]["key_id"]
    assert out["human"] == HUMAN_PUB
    return out


def test_default_rules_shape_the_signed_tier(tmp_path):
    pubs = _pubs(tmp_path)
    rules = json.loads(_signed_rules(tmp_path, pubs))
    assert set(rules["signature_required_kinds"]) >= FIVE
    assert set(rules["author_keys"]) == {"human", "agent", "evaluator"}
    assert bytes(rules["author_keys"]["human"][0]).hex() == HUMAN_PUB
    # Refusals before anything is written.
    with pytest.raises(ValueError, match="no author binding"):
        bellbook.default_rules({"agent": "provider"}, author_keys={"ghost": [HUMAN_PUB]})
    with pytest.raises(ValueError, match="64 lowercase hex"):
        bellbook.default_rules({"agent": "provider"}, author_keys={"agent": ["abc"]})
    with pytest.raises(ValueError, match="lists no keys"):
        bellbook.default_rules({"agent": "provider"}, author_keys={"agent": []})


def test_signed_story_from_python_alone(tmp_path):
    pubs = _pubs(tmp_path)
    rules = _signed_rules(tmp_path, pubs)

    # A pinned actor writing unsigned is impersonation: a durable rejected
    # record with the verifier's reason, not an exception.
    unsigned = bellbook.Writer(os.path.join(str(tmp_path), "unsigned"), rules)
    r = unsigned.request(author="human", objective="ship the signed build")
    assert not r.accepted and r.reason == "SignatureMissing"
    del unsigned

    # A signer for an actor the rules do not know is refused up front.
    with pytest.raises(ValueError, match="not registered"):
        bellbook.Writer(os.path.join(str(tmp_path), "ghost"), rules, signers={"ghost": HUMAN})
    with pytest.raises(ValueError, match="64 hex characters or 32 bytes"):
        bellbook.Writer(os.path.join(str(tmp_path), "bad"), rules, signers={"human": "zz"})

    w = bellbook.Writer(
        os.path.join(str(tmp_path), "log"),
        rules,
        signers={"human": HUMAN, "agent": bytes.fromhex(AGENT), "evaluator": EVALUATOR},
    )
    req = w.request(author="human", objective="ship the signed build")
    r1 = w.requirement(author="human", request=req.id, key="R1", description="unit tests pass")
    c0 = w.candidate(author="agent", git_tree=TREE, artifacts=[f"git-tree-sha1:{TREE}:src"])
    # attested=True needs the extended shape...
    with pytest.raises(ValueError, match="extended shape"):
        w.evaluate(author="evaluator", candidate=c0.id, criterion="unit-tests", passed=True, attested=True)
    # ...and a signer for the author (agent-as-evaluator would also fail D4,
    # but the point here is a signer-less actor).
    plain = bellbook.Writer(os.path.join(str(tmp_path), "plain"), bellbook.default_rules(
        {"agent": "provider", "evaluator": "provider"}))
    pc = plain.candidate(author="agent", git_tree=TREE)
    with pytest.raises(ValueError, match="requires a signer"):
        plain.evaluate(author="evaluator", candidate=pc.id, criterion="c", passed=True,
                       evaluator="h", basis="declared", attested=True)
    del plain

    e0 = w.evaluate(
        author="evaluator",
        candidate=c0.id,
        criterion="unit-tests",
        passed=True,
        evaluator="test-harness",
        basis="recomputed",
        procedure_hash=DIGEST,
        input_hash=DIGEST,
        requirements=[r1.id],
        artifacts=[f"git-tree-sha1:{TREE}"],
        attested=True,
    )
    s0 = w.select(author="agent", objective="deliver", consider=[c0.id], choose=[c0.id], uses_eval=[e0.id])
    for c in (req, r1, c0, e0, s0):
        assert c.accepted, c.reason

    receipt = w.receipt(profiles=["bellbook-core-v1", "delivery-receipt-v1", "bellbook-core-signed-v1"])
    report = bellbook.validate(receipt)
    assert report.status == "clean"
    assert [p["id"] for p in report.profiles] == [
        "bellbook-core-v1", "delivery-receipt-v1", "bellbook-core-signed-v1"
    ]
    assert all(p["met"] for p in report.profiles)
    parsed = bellbook.read(receipt)
    by_id = {r.id: r for r in parsed.records}
    assert all(by_id[c.id].signed for c in (req, r1, c0, e0, s0))
    # `Record.schema` is the schema id: sha256 of the schema name.
    schema_id = lambda name: hashlib.sha256(name.encode()).hexdigest()  # noqa: E731
    assert by_id[e0.id].schema == schema_id("bellbook.evaluation.attested.v1")
    assert by_id[c0.id].schema == schema_id("bellbook.candidate.v1")

    # A record signed with a key the rules do not pin for its author: the
    # signature verifies against the key it carries and binds nothing.
    wrong = bellbook.Writer(
        os.path.join(str(tmp_path), "wrong"),
        rules,
        signers={"human": AGENT},
    )
    r = wrong.request(author="human", objective="ship")
    assert not r.accepted and r.reason == "SignatureInvalid"


def test_signed_tier_profile_through_the_wheel(tmp_path):
    """The signed tier as the wheel reports it: a signed, attested loop
    required against `bellbook-core-signed-v1` is Conformant on all four
    clauses, and `met` is what the exit code would be derived from."""
    pubs = _pubs(tmp_path)
    rules = _signed_rules(tmp_path, pubs)
    w = bellbook.Writer(os.path.join(str(tmp_path), "log"), rules, signers={"agent": AGENT, "evaluator": EVALUATOR})
    c0 = w.candidate(author="agent", git_tree=TREE)
    e0 = w.evaluate(author="evaluator", candidate=c0.id, criterion="c", passed=True,
                    evaluator="h", basis="declared", attested=True)
    s0 = w.select(author="agent", objective="ship", consider=[c0.id], choose=[c0.id], uses_eval=[e0.id])
    assert s0.accepted, s0.reason
    report = bellbook.validate(w.receipt(), require_profile="bellbook-core-signed-v1")
    p = report.profiles[0]
    assert p["id"] == "bellbook-core-signed-v1"
    assert p["status"] == "Conformant" and p["met"]
    assert p["declared"] is False and p["declaration_matches"] is None
    assert [c["id"] for c in p["clauses"]] == ["S0", "S1", "S2", "S3"]
