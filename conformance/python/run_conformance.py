#!/usr/bin/env python3
"""Run the independent Python validator against Bellbook's published vectors and
conformance corpus, asserting cross-implementation agreement.

This proves an implementation with no shared code path (see
`bellbook_conformance.py`) computes the same canonical forms, record ids, head
and rules hashes, and reaches the same structural-rejection decisions as the
Rust reference. It exits non-zero on any disagreement.

Scope of THIS increment (issue #5, first step): canonicalization, ids, hashes,
strict decoding, and structural log integrity. It does not re-derive verdicts
(the per-record rule battery, retraction, and taint); cases that hinge on that
are reported as `deferred` rather than skipped silently, and are the subject of
the next increment. Run from anywhere:

    python3 conformance/python/run_conformance.py
"""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bellbook_conformance as bb  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS = ROOT / "spec" / "test-vectors-v0.2.json"
CORPUS = ROOT / "spec" / "conformance" / "v0.2"


class Failed(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise Failed(msg)


def load(path: pathlib.Path):
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------


def run_test_vectors() -> tuple[int, list[str]]:
    vf = load(VECTORS)
    notes: list[str] = []
    n = 0
    check(len(vf["vectors"]) >= 12, "test-vectors: fewer than the 12 published per-kind vectors")
    check(vf.get("signed_vector") is not None, "test-vectors: signed vector missing")

    # Unsigned per-kind vectors: independently rebuild the canonical id form and
    # confirm it is byte-identical to the published form and hashes to the id.
    for vec in vf["vectors"]:
        chf = vec["canonical_hash_form"]
        record_form = json.loads(chf)
        mine = bb.jcs(record_form)
        check(mine == chf, f"vector {vec['kind']}: canonical form differs from published")
        check(
            bb.sha256(mine.encode("utf-8")).hex() == vec["id"],
            f"vector {vec['kind']}: recomputed id differs from published",
        )
        n += 1

    # Signed vector: canonical id form -> id, and the Ed25519 signature verifies
    # over the domain-wrapped signing form. The substitute case must change the id.
    sv = vf.get("signed_vector")
    if sv:
        check(
            bb.jcs(json.loads(sv["canonical_id_form"])) == sv["canonical_id_form"],
            "signed vector: canonical id form differs from published",
        )
        check(
            bb.sha256(sv["canonical_id_form"].encode("utf-8")).hex() == sv["id"],
            "signed vector: recomputed id differs from published",
        )
        check(
            bb.sha256(sv["substitute_canonical_id_form"].encode("utf-8")).hex() == sv["substitute_id"],
            "signed vector: substitute id differs from published",
        )
        check(
            sv["substitute_id"] != sv["id"],
            "signed vector: key substitution must change the id (signature is bound into the id)",
        )
        # The domain-wrapped signing form is derived independently and must equal
        # the published one (this is the bytes an Ed25519 signature covers).
        signed_record = json.loads(sv["canonical_id_form"])
        check(
            bb.signing_bytes(signed_record).decode("utf-8") == sv["signing_form"],
            "signed vector: recomputed signing form differs from published",
        )
        n += 4
        notes += _verify_signature(sv)

    return n, notes


@contextlib.contextmanager
def _quiet_native_stderr():
    """Silence file-descriptor-level stderr so a failed native import (e.g. a
    broken `cryptography` build) does not print an alarming panic trace."""
    saved = os.dup(2)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 2)
        yield
    finally:
        os.dup2(saved, 2)
        os.close(devnull)
        os.close(saved)


def _verify_signature(sv: dict) -> list[str]:
    with _quiet_native_stderr():
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            # `cryptography` absent, or its native bindings fail to load (as in
            # some minimal environments). The signature check is optional, so it
            # degrades to a skip - unless BELLBOOK_REQUIRE_SIGNATURE is set (CI
            # sets it, so a silently-skipped signature check fails the job).
            if os.environ.get("BELLBOOK_REQUIRE_SIGNATURE"):
                raise Failed(
                    "signed vector: `cryptography` is required "
                    "(BELLBOOK_REQUIRE_SIGNATURE set) but could not be loaded"
                )
            return ["signed vector: Ed25519 check skipped (`cryptography` unavailable)"]

    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sv["public_key_hex"]))
    try:
        pk.verify(bytes.fromhex(sv["signature_hex"]), sv["signing_form"].encode("utf-8"))
    except InvalidSignature:
        raise Failed("signed vector: genuine signature did not verify")

    # The genuine signature must NOT verify under the substitute key.
    sub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sv["substitute_public_key_hex"]))
    try:
        sub.verify(bytes.fromhex(sv["signature_hex"]), sv["signing_form"].encode("utf-8"))
        raise Failed("signed vector: signature wrongly verified under the substitute key")
    except InvalidSignature:
        pass
    return ["signed vector: Ed25519 signature verified independently"]


# ---------------------------------------------------------------------------


def run_record_cases() -> tuple[int, list[str]]:
    cases = load(CORPUS / "record-cases.json")["cases"]
    check(len(cases) > 0, "record-cases.json is empty")
    ids = 0
    for c in cases:
        for r in c["prior"] + [c["candidate"]]:
            check(
                bb.record_id(r) == bb.bytes32(r["id"]),
                f"record case `{c['name']}`: recomputed id differs from stored",
            )
            ids += 1
    notes = [
        f"recomputed {ids} record ids across {len(cases)} record cases (all match)",
        "verdict re-derivation for record cases is the next increment (deferred)",
    ]
    return ids, notes


def run_receipt_cases() -> tuple[int, list[str]]:
    cases = load(CORPUS / "receipt-cases.json")["cases"]
    check(len(cases) > 0, "receipt-cases.json is empty")
    reproduced = 0
    notes: list[str] = []
    for c in cases:
        rc = c["receipt"]
        records = rc["records"]
        expect = c["expect"]
        struct = bb.check_structure(records)
        if not struct.ok:
            # Our structural layer rejects -> the corpus must also call it Invalid.
            check(
                expect["status"] == "Invalid",
                f"receipt case `{c['name']}`: we reject structurally but corpus says {expect['status']}",
            )
            reproduced += 1
        elif expect["status"] == "Invalid":
            # Structurally intact but Invalid: detectable only by re-deriving the
            # verdict (e.g. a forged verdict). Beyond this increment.
            notes.append(f"`{c['name']}`: Invalid via verdict re-derivation (deferred)")
        else:
            # Clean or Tainted: structurally valid. Hashes and count must agree.
            check(
                bb.head_hash(records) == bb.bytes32(expect["head_hash"]),
                f"receipt case `{c['name']}`: head_hash differs",
            )
            check(
                bb.rules_hash(rc["rules"]) == bb.bytes32(expect["rules_hash"]),
                f"receipt case `{c['name']}`: rules_hash differs",
            )
            check(
                len(records) == expect["record_count"],
                f"receipt case `{c['name']}`: record_count differs",
            )
            reproduced += 1
            if expect["status"] == "Tainted":
                notes.append(f"`{c['name']}`: structure+hashes match; taint set deferred")
    return reproduced, notes


def run_malformed_cases() -> tuple[int, list[str]]:
    cases = load(CORPUS / "malformed-cases.json")["cases"]
    reproduced = 0
    check(len(cases) > 0, "malformed-cases.json is empty")
    for c in cases:
        limits = c.get("limits") or {}
        status, _problem = bb.validate(
            c["input"],
            max_bytes=limits.get("max_bytes"),
            max_records=limits.get("max_records"),
            max_payload_bytes=limits.get("max_payload_bytes"),
            max_refs_per_record=limits.get("max_refs_per_record"),
        )
        check(
            status == "Invalid" and c["expect"]["status"] == "Invalid",
            f"malformed case `{c['name']}`: expected mutual Invalid, got {status} vs {c['expect']['status']}",
        )
        reproduced += 1
    return reproduced, [f"reproduced rejection on {reproduced} malformed documents"]


# ---------------------------------------------------------------------------


def main() -> int:
    sections = [
        ("test vectors", run_test_vectors),
        ("record cases (ids)", run_record_cases),
        ("receipt cases (structure + hashes)", run_receipt_cases),
        ("malformed cases (rejection)", run_malformed_cases),
    ]
    total = 0
    all_notes: list[tuple[str, list[str]]] = []
    try:
        for title, fn in sections:
            count, notes = fn()
            total += count
            all_notes.append((title, notes))
            print(f"[ok] {title}: {count} checks passed")
            for note in notes:
                print(f"     - {note}")
    except Failed as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        return 1

    print(f"\nAll independent checks passed ({total} assertions).")
    print("Independent implementation agrees with the Rust reference on")
    print("canonicalization, record ids, head/rules hashes, strict decoding,")
    print("and structural log integrity across the vectors and the full corpus.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
