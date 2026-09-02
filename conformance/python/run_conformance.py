#!/usr/bin/env python3
"""Run the independent Python validator against Bellbook's published vectors and
conformance corpus, asserting cross-implementation agreement.

This proves an implementation with no shared code path (see
`bellbook_conformance.py`) computes the same canonical forms, record ids, head
and rules hashes, and reaches the same structural-rejection decisions as the
Rust reference. It exits non-zero on any disagreement.

This now covers both increments of issue #5: canonicalization, ids, hashes,
strict decoding, and structural log integrity (`bellbook_conformance.py`), plus
the full verdict rule battery, retraction, and transitive taint
(`bellbook_verdict.py`) - every record case's verdict and every receipt case's
status, reason, and retracted/tainted sets are re-derived independently. Run
from anywhere:

    python3 conformance/python/run_conformance.py
"""

from __future__ import annotations

import contextlib
import functools
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bellbook_conformance as bb  # noqa: E402
import bellbook_profiles as bp  # noqa: E402
import bellbook_queries as bq  # noqa: E402
import bellbook_verdict as bv  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Every epoch this validator replays (SPEC 14): the frozen 0.3 artifacts and
# the current 0.4 ones, each run in full. The 0.3 run is the independent
# half of the epoch promise: a 0.3 receipt reaches the identical decision
# under a validator that implements 0.4.
EPOCHS = [
    (v, ROOT / "spec" / f"test-vectors-v{v}.json", ROOT / "spec" / "conformance" / f"v{v}")
    for v in bb.SUPPORTED_SPEC_VERSIONS
]


class Failed(Exception):
    pass


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise Failed(msg)


def load(path: pathlib.Path):
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------


def run_test_vectors(vectors: pathlib.Path, spec_version: str) -> tuple[int, list[str]]:
    vf = load(vectors)
    check(vf["spec_version"] == spec_version, f"{vectors.name}: wrong spec_version")
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


def _require_signature_or_skip(where: str, skipped: list[str], name: str) -> None:
    """A case whose verdict needs a present signature verified. In CI
    (`BELLBOOK_REQUIRE_SIGNATURE`) this is a hard failure; elsewhere it degrades
    to a recorded skip, exactly as the signed test vector does."""
    if os.environ.get("BELLBOOK_REQUIRE_SIGNATURE"):
        raise Failed(
            f"{where}: `cryptography` is required (BELLBOOK_REQUIRE_SIGNATURE set) "
            "to verify the record's signature but could not be loaded"
        )
    skipped.append(name)


def run_record_cases(corpus: pathlib.Path, spec_version: str) -> tuple[int, list[str]]:
    doc = load(corpus / "record-cases.json")
    check(doc["spec_version"] == spec_version, "record-cases.json: wrong spec_version")
    cases = doc["cases"]
    check(len(cases) > 0, "record-cases.json is empty")
    ids = 0
    verdicts = 0
    sig_skipped: list[str] = []
    for c in cases:
        # 1. Every stored id recomputes from content.
        for r in c["prior"] + [c["candidate"]]:
            check(
                bb.record_id(r) == bb.bytes32(r["id"]),
                f"record case `{c['name']}`: recomputed id differs from stored",
            )
            ids += 1
        # 2. Independently re-derive the verdict and compare to the stored one.
        rules = bv.Rules(c["rules"], spec_version)
        state = bv.build_state_unchecked(c["prior"])
        expected = {"result": c["expect"]["result"], "reason": c["expect"].get("reason")}
        try:
            with _quiet_native_stderr():
                got = bv.verify_record(c["candidate"], c["prior"], rules, state)
        except bv.SignatureUnavailable:
            _require_signature_or_skip(f"record case `{c['name']}`", sig_skipped, c["name"])
            continue
        check(
            got == expected,
            f"record case `{c['name']}`: re-derived verdict {got} differs from stored {expected}",
        )
        verdicts += 1
    notes = [
        f"recomputed {ids} record ids across {len(cases)} record cases (all match)",
        f"independently re-derived {verdicts} verdicts (result + reason) matching the stored verdict",
    ]
    if sig_skipped:
        notes.append(
            "signature cases skipped (`cryptography` unavailable): " + ", ".join(sig_skipped)
        )
    return ids + verdicts, notes


def run_receipt_cases(corpus: pathlib.Path, spec_version: str) -> tuple[int, list[str]]:
    doc = load(corpus / "receipt-cases.json")
    check(doc["spec_version"] == spec_version, "receipt-cases.json: wrong spec_version")
    cases = doc["cases"]
    check(len(cases) > 0, "receipt-cases.json is empty")
    assertions = 0
    statuses = {"Clean": 0, "Tainted": 0, "Invalid": 0}
    sig_skipped: list[str] = []
    for c in cases:
        rc = c["receipt"]
        records = rc["records"]
        expect = c["expect"]
        check(
            rc["spec_version"] == spec_version,
            f"receipt case `{c['name']}`: receipt declares {rc['spec_version']!r}",
        )

        # Structural cross-checks: head hash, rules hash, and record count are
        # reproduced independently for every case (including Invalid ones -
        # validate() reports them regardless of replay outcome).
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
        assertions += 3

        # Semantic reproduction: full replay yields the same status, reason, and
        # retracted/tainted sets as the reference.
        try:
            with _quiet_native_stderr():
                report = bv.validate_receipt(records, rc["rules"], rc["spec_version"])
        except bv.SignatureUnavailable:
            _require_signature_or_skip(f"receipt case `{c['name']}`", sig_skipped, c["name"])
            continue
        check(
            report["status"] == expect["status"],
            f"receipt case `{c['name']}`: status {report['status']} differs from {expect['status']}",
        )
        check(
            report["reason"] == expect.get("reason"),
            f"receipt case `{c['name']}`: reason {report['reason']} differs from {expect.get('reason')}",
        )
        expect_ret = sorted(bb.bytes32(x).hex() for x in expect.get("retracted", []))
        expect_tai = sorted(bb.bytes32(x).hex() for x in expect.get("tainted", []))
        check(
            report["retracted"] == expect_ret,
            f"receipt case `{c['name']}`: retracted set differs",
        )
        check(
            report["tainted"] == expect_tai,
            f"receipt case `{c['name']}`: tainted set differs",
        )
        # Standing section (SPEC §7.2): compromised/unsound id sets and the
        # restorations map, re-derived independently and compared byte for
        # decision.
        exp_std = expect.get("standing", {}) or {}
        exp_comp = sorted(bb.bytes32(x).hex() for x in exp_std.get("compromised", []))
        exp_uns = sorted(bb.bytes32(x).hex() for x in exp_std.get("unsound", []))
        exp_rest = sorted(
            (bb.bytes32(k).hex(), sorted(bb.bytes32(v).hex() for v in vs))
            for k, vs in exp_std.get("restorations", [])
        )
        got_std = report["standing"]
        got_rest = [(k, list(vs)) for k, vs in got_std["restorations"]]
        check(
            got_std["compromised"] == exp_comp,
            f"receipt case `{c['name']}`: standing.compromised differs",
        )
        check(
            got_std["unsound"] == exp_uns,
            f"receipt case `{c['name']}`: standing.unsound differs",
        )
        check(
            got_rest == exp_rest,
            f"receipt case `{c['name']}`: standing.restorations differs",
        )
        assertions += 7
        statuses[report["status"]] = statuses.get(report["status"], 0) + 1

    notes = [
        "independently replayed each receipt: status, reason, retracted/tainted, "
        "and the standing section (compromised, unsound, restorations) match "
        f"({statuses['Clean']} Clean, {statuses['Tainted']} Tainted, "
        f"{statuses['Invalid']} Invalid)",
    ]
    if sig_skipped:
        notes.append("signature cases skipped (`cryptography` unavailable): " + ", ".join(sig_skipped))
    return assertions, notes


def run_malformed_cases(corpus: pathlib.Path, spec_version: str) -> tuple[int, list[str]]:
    doc = load(corpus / "malformed-cases.json")
    check(doc["spec_version"] == spec_version, "malformed-cases.json: wrong spec_version")
    cases = doc["cases"]
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


def run_query_cases(corpus: pathlib.Path, spec_version: str) -> tuple[int, list[str]]:
    """RFC-0002 named query set: re-derive every stored query answer from the
    stored receipt with the from-scratch implementation in
    `bellbook_queries.py` and require deep JSON equality with the reference's
    surface shapes."""
    doc = load(corpus / "query-cases.json")
    check(doc["spec_version"] == spec_version, "query-cases.json: wrong spec_version")
    cases = doc["cases"]
    check(len(cases) > 0, "query-cases.json is empty")
    assertions = 0
    per_query: dict[str, int] = {}
    for c in cases:
        rc = c["receipt"]
        try:
            ctx = bq.QueryContext(rc["records"], rc["rules"])
        except ValueError as e:
            raise Failed(f"query case `{c['name']}`: receipt must verify: {e}") from e
        for v in c["queries"]:
            got = bq.run_query(ctx, v["query"], v["args"])
            check(
                got == v["expect"],
                f"query case `{c['name']}`: {v['query']} {v['args']} differs:\n"
                f"  got:    {json.dumps(got, sort_keys=True)[:400]}\n"
                f"  expect: {json.dumps(v['expect'], sort_keys=True)[:400]}",
            )
            assertions += 1
            per_query[v["query"]] = per_query.get(v["query"], 0) + 1
    # Coverage: every named query has at least one vector.
    named = {"descent", "descendants", "siblings", "frontier", "standing", "evidence", "selected"}
    missing = named - set(per_query)
    check(not missing, f"query corpus covers no vector for: {sorted(missing)}")
    notes = ["queries covered: " + ", ".join(f"{k}={per_query[k]}" for k in sorted(per_query))]
    return assertions, notes


def run_profile_cases() -> tuple[int, list[str]]:
    """bellbook-core-v1 (RFC-0003 section 4.5): recompute the profile hash
    from the published clause table, then re-derive every stored profile
    result - status and per-clause pass flags - from the stored receipt with
    the from-scratch implementation in `bellbook_profiles.py`."""
    pdir = ROOT / "spec" / "profiles" / "bellbook-core-v1"
    table = load(pdir / "profile.json")
    doc = load(pdir / "cases.json")
    cases = doc["cases"]
    check(len(cases) > 0, "profile cases.json is empty")
    declared = bb.bytes32(doc["hash"])
    check(
        bp.profile_hash(table) == declared,
        "profile hash recomputed from profile.json differs from the declared hash",
    )
    assertions = 1
    statuses: dict[str, int] = {}
    failing_clauses: set[str] = set()
    for c in cases:
        rc = c["receipt"]
        records = rc["records"]
        with _quiet_native_stderr():
            report = bv.validate_receipt(records, rc["rules"])
        got = bp.evaluate(doc["profile"], rc["rules"], records, report, table)
        expect = c["expect"]
        check(
            got["status"] == expect["status"],
            f"profile case `{c['name']}`: status {got['status']} differs from {expect['status']}",
        )
        check(got["hash"] == declared, f"profile case `{c['name']}`: hash differs")
        got_flags = [(k["id"], k["passed"]) for k in got["clauses"]]
        exp_flags = [(k["id"], k["passed"]) for k in expect["clauses"]]
        check(
            got_flags == exp_flags,
            f"profile case `{c['name']}`: clause results differ:\n  got:    {got_flags}\n  expect: {exp_flags}",
        )
        assertions += 3
        statuses[got["status"]] = statuses.get(got["status"], 0) + 1
        failing_clauses.update(k["id"] for k in got["clauses"] if not k["passed"])
    # Coverage: both outcomes appear, and every failable clause has a
    # rejecting vector (B5 and B6 are reporting clauses and always hold).
    check("Conformant" in statuses and "NonConformant" in statuses, "profile corpus covers one outcome only")
    missing = {"B1", "B2", "B3", "B4"} - failing_clauses
    check(not missing, f"profile corpus has no rejecting vector for: {sorted(missing)}")
    notes = [
        "outcomes: " + ", ".join(f"{k}={statuses[k]}" for k in sorted(statuses)),
        "rejecting vectors cover clauses: " + ", ".join(sorted(failing_clauses)),
    ]
    return assertions, notes


def main() -> int:
    sections = []
    for spec_version, vectors, corpus in EPOCHS:
        tag = f"[spec {spec_version}]"
        sections += [
            (f"test vectors {tag}", functools.partial(run_test_vectors, vectors, spec_version)),
            (f"record cases (ids) {tag}", functools.partial(run_record_cases, corpus, spec_version)),
            (
                f"receipt cases (structure + hashes) {tag}",
                functools.partial(run_receipt_cases, corpus, spec_version),
            ),
            (
                f"malformed cases (rejection) {tag}",
                functools.partial(run_malformed_cases, corpus, spec_version),
            ),
            (
                f"query cases (RFC-0002 named set) {tag}",
                functools.partial(run_query_cases, corpus, spec_version),
            ),
        ]
    sections.append(("profile cases (bellbook-core-v1)", run_profile_cases))
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
    print("structural log integrity, and the full verdict rule battery")
    print("(per-record verdicts, retraction, and taint), the RFC-0002")
    print("named query set, and the bellbook-core-v1 profile, across the")
    print("vectors and the entire conformance corpus of every supported")
    print("epoch (" + ", ".join(v for v, _, _ in EPOCHS) + ").")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
