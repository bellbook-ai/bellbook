"""Independent implementation of profile evaluation (RFC-0003 section 4.5,
SPEC section 12.2): the `bellbook-core-v1` baseline.

From-scratch, like the rest of this validator: no shared code path with the
Rust reference. A profile is evaluated over the receipt's wire rules, its
records, and the validation report this package already produces, and
yields the same surface result the reference emits - id, hash, status, and
per-clause results - so the profile vectors hold both implementations to one
contract. Profile conformance is a report alongside the verdict; it never
changes the verdict.

The clause *statements* are not duplicated here: the profile hash commits to
the clause table published in `spec/profiles/bellbook-core-v1/profile.json`,
and this module recomputes that hash from the published table. The clause
*semantics* are implemented independently below.
"""

from __future__ import annotations

from typing import Any

import bellbook_conformance as bb
import bellbook_verdict as bv

CORE_V1 = "bellbook-core-v1"

# Evidence classes, strongest first; a threshold "no weaker than" a base
# class means its index is at most the base class's index.
EVIDENCE_ORDER = ["Deterministic", "Verified", "Reported", "Inferred", "Assumed"]

# Schema base classes the baseline pins (SPEC section 7).
BASE_CLASS = {"Candidate": "Reported", "Evaluation": "Reported", "Selection": "Inferred"}


def profile_hash(table: dict) -> bytes:
    """SHA-256 over the JCS form of a profile's clause table."""
    return bb.sha256(bb.canonical_bytes(table))


def _clause(cid: str, passed: bool, detail: str) -> dict:
    return {"id": cid, "passed": passed, "detail": detail}


def evaluate_core_v1(rules_wire: dict, records: list[dict], report: dict, table: dict) -> dict:
    """Evaluate `bellbook-core-v1` clauses B1-B6.

    `report` is the dict `bellbook_verdict.validate_receipt` returns (its
    `status` is "Clean" | "Tainted" | "Invalid"); `table` is the published
    clause table whose hash the result carries.
    """
    clauses: list[dict] = []
    status = report["status"]

    # B1: replay outcome.
    clauses.append(_clause("B1", status != "Invalid", f"status {status}"))

    # B2: roles registered. Replay rejects unregistered authors, so under B1
    # every accepted author is registered; the clause checks non-emptiness.
    roles = dict(rules_wire["author_roles"])
    clauses.append(_clause("B2", len(roles) > 0, f"{len(roles)} registered author role(s)"))

    # B3: thresholds present and no weaker than the base class.
    thresholds = dict(rules_wire["evidence_thresholds"])
    b3 = True
    parts = []
    for kind, base in BASE_CLASS.items():
        t = thresholds.get(kind)
        if t is None:
            b3 = False
            parts.append(f"{kind}=missing")
        elif EVIDENCE_ORDER.index(t) <= EVIDENCE_ORDER.index(base):
            parts.append(f"{kind}={t}")
        else:
            b3 = False
            parts.append(f"{kind}={t} (weaker than {base})")
    clauses.append(_clause("B3", b3, ", ".join(parts)))

    # B4: a declared, bounded context size.
    mcr = rules_wire["max_context_records"]
    clauses.append(_clause("B4", 1 <= mcr <= 100_000, f"max_context_records {mcr}"))

    # B5: authority readable; always holds, the value is the detail.
    admins = ", ".join(sorted(rules_wire["admin_retraction_actors"]))
    reaff = ", ".join(sorted(rules_wire.get("reaffirmation_actors", [])))
    clauses.append(
        _clause("B5", True, f"admin_retraction_actors [{admins}], reaffirmation_actors [{reaff}]")
    )

    # B6: binding modes of accepted Candidates; always holds.
    manifest = reported = 0
    if status != "Invalid":
        accepted = bv.build_state_unchecked(records).accepted
        for r in records:
            if r["kind"] != "Candidate" or bv.h(r["id"]) not in accepted:
                continue
            mode = bv.payload(r)["source"]["binding"]
            if mode == "manifest":
                manifest += 1
            elif mode == "reported":
                reported += 1
    clauses.append(
        _clause("B6", True, f"candidates: {manifest} manifest-bound, {reported} reported")
    )

    return {
        "id": CORE_V1,
        "hash": profile_hash(table),
        "status": "Conformant" if all(c["passed"] for c in clauses) else "NonConformant",
        "clauses": clauses,
        "declared": False,
        "declaration_matches": None,
    }


def evaluate(profile_id: str, rules_wire: dict, records: list[dict], report: dict, table: Any) -> dict:
    """Dispatch by profile id; unknown ids are reported, never errors. The
    result is an undeclared (required) evaluation; see `evaluate_declared`."""
    if profile_id == CORE_V1:
        return evaluate_core_v1(rules_wire, records, report, table)
    return {
        "id": profile_id,
        "hash": bytes(32),
        "status": "Unknown",
        "clauses": [],
        "declared": False,
        "declaration_matches": None,
    }


def evaluate_declared(
    decl: dict, rules_wire: dict, records: list[dict], report: dict, tables: dict[str, dict]
) -> dict:
    """Evaluate a profile the receipt declares (SPEC section 12). The
    declaration is a claim, not trusted: the profile is evaluated exactly as
    `evaluate` does, from this implementation's own clause table, and the
    result records whether the declared version and hash name that table.
    An unknown id has nothing to compare (`declaration_matches` is None)."""
    table = tables.get(decl["id"])
    got = evaluate(decl["id"], rules_wire, records, report, table)
    got["declared"] = True
    if table is not None:
        got["declaration_matches"] = (
            decl["version"] == table["version"] and bb.bytes32(decl["hash"]) == got["hash"]
        )
    return got


def evaluate_receipt(
    receipt: dict, records: list[dict], report: dict, required: list[str], tables: dict[str, dict]
) -> list[dict]:
    """Every profile result a validation reports: the receipt's declarations
    in declaration order, then each `required` id it did not declare, in
    request order. A required id the receipt declares is evaluated once, as
    declared."""
    rules_wire = receipt["rules"]
    out = [
        evaluate_declared(d, rules_wire, records, report, tables)
        for d in bb.decode_declarations(receipt)
    ]
    for pid in required:
        if any(p["id"] == pid for p in out):
            continue
        out.append(evaluate(pid, rules_wire, records, report, tables.get(pid)))
    return out


def met(result: dict) -> bool:
    """Whether a profile counts as met: Conformant, and if declared, a
    declaration that names the evaluated table."""
    return result["status"] == "Conformant" and result["declaration_matches"] is not False
