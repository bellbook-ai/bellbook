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


# ---------------------------------------------------------------------------
# delivery-receipt-v1 (RFC-0003 section 4.6)
# ---------------------------------------------------------------------------

DELIVERY_V1 = "delivery-receipt-v1"
DELIVERY_CLAUSES = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"]


def _short(hex_id: str) -> str:
    return hex_id[:12]


def _v2(r: dict) -> dict | None:
    """The payload of an extended evaluation, or None for the v1 shape (which
    carries no evaluator, evidence, or requirements)."""
    data = bv.payload(r)
    return data if "evaluator" in data else None


def evaluate_delivery_v1(
    rules_wire: dict,
    records: list[dict],
    report: dict,
    table: dict,
    declarations: list[dict],
    tables: dict[str, dict],
) -> dict:
    """Evaluate `delivery-receipt-v1` clauses D0-D7 over the receipt.

    A delivery claim is an accepted Selected selection whose Used
    evaluations bind to requirements of exactly one Request (RFC-0003
    section 4.4). Per request the latest sound claim is evaluated and the
    earlier ones reported superseded. Every clause is fail-closed.
    """
    status = report["status"]

    def result(clauses: list[dict]) -> dict:
        return {
            "id": DELIVERY_V1,
            "hash": profile_hash(table),
            "status": "Conformant" if all(c["passed"] for c in clauses) else "NonConformant",
            "clauses": clauses,
            "declared": False,
            "declaration_matches": None,
        }

    if status == "Invalid":
        return result([_clause(cid, False, "receipt is Invalid") for cid in DELIVERY_CLAUSES])

    accepted = bv.build_state_unchecked(records).accepted
    retracted = set(report["retracted"])
    tainted = set(report["tainted"])
    unsound = set(report["standing"]["unsound"])
    by_id = {bv.h(r["id"]): r for r in records}

    def is_accepted(hid: str) -> bool:
        return hid in accepted and hid in by_id

    def requirement_request(hid: str) -> str | None:
        r = by_id.get(hid)
        if r is None or r["kind"] != "Requirement" or not is_accepted(hid):
            return None
        causes = bv.refs_of(r, "Cause")
        return bv.h(causes[0]["target"]) if causes else None

    # D0: find the claims, group by request, keep the latest sound one.
    candidates = []
    for r in records:
        hid = bv.h(r["id"])
        if r["kind"] != "Selection" or not is_accepted(hid):
            continue
        data = bv.payload(r)
        outcome = data["outcome"]
        if not (isinstance(outcome, dict) and "selected" in outcome):
            continue
        chosen = [bv.h(c) for c in outcome["selected"]["candidates"]]
        used = []
        for ref in bv.refs_of(r, "Use"):
            t = by_id.get(bv.h(ref["target"]))
            if t is not None and t["kind"] == "Evaluation" and is_accepted(bv.h(t["id"])):
                used.append(t)
        requests = set()
        for e in used:
            v2 = _v2(e)
            if v2 is None:
                continue
            for rid in v2["requirements"]:
                req = requirement_request(bv.h(rid))
                if req is not None:
                    requests.add(req)
        if len(requests) != 1:
            continue
        candidates.append(
            {"selection": r, "id": hid, "request": requests.pop(), "chosen": chosen, "used": used}
        )

    def sound(hid: str) -> bool:
        return hid not in unsound and hid not in retracted and hid not in tainted

    by_request: dict[str, list[dict]] = {}
    for c in candidates:
        by_request.setdefault(c["request"], []).append(c)
    claims = []
    superseded = []
    for _req in sorted(by_request):
        group = sorted(by_request[_req], key=lambda c: c["selection"]["time"])
        pick = len(group) - 1
        for i in range(len(group) - 1, -1, -1):
            if sound(group[i]["id"]):
                pick = i
                break
        for i, c in enumerate(group):
            (claims if i == pick else superseded).append(c)
    claims.sort(key=lambda c: c["selection"]["time"])

    clauses: list[dict] = []
    if not claims:
        clauses.append(
            _clause(
                "D0",
                False,
                "no delivery claim: no accepted Selected selection whose used evaluations "
                "bind to requirements of exactly one request",
            )
        )
        clauses.extend(_clause(cid, False, "no claim to evaluate") for cid in DELIVERY_CLAUSES[1:])
        return result(clauses)
    d0 = "; ".join(f"claim {_short(c['id'])} for request {_short(c['request'])}" for c in claims)
    if superseded:
        d0 += "; superseded: " + ", ".join(_short(c["id"]) for c in superseded)
    clauses.append(_clause("D0", True, d0))

    agg = {cid: [True, []] for cid in ("D1", "D2", "D3", "D4", "D5", "D7")}

    def note(cid: str, ok: bool, text: str) -> None:
        if not ok:
            agg[cid][0] = False
        agg[cid][1].append(text)

    for claim in claims:
        tag = _short(claim["id"])
        used_v2 = [(e, _v2(e)) for e in claim["used"]]
        used_v2 = [(e, d) for e, d in used_v2 if d is not None]

        # Required requirements under the request, at the head.
        required = []
        for r in records:
            hid = bv.h(r["id"])
            if (
                r["kind"] != "Requirement"
                or not is_accepted(hid)
                or hid in retracted
                or requirement_request(hid) != claim["request"]
            ):
                continue
            data = bv.payload(r)
            if data["required"]:
                required.append((hid, data["key"]))
        required_ids = {hid for hid, _ in required}

        # D1: coverage by a passed, unretracted evaluation.
        uncovered = [
            key
            for hid, key in required
            if not any(
                bv.h(e["id"]) not in retracted
                and d["outcome"] == "passed"
                and hid in {bv.h(x) for x in d["requirements"]}
                for e, d in used_v2
            )
        ]
        if uncovered:
            note("D1", False, f"{tag}: uncovered {', '.join(uncovered)}")
        else:
            note("D1", True, f"{tag}: {len(required)} required requirement(s) covered")

        # D2: no non-passing evaluation over a required requirement.
        non_passing = []
        for e, d in used_v2:
            binds_required = any(bv.h(x) in required_ids for x in d["requirements"])
            if binds_required and d["outcome"] != "passed":
                label = d["outcome"] if isinstance(d["outcome"], str) else "scored"
                non_passing.append(f"{_short(bv.h(e['id']))} {label}")
        if non_passing:
            note("D2", False, f"{tag}: non-passing {', '.join(non_passing)}")
        else:
            note("D2", True, f"{tag}: every required-bound evaluation passed")

        # D3: one candidate, judged by every evaluation, evidence on record.
        notes = []
        chosen = claim["chosen"][0] if len(claim["chosen"]) == 1 else None
        if chosen is None:
            notes.append(f"chooses {len(claim['chosen'])} candidates")
        candidate_rec = by_id.get(chosen) if chosen else None
        on_record: set[tuple[str, str]] = set()
        if candidate_rec is not None:
            for a in bv.payload(candidate_rec).get("artifacts") or []:
                on_record.add((a["scheme"], a["digest"]))
            for r in records:
                if (
                    r["kind"] == "Result"
                    and is_accepted(bv.h(r["id"]))
                    and r["thread"] == claim["selection"]["thread"]
                ):
                    for a in bv.payload(r).get("artifacts") or []:
                        on_record.add((a["scheme"], a["digest"]))
        if len(used_v2) != len(claim["used"]):
            notes.append(
                f"{len(claim['used']) - len(used_v2)} evaluation(s) without an evidence set (v1 shape)"
            )
        for e, d in used_v2:
            eid = _short(bv.h(e["id"]))
            if bv.h(d["candidate"]) != chosen:
                notes.append(f"{eid} judges another candidate")
            if not d["evidence"]:
                notes.append(f"{eid} has no evidence")
            for a in d["evidence"]:
                if (a["scheme"], a["digest"]) not in on_record:
                    notes.append(f"{eid} cites {a['scheme']}:{a['digest']} which is not on the record")
        if notes:
            note("D3", False, f"{tag}: " + "; ".join(notes))
        else:
            note(
                "D3",
                True,
                f"{tag}: {len(used_v2)} evaluation(s) bound to the chosen candidate, evidence on the record",
            )

        # D4: producer and evaluator distinct.
        producer = candidate_rec["author"]["id"] if candidate_rec is not None else None
        self_judged = [
            _short(bv.h(e["id"])) for e in claim["used"] if e["author"]["id"] == producer
        ]
        if producer is None:
            note("D4", False, f"{tag}: no single claimed candidate")
        elif self_judged:
            note("D4", False, f"{tag}: producer {producer!r} authored evaluation(s) {', '.join(self_judged)}")
        else:
            note("D4", True, f"{tag}: producer {producer!r}, every evaluator distinct")

        # D5: decider binding present; weakest basis reported.
        unbound = []
        if len(used_v2) != len(claim["used"]):
            unbound.append(
                f"{len(claim['used']) - len(used_v2)} evaluation(s) carry no decider binding (v1 shape)"
            )
        any_declared = False
        for e, d in used_v2:
            ev = d["evaluator"]
            if ev.get("procedure_hash") is None or ev.get("input_hash") is None:
                unbound.append(f"{_short(bv.h(e['id']))} lacks procedure_hash or input_hash")
            any_declared = any_declared or d["basis"] == "declared"
        basis_label = "none" if not used_v2 else ("declared" if any_declared else "recomputed")
        if not unbound and used_v2:
            note("D5", True, f"{tag}: weakest basis {basis_label}")
        else:
            if not unbound:
                unbound.append("no evaluation used")
            note("D5", False, f"{tag}: {'; '.join(unbound)}; weakest basis {basis_label}")

        # D7: standing at the head.
        why = [
            w
            for w, bad in (
                ("unsound", claim["id"] in unsound),
                ("tainted", claim["id"] in tainted),
                ("retracted", claim["id"] in retracted),
            )
            if bad
        ]
        if why:
            note("D7", False, f"{tag}: {', '.join(why)}")
        else:
            note("D7", True, f"{tag}: sound, untainted")

    # D6: the capability profile, declared or evaluated as the fallback.
    core_decl = next((d for d in declarations if d["id"] == CORE_V1), None)
    if core_decl is not None:
        core = evaluate_declared(core_decl, rules_wire, records, report, tables)
    else:
        core = evaluate(CORE_V1, rules_wire, records, report, tables.get(CORE_V1))
    if core["declared"] and core["declaration_matches"] is True:
        suffix = " (declared, declaration matches)"
    elif core["declared"] and core["declaration_matches"] is False:
        suffix = " (declared, DECLARATION MISMATCH)"
    elif core["declared"]:
        suffix = " (declared)"
    else:
        suffix = " (not declared; evaluated as the fallback)"
    d6 = _clause("D6", met(core), f"{CORE_V1}: {core['status']}{suffix}")

    for cid in ("D1", "D2", "D3", "D4", "D5"):
        clauses.append(_clause(cid, agg[cid][0], "; ".join(agg[cid][1])))
    clauses.append(d6)
    clauses.append(_clause("D7", agg["D7"][0], "; ".join(agg["D7"][1])))
    return result(clauses)


def evaluate(
    profile_id: str,
    rules_wire: dict,
    records: list[dict],
    report: dict,
    table: Any,
    declarations: list[dict] | None = None,
    tables: dict[str, dict] | None = None,
) -> dict:
    """Dispatch by profile id; unknown ids are reported, never errors. The
    result is an undeclared (required) evaluation; see `evaluate_declared`.
    `declarations` and `tables` let a profile consult the receipt's other
    declarations (delivery-receipt-v1 D6 needs the baseline)."""
    if profile_id == CORE_V1:
        return evaluate_core_v1(rules_wire, records, report, table)
    if profile_id == DELIVERY_V1:
        return evaluate_delivery_v1(
            rules_wire, records, report, table, declarations or [], tables or {}
        )
    return {
        "id": profile_id,
        "hash": bytes(32),
        "status": "Unknown",
        "clauses": [],
        "declared": False,
        "declaration_matches": None,
    }


def evaluate_declared(
    decl: dict,
    rules_wire: dict,
    records: list[dict],
    report: dict,
    tables: dict[str, dict],
    declarations: list[dict] | None = None,
) -> dict:
    """Evaluate a profile the receipt declares (SPEC section 12). The
    declaration is a claim, not trusted: the profile is evaluated exactly as
    `evaluate` does, from this implementation's own clause table, and the
    result records whether the declared version and hash name that table.
    An unknown id has nothing to compare (`declaration_matches` is None)."""
    table = tables.get(decl["id"])
    got = evaluate(decl["id"], rules_wire, records, report, table, declarations, tables)
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
    declarations = bb.decode_declarations(receipt)
    out = [
        evaluate_declared(d, rules_wire, records, report, tables, declarations)
        for d in declarations
    ]
    for pid in required:
        if any(p["id"] == pid for p in out):
            continue
        out.append(
            evaluate(pid, rules_wire, records, report, tables.get(pid), declarations, tables)
        )
    return out


def met(result: dict) -> bool:
    """Whether a profile counts as met: Conformant, and if declared, a
    declaration that names the evaluated table."""
    return result["status"] == "Conformant" and result["declaration_matches"] is not False
