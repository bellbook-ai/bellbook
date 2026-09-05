#!/usr/bin/env python3
"""Validate one receipt with the independent implementation.

    python3 conformance/python/validate_receipt.py RECEIPT [--require-profile ID ...] [--json]

The skeptic's entry point: structural decode, whole-log replay, every
profile the receipt declares (never trusted), then each required profile it
did not declare. Prints the same facts `bellbook validate` prints and exits
the same way: 0 Clean and every profile met, 1 Invalid, 2 Tainted, 3 valid
but a declared or required profile not met. Standard library only; the
`bellbook` package is never imported, so agreement with the reference is a
fact of the run, not a shared code path.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bellbook_conformance as bc  # noqa: E402
import bellbook_profiles as bp  # noqa: E402
import bellbook_verdict as bv  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILES = ROOT / "spec" / "profiles"


def _hex(b) -> str:
    return bytes(b).hex() if not isinstance(b, str) else b


def _usage(code: int) -> int:
    print(__doc__.strip(), file=sys.stderr)
    return code


def main(argv: list[str]) -> int:
    path = None
    required: list[str] = []
    as_json = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--json":
            as_json = True
        elif a == "--require-profile":
            i += 1
            while i < len(argv) and not argv[i].startswith("--"):
                required.append(argv[i])
                i += 1
            continue
        elif a.startswith("--"):
            return _usage(64)
        elif path is None:
            path = a
        else:
            return _usage(64)
        i += 1
    if path is None:
        return _usage(64)
    if "bellbook" in sys.modules:
        print("refusing to run: the bellbook package is imported", file=sys.stderr)
        return 70

    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        return 66

    status, problem = bc.validate(text)
    out: dict = {"status": "Invalid", "reason": None, "problem": None, "profiles": []}
    if status != "StructurallyValid":
        out["problem"] = problem
    else:
        rc = json.loads(text)
        report = bv.validate_receipt(rc["records"], rc["rules"], rc["spec_version"])
        tables = {
            p.name: json.loads((p / "profile.json").read_text()) for p in PROFILES.iterdir() if p.is_dir()
        }
        profiles = bp.evaluate_receipt(rc, rc["records"], report, required, tables)
        out.update(
            status=report["status"],
            reason=report["reason"],
            records=len(rc["records"]),
            retracted=[_hex(x) for x in report["retracted"]],
            tainted=[_hex(x) for x in report["tainted"]],
            profiles=[
                {
                    "id": g["id"],
                    "hash": _hex(g["hash"]),
                    "status": g["status"],
                    "declared": g["declared"],
                    "declaration_matches": g["declaration_matches"],
                    "met": bp.met(g),
                    "clauses": g["clauses"],
                }
                for g in profiles
            ],
        )

    if as_json:
        print(json.dumps(out, indent=2))
    else:
        print(f"status:          {out['status'].upper()}")
        if out["problem"] is not None:
            print(f"problem:         {out['problem']}")
        if out["reason"] is not None:
            print(f"reject reason:   {out['reason']}")
        if "records" in out:
            print(f"records:         {out['records']}")
        for p in out["profiles"]:
            origin = "required"
            if p["declared"]:
                origin = "declared, declaration " + (
                    "matches" if p["declaration_matches"] else "MISMATCH"
                    if p["declaration_matches"] is False else "unverifiable"
                )
            print(f"profile {p['id']}: {p['status'].upper()} ({origin})")
            print(f"  hash:          {p['hash']}")
            for c in p["clauses"]:
                print(f"  {'ok  ' if c['passed'] else 'FAIL'} {c['id']}: {c['detail']}")

    if out["status"] == "Invalid":
        return 1
    if any(not p["met"] for p in out["profiles"]):
        return 3
    return 0 if out["status"] == "Clean" else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
