#!/usr/bin/env python3
"""Epoch check: the committed receipts of a frozen spec epoch validate
identically under that epoch's pinned, published validator (issues #34, #109).

Each published epoch is a compatibility promise. Beyond the byte-freeze gate
on its artifacts (`tests/frozen_v02.rs`, `tests/frozen_v03.rs`) and the
same-decision gate under the current tree (`tests/epoch_v03.rs`), this check
proves the property that matters to anyone holding an old receipt: the
*published* crate of that epoch - not the current tree - still reaches the
exact same decision on every committed receipt case. Run in CI against a
`cargo install`ed binary, so a future change that silently altered an
epoch's semantics could not pass by editing both the validator and its
expectations together.

Usage:
    python3 scripts/epoch_check.py <path-to-published-bellbook-binary> <spec-version>

    e.g. scripts/epoch_check.py $TMP/bb020/bin/bellbook 0.2   (published 0.2.0)
         scripts/epoch_check.py $TMP/bb070/bin/bellbook 0.3   (published 0.7.0)

Exit 0 iff every case matches; non-zero prints the first divergence.
"""

import json
import subprocess
import sys
from pathlib import Path

# Fields the published report exposes, mapped to the corpus's expected-key
# names. Comparing all of them (not just status) is what makes this an
# "identical decision" check rather than a coarse pass/fail.
FIELD_MAP = {
    "status": "status",
    "reason": "reason",
    "record_count": "record_count",
    "head_hash": "head_hash",
    "rules_hash": "rules_hash",
    "retracted_records": "retracted",
    "tainted_records": "tainted",
    "standing": "standing",
}

REPO = Path(__file__).resolve().parent.parent


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    binary, version = sys.argv[1], sys.argv[2]
    cases_path = REPO / "spec" / "conformance" / f"v{version}" / "receipt-cases.json"

    corpus = json.loads(cases_path.read_text())
    if corpus.get("spec_version") != version:
        print(f"error: {cases_path} is not a v{version} corpus")
        return 2

    cases = corpus["cases"]
    tmp = REPO / "target" / f"epoch-receipt-v{version}.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)

    checked = 0
    for case in cases:
        name = case["name"]
        expect = case["expect"]
        tmp.write_text(json.dumps(case["receipt"]))

        proc = subprocess.run(
            [binary, "validate", str(tmp), "--json"],
            capture_output=True,
            text=True,
        )
        # A validate exit code of 0/1/2 is expected (clean/invalid/tainted);
        # anything else means the binary failed to run, not a verdict.
        if proc.returncode not in (0, 1, 2) or not proc.stdout.strip():
            print(f"FAIL {name}: validator did not produce a report "
                  f"(exit {proc.returncode})\n{proc.stderr}")
            return 1
        got = json.loads(proc.stdout)

        for got_key, exp_key in FIELD_MAP.items():
            if exp_key not in expect or got_key not in got:
                # A field the corpus did not record, or the published binary
                # does not report (older epochs predate `standing`), is not
                # part of that epoch's promise.
                continue
            if got.get(got_key) != expect[exp_key]:
                print(
                    f"FAIL {name}: field {exp_key!r} diverged\n"
                    f"  published v{version} validator: {got.get(got_key)!r}\n"
                    f"  committed expectation:        {expect[exp_key]!r}"
                )
                return 1
        checked += 1
        print(f"ok   {name}  ({expect['status']})")

    print(
        f"\nAll {checked} committed v{version} receipts validate identically under "
        f"the published v{version} validator ({binary})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
