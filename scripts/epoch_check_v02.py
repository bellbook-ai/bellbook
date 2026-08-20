#!/usr/bin/env python3
"""Epoch check: the committed v0.2 receipts validate identically under the
pinned, published v0.2 validator (issue #34).

v0.2 is a published compatibility epoch. Beyond the byte-freeze gate on the
v0.2 artifacts (`tests/frozen_v02.rs`), this check proves the stronger
property that matters to anyone holding a v0.2 receipt: the *published* 0.2.0
crate - not the current tree - still reaches the exact same decision on every
committed v0.2 receipt case. Run in CI against a `cargo install`ed 0.2.0
binary, so a future change that silently altered v0.2 semantics could not
pass by editing both the validator and its expectations together.

Usage:
    python3 scripts/epoch_check_v02.py <path-to-published-bellbook-binary>

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
}

REPO = Path(__file__).resolve().parent.parent
CASES = REPO / "spec" / "conformance" / "v0.2" / "receipt-cases.json"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    binary = sys.argv[1]

    corpus = json.loads(CASES.read_text())
    if corpus.get("spec_version") != "0.2":
        print(f"error: {CASES} is not a v0.2 corpus")
        return 2

    cases = corpus["cases"]
    tmp = REPO / "target" / "epoch-receipt.json"
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
            if exp_key not in expect:
                continue
            if got.get(got_key) != expect[exp_key]:
                print(
                    f"FAIL {name}: field {exp_key!r} diverged\n"
                    f"  published 0.2.0 validator: {got.get(got_key)!r}\n"
                    f"  committed expectation:     {expect[exp_key]!r}"
                )
                return 1
        checked += 1
        print(f"ok   {name}  ({expect['status']})")

    print(
        f"\nAll {checked} committed v0.2 receipts validate identically under "
        f"the published v0.2 validator ({binary})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
