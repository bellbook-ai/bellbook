//! Interim freeze gate for the published spec v0.2 artifacts.
//!
//! Spec v0.2 is a published compatibility epoch: its vectors and conformance
//! corpus must never change (SPEC.md §14, CHANGELOG "frozen in place"). Once
//! the epoch CI job lands (issue #34) the pinned, published v0.2 validator
//! re-validates the frozen receipts directly; until then this test pins the
//! byte-exact SHA-256 of each frozen file so an accidental edit fails CI
//! rather than passing silently (the live suites now exercise only the v0.3
//! artifacts).
//!
//! If a v0.2 hash below must change, that is a backward-compatibility break
//! and needs an explicit, documented decision - not a hash bump.

use std::path::Path;

fn sha256_hex(path: &str) -> String {
    use bellbook::sha256;
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("frozen v0.2 artifact {path} missing: {e}"));
    bellbook::hex_encode(&sha256(&bytes))
}

#[test]
fn v02_artifacts_are_byte_frozen() {
    // (path, expected SHA-256 of the committed bytes).
    let frozen = [
        (
            "spec/test-vectors-v0.2.json",
            "a9c488fe345920c0bc0d919ceaca6461068e7cf78073b82cb191e6c95e78983f",
        ),
        (
            "spec/conformance/v0.2/record-cases.json",
            "9c4edb1a9c1324d3246f970f9ab3a65eaba97e95fce5b8ce482487417595e961",
        ),
        (
            "spec/conformance/v0.2/receipt-cases.json",
            "4179cf7c2c226f1fff72bd158736a828b2678f981d7fc369a03ac723b87fa2d6",
        ),
        (
            "spec/conformance/v0.2/malformed-cases.json",
            "5ace584ba4c5ef9cdc6c11af87c7bfdd00cddb31742e0174d2ae817d65833f5a",
        ),
    ];
    for (path, expected) in frozen {
        assert_eq!(
            sha256_hex(path),
            expected,
            "frozen v0.2 artifact {path} changed; v0.2 is a published epoch and \
             must not be edited (SPEC.md §14). If this is a deliberate, \
             documented backward-compatibility decision, update the pin."
        );
    }
}
