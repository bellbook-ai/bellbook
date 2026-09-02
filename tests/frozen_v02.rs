//! Interim freeze gate for the published spec v0.2 artifacts.
//!
//! Spec v0.2 is a published compatibility epoch: its vectors and conformance
//! corpus must never change (SPEC.md §14, CHANGELOG "frozen in place"). This
//! test pins the SHA-256 of each frozen file so an accidental edit fails CI
//! rather than passing silently (the live suites now exercise only the v0.3
//! artifacts). The complementary cross-version check - that the *published*
//! 0.2.0 validator still reaches the same decision on every committed v0.2
//! receipt - runs in CI as the `epoch-v02` job
//! (`scripts/epoch_check.py`); together they pin both the bytes and their
//! meaning under the published validator.
//!
//! The hash is taken over LF-normalized content: `.gitattributes` already
//! forces these files to LF on every platform, and normalizing here as well
//! makes the gate independent of any checkout's line-ending config (a raw
//! byte hash diverged on Windows CRLF checkouts). A line-ending change is
//! not a content edit, which is what this gate exists to catch.
//!
//! If a v0.2 hash below must change, that is a backward-compatibility break
//! and needs an explicit, documented decision - not a hash bump.

use std::path::Path;

fn content_hash(path: &str) -> String {
    use bellbook::sha256;
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("frozen v0.2 artifact {path} missing: {e}"));
    // Strip CR so CRLF and LF checkouts hash identically.
    let normalized: Vec<u8> = bytes.into_iter().filter(|&b| b != b'\r').collect();
    bellbook::hex_encode(&sha256(&normalized))
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
            content_hash(path),
            expected,
            "frozen v0.2 artifact {path} changed; v0.2 is a published epoch and \
             must not be edited (SPEC.md §14). If this is a deliberate, \
             documented backward-compatibility decision, update the pin."
        );
    }
}
