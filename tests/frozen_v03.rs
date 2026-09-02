//! Freeze gate for the published spec v0.3 artifacts.
//!
//! Spec v0.3 is a published compatibility epoch (crates 0.3.0 through
//! 0.7.0): its test vectors and conformance corpus must never change
//! (SPEC.md §14). This test pins the SHA-256 of each frozen file so an
//! accidental edit fails CI rather than passing silently; the live generator
//! suites now produce and check only the v0.4 artifacts. Two complementary
//! checks pin the *meaning* of these bytes: `tests/epoch_v03.rs` re-derives
//! every stored 0.3 outcome under the current validator (a 0.3 receipt
//! validates identically under a 0.4 validator), and the `epoch-v03` CI job
//! replays the 0.3 receipts through the published 0.7.0 binary
//! (`scripts/epoch_check.py`).
//!
//! The hash is taken over LF-normalized content, as `tests/frozen_v02.rs`
//! does: a line-ending change is not a content edit.
//!
//! If a v0.3 hash below must change, that is a backward-compatibility break
//! and needs an explicit, documented decision - not a hash bump.

use std::path::Path;

fn content_hash(path: &str) -> String {
    use bellbook::sha256;
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|e| panic!("frozen v0.3 artifact {path} missing: {e}"));
    let normalized: Vec<u8> = bytes.into_iter().filter(|&b| b != b'\r').collect();
    bellbook::hex_encode(&sha256(&normalized))
}

#[test]
fn v03_artifacts_are_byte_frozen() {
    // (path, expected SHA-256 of the committed bytes at the close of the
    // 0.3 epoch, crate 0.7.0).
    let frozen = [
        (
            "spec/test-vectors-v0.3.json",
            "5d9c401bf41587867f793859d6adadf0ec7978e4717667b1b8b0ccf03e03fdc8",
        ),
        (
            "spec/conformance/v0.3/record-cases.json",
            "ae5be203dbaf008ef75fa57c0cb73c990159aa7f6a8be936dc5b6000e66a7c66",
        ),
        (
            "spec/conformance/v0.3/receipt-cases.json",
            "76cfd062fbbe05664acbe90ea0ddc38f7ceb8a5005f18f3dce24f8ececa27328",
        ),
        (
            "spec/conformance/v0.3/malformed-cases.json",
            "48ef6e2941a5347acb7ed37b406ccf50e451a48173080cb4cb6a3560374ba629",
        ),
        (
            "spec/conformance/v0.3/query-cases.json",
            "8233f9a14b0749491c890a5da3181b1125391547e625885400e9d62b318fcaf9",
        ),
    ];
    for (path, expected) in frozen {
        assert_eq!(
            content_hash(path),
            expected,
            "frozen v0.3 artifact {path} changed; v0.3 is a published epoch and \
             must not be edited (SPEC.md §14). If this is a deliberate, \
             documented backward-compatibility decision, update the pin."
        );
    }
}
