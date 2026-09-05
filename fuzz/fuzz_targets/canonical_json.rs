#![no_main]

//! RFC 8785 canonicalization underlies every record id, so over any parseable
//! JSON value it must never panic, and where it produces output that output
//! must be a fixed point: canonicalizing the canonical form reproduces it
//! byte-for-byte. Refusal is part of the contract, not a crash: integers
//! outside the I-JSON safe range (|n| > 2^53 - 1) are rejected with an error
//! rather than silently rounded, so an `Err` is an acceptable outcome and the
//! refusal must itself be stable across a re-parse of the same bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        match bellbook::canonical_json(&value) {
            Ok(once) => {
                let reparsed: serde_json::Value =
                    serde_json::from_slice(&once).expect("canonical output is valid JSON");
                let twice = bellbook::canonical_json(&reparsed)
                    .expect("re-canonicalizing a canonical form");
                assert_eq!(once, twice, "canonical form is not idempotent");
            }
            Err(_) => {
                let again: serde_json::Value =
                    serde_json::from_slice(data).expect("the same bytes parsed once already");
                assert!(
                    bellbook::canonical_json(&again).is_err(),
                    "a refusal must be deterministic"
                );
            }
        }
    }
});
