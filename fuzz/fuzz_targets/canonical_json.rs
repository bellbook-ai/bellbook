#![no_main]

//! RFC 8785 canonicalization underlies every record id, so it must be total
//! and idempotent over any parseable JSON value: canonicalizing the canonical
//! form must reproduce it byte-for-byte.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let once = bellbook::canonical_json(&value).expect("canonicalizing a parsed value");
        let reparsed: serde_json::Value =
            serde_json::from_slice(&once).expect("canonical output is valid JSON");
        let twice = bellbook::canonical_json(&reparsed).expect("re-canonicalizing");
        assert_eq!(once, twice, "canonical form is not idempotent");
    }
});
