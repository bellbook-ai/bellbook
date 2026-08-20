#![no_main]

//! Parsing a receipt must be total (never panic), and any receipt that parses
//! must survive a canonical round-trip unchanged: serialize to canonical bytes,
//! parse again, and get an equal receipt. A mismatch would mean the canonical
//! form is not a fixed point, which the ids depend on.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = bellbook::Receipt::from_bytes(data) {
        let bytes = receipt.to_bytes().expect("re-serializing a parsed receipt");
        let again = bellbook::Receipt::from_bytes(&bytes).expect("re-parsing canonical bytes");
        assert_eq!(receipt, again, "receipt not stable across a canonical round-trip");
    }
});
