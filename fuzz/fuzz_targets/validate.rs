#![no_main]

//! The security boundary: `validate` takes arbitrary, possibly hostile bytes
//! and must reach a Clean / Tainted / Invalid decision without panicking,
//! aborting, or contradicting itself. libFuzzer explores the byte space with
//! coverage guidance, reaching parser and replay paths a fixed corpus misses.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let report = bellbook::validate(data);
    // A cheap always-true invariant, so a self-contradictory report is a
    // finding rather than a silent non-crash.
    assert!(report.checked_records <= report.record_count);
});
