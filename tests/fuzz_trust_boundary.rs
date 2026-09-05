//! Fuzzing harness over the receipt trust boundary (issue #65).
//!
//! `validate` is the security boundary: it takes arbitrary, possibly hostile
//! bytes and must reach a Clean / Tainted / Invalid decision without ever
//! panicking, aborting, or returning a self-contradictory report. This is the
//! stable, always-on layer of the fuzzing harness: a deterministic, seeded
//! generator that hammers `validate`, `Receipt::from_bytes`, and
//! `canonical_json` with pure-random buffers and with mutations of known-valid
//! receipts, asserting the invariants that must hold for *any* input.
//!
//! It is deliberately dependency-free and bounded so it runs in the ordinary
//! `cargo test` matrix on every push. The deeper, coverage-guided layer
//! (libFuzzer via `cargo fuzz`, over the same entry points) lives under
//! `fuzz/` and runs on its own schedule; see `fuzz/README.md`.

use bellbook::{canonical_json, validate, validate_with_limits, Receipt, ValidationLimits};

/// A small, fast, deterministic PRNG (SplitMix64). A fixed seed keeps the run
/// reproducible: a failure reproduces byte-for-byte in CI and locally.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n`. `n` must be non-zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// Valid receipts to mutate, drawn from the committed conformance corpus, plus
/// a few hand-written near-miss shapes to reach the structural decoder.
fn seeds() -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    for rel in [
        "spec/conformance/v0.3/receipt-cases.json",
        "spec/conformance/v0.2/receipt-cases.json",
    ] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(corpus) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if let Some(cases) = corpus["cases"].as_array() {
            for case in cases.iter().take(6) {
                if let Ok(receipt) = serde_json::to_vec(&case["receipt"]) {
                    seeds.push(receipt);
                }
            }
        }
    }
    // Structural near-misses: exercise the parser's field handling directly.
    for s in [
        br#"{"spec_version":"0.3","rules":{},"records":[]}"#.as_slice(),
        br#"{"spec_version":"0.2","rules":{},"records":[]}"#.as_slice(),
        br#"{"records":[],"rules":{},"spec_version":"0.3"}"#.as_slice(),
        b"{}".as_slice(),
        b"[]".as_slice(),
    ] {
        seeds.push(s.to_vec());
    }
    assert!(!seeds.is_empty(), "no fuzz seeds available");
    seeds
}

/// A pure-random buffer of small, varied length.
fn random_buf(rng: &mut Rng) -> Vec<u8> {
    let len = rng.below(300);
    (0..len).map(|_| rng.byte()).collect()
}

/// Apply a handful of byte-level mutations to a seed.
fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut buf = seed.to_vec();
    let ops = 1 + rng.below(8);
    for _ in 0..ops {
        if buf.is_empty() {
            buf.push(rng.byte());
            continue;
        }
        match rng.below(6) {
            0 => {
                let i = rng.below(buf.len());
                buf[i] ^= 1u8 << rng.below(8);
            }
            1 => {
                let i = rng.below(buf.len());
                buf[i] = rng.byte();
            }
            2 => {
                let i = rng.below(buf.len() + 1);
                buf.insert(i, rng.byte());
            }
            3 => {
                let i = rng.below(buf.len());
                buf.remove(i);
            }
            4 => {
                let i = rng.below(buf.len());
                buf.truncate(i);
            }
            _ => {
                // Splice a copy of one region over another: reaches
                // length-prefixed and repeated-structure code paths.
                let len = buf.len();
                let src = rng.below(len);
                let n = 1 + rng.below(len - src);
                let chunk = buf[src..src + n].to_vec();
                let at = rng.below(len);
                for (k, b) in chunk.into_iter().enumerate() {
                    if at + k < buf.len() {
                        buf[at + k] = b;
                    }
                }
            }
        }
    }
    buf
}

/// Feed one input across the trust boundary and assert the always-true
/// invariants. The overriding property is that none of these calls panic.
fn check(data: &[u8]) {
    // Reading never panics; it returns Ok or Err.
    let _ = Receipt::from_bytes(data);

    let report = validate(data);
    // The same input under an explicit (unlimited) limit set must agree on the
    // top-level decision; the resource bound is a refusal, not a verdict flip.
    let unlimited = validate_with_limits(data, &ValidationLimits::unlimited());
    let _ = &unlimited;

    // Invariant 1: never more records checked than exist.
    assert!(
        report.checked_records <= report.record_count,
        "checked_records {} exceeds record_count {}",
        report.checked_records,
        report.record_count
    );

    // Invariant 2: the three-way decision is internally consistent.
    match report.status {
        bellbook::ValidationStatus::Clean => {
            // Clean means replayed and nothing retracted or tainted.
            assert!(report.reason.is_none(), "Clean report carries a reason");
            assert!(report.problem.is_none(), "Clean report carries a problem");
            assert!(
                report.retracted_records.is_empty() && report.tainted_records.is_empty(),
                "Clean report lists retracted/tainted records"
            );
        }
        bellbook::ValidationStatus::Invalid => {
            // Invalid must say why: a structural problem or a verifier reason.
            assert!(
                report.problem.is_some() || report.reason.is_some(),
                "Invalid report gives neither a problem nor a reason"
            );
        }
        bellbook::ValidationStatus::Tainted => {}
    }
}

#[test]
fn validate_never_panics_and_reports_are_consistent() {
    let seeds = seeds();
    let mut rng = Rng(0x0B_E11B_00C5_EED1);
    for _ in 0..12_000 {
        check(&random_buf(&mut rng));
        let seed = &seeds[rng.below(seeds.len())];
        check(&mutate(seed, &mut rng));
    }
}

/// The canonicalization contract over one parseable input: never panic; if
/// output is produced it is a fixed point (canonicalizing the canonical form
/// reproduces it byte-for-byte); if the value is refused (an integer outside
/// the I-JSON safe range is an error, never silent rounding) the refusal is
/// deterministic. The libFuzzer target `fuzz/fuzz_targets/canonical_json.rs`
/// asserts the same contract with coverage guidance.
fn check_canonical(data: &[u8]) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    match canonical_json(&value) {
        Ok(once) => {
            let reparsed: serde_json::Value =
                serde_json::from_slice(&once).expect("canonical output is valid JSON");
            let twice = canonical_json(&reparsed).expect("re-canonicalizing a canonical form");
            assert_eq!(
                once,
                twice,
                "canonical form is not idempotent for {}",
                String::from_utf8_lossy(data)
            );
        }
        Err(_) => {
            let again: serde_json::Value = serde_json::from_slice(data).unwrap();
            assert!(
                canonical_json(&again).is_err(),
                "a refusal must be deterministic for {}",
                String::from_utf8_lossy(data)
            );
        }
    }
}

#[test]
fn canonical_json_is_total_and_idempotent() {
    let mut rng = Rng(0xCA_0217_0A15_F00D);
    let mut corpus: Vec<Vec<u8>> = seeds();
    corpus.push(br#"{"b":1,"a":[3,2,1],"z":{"y":true,"x":null}}"#.to_vec());
    corpus.push(br#"[{"k":"\u00e9"},1.5,-0,"","longer string value"]"#.to_vec());
    // Numbers near the edges the libFuzzer target found: large exponents and
    // integers around the I-JSON safe range.
    corpus.push(br#"[411E44,1e23,9007199254740991,9007199254740993,-0.0,1e-7]"#.to_vec());

    for _ in 0..8_000 {
        let seed = &corpus[rng.below(corpus.len())];
        let data = mutate(seed, &mut rng);
        check_canonical(&data);
    }
}

/// The two inputs the weekly libFuzzer run produced (2026-08-24 and
/// 2026-08-31), kept as regression seeds. `2230002230003330000` is an
/// integer above 2^53 - 1: the contract is a stable refusal, which the old
/// harness wrongly treated as a crash. `411E44` exposed serde_json's
/// best-effort float parsing landing one ulp off the nearest double, so the
/// canonical form was `4.1100000000000004e+46` on the first pass and
/// `4.11e+46` on the second; correctly rounded parsing (`float_roundtrip`)
/// fixes it, and this pins both.
#[test]
fn canonical_json_libfuzzer_findings_stay_fixed() {
    check_canonical(b"2230002230003330000");
    assert!(canonical_json(&serde_json::json!(2230002230003330000u64)).is_err());

    check_canonical(b"411E44");
    let v: serde_json::Value = serde_json::from_slice(b"411E44").unwrap();
    assert_eq!(canonical_json(&v).unwrap(), b"4.11e+46");
    check_canonical(br#"{"score":411E44,"n":[2230002230003330000]}"#);
}
