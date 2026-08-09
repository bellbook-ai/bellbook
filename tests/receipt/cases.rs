#[test]
fn test_export_validate_roundtrip_clean() {
    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);
    let receipt = Receipt::new(&records, &rules);
    let bytes = receipt.to_bytes().unwrap();

    let report = validate(&bytes);
    assert_eq!(report.status, ValidationStatus::Clean);
    assert_eq!(report.record_count, records.len() as u64);
    assert_eq!(report.checked_records, records.len() as u64);
    assert_eq!(report.reason, None);
    assert_eq!(report.problem, None);
    assert_eq!(report.rules_hash, sha256_canonical(&rules).unwrap());

    // The report's head hash matches an independently produced attestation.
    let att = head_attestation(&records, "2026-08-07T00:00:00Z".into()).unwrap();
    assert_eq!(report.head_hash, att.head_hash);
    assert_eq!(report.record_count, att.record_count);
}

#[test]
fn test_validate_surfaces_taint() {
    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), true);
    let report = validate(&Receipt::new(&records, &rules).to_bytes().unwrap());
    assert_eq!(report.status, ValidationStatus::Tainted);
    assert_eq!(report.retracted_records.len(), 1);
    assert_eq!(report.tainted_records.len(), 1);
}

#[test]
fn test_validate_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let (mut records, rules) = small_log(dir.path(), false);
    // Tamper with a committed payload byte.
    records[0].data[10] ^= 0x01;
    let report = validate(&Receipt::new(&records, &rules).to_bytes().unwrap());
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(report.reason.is_some());
}

#[test]
fn test_validate_rejects_garbage_and_wrong_version() {
    let report = validate(b"not json at all");
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(report.problem.unwrap().contains("unparseable"));

    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);
    let mut receipt = Receipt::new(&records, &rules);
    receipt.spec_version = "9.9".into();
    let report = validate(&receipt.to_bytes().unwrap());
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(report.problem.unwrap().contains("unsupported spec version"));
}

#[test]
fn test_receipt_wire_rejects_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);
    let receipt = Receipt::new(&records, &rules);

    let mut top_level = serde_json::to_value(&receipt).unwrap();
    top_level
        .as_object_mut()
        .unwrap()
        .insert("checkpoint".into(), serde_json::json!({"trusted": true}));
    assert_eq!(
        validate(&serde_json::to_vec(&top_level).unwrap()).status,
        ValidationStatus::Invalid
    );

    let mut record_envelope = serde_json::to_value(&receipt).unwrap();
    record_envelope["records"][0]
        .as_object_mut()
        .unwrap()
        .insert("policy_decision".into(), serde_json::json!("permit"));
    assert_eq!(
        validate(&serde_json::to_vec(&record_envelope).unwrap()).status,
        ValidationStatus::Invalid
    );

    let mut rule_document = serde_json::to_value(&receipt).unwrap();
    rule_document["rules"]
        .as_object_mut()
        .unwrap()
        .insert("profile".into(), serde_json::json!("bellbook-core-v1"));
    assert_eq!(
        validate(&serde_json::to_vec(&rule_document).unwrap()).status,
        ValidationStatus::Invalid
    );
}

#[test]
fn test_receipt_wire_rejects_duplicate_rule_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (records, mut rules) = small_log(dir.path(), false);

    let receipt = Receipt::new(&records, &rules);
    let canonical = String::from_utf8(receipt.to_bytes().unwrap()).unwrap();
    let role_needle = "\"author_roles\":{\"agent\":\"Provider\"";
    assert!(canonical.contains(role_needle));
    let duplicate_role = canonical.replacen(
        role_needle,
        "\"author_roles\":{\"agent\":\"Provider\",\"agent\":\"User\"",
        1,
    );
    assert_eq!(
        validate(duplicate_role.as_bytes()).status,
        ValidationStatus::Invalid
    );

    let rules_value = serde_json::to_value(&rules).unwrap();
    let first_pair = serde_json::to_string(&rules_value["kind_schema_map"][0]).unwrap();
    let pair_needle = format!("\"kind_schema_map\":[{first_pair}");
    assert!(canonical.contains(&pair_needle));
    let duplicate_pair = canonical.replacen(
        &pair_needle,
        &format!("\"kind_schema_map\":[{first_pair},{first_pair}"),
        1,
    );
    assert_eq!(
        validate(duplicate_pair.as_bytes()).status,
        ValidationStatus::Invalid
    );

    let pinned_key = [7u8; 32];
    rules
        .author_keys
        .insert("human".into(), [pinned_key].into_iter().collect());
    let keyed_receipt = Receipt::new(&records, &rules);
    let keyed = String::from_utf8(keyed_receipt.to_bytes().unwrap()).unwrap();
    let key_json = serde_json::to_string(&pinned_key).unwrap();
    let key_needle = format!("\"author_keys\":{{\"human\":[{key_json}]");
    assert!(keyed.contains(&key_needle));
    let duplicate_key = keyed.replacen(
        &key_needle,
        &format!("\"author_keys\":{{\"human\":[{key_json},{key_json}]"),
        1,
    );
    assert_eq!(
        validate(duplicate_key.as_bytes()).status,
        ValidationStatus::Invalid
    );
}

/// Receipts carry no checkpoint: a receipt whose JSON smuggles one in is
/// simply not a valid Receipt, and validation always replays from
/// genesis - a forged Accept verdict anywhere in the log is caught even
/// though the producer controls every byte of the receipt.
#[test]
fn test_validate_always_replays_from_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let (mut records, rules) = small_log(dir.path(), false);

    // Forge: flip the request's verdict payload to Reject while keeping
    // the verdict record self-consistent (id recomputed). Under a trusted
    // checkpoint this would be attested; in a receipt it must be caught
    // by full verdict re-derivation.
    let forged_verdict_data = encode(&VerdictData {
        result: VerdictResult::Reject,
        reason: Some(ReasonCode::InvalidPayload),
    })
    .unwrap();
    records[1].data = forged_verdict_data;
    let recomputed = records[1].compute_id().unwrap();
    records[1].id = recomputed;

    let report = validate(&Receipt::new(&records, &rules).to_bytes().unwrap());
    assert_eq!(report.status, ValidationStatus::Invalid);
}

/// Host-side checkpoint use: prefix record content is bound by id
/// recomputation even under a checkpoint - swapping bytes in a prefix
/// record while keeping its stored id is rejected.
#[test]
fn test_checkpointed_verify_log_rejects_prefix_content_swap() {
    let dir = tempfile::tempdir().unwrap();
    let (mut records, rules) = small_log(dir.path(), false);
    let state = build_state_unchecked(&records).unwrap();
    let cp = create_checkpoint(&records, &state).unwrap();

    // Sanity: the honest log verifies under its own checkpoint.
    let ok = verify_log(
        &records,
        &rules,
        Some(&TrustedCheckpoint::assume_verified(cp.clone(), &rules).unwrap()),
    );
    assert_eq!(ok.result, VerdictResult::Accept);

    // Swap content inside the checkpointed prefix, keeping the stored id
    // (so the checkpoint's log_hash over stored ids still matches).
    records[0].data[10] ^= 0x01;
    let bad = verify_log(
        &records,
        &rules,
        Some(&TrustedCheckpoint::assume_verified(cp.clone(), &rules).unwrap()),
    );
    assert_eq!(bad.result, VerdictResult::Reject);
}

#[test]
fn test_cli_validate() {
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);
    let receipt_path = dir.path().join("receipt.json");
    std::fs::write(
        &receipt_path,
        Receipt::new(&records, &rules).to_bytes().unwrap(),
    )
    .unwrap();

    // Human-readable output, exit 0 on clean.
    let out = Command::new(env!("CARGO_BIN_EXE_bellbook"))
        .args(["validate", receipt_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {:?}", out.stderr);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("status:          CLEAN"), "{text}");

    // JSON output parses back into a Report.
    let out = Command::new(env!("CARGO_BIN_EXE_bellbook"))
        .args(["validate", receipt_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let report: bellbook::receipt::Report = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report.status, ValidationStatus::Clean);

    // Tainted receipt exits 2.
    let dir2 = tempfile::tempdir().unwrap();
    let (records2, rules2) = small_log(dir2.path(), true);
    let tainted_path = dir2.path().join("tainted.json");
    std::fs::write(
        &tainted_path,
        Receipt::new(&records2, &rules2).to_bytes().unwrap(),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bellbook"))
        .args(["validate", tainted_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // Tampered receipt exits 1.
    let mut tampered = records.clone();
    tampered[0].data[5] ^= 1;
    let bad_path = dir.path().join("bad.json");
    std::fs::write(
        &bad_path,
        Receipt::new(&tampered, &rules).to_bytes().unwrap(),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bellbook"))
        .args(["validate", bad_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // Usage error exits 64.
    let out = Command::new(env!("CARGO_BIN_EXE_bellbook"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
}

// ---------------------------------------------------------------------------
// Hostile-input, canonical-payload, checkpoint, and resource-limit coverage.
// ---------------------------------------------------------------------------

/// A hostile logical time of u64::MAX must reject, never overflow (this
/// test runs under debug overflow checks, so a wrapping/unchecked add
/// would panic here).
#[test]
fn test_hostile_time_overflow_rejects_without_panic() {
    let dir = tempfile::tempdir().unwrap();
    let (mut records, rules) = small_log(dir.path(), false);
    records[0].time = u64::MAX;
    records[1].time = 0;
    // An attacker hands us raw JSON, not our canonical serializer (which
    // itself refuses out-of-I-JSON-range integers) - so build the hostile
    // bytes with plain serde.
    let bytes = serde_json::to_vec(&Receipt::new(&records, &rules)).unwrap();
    let report = validate(&bytes);
    assert_eq!(report.status, ValidationStatus::Invalid);
}

/// Payload bytes must be the exact JCS canonical serialization: unknown
/// fields, duplicate keys, and non-canonical formatting all reject even
/// when the id is recomputed to match the mutated bytes.
#[test]
fn test_non_canonical_payloads_reject() {
    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);

    let hostile_payloads: [&[u8]; 3] = [
        // Unknown field smuggled into an otherwise-valid payload.
        br#"{"attachments":[],"extra":"smuggled","objective":"receipt demo","parent_request_id":null,"scope":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10]}"#,
        // Duplicate key.
        br#"{"attachments":[],"objective":"a","objective":"b","parent_request_id":null,"scope":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10]}"#,
        // Same content, non-canonical whitespace.
        br#"{ "attachments":[],"objective":"receipt demo","parent_request_id":null,"scope":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10] }"#,
    ];

    for payload in hostile_payloads {
        let mut mutated = records.clone();
        mutated[0].data = payload.to_vec();
        // Recompute the id so only the canonical-payload rule can catch it.
        mutated[0].id = mutated[0].compute_id().unwrap();
        let report = validate(&Receipt::new(&mutated, &rules).to_bytes().unwrap());
        assert_eq!(
            report.status,
            ValidationStatus::Invalid,
            "payload accepted: {:?}",
            String::from_utf8_lossy(payload)
        );
    }
}

/// TrustedCheckpoint: from_verified_log succeeds only on a verifying log,
/// and a checkpoint established under different rules is rejected.
#[test]
fn test_trusted_checkpoint_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);

    // The safe producer: full replay, then accelerated re-verification.
    let trusted = TrustedCheckpoint::from_verified_log(&records, &rules).unwrap();
    let verdict = verify_log(&records, &rules, Some(&trusted));
    assert_eq!(verdict.result, VerdictResult::Accept);

    // A forged log yields no trusted checkpoint at all.
    let mut forged = records.clone();
    forged[0].data[10] ^= 1;
    assert!(TrustedCheckpoint::from_verified_log(&forged, &rules).is_none());

    // A checkpoint bound to different rules attests nothing here.
    let mut other_rules = rules.clone();
    other_rules.signature_required_kinds.insert(Kind::Request);
    let cross =
        TrustedCheckpoint::assume_verified(trusted.checkpoint().clone(), &other_rules).unwrap();
    let verdict = verify_log(&records, &rules, Some(&cross));
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidCheckpoint));
}

/// Resource limits: oversized inputs are refused with a structural
/// failure before any verification work.
#[test]
fn test_validation_limits() {
    use bellbook::receipt::{validate_with_limits, ValidationLimits};

    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);
    let bytes = Receipt::new(&records, &rules).to_bytes().unwrap();

    let tight_bytes = ValidationLimits {
        max_bytes: 16,
        ..ValidationLimits::default()
    };
    let report = validate_with_limits(&bytes, &tight_bytes);
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(report.problem.unwrap().contains("size limit"));

    let tight_records = ValidationLimits {
        max_records: 2,
        ..ValidationLimits::default()
    };
    let report = validate_with_limits(&bytes, &tight_records);
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(report.problem.unwrap().contains("record limit"));

    let tight_payload = ValidationLimits {
        max_payload_bytes: 4,
        ..ValidationLimits::default()
    };
    let report = validate_with_limits(&bytes, &tight_payload);
    assert_eq!(report.status, ValidationStatus::Invalid);
    assert!(report.problem.unwrap().contains("payload size limit"));

    // Default limits accept a normal receipt untouched.
    assert_eq!(validate(&bytes).status, ValidationStatus::Clean);
}

/// The CLI refuses oversized files before reading them.
#[test]
fn test_cli_max_size() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let (records, rules) = small_log(dir.path(), false);
    let path = dir.path().join("receipt.json");
    std::fs::write(&path, Receipt::new(&records, &rules).to_bytes().unwrap()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_bellbook"))
        .args(["validate", path.to_str().unwrap(), "--max-size", "10"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
    assert!(String::from_utf8_lossy(&out.stderr).contains("exceeds --max-size"));

    // Within the limit it validates normally.
    let out = Command::new(env!("CARGO_BIN_EXE_bellbook"))
        .args(["validate", path.to_str().unwrap(), "--max-size", "10000000"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

/// The committed example receipt (spec/examples/receipt.json, generated
/// by `cargo run --example export_receipt`) must stay valid and Clean;
/// regenerate it when the format intentionally changes.
#[test]
fn test_committed_example_receipt_validates_clean() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("spec/examples/receipt.json");
    let bytes = std::fs::read(&path)
        .expect("spec/examples/receipt.json missing - run: cargo run --example export_receipt > spec/examples/receipt.json");
    let report = validate(&bytes);
    assert_eq!(
        report.status,
        ValidationStatus::Clean,
        "committed example receipt no longer validates ({:?}/{:?}); regenerate it and \
         document the format change",
        report.problem,
        report.reason
    );
    assert_eq!(report.record_count, 10);
}

