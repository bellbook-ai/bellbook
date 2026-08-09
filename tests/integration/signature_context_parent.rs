// ---------------------------------------------------------------------------
// Verdict-signature, tainted-context, and parentage regressions
// default, request parent cardinality, attestation timestamps
// ---------------------------------------------------------------------------

/// The completed subject signature is part of the record id. Removing an
/// optional valid signature cannot leave a receipt Clean under the same id.
#[test]
fn test_subject_signature_removal_changes_id_and_invalidates_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let signer = Ed25519Signer::from_secret_bytes(&[41u8; 32]);
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit_signed(request_proposal(), &rules, &mut state, &signer)
        .unwrap();

    let original_id = writer.records()[0].id;
    let mut records = writer.records().to_vec();
    records[0].author.signature = None;
    assert_ne!(records[0].compute_id().unwrap(), original_id);

    let receipt = bellbook::receipt::Receipt::new(&records, &rules);
    let report = bellbook::receipt::validate(&receipt.to_bytes().unwrap());
    assert_eq!(report.status, bellbook::receipt::ValidationStatus::Invalid);
    assert_eq!(report.reason, Some(ReasonCode::InvalidPayload));
}

/// Multiple keys may authenticate one actor, but each signature yields a
/// distinct record id; substitution under a retained id is detected.
#[test]
fn test_valid_signature_substitution_changes_record_id() {
    let signer_a = Ed25519Signer::from_secret_bytes(&[42u8; 32]);
    let signer_b = Ed25519Signer::from_secret_bytes(&[43u8; 32]);
    let mut record = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: 1,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data: encode(&RequestData {
            objective: "signature binding".into(),
            scope: SCOPE,
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap(),
        refs: vec![],
        evidence: Evidence::Reported,
    };
    record.author.signature = Some(signer_a.sign(&record).unwrap());
    record = record.with_computed_id().unwrap();
    let id_a = record.id;

    record.author.signature = Some(signer_b.sign(&record).unwrap());
    let id_b = record.compute_id().unwrap();
    assert_ne!(id_a, id_b);
}

/// Verdicts are required to be unsigned; attaching signature bytes must
/// make the receipt Invalid, not leave it Clean.
#[test]
fn test_verdict_signature_bytes_reject() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Clean baseline.
    let receipt = bellbook::receipt::Receipt::new(writer.records(), &rules);
    assert_eq!(
        bellbook::receipt::validate(&receipt.to_bytes().unwrap()).status,
        bellbook::receipt::ValidationStatus::Clean
    );

    // Attach signature bytes to the verdict record: same ids, same head
    // hash, different receipt bytes - must now be Invalid.
    let mut records = writer.records().to_vec();
    assert_eq!(records[1].kind, Kind::Verdict);
    records[1].author.signature = Some(Signature {
        key_id: "aa".repeat(32),
        sig: vec![0u8; 64],
    });
    let forged = bellbook::receipt::Receipt::new(&records, &rules);
    let report = bellbook::receipt::validate(&forged.to_bytes().unwrap());
    assert_eq!(report.status, bellbook::receipt::ValidationStatus::Invalid);

    // Direct replay agrees.
    let verdict = verify_log(&records, &rules, None);
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidPayload));
}

/// Tainted records are excluded from context by default; IncludeTainted
/// opts in and labels them.
#[test]
fn test_context_excludes_tainted_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (a1, _) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (result_id, _) = writer
        .commit(result_proposal(a1), &rules, &mut state)
        .unwrap();
    let (summary_id, v) = writer
        .commit(summary_proposal(&[result_id]), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Retract the result: the summary becomes tainted.
    let (_, v) = writer
        .commit(retraction_proposal(result_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert!(state.tainted_records.contains(&summary_id));

    // Default context: neither the retracted result nor the tainted
    // summary appears.
    let ctx = build_context(writer.records(), &state, &rules, THREAD);
    assert!(!ctx.records.iter().any(|r| r.id == result_id));
    assert!(!ctx.records.iter().any(|r| r.id == summary_id));
    assert!(ctx.tainted_records.is_empty());

    // Explicit opt-in: the tainted summary is selectable and labeled;
    // the retracted result stays excluded.
    let ctx = build_context_with(
        writer.records(),
        &state,
        &rules,
        THREAD,
        ContextPolicy::IncludeTainted,
    );
    assert!(ctx.records.iter().any(|r| r.id == summary_id));
    assert!(!ctx.records.iter().any(|r| r.id == result_id));
    assert!(ctx.tainted_records.contains(&summary_id));
}

/// Request parentage is unambiguous: undeclared, surplus, or mismatched
/// parent Cause refs reject; the declared graph is the only graph.
#[test]
fn test_request_parent_cardinality() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (p1, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (p2, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let child = |parent: Option<RecordId>, causes: &[RecordId]| Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data: encode(&RequestData {
            objective: "delegated child".into(),
            scope: SCOPE,
            attachments: vec![],
            parent_request_id: parent,
        })
        .unwrap(),
        refs: causes
            .iter()
            .copied()
            .map(|target| Ref {
                type_: RefType::Cause,
                target,
            })
            .collect(),
    };

    // Undeclared parent: Cause ref with parent_request_id None.
    let (_, v) = writer
        .commit(child(None, &[p1]), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));

    // Declared parent with no Cause ref.
    let (_, v) = writer
        .commit(child(Some(p1), &[]), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);

    // Declared parent with a surplus second parent Cause.
    let (_, v) = writer
        .commit(child(Some(p1), &[p1, p2]), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);

    // Declared parent whose Cause names a different request.
    let (_, v) = writer
        .commit(child(Some(p1), &[p2]), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);

    // The one coherent form: declared parent, exactly one matching Cause.
    let (_, v) = writer
        .commit(child(Some(p1), &[p1]), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
}

/// head_attestation only produces canonical RFC 3339 UTC timestamps.
#[test]
fn test_head_attestation_timestamp_validation() {
    assert!(head_attestation(&[], "2026-08-08T12:00:00Z".into()).is_ok());
    // Leap day on a leap year.
    assert!(head_attestation(&[], "2024-02-29T00:00:00Z".into()).is_ok());

    for bad in [
        "",
        "2026-08-08 12:00:00Z",      // space separator
        "2026-08-08T12:00:00",       // missing Z
        "2026-08-08T12:00:00+00:00", // offset instead of Z
        "2026-08-08T12:00:00.000Z",  // fractional seconds
        "2026-13-01T00:00:00Z",      // month 13
        "2026-02-29T00:00:00Z",      // not a leap year
        "2026-08-08T24:00:00Z",      // hour 24
        "2026-08-08t12:00:00z",      // lowercase
        "not a timestamp",
    ] {
        assert!(
            head_attestation(&[], bad.into()).is_err(),
            "accepted nonconforming timestamp {bad:?}"
        );
    }
}
