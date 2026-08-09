// ---------------------------------------------------------------------------
// Empty-log checkpoint and linear-cost verification regressions
// ---------------------------------------------------------------------------

/// Deleting attested history must never verify: an empty (or truncated)
/// records slice presented against a trusted checkpoint covering more
/// records rejects with InvalidCheckpoint instead of accepting before the
/// checkpoint is even examined.
#[test]
fn test_empty_log_with_nonempty_checkpoint_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let records = writer.records().to_vec();
    let trusted = TrustedCheckpoint::from_verified_log(&records, &rules).unwrap();

    // The log was deleted out from under the retained checkpoint.
    let verdict = verify_log(&[], &rules, Some(&trusted));
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidCheckpoint));

    // Truncation short of empty is equally deleted history.
    let verdict = verify_log(&records[..1], &rules, Some(&trusted));
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidCheckpoint));

    // The intact log still verifies under its own checkpoint, and an
    // empty log with no checkpoint stays trivially valid.
    assert_eq!(
        verify_log(&records, &rules, Some(&trusted)).result,
        VerdictResult::Accept
    );
    assert_eq!(verify_log(&[], &rules, None).result, VerdictResult::Accept);
}

/// A trusted checkpoint covering an empty prefix grants nothing: replay
/// starts at genesis, so the first record must still have time 1. A
/// self-consistent log starting at time 100 must reject with or without
/// the empty-prefix checkpoint.
#[test]
fn test_empty_prefix_checkpoint_does_not_exempt_genesis_time() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let records = writer.records().to_vec();

    // Re-time the pair to start at 100, recomputing ids so the log is
    // self-consistent apart from not starting at time 1.
    let subject = Record {
        time: 100,
        ..records[0].clone()
    }
    .with_computed_id()
    .unwrap();
    let verdict_rec = Record {
        time: 101,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: subject.id,
        }],
        ..records[1].clone()
    }
    .with_computed_id()
    .unwrap();
    let shifted = vec![subject, verdict_rec];

    let empty_cp = TrustedCheckpoint::from_verified_log(&[], &rules).unwrap();

    // Without a checkpoint the shifted log already rejects...
    assert_eq!(
        verify_log(&shifted, &rules, None).result,
        VerdictResult::Reject
    );
    // ...and a checkpoint over an empty prefix must not change that.
    let verdict = verify_log(&shifted, &rules, Some(&empty_cp));
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidPayload));

    // The honest log still verifies under the empty-prefix checkpoint.
    assert_eq!(
        verify_log(&records, &rules, Some(&empty_cp)).result,
        VerdictResult::Accept
    );
}

/// Verification cost must stay linear in log size (SPEC section 12.3): a
/// synthetic log of 10,000 records replays through the id index. Under
/// the old per-lookup prefix scans this log forced tens of millions of
/// record comparisons; a superlinear regression makes this test visibly
/// slow long before it fails anything else.
#[test]
fn test_verify_log_scales_linearly() {
    let rules = test_rules();
    let n_pairs = 5_000usize;
    let mut records = Vec::with_capacity(n_pairs * 2);
    let verdict_data = encode(&VerdictData {
        result: VerdictResult::Accept,
        reason: None,
    })
    .unwrap();
    for k in 0..n_pairs {
        let data = encode(&RequestData {
            objective: format!("request {k}"),
            scope: SCOPE,
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap();
        let subject = Record {
            id: [0u8; 32],
            space: SPACE,
            thread: THREAD,
            time: (k as u64) * 2 + 1,
            author: human_author(),
            kind: Kind::Request,
            schema: schema_id(SCHEMA_REQUEST),
            data,
            refs: vec![],
            evidence: Evidence::Reported,
        }
        .with_computed_id()
        .unwrap();
        let verdict = Record {
            id: [0u8; 32],
            space: SPACE,
            thread: THREAD,
            time: (k as u64) * 2 + 2,
            author: Author {
                id: "verifier".into(),
                type_: AuthorType::Verifier,
                signature: None,
            },
            kind: Kind::Verdict,
            schema: schema_id(SCHEMA_VERDICT),
            data: verdict_data.clone(),
            refs: vec![Ref {
                type_: RefType::Cause,
                target: subject.id,
            }],
            evidence: Evidence::Deterministic,
        }
        .with_computed_id()
        .unwrap();
        records.push(subject);
        records.push(verdict);
    }

    let report = verify_log(&records, &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
    assert_eq!(report.checked_records, (n_pairs * 2) as u64);
}

