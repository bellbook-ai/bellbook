// ---------------------------------------------------------------------------
// Tail-authority recovery and phantom-state regressions
// responses, safe state construction
// ---------------------------------------------------------------------------

fn append_raw_record_frame(dir: &std::path::Path, record: &Record) {
    use std::io::Write;
    let bytes = canonical_json(record).unwrap();
    let len = u32::try_from(bytes.len()).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("records.log"))
        .unwrap();
    file.write_all(&len.to_be_bytes()).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_data().unwrap();
}

/// Build a valid, unverdicted subject directly in the log (simulating a
/// crash after the subject fsync but before the verdict), optionally
/// leaving `.intent` in an arbitrary state, then reopen and require
/// recovery to restore pairing from the log tail alone.
fn crash_recovery_scenario(intent_bytes: Option<Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();

    // A normally committed pair first. Capture the next writer-assigned time
    // before dropping the writer; raw storage handles are intentionally not
    // part of the public API.
    let next_time = {
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();
        let (_, v) = writer
            .commit(request_proposal(), &rules, &mut state)
            .unwrap();
        assert_eq!(v.result, VerdictResult::Accept);
        writer.next_time()
    }; // writer dropped: lock released

    // Crash simulation: append a valid subject with no verdict.
    let subject_id = {
        let subject = Record {
            id: [0u8; 32],
            space: SPACE,
            thread: THREAD,
            time: next_time,
            author: human_author(),
            kind: Kind::Request,
            schema: schema_id(SCHEMA_REQUEST),
            data: encode(&RequestData {
                objective: "interrupted commit".into(),
                scope: SCOPE,
                attachments: vec![],
                parent_request_id: None,
            })
            .unwrap(),
            refs: vec![],
            evidence: Evidence::Reported,
        }
        .with_computed_id()
        .unwrap();
        let id = subject.id;
        append_raw_record_frame(dir.path(), &subject);
        id
    };
    match intent_bytes {
        Some(bytes) => std::fs::write(dir.path().join(".intent"), bytes).unwrap(),
        None => {
            let _ = std::fs::remove_file(dir.path().join(".intent"));
        }
    }

    // Reopen: the tail is the recovery authority, whatever .intent says.
    let writer = LogWriter::open(dir.path(), &rules).unwrap();
    let records = writer.records();
    assert_eq!(records.len(), 4, "subject must have received its verdict");
    let last = records.last().unwrap();
    assert_eq!(last.kind, Kind::Verdict);
    assert_eq!(last.refs[0].target, subject_id);
    assert!(!dir.path().join(".intent").exists());

    // The recovered log replays cleanly.
    let report = verify_log(records, &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// Crash after the subject fsync with the intent file entirely absent
/// (its truncating rewrite plus a directory-loss crash could delete it).
#[test]
fn test_recovery_subject_present_intent_absent() {
    crash_recovery_scenario(None);
}

/// Crash mid-rewrite leaving an EMPTY intent file: previously treated as
/// "no intent", permanently orphaning the subject.
#[test]
fn test_recovery_subject_present_intent_empty() {
    crash_recovery_scenario(Some(Vec::new()));
}

/// Crash leaving a torn, unparseable intent.
#[test]
fn test_recovery_subject_present_intent_torn() {
    crash_recovery_scenario(Some(b"{\"subject_id\":[1,2".to_vec()));
}

/// Intent still says written:false even though the subject IS durable
/// (the flag write raced the crash). The tail wins.
#[test]
fn test_recovery_subject_present_intent_written_false() {
    let stale = serde_json::to_vec(&serde_json::json!({
        "subject_id": vec![7u8; 32],
        "written": false,
    }))
    .unwrap();
    crash_recovery_scenario(Some(stale));
}

/// A healthy log (verdict at the tail) with a stale corrupt intent:
/// reopen must not append anything, and the intent is cleared.
#[test]
fn test_recovery_healthy_tail_with_corrupt_intent() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    {
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();
        writer
            .commit(request_proposal(), &rules, &mut state)
            .unwrap();
    }
    std::fs::write(dir.path().join(".intent"), b"garbage").unwrap();

    let writer = LogWriter::open(dir.path(), &rules).unwrap();
    assert_eq!(writer.records().len(), 2);
    assert!(!dir.path().join(".intent").exists());
    assert_eq!(
        verify_log(writer.records(), &rules, None).result,
        VerdictResult::Accept
    );
}

/// A torn trailing subject FRAME (crash mid-append) is truncated away,
/// and the log reopens at the last complete pair.
#[test]
fn test_recovery_torn_subject_frame_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    {
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();
        writer
            .commit(request_proposal(), &rules, &mut state)
            .unwrap();
    }
    // Append a torn frame: a length prefix promising more bytes than exist.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("records.log"))
            .unwrap();
        f.write_all(&999u32.to_be_bytes()).unwrap();
        f.write_all(b"{\"partial").unwrap();
    }

    let writer = LogWriter::open(dir.path(), &rules).unwrap();
    assert_eq!(writer.records().len(), 2);
    assert_eq!(
        verify_log(writer.records(), &rules, None).result,
        VerdictResult::Accept
    );
}

/// A fabricated State naming a phantom request must not let a Response
/// (or an Action) for it be accepted: the prior-log lookup is mandatory.
#[test]
fn test_phantom_state_request_rejected() {
    let rules = test_rules();
    let mut state = State::default();
    let phantom: RecordId = [9u8; 32];
    state.active_requests.insert(phantom);

    let response = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: 1,
        author: provider_author(),
        kind: Kind::Response,
        schema: schema_id(SCHEMA_RESPONSE),
        data: encode(&ResponseData {
            request_id: phantom,
            content: "answering a request that does not exist".into(),
            turn_index: 0,
            closes_request: false,
        })
        .unwrap(),
        refs: vec![],
        evidence: Evidence::Reported,
    }
    .with_computed_id()
    .unwrap();

    let verdict = verify_record(&response, &[], &rules, &state);
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::RequestMissing));
}

/// The writer refuses a fabricated or stale derived state before appending.
#[test]
fn test_writer_rejects_state_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut fabricated = State::default();
    fabricated.active_requests.insert([9u8; 32]);

    let result = writer.commit(request_proposal(), &rules, &mut fabricated);
    assert!(matches!(result, Err(LogError::StateMismatch)));
    assert!(writer.records().is_empty());
}

/// One writer cannot mix rule sets across commits.
#[test]
fn test_writer_rejects_rule_drift() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut changed_rules = rules.clone();
    changed_rules.max_context_records += 1;
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let result = writer.commit(request_proposal(), &changed_rules, &mut state);
    assert!(matches!(result, Err(LogError::RulesMismatch)));
    assert!(writer.records().is_empty());
}

/// Opening for writes fails when existing history does not replay.
#[test]
fn test_writer_rejects_invalid_existing_log() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let next_time = {
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();
        writer
            .commit(request_proposal(), &rules, &mut state)
            .unwrap();
        writer.next_time()
    };

    let forged_tail = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: next_time,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data: encode(&RequestData {
            objective: "tampered tail".into(),
            scope: SCOPE,
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap(),
        refs: vec![],
        evidence: Evidence::Reported,
    };
    append_raw_record_frame(dir.path(), &forged_tail);

    assert!(matches!(
        LogWriter::open(dir.path(), &rules),
        Err(LogError::InvalidExistingLog { .. })
    ));
}

/// verify_and_build_state only yields state for logs that replay Accept;
/// build_state_unchecked remains available for pre-verified logs.
#[test]
fn test_verify_and_build_state() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Valid log: safe build equals the writer-maintained state.
    let built = verify_and_build_state(writer.records(), &rules).unwrap();
    assert_eq!(built, state);

    // Forged log (tampered payload): safe build refuses with the verdict.
    let mut forged = writer.records().to_vec();
    forged[0].data[0] ^= 0xff;
    let err = verify_and_build_state(&forged, &rules).unwrap_err();
    assert_eq!(err.result, VerdictResult::Reject);
}

