// ---------------------------------------------------------------------------
// Commit flow tests
// ---------------------------------------------------------------------------

#[test]
fn test_batch_commit_ordering() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Create multiple requests as a batch
    let mut proposals = vec![];
    for i in 0..3 {
        let data = encode(&RequestData {
            objective: format!("objective {}", i),
            scope: SCOPE,
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap();
        proposals.push(Proposal {
            space: SPACE,
            thread: THREAD,
            author: human_author(),
            kind: Kind::Request,
            schema: schema_id(SCHEMA_REQUEST),
            data,
            refs: vec![],
        });
    }

    let results = writer.batch_commit(proposals, &rules, &mut state).unwrap();

    // All should be accepted
    assert_eq!(results.len(), 3);
    for (_, verdict) in &results {
        assert_eq!(verdict.result, VerdictResult::Accept);
    }

    // Log should have 6 records (3 subjects + 3 verdicts)
    assert_eq!(writer.records().len(), 6);

    // Each pair should be (subject, verdict)
    for chunk in writer.records().chunks(2) {
        assert_ne!(chunk[0].kind, Kind::Verdict);
        assert_eq!(chunk[1].kind, Kind::Verdict);
    }
}

// ---------------------------------------------------------------------------
// verify_log tests
// ---------------------------------------------------------------------------

#[test]
fn test_verify_log_accepts_valid() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Build a valid log with several records
    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (action_id, _) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let _ = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();

    let log_verdict = verify_log(writer.records(), &rules, None);
    assert_eq!(log_verdict.result, VerdictResult::Accept);
}

#[test]
fn test_verify_log_rejects_time_gap() {
    // Manually construct records with a time gap
    let rules = test_rules();

    let data = encode(&RequestData {
        objective: "test".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();

    let r1 = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: 1,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data: data.clone(),
        refs: vec![],
        evidence: Evidence::Reported,
    }
    .with_computed_id()
    .unwrap();

    // Create verdict for r1
    let verdict_data = VerdictData {
        result: VerdictResult::Accept,
        reason: None,
    };
    let v1 = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: 2,
        author: Author {
            id: "verifier".into(),
            type_: AuthorType::Verifier,
            signature: None,
        },
        kind: Kind::Verdict,
        schema: schema_id(SCHEMA_VERDICT),
        data: encode(&verdict_data).unwrap(),
        refs: vec![Ref {
            type_: RefType::Cause,
            target: r1.id,
        }],
        evidence: Evidence::Deterministic,
    }
    .with_computed_id()
    .unwrap();

    // Create r2 with time gap (time=5 instead of 3)
    let r2 = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: 5, // GAP: should be 3
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data,
        refs: vec![],
        evidence: Evidence::Reported,
    }
    .with_computed_id()
    .unwrap();

    let records = vec![r1, v1, r2];

    let log_verdict = verify_log(&records, &rules, None);
    assert_eq!(log_verdict.result, VerdictResult::Reject);
}

#[test]
fn test_verify_log_rejects_missing_verdict() {
    // Create a log with a subject record but no following verdict
    let rules = test_rules();
    let data = encode(&RequestData {
        objective: "test".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();

    let r1 = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: 1,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data,
        refs: vec![],
        evidence: Evidence::Reported,
    }
    .with_computed_id()
    .unwrap();

    let records = vec![r1];
    let log_verdict = verify_log(&records, &rules, None);
    assert_eq!(log_verdict.result, VerdictResult::Reject);
}

// ---------------------------------------------------------------------------
// Full flow integration: Ask approval flow
// ---------------------------------------------------------------------------

#[test]
fn test_ask_flow_exact_approval() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Grant Ask capability
    let (cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Ask),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Pre-compute the action data for exact approval
    let action_data = ActionData {
        request_id,
        action_class: "shell".into(),
        scope: SCOPE,
        exec_mode: ExecMode::Internal,
        params: serde_json::json!({}),
    };

    // Commit exact approval
    let (approval_id, v) = writer
        .commit(
            approval_exact_proposal(ACTOR, &action_data),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Now the action should be accepted
    let (action_id, verdict) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id, approval_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);
    assert!(state.open_actions.contains(&action_id));
}

#[test]
fn test_ask_flow_class_approval() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Grant Ask capability
    let (cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Ask),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Commit class approval (covers all "shell" actions for ACTOR)
    let (approval_id, v) = writer
        .commit(
            approval_class_proposal("shell", Some(ACTOR), None),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Action should be accepted
    let (_, verdict) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id, approval_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);
}

// ---------------------------------------------------------------------------
// Multi-action request completion
// ---------------------------------------------------------------------------

#[test]
fn test_request_stays_active_until_all_actions_closed() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");

    // Create two actions
    let (action1, _) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (action2, _) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();

    assert!(state.active_requests.contains(&request_id));

    // Close first action
    writer
        .commit(result_proposal(action1), &rules, &mut state)
        .unwrap();
    // Request should still be active
    assert!(state.active_requests.contains(&request_id));

    // Close second action
    writer
        .commit(result_proposal(action2), &rules, &mut state)
        .unwrap();
    // Still active: only the explicit closing response completes it.
    assert!(state.active_requests.contains(&request_id));
    let (_, v) = writer
        .commit(closing_response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert!(!state.active_requests.contains(&request_id));
}

// ---------------------------------------------------------------------------
// External action flow
// ---------------------------------------------------------------------------

#[test]
fn test_external_action_accepts_external_receipt() {
    let dir = tempfile::tempdir().unwrap();
    // Verified evidence is earned: the external result must be signed by a
    // key-pinned executor, so pin the executor's key in the rules.
    let executor_signer = Ed25519Signer::from_secret_bytes(&[7u8; 32]);
    let mut rules = test_rules();
    rules.author_keys.insert(
        "tool_executor".into(),
        [executor_signer.public_key()].into_iter().collect(),
    );
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let (cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Commit an External action
    let action_data = ActionData {
        request_id,
        action_class: "shell".into(),
        scope: SCOPE,
        exec_mode: ExecMode::External,
        params: serde_json::json!({}),
    };
    let (action_id, v) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: provider_author(),
                kind: Kind::Action,
                schema: schema_id(SCHEMA_ACTION),
                data: encode(&action_data).unwrap(),
                refs: vec![Ref {
                    type_: RefType::Require,
                    target: cap_id,
                }],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Submit external receipt, signed by the pinned executor - accepted
    let (_, verdict) = writer
        .commit_signed(
            external_result_proposal(action_id),
            &rules,
            &mut state,
            &executor_signer,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);

    // An unsigned external result is not Verified evidence and rejects.
    let (aid2, v) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: provider_author(),
                kind: Kind::Action,
                schema: schema_id(SCHEMA_ACTION),
                data: encode(&ActionData {
                    request_id,
                    action_class: "shell".into(),
                    scope: SCOPE,
                    exec_mode: ExecMode::External,
                    params: serde_json::json!({"n": 2}),
                })
                .unwrap(),
                refs: vec![Ref {
                    type_: RefType::Require,
                    target: cap_id,
                }],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, verdict) = writer
        .commit(external_result_proposal(aid2), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::SignatureMissing));
}

