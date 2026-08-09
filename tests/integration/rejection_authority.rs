#[test]
fn test_approval_missing() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Grant an Ask capability but commit NO approval
    let (cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Ask),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (_, verdict) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::ApprovalMissing));
}

#[test]
fn test_approval_expired() {
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

    // Grant a class approval with a very short expiry (time=1 means it expires immediately
    // since time is monotonic and the approval itself will get time > current)
    // The approval record will get some time T. We need the action's time > expiry.
    // Set expiry = 1 so it's already expired by the time the action is committed.
    let (_, v) = writer
        .commit(
            approval_class_proposal("shell", Some(ACTOR), Some(1)),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (_, verdict) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::ApprovalExpired));
}

#[test]
fn test_action_closed() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (_request_id, action_id) = setup_open_action(&mut writer, &rules, &mut state, "shell");

    // Close the action with a result
    let (_, v) = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Try to submit another result for the same (now closed) action
    let (_, verdict) = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::ActionClosed));
}

#[test]
fn test_replacement_invalid_wrong_kind() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit an request
    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Try to commit a Response with a Replace ref targeting the request
    // Replace is only valid on Summary, Capability, Approval
    let data = encode(&ResponseData {
        request_id,
        content: "test".into(),
        turn_index: 0,
        closes_request: false,
    })
    .unwrap();

    // We need an active request for the response to not fail on RequestMissing first.
    // request_id is active. But the Replace ref targeting it will trigger ReplacementInvalid
    // because Response kind doesn't support Replace refs.
    let proposal = Proposal {
        space: SPACE,
        thread: THREAD,
        author: provider_author(),
        kind: Kind::Response,
        schema: schema_id(SCHEMA_RESPONSE),
        data,
        refs: vec![Ref {
            type_: RefType::Replace,
            target: request_id,
        }],
    };

    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::ReplacementInvalid));
}

#[test]
fn test_replacement_invalid_different_kind_target() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit an request (to have an accepted record to reference)
    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Try to commit a Capability with a Replace ref targeting the Request (wrong kind)
    let data = encode(&CapabilityData {
        actor_id: ACTOR.into(),
        action_class: "shell".into(),
        scope: SCOPE,
        mode: CapabilityMode::Auto,
        expiry: None,
    })
    .unwrap();
    let proposal = Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Capability,
        schema: schema_id(SCHEMA_CAPABILITY),
        data,
        refs: vec![Ref {
            type_: RefType::Replace,
            target: request_id,
        }],
    };

    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::ReplacementInvalid));
}

#[test]
fn test_external_receipt_required() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
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

    // Submit an Internal result (schema = SCHEMA_RESULT) for an External action
    // Should fail with ExternalReceiptRequired
    let (_, verdict) = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::ExternalReceiptRequired));
}

#[test]
fn test_invalid_payload_approval_both_none() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Approval with both target_action and action_class as None
    let data = encode(&ApprovalData {
        target_action: None,
        action_class: None,
        scope: SCOPE,
        actor_id: None,
        expiry: None,
    })
    .unwrap();
    let proposal = Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Approval,
        schema: schema_id(SCHEMA_APPROVAL),
        data,
        refs: vec![],
    };

    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidPayload));
}

#[test]
fn test_refusal_valid() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (_request_id, action_id) = setup_open_action(&mut writer, &rules, &mut state, "shell");

    // Refuse the open action
    let (_, verdict) = writer
        .commit(refusal_action_proposal(action_id), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);
    assert!(verdict.reason.is_none());

    // Action should now be closed
    assert!(!state.open_actions.contains(&action_id));
}

