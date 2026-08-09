// ---------------------------------------------------------------------------
// Response checks
// ---------------------------------------------------------------------------

#[test]
fn test_response_requires_active_request() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Response to active request should work
    let (_, v) = writer
        .commit(response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Cancel the request
    writer
        .commit(refusal_request_proposal(request_id), &rules, &mut state)
        .unwrap();

    // Response to cancelled request should fail
    let (_, v) = writer
        .commit(response_proposal(request_id, 1), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::RequestMissing));
}

// ---------------------------------------------------------------------------
// Refusal targeting closed action
// ---------------------------------------------------------------------------

#[test]
fn test_refusal_on_closed_action_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (_request_id, action_id) = setup_open_action(&mut writer, &rules, &mut state, "shell");

    // Close the action
    writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();

    // Refuse the now-closed action
    let (_, v) = writer
        .commit(refusal_action_proposal(action_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::ActionClosed));
}

// ---------------------------------------------------------------------------
// build_state_unchecked/apply_record equivalence with larger log
// ---------------------------------------------------------------------------

#[test]
fn test_state_equivalence_complex_log() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Build a complex log
    let (int1, cap_id) = setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (act1, _) = writer
        .commit(
            action_proposal_with_authority(int1, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    writer
        .commit(response_proposal(int1, 0), &rules, &mut state)
        .unwrap();
    writer
        .commit(result_proposal(act1), &rules, &mut state)
        .unwrap();

    // Second request
    let (int2, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (act2, _) = writer
        .commit(
            action_proposal_with_authority(int2, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();

    // Refuse the second action
    writer
        .commit(refusal_action_proposal(act2), &rules, &mut state)
        .unwrap();

    // Rebuild from log
    let rebuilt = build_state_unchecked(writer.records()).unwrap();

    assert_eq!(state.accepted_records, rebuilt.accepted_records);
    assert_eq!(state.active_requests, rebuilt.active_requests);
    assert_eq!(state.open_actions, rebuilt.open_actions);
    assert_eq!(state.active_capabilities, rebuilt.active_capabilities);
    assert_eq!(state.replaced_records, rebuilt.replaced_records);
}

// ---------------------------------------------------------------------------
// verify_log with checkpoint
// ---------------------------------------------------------------------------

#[test]
fn test_verify_log_with_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Build some records
    let (_request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Create checkpoint after first pair
    let cp = create_checkpoint(writer.records(), &state).unwrap();

    // Add more records
    let (_cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Verify with checkpoint should still accept
    let log_verdict = verify_log(
        writer.records(),
        &rules,
        Some(&TrustedCheckpoint::assume_verified(cp, &rules).unwrap()),
    );
    assert_eq!(log_verdict.result, VerdictResult::Accept);
}

// ---------------------------------------------------------------------------
// Empty log
// ---------------------------------------------------------------------------

#[test]
fn test_verify_log_empty() {
    let rules = test_rules();
    let log_verdict = verify_log(&[], &rules, None);
    assert_eq!(log_verdict.result, VerdictResult::Accept);
    assert_eq!(log_verdict.checked_records, 0);
}

