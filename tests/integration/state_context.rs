// ---------------------------------------------------------------------------
// State tests
// ---------------------------------------------------------------------------

#[test]
fn test_build_state_accepted_records() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, v) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Rebuild state from log records
    let rebuilt = build_state_unchecked(writer.records()).unwrap();
    assert!(rebuilt.accepted_records.contains(&request_id));
    assert!(rebuilt.active_requests.contains(&request_id));
}

#[test]
fn test_apply_record_equals_build_state() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit a sequence of records
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

    // Rebuild state from scratch
    let rebuilt = build_state_unchecked(writer.records()).unwrap();

    // Both methods should produce the same accepted_records
    assert_eq!(state.accepted_records, rebuilt.accepted_records);
    assert_eq!(state.active_requests, rebuilt.active_requests);
    assert_eq!(state.open_actions, rebuilt.open_actions);
    assert_eq!(state.active_capabilities, rebuilt.active_capabilities);
}

#[test]
fn test_request_lifecycle_completed() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    assert!(state.active_requests.contains(&request_id));

    // Create an action
    let (action_id, _) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert!(state.open_actions.contains(&action_id));
    // Request is still active while action is open
    assert!(state.active_requests.contains(&request_id));

    // Close the action with a result
    let (_, v) = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    assert!(!state.open_actions.contains(&action_id));

    // Closing the last action never completes the request: completion is
    // always the explicit closing response (or a request-targeting
    // Refusal), so sequential follow-up actions stay possible.
    assert!(state.active_requests.contains(&request_id));
    let (_, v) = writer
        .commit(closing_response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert!(!state.active_requests.contains(&request_id));
}

#[test]
fn test_request_lifecycle_cancelled_by_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, v) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert!(state.active_requests.contains(&request_id));

    // Refuse the request directly
    let (_, v) = writer
        .commit(refusal_request_proposal(request_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Request is no longer active
    assert!(!state.active_requests.contains(&request_id));
}

#[test]
fn test_capability_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit a Deny capability
    let (cap1_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Deny),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Replace it with Auto capability
    let data = encode(&CapabilityData {
        actor_id: ACTOR.into(),
        action_class: "shell".into(),
        scope: SCOPE,
        mode: CapabilityMode::Auto,
        expiry: None,
    })
    .unwrap();
    let replacement = Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Capability,
        schema: schema_id(SCHEMA_CAPABILITY),
        data,
        refs: vec![Ref {
            type_: RefType::Replace,
            target: cap1_id,
        }],
    };

    let (cap2_id, v) = writer.commit(replacement, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Old capability should be replaced
    assert!(state.replaced_records.contains(&cap1_id));
    // New capability should be active
    let key = (ACTOR.to_string(), "shell".to_string(), SCOPE);
    assert_eq!(state.active_capabilities.get(&key), Some(&cap2_id));
}

#[test]
fn test_usage_counts_accumulation() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id1, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (action_id, v) = writer
        .commit(
            action_proposal_with_authority(request_id1, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Close the action
    let (result_id, v) = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Now we need a second request+action+result so we have two accepted results
    // to use as consuming_record. Actually, we need to commit a new request first
    // since the first one got completed.
    let (request_id2, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (action_id2, _) = writer
        .commit(
            action_proposal_with_authority(request_id2, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (result_id2, v) = writer
        .commit(result_proposal(action_id2), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Submit usage records
    let (_, v) = writer
        .commit(
            usage_proposal(action_id, result_id, UsageOutcome::Done),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (_, v) = writer
        .commit(
            usage_proposal(action_id, result_id2, UsageOutcome::NotDone),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Check usage counts
    let key = (action_id, "context".to_string());
    let counts = state.usage_counts.get(&key).unwrap();
    assert_eq!(counts.done, 1);
    assert_eq!(counts.not_done, 1);
    assert_eq!(counts.no_change, 0);
}

// ---------------------------------------------------------------------------
// Context tests
// ---------------------------------------------------------------------------

#[test]
fn test_context_excludes_verdicts_and_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit an request
    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Commit a capability, then replace it
    let (cap1_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Deny),
            &rules,
            &mut state,
        )
        .unwrap();

    let replacement_data = encode(&CapabilityData {
        actor_id: ACTOR.into(),
        action_class: "shell".into(),
        scope: SCOPE,
        mode: CapabilityMode::Auto,
        expiry: None,
    })
    .unwrap();
    let (cap2_id, _) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: human_author(),
                kind: Kind::Capability,
                schema: schema_id(SCHEMA_CAPABILITY),
                data: replacement_data,
                refs: vec![Ref {
                    type_: RefType::Replace,
                    target: cap1_id,
                }],
            },
            &rules,
            &mut state,
        )
        .unwrap();

    let ctx = build_context(writer.records(), &state, &rules, THREAD);

    // Context should not contain any Verdict records
    assert!(ctx.records.iter().all(|r| r.kind != Kind::Verdict));

    // Context should not contain the replaced capability
    let ctx_ids: BTreeSet<RecordId> = ctx.records.iter().map(|r| r.id).collect();
    assert!(!ctx_ids.contains(&cap1_id));

    // Context should contain the request and the replacement capability
    assert!(ctx_ids.contains(&request_id));
    assert!(ctx_ids.contains(&cap2_id));
}

#[test]
fn test_context_respects_max_records_cap() {
    let dir = tempfile::tempdir().unwrap();
    let small_rules = VerifierRules::new(SPACE, 2).with_author_role("human", AuthorType::User); // cap at 2
    let mut writer = LogWriter::open(dir.path(), &small_rules).unwrap();
    let mut state = State::default();

    // Commit 3 requests (each accepted)
    let (id1, _) = writer
        .commit(request_proposal(), &small_rules, &mut state)
        .unwrap();
    let (id2, _) = writer
        .commit(request_proposal(), &small_rules, &mut state)
        .unwrap();
    let (id3, _) = writer
        .commit(request_proposal(), &small_rules, &mut state)
        .unwrap();

    let ctx = build_context(writer.records(), &state, &small_rules, THREAD);

    // Should be capped at 2 records (most recent by time desc)
    assert_eq!(ctx.records.len(), 2);

    // Should contain the two most recent
    let ctx_ids: BTreeSet<RecordId> = ctx.records.iter().map(|r| r.id).collect();
    assert!(ctx_ids.contains(&id3));
    assert!(ctx_ids.contains(&id2));
    assert!(!ctx_ids.contains(&id1));
}

#[test]
fn test_context_includes_usage_feedback() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id1, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (action_id, v) = writer
        .commit(
            action_proposal_with_authority(request_id1, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (_result_id, _) = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();

    // Need a second result as consuming_record for usage
    let (request_id2, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (action_id2, _) = writer
        .commit(
            action_proposal_with_authority(request_id2, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (result_id2, _) = writer
        .commit(result_proposal(action_id2), &rules, &mut state)
        .unwrap();

    // Submit usage for action_id (which is in context since it's accepted)
    let (_, v) = writer
        .commit(
            usage_proposal(action_id, result_id2, UsageOutcome::Done),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let ctx = build_context(writer.records(), &state, &rules, THREAD);

    // action_id is in context, so its usage should appear in usage_feedback
    let key = (action_id, "context".to_string());
    assert!(ctx.usage_feedback.contains_key(&key));
    let counts = ctx.usage_feedback.get(&key).unwrap();
    assert_eq!(counts.done, 1);
}

#[test]
fn test_context_keeps_summary_and_sources() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (response_id, _) = writer
        .commit(response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    let (action_id, _) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (result_id, _) = writer
        .commit(result_proposal(action_id), &rules, &mut state)
        .unwrap();
    let (summary_id, summary_verdict) = writer
        .commit(
            summary_proposal(&[request_id, response_id, action_id, result_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(summary_verdict.result, VerdictResult::Accept);

    let ctx = build_context(writer.records(), &state, &rules, THREAD);
    let ctx_ids: BTreeSet<RecordId> = ctx.records.iter().map(|r| r.id).collect();

    assert!(ctx_ids.contains(&summary_id));
    assert!(ctx_ids.contains(&request_id));
    assert!(ctx_ids.contains(&response_id));
    assert!(ctx_ids.contains(&action_id));
    assert!(ctx_ids.contains(&result_id));
}

