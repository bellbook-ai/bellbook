// ---------------------------------------------------------------------------
// Author-registration and action/request-scope regressions
// exact-approval scope consistency
// ---------------------------------------------------------------------------

/// Every non-Verdict kind requires a registered author: unregistered
/// actors cannot close requests with Refusals, inject Summaries, skew
/// Usage feedback, or retract records - even with a plausible declared
/// type.
#[test]
fn test_unregistered_actors_cannot_author_control_records() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
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

    let stranger = |type_: AuthorType| Author {
        id: "stranger".into(),
        type_,
        signature: None,
    };

    // Unregistered "User" Refusal against the request.
    let mut refusal = refusal_request_proposal(request_id);
    refusal.author = stranger(AuthorType::User);
    let (_, v) = writer.commit(refusal, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));
    assert!(state.active_requests.contains(&request_id));

    // Unregistered "Provider" Summary.
    let mut summary = summary_proposal(&[result_id]);
    summary.author = stranger(AuthorType::Provider);
    let (_, v) = writer.commit(summary, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));

    // Unregistered "Provider" Usage feedback.
    let mut usage = usage_proposal(request_id, result_id, UsageOutcome::Done);
    usage.author = stranger(AuthorType::Provider);
    usage.data = encode(&UsageData {
        actor: "stranger".into(),
        used_record: request_id,
        consuming_record: result_id,
        role: "context".into(),
        outcome: UsageOutcome::Done,
    })
    .unwrap();
    let (_, v) = writer.commit(usage, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));

    // Unregistered Retraction (even of a record it could otherwise own).
    let mut retraction = retraction_proposal(result_id);
    retraction.author = stranger(AuthorType::User);
    let (_, v) = writer.commit(retraction, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));
}

/// A capability for scope B must not let the provider serve a scope-A
/// request with a scope-B action.
#[test]
fn test_action_must_match_request_scope() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Request operates in SCOPE (scope A).
    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Valid capability in a different scope B.
    let scope_b: [u8; 32] = [77u8; 32];
    let (cap_id, v) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: human_author(),
                kind: Kind::Capability,
                schema: schema_id(SCHEMA_CAPABILITY),
                data: encode(&CapabilityData {
                    actor_id: ACTOR.into(),
                    action_class: "shell".into(),
                    scope: scope_b,
                    mode: CapabilityMode::Auto,
                    expiry: None,
                })
                .unwrap(),
                refs: vec![],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Action in scope B against the scope-A request: rejected.
    let (_, v) = writer
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
                    scope: scope_b,
                    exec_mode: ExecMode::Internal,
                    params: serde_json::json!({}),
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
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));
}

/// An exact approval whose declared scope differs from the action's is
/// unusable, even if its target hash would match.
#[test]
fn test_exact_approval_scope_must_match_action() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Ask),
            &rules,
            &mut state,
        )
        .unwrap();

    let action_data = ActionData {
        request_id,
        action_class: "shell".into(),
        scope: SCOPE,
        exec_mode: ExecMode::Internal,
        params: serde_json::json!({}),
    };

    // Approval with the correct target hash but a different declared
    // scope: the hash matches, the declaration does not.
    let target_hash = sha256_canonical(&(&ACTOR.to_string(), &action_data)).unwrap();
    let (approval_id, v) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: human_author(),
                kind: Kind::Approval,
                schema: schema_id(SCHEMA_APPROVAL),
                data: encode(&ApprovalData {
                    target_action: Some(target_hash),
                    action_class: None,
                    scope: [88u8; 32],
                    actor_id: Some(ACTOR.into()),
                    expiry: None,
                })
                .unwrap(),
                refs: vec![],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (_, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id, approval_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::ApprovalMissing));
}

