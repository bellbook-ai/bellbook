// ---------------------------------------------------------------------------
// Author-role, authority-binding, revocation, and lifecycle regressions
// explicit request lifecycle, plan proof binding, approval exactly-one
// ---------------------------------------------------------------------------

/// The kind-to-author-type table is enforced: governance kinds cannot be
/// authored by the governed parties.
#[test]
fn test_author_role_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // A Provider-authored Approval must reject: the governed agent cannot
    // authorize itself.
    let mut approval = approval_class_proposal("shell", None, None);
    approval.author = provider_author();
    let (_, v) = writer.commit(approval, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));

    // An Executor-authored Capability must reject.
    let mut cap = capability_proposal(ACTOR, "shell", CapabilityMode::Auto);
    cap.author = executor_author();
    let (_, v) = writer.commit(cap, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));

    // A Provider-authored Request must reject: objectives come from the
    // principal.
    let mut req = request_proposal();
    req.author = provider_author();
    let (_, v) = writer.commit(req, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));
}

/// An action that does not Require-ref the capability that authorizes it
/// rejects: the record graph must show which authority was used.
#[test]
fn test_action_requires_authority_ref() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (_, v) = writer
        .commit(action_proposal(request_id, "shell"), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorityRefMissing));
}

/// Retracting a capability deactivates it operationally (it stops
/// authorizing future actions) and taints prior actions that used it.
#[test]
fn test_retracted_capability_stops_authorizing() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");
    let (action1, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (_, v) = writer
        .commit(retraction_proposal(cap_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Operationally deactivated, not just epistemically marked.
    let key = (ACTOR.to_string(), "shell".to_string(), SCOPE);
    assert!(!state.active_capabilities.contains_key(&key));
    // The prior action rested on the retracted grant (Require edge).
    assert!(state.tainted_records.contains(&action1));

    // A new action can no longer use the retracted grant.
    let (_, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    // The generic Require rule fires first: a Require ref to a retracted
    // record is unsatisfiable (SPEC section 2).
    assert_eq!(v.reason, Some(ReasonCode::RefUnresolved));

    // Incremental fold and full rebuild agree after deactivation.
    let rebuilt = build_state_unchecked(writer.records()).unwrap();
    assert_eq!(rebuilt, state);
}

/// Retracting an approval deactivates it: later Ask-mode actions reject
/// with ApprovalMissing.
#[test]
fn test_retracted_approval_stops_authorizing() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, v) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Ask),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (approval_id, v) = writer
        .commit(
            approval_class_proposal("shell", Some(ACTOR), None),
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
    assert_eq!(v.result, VerdictResult::Accept);

    let (_, v) = writer
        .commit(retraction_proposal(approval_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert!(state.class_approvals.is_empty());

    let (_, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id, approval_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    // Generic Require rule: the retracted approval cannot be required.
    assert_eq!(v.reason, Some(ReasonCode::RefUnresolved));
}

/// A sequential workflow permits a second action after the
/// first result must be accepted - a request only completes on its
/// explicit closing response.
#[test]
fn test_sequential_actions_across_results() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");

    let (a1, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, v) = writer
        .commit(result_proposal(a1), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Sequential follow-up work on the same request.
    let (a2, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, v) = writer
        .commit(result_proposal(a2), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Explicit completion, then no further work.
    let (_, v) = writer
        .commit(closing_response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::RequestMissing));
}

/// Response turns are gap-free and in order, and a closing response is
/// only valid with no open actions.
#[test]
fn test_response_turn_ordering_and_closure() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, cap_id) =
        setup_request_and_capability(&mut writer, &rules, &mut state, "shell");

    // Out-of-order turn rejects.
    let (_, v) = writer
        .commit(response_proposal(request_id, 1), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));

    let (_, v) = writer
        .commit(response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Duplicate turn rejects.
    let (_, v) = writer
        .commit(response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);

    // A closing response while an action is open rejects.
    let (a1, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, v) = writer
        .commit(closing_response_proposal(request_id, 1), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));

    // Close the action, then the closing response is valid.
    let (_, v) = writer
        .commit(result_proposal(a1), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, v) = writer
        .commit(closing_response_proposal(request_id, 1), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert!(!state.active_requests.contains(&request_id));
}

/// A Completed plan cannot cite nonexistent, foreign, or premature proof.
#[test]
fn test_plan_proof_binding() {
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
    let (result_id, v) = writer
        .commit(result_proposal(a1), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let task = |status: TaskStatus, result_record_id: Option<RecordId>| PlanTask {
        id: "t1".into(),
        description: "do the work".into(),
        kind: PlanTaskKind::Generic,
        tool_hint: None,
        inputs_from: vec![],
        produces: None,
        done_when: TaskDoneWhen::ToolSuccess,
        status,
        result_record_id,
        depends_on: vec![],
        on_failure: FailurePolicy::Abort,
    };

    // Valid: Done task bound to the real, accepted, same-request Result.
    let (_, v) = writer
        .commit(
            plan_proposal(
                request_id,
                vec![task(TaskStatus::Done, Some(result_id))],
                PlanStatus::Completed,
            ),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Nonexistent proof rejects.
    let (_, v) = writer
        .commit(
            plan_proposal(
                request_id,
                vec![task(TaskStatus::Done, Some([9u8; 32]))],
                PlanStatus::Completed,
            ),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));

    // A non-terminal task carrying proof rejects.
    let (_, v) = writer
        .commit(
            plan_proposal(
                request_id,
                vec![task(TaskStatus::Running, Some(result_id))],
                PlanStatus::Running,
            ),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);

    // inputs_from must name real tasks.
    let mut bad_inputs = task(TaskStatus::Pending, None);
    bad_inputs.inputs_from = vec!["ghost".into()];
    let (_, v) = writer
        .commit(
            plan_proposal(request_id, vec![bad_inputs], PlanStatus::Running),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);

    // Proof from a different request rejects.
    let (request2, v) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, v) = writer
        .commit(
            plan_proposal(
                request2,
                vec![task(TaskStatus::Done, Some(result_id))],
                PlanStatus::Completed,
            ),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
}

/// Exactly one approval form: carrying both exact and class fields would
/// silently broaden one authorization into two.
#[test]
fn test_approval_both_forms_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let data = encode(&ApprovalData {
        target_action: Some([9u8; 32]),
        action_class: Some("shell".into()),
        scope: SCOPE,
        actor_id: None,
        expiry: None,
    })
    .unwrap();
    let (_, v) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: human_author(),
                kind: Kind::Approval,
                schema: schema_id(SCHEMA_APPROVAL),
                data,
                refs: vec![],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));
}

/// A summary with no Use refs is an unfounded claim and rejects; usage
/// payload actor must match the envelope author.
#[test]
fn test_summary_needs_sources_and_usage_actor_binding() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (_, v) = writer
        .commit(summary_proposal(&[]), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));

    // Usage whose payload actor differs from the record author rejects.
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
    let mut usage = usage_proposal(request_id, result_id, UsageOutcome::Done);
    usage.data = encode(&UsageData {
        actor: "someone-else".into(),
        used_record: request_id,
        consuming_record: result_id,
        role: "context".into(),
        outcome: UsageOutcome::Done,
    })
    .unwrap();
    let (_, v) = writer.commit(usage, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));
}

