// ---------------------------------------------------------------------------
// Identity-to-role and exact-approval binding regressions
// single use, retraction ownership, generic Require semantics
// ---------------------------------------------------------------------------

/// The adversarial impersonation case: a registered Provider (even with a
/// pinned signing key, validly signed) cannot author an Approval by
/// declaring itself User - the identity-to-role binding rejects it.
#[test]
fn test_registered_provider_cannot_impersonate_user() {
    let dir = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::from_secret_bytes(&[11u8; 32]);
    let mut rules = test_rules();
    rules
        .author_keys
        .insert(ACTOR.into(), [signer.public_key()].into_iter().collect());
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Unsigned impersonation: agent claims User on an Approval.
    let mut approval = approval_class_proposal("shell", None, None);
    approval.author = Author {
        id: ACTOR.into(),
        type_: AuthorType::User,
        signature: None,
    };
    let (_, v) = writer.commit(approval, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));

    // Signed impersonation: the pinned Provider key signs an Approval
    // declaring User. The signature verifies; the role binding rejects.
    let mut approval = approval_class_proposal("shell", None, None);
    approval.author = Author {
        id: ACTOR.into(),
        type_: AuthorType::User,
        signature: None,
    };
    let (_, v) = writer
        .commit_signed(approval, &rules, &mut state, &signer)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));

    // An unregistered actor cannot author authority/work kinds at all.
    let mut cap = capability_proposal(ACTOR, "shell", CapabilityMode::Auto);
    cap.author = Author {
        id: "stranger".into(),
        type_: AuthorType::User,
        signature: None,
    };
    let (_, v) = writer.commit(cap, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));
}

/// Exact approvals are bound to one actor's one action and are single
/// use: a second identical action needs a fresh approval, and another
/// actor's identical action data never matches.
#[test]
fn test_exact_approval_single_use_and_actor_bound() {
    let dir = tempfile::tempdir().unwrap();
    let mut rules = test_rules();
    rules
        .author_roles
        .insert("agent2".into(), AuthorType::Provider);
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
    // Second provider with its own Ask capability.
    let (cap2_id, _) = writer
        .commit(
            capability_proposal("agent2", "shell", CapabilityMode::Ask),
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
    let (approval_id, v) = writer
        .commit(
            approval_exact_proposal(ACTOR, &action_data),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Another actor with byte-identical action data cannot use it.
    let mut foreign = action_proposal_with_authority(request_id, "shell", &[cap2_id, approval_id]);
    foreign.author = Author {
        id: "agent2".into(),
        type_: AuthorType::Provider,
        signature: None,
    };
    let (_, v) = writer.commit(foreign, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::ApprovalMissing));

    // The approved actor uses it once...
    let (_, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id, approval_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    // ...and it is consumed: the identical action again is unapproved.
    let (_, v) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id, approval_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::ApprovalMissing));

    // Incremental fold and full rebuild agree on consumption.
    let rebuilt = build_state_unchecked(writer.records()).unwrap();
    assert_eq!(rebuilt, state);
}

/// Retraction is ownership-bound: a Provider cannot retract a User's
/// Capability or an Executor's Result; it can retract its own records,
/// and a configured administrator can retract anything retractable.
#[test]
fn test_retraction_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules(); // admin_retraction_actors = {"human"}
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

    // Provider retracting the User's capability: rejected.
    let mut r = retraction_proposal(cap_id);
    r.author = provider_author();
    let (_, v) = writer.commit(r, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));
    // The capability is untouched.
    let key = (ACTOR.to_string(), "shell".to_string(), SCOPE);
    assert!(state.active_capabilities.contains_key(&key));

    // Provider retracting the Executor's result: rejected.
    let mut r = retraction_proposal(result_id);
    r.author = provider_author();
    let (_, v) = writer.commit(r, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::AuthorRoleInvalid));

    // Provider retracting its own summary: accepted.
    let mut r = retraction_proposal(summary_id);
    r.author = provider_author();
    let (_, v) = writer.commit(r, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // The human administrator can retract the executor's result.
    let (_, v) = writer
        .commit(retraction_proposal(result_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
}

/// Generic Require semantics: a Require ref must name accepted,
/// non-retracted, non-tainted state - on any kind of record.
#[test]
fn test_require_ref_must_target_accepted_state() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // A rejected record (response to a nonexistent request).
    let (rejected_id, v) = writer
        .commit(response_proposal([9u8; 32], 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);

    // Any record Require-refing it must reject, generically.
    let mut req = request_proposal();
    req.refs = vec![Ref {
        type_: RefType::Require,
        target: rejected_id,
    }];
    let (_, v) = writer.commit(req, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::RefUnresolved));

    // A Use ref to the rejected record stays legal but contributes floor
    // evidence: the summary derives Assumed.
    let mut summary = summary_proposal(&[rejected_id]);
    summary.refs = vec![Ref {
        type_: RefType::Use,
        target: rejected_id,
    }];
    let (sid, v) = writer.commit(summary, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert_eq!(writer.get(sid).unwrap().evidence, Evidence::Assumed);
}

/// A closing Response cannot strand a running Plan: the plan must reach
/// Completed or Abandoned first.
#[test]
fn test_closing_response_requires_settled_plan() {
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

    let task = |status: TaskStatus, result_record_id: Option<RecordId>| PlanTask {
        id: "t1".into(),
        description: "the work".into(),
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

    // Running plan on the request.
    let (_, v) = writer
        .commit(
            plan_proposal(
                request_id,
                vec![task(TaskStatus::Running, None)],
                PlanStatus::Running,
            ),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Closing response while the plan runs: rejected.
    let (_, v) = writer
        .commit(closing_response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));

    // Complete the plan, then closing is valid.
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
    let (_, v) = writer
        .commit(closing_response_proposal(request_id, 0), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    assert!(!state.active_requests.contains(&request_id));
}

