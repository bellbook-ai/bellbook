// ---------------------------------------------------------------------------
// Retraction and taint
// ---------------------------------------------------------------------------

fn retraction_proposal(target_id: RecordId) -> Proposal {
    let data = encode(&RetractionData {
        target_id,
        reason: "contradicted by real-world outcome".into(),
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Retraction,
        schema: schema_id(SCHEMA_RETRACTION),
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: target_id,
        }],
    }
}

/// The SPEC §7.1 worked example: a Result later contradicted by outcome is
/// retracted; the Summary that used it becomes tainted. The tainted chain
/// still replays as Accept, and the report surfaces both sets.
#[test]
fn test_retraction_taints_use_dependents() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "tool", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    let (aid, _) = writer
        .commit(
            action_proposal_with_authority(rid, "tool", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (res_id, _) = writer
        .commit(result_proposal(aid), &rules, &mut state)
        .unwrap();

    // Summary that epistemically depends on the result via a Use ref.
    let mut summary = summary_proposal(&[res_id]);
    summary.refs.push(Ref {
        type_: RefType::Use,
        target: res_id,
    });
    let (sid, sv) = writer.commit(summary, &rules, &mut state).unwrap();
    assert_eq!(sv.result, VerdictResult::Accept);

    // Retract the result.
    let (_, rv) = writer
        .commit(retraction_proposal(res_id), &rules, &mut state)
        .unwrap();
    assert_eq!(rv.result, VerdictResult::Accept);

    assert!(state.retracted_records.contains(&res_id));
    assert!(state.tainted_records.contains(&sid));
    // The retracted record itself is retracted, not tainted-by-dependence.
    assert!(!state.tainted_records.contains(&res_id));

    // Honest history stays verifiable: replay still accepts and the report
    // surfaces the retracted/tainted ids.
    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
    assert!(report.retracted_records.contains(&res_id));
    assert!(report.tainted_records.contains(&sid));

    // Incremental fold and full rebuild agree on taint.
    let rebuilt = build_state_unchecked(writer.records()).unwrap();
    assert_eq!(rebuilt, state);

    // Context excludes both the retracted result and, by default, the
    // tainted summary; IncludeTainted opts back in with labeling.
    let ctx = build_context(writer.records(), &state, &rules, THREAD);
    assert!(!ctx.records.iter().any(|r| r.id == res_id));
    assert!(!ctx.records.iter().any(|r| r.id == sid));
    let ctx = build_context_with(
        writer.records(),
        &state,
        &rules,
        THREAD,
        ContextPolicy::IncludeTainted,
    );
    assert!(ctx.records.iter().any(|r| r.id == sid));
    assert!(ctx.tainted_records.contains(&sid));
}

/// Cause refs are provenance, not epistemic dependence: retracting an
/// Action does not taint the Result that closed it.
#[test]
fn test_retraction_does_not_taint_cause_dependents() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "tool", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    let (aid, _) = writer
        .commit(
            action_proposal_with_authority(rid, "tool", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (res_id, _) = writer
        .commit(result_proposal(aid), &rules, &mut state)
        .unwrap();

    let (_, rv) = writer
        .commit(retraction_proposal(aid), &rules, &mut state)
        .unwrap();
    assert_eq!(rv.result, VerdictResult::Accept);

    assert!(state.retracted_records.contains(&aid));
    // The result Cause-refs the action but does not rest on its content.
    assert!(!state.tainted_records.contains(&res_id));
}

/// A record committed *after* a retraction that Use-refs the retracted
/// record derives floor evidence (Assumed) and is tainted immediately.
#[test]
fn test_use_of_retracted_record_degrades_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "tool", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    let (aid, _) = writer
        .commit(
            action_proposal_with_authority(rid, "tool", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (res_id, _) = writer
        .commit(result_proposal(aid), &rules, &mut state)
        .unwrap();
    writer
        .commit(retraction_proposal(res_id), &rules, &mut state)
        .unwrap();

    let mut summary = summary_proposal(&[res_id]);
    summary.refs.push(Ref {
        type_: RefType::Use,
        target: res_id,
    });
    let (sid, sv) = writer.commit(summary, &rules, &mut state).unwrap();
    assert_eq!(sv.result, VerdictResult::Accept);
    let committed = writer.get(sid).unwrap();
    assert_eq!(committed.evidence, Evidence::Assumed);
    assert!(state.tainted_records.contains(&sid));

    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// Taint cascades transitively through chains of Use refs.
#[test]
fn test_taint_cascades_transitively() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "tool", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    let (aid, _) = writer
        .commit(
            action_proposal_with_authority(rid, "tool", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (res_id, _) = writer
        .commit(result_proposal(aid), &rules, &mut state)
        .unwrap();

    // summary1 uses the result; summary2 uses summary1.
    let mut s1 = summary_proposal(&[res_id]);
    s1.refs.push(Ref {
        type_: RefType::Use,
        target: res_id,
    });
    let (s1_id, _) = writer.commit(s1, &rules, &mut state).unwrap();

    let mut s2 = summary_proposal(&[s1_id]);
    s2.refs.push(Ref {
        type_: RefType::Use,
        target: s1_id,
    });
    let (s2_id, _) = writer.commit(s2, &rules, &mut state).unwrap();

    writer
        .commit(retraction_proposal(res_id), &rules, &mut state)
        .unwrap();

    assert!(state.tainted_records.contains(&s1_id));
    assert!(state.tainted_records.contains(&s2_id));
}

/// Retracting a Verdict, a Retraction, or a rejected record is invalid.
#[test]
fn test_retraction_invalid_targets() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let verdict_id = writer.records()[1].id;

    // Verdict target.
    let (_, v) = writer
        .commit(retraction_proposal(verdict_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::InvalidPayload));

    // Rejected record target: an action with no capability is rejected.
    let (bad_aid, bad_v) = writer
        .commit(action_proposal(rid, "no_cap_tool"), &rules, &mut state)
        .unwrap();
    assert_eq!(bad_v.result, VerdictResult::Reject);
    let (_, v2) = writer
        .commit(retraction_proposal(bad_aid), &rules, &mut state)
        .unwrap();
    assert_eq!(v2.result, VerdictResult::Reject);

    // Retraction-of-retraction target.
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "tool", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    let (aid, _) = writer
        .commit(
            action_proposal_with_authority(rid, "tool", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    let (res_id, _) = writer
        .commit(result_proposal(aid), &rules, &mut state)
        .unwrap();
    let (retr_id, rv) = writer
        .commit(retraction_proposal(res_id), &rules, &mut state)
        .unwrap();
    assert_eq!(rv.result, VerdictResult::Accept);
    let (_, v3) = writer
        .commit(retraction_proposal(retr_id), &rules, &mut state)
        .unwrap();
    assert_eq!(v3.result, VerdictResult::Reject);

    // The whole log - including the rejected retractions - still replays.
    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// Regression: checkpointing a state with tuple-keyed entries (capabilities,
/// class approvals, usage counts) must serialize. Under 0.1 these maps hit
/// serde_json's "key must be a string" and checkpoint creation failed.
#[test]
fn test_checkpoint_with_populated_tuple_key_maps() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "tool", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    writer
        .commit(
            approval_class_proposal("tool", None, None),
            &rules,
            &mut state,
        )
        .unwrap();

    let cp = create_checkpoint(writer.records(), &state).unwrap();

    let (aid, _) = writer
        .commit(
            action_proposal_with_authority(rid, "tool", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    writer
        .commit(result_proposal(aid), &rules, &mut state)
        .unwrap();

    let log_verdict = verify_log(
        writer.records(),
        &rules,
        Some(&TrustedCheckpoint::assume_verified(cp, &rules).unwrap()),
    );
    assert_eq!(log_verdict.result, VerdictResult::Accept);

    // State also round-trips through its serialized form.
    let bytes = serde_json::to_vec(&state).unwrap();
    let back: State = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, state);
}

