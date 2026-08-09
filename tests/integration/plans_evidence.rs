// ---------------------------------------------------------------------------
// Plan rules - task graphs
// ---------------------------------------------------------------------------

fn plan_task(id: &str, depends_on: Vec<&str>, status: TaskStatus) -> PlanTask {
    PlanTask {
        id: id.into(),
        description: format!("task {id}"),
        kind: PlanTaskKind::Generic,
        tool_hint: None,
        inputs_from: vec![],
        produces: None,
        done_when: TaskDoneWhen::ToolSuccess,
        status,
        result_record_id: None,
        depends_on: depends_on.into_iter().map(String::from).collect(),
        on_failure: FailurePolicy::Continue,
    }
}

fn plan_proposal(request_id: RecordId, tasks: Vec<PlanTask>, status: PlanStatus) -> Proposal {
    let data = encode(&PlanData {
        request_id,
        tasks,
        status,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: provider_author(),
        kind: Kind::Plan,
        schema: schema_id(SCHEMA_PLAN),
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: request_id,
        }],
    }
}

/// A well-formed plan (acyclic dependencies, running status) for an active
/// request is accepted and becomes the request's active plan.
#[test]
fn test_plan_accepted_and_tracked() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let tasks = vec![
        plan_task("a", vec![], TaskStatus::Running),
        plan_task("b", vec!["a"], TaskStatus::Pending),
    ];
    let (pid, verdict) = writer
        .commit(
            plan_proposal(rid, tasks, PlanStatus::Running),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);
    assert_eq!(state.active_plans.get(&rid), Some(&pid));
}

/// Structural plan violations reject with InvalidPayload: cyclic
/// dependencies, unknown dependency ids, duplicate task ids, empty task
/// lists, and statuses inconsistent with the task states.
#[test]
fn test_plan_structural_violations_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let cases: Vec<(&str, Vec<PlanTask>, PlanStatus)> = vec![
        (
            "dependency cycle",
            vec![
                plan_task("a", vec!["b"], TaskStatus::Pending),
                plan_task("b", vec!["a"], TaskStatus::Pending),
            ],
            PlanStatus::Running,
        ),
        (
            "unknown dependency id",
            vec![plan_task("a", vec!["ghost"], TaskStatus::Pending)],
            PlanStatus::Running,
        ),
        (
            "duplicate task ids",
            vec![
                plan_task("a", vec![], TaskStatus::Pending),
                plan_task("a", vec![], TaskStatus::Pending),
            ],
            PlanStatus::Running,
        ),
        ("empty task list", vec![], PlanStatus::Running),
        (
            "completed plan with non-done task",
            vec![plan_task("a", vec![], TaskStatus::Failed)],
            PlanStatus::Completed,
        ),
        (
            "running plan with all tasks terminal",
            vec![plan_task("a", vec![], TaskStatus::Done)],
            PlanStatus::Running,
        ),
        (
            "abandoned plan with nothing failed or skipped",
            vec![plan_task("a", vec![], TaskStatus::Done)],
            PlanStatus::Abandoned,
        ),
    ];

    for (label, tasks, status) in cases {
        let (_, verdict) = writer
            .commit(plan_proposal(rid, tasks, status), &rules, &mut state)
            .unwrap();
        assert_eq!(verdict.result, VerdictResult::Reject, "{label}");
        assert_eq!(verdict.reason, Some(ReasonCode::InvalidPayload), "{label}");
    }
}

/// A plan naming a request that is not active rejects with RequestMissing.
#[test]
fn test_plan_requires_active_request() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    // Commit a request, then cancel it via Refusal so it is inactive.
    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let refusal = Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Refusal,
        schema: schema_id(SCHEMA_REFUSAL),
        data: encode(&RefusalData {
            target_id: rid,
            target_kind: RefusalTarget::Request,
            reason_code: None,
        })
        .unwrap(),
        refs: vec![Ref {
            type_: RefType::Cause,
            target: rid,
        }],
    };
    let (_, v) = writer.commit(refusal, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let tasks = vec![plan_task("a", vec![], TaskStatus::Pending)];
    let (_, verdict) = writer
        .commit(
            plan_proposal(rid, tasks, PlanStatus::Running),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::RequestMissing));
}

/// A completed plan is accepted and clears the request's active-plan slot.
#[test]
fn test_plan_completion_clears_active_plan() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let (pid, v1) = writer
        .commit(
            plan_proposal(
                rid,
                vec![plan_task("a", vec![], TaskStatus::Running)],
                PlanStatus::Running,
            ),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v1.result, VerdictResult::Accept);
    assert_eq!(state.active_plans.get(&rid), Some(&pid));

    // Replace the running plan with a completed one.
    let mut done = plan_proposal(
        rid,
        vec![plan_task("a", vec![], TaskStatus::Done)],
        PlanStatus::Completed,
    );
    done.refs.push(Ref {
        type_: RefType::Replace,
        target: pid,
    });
    let (_, v2) = writer.commit(done, &rules, &mut state).unwrap();
    assert_eq!(v2.result, VerdictResult::Accept);
    assert!(!state.active_plans.contains_key(&rid));
    assert!(state.replaced_records.contains(&pid));
}

// ---------------------------------------------------------------------------
// Evidence thresholds (EvidenceBelowThreshold)
// ---------------------------------------------------------------------------

/// A summary whose derived evidence is weaker than the configured threshold
/// is rejected with EvidenceBelowThreshold; the rejection replays identically.
#[test]
fn test_evidence_below_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let mut rules = test_rules();
    // Summaries must rest on Deterministic or Verified inputs only.
    rules
        .evidence_thresholds
        .insert(Kind::Summary, Evidence::Verified);
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Summary base evidence is Inferred, weaker than Verified: rejected.
    let (sid, verdict) = writer
        .commit(summary_proposal(&[rid]), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::EvidenceBelowThreshold));
    assert!(!state.accepted_records.contains(&sid));

    // The rejected record stays in the log and the whole log still replays.
    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// Without a configured threshold the same summary is accepted.
#[test]
fn test_evidence_threshold_absent_accepts() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (_, verdict) = writer
        .commit(summary_proposal(&[rid]), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);
}

