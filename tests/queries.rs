//! The named query set q1-q7 (RFC-0002) over a real log: the
//! broken-benchmark shape (root, continuation, derivations at depth, a
//! motivated-by repair, a retraction, and a restoring reaffirmation), which
//! exercises every annotation a query can emit. Assertions pin exact ids
//! and orders, not just counts.

#![cfg(feature = "persist")]

use bellbook::*;

fn cause_ref(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Cause,
        target,
    }
}
fn use_ref(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Use,
        target,
    }
}
fn require_ref(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Require,
        target,
    }
}
fn replace_ref(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Replace,
        target,
    }
}

fn source(tree: &str) -> SourceBinding {
    SourceBinding {
        git: GitSource {
            algo: SourceAlgo::Sha1,
            tree: tree.into(),
            commit: None,
        },
        manifest_hash: None,
        binding: BindingMode::Reported,
    }
}

#[allow(clippy::too_many_arguments)]
fn commit<T: serde::Serialize>(
    writer: &mut LogWriter,
    rules: &VerifierRules,
    state: &mut State,
    author_id: &str,
    kind: Kind,
    schema: &str,
    payload: &T,
    refs: Vec<Ref>,
    space: SpaceId,
    expect_accept: bool,
) -> RecordId {
    let (id, verdict) = writer
        .commit(
            Proposal {
                space,
                thread: space,
                author: Author {
                    id: author_id.into(),
                    type_: AuthorType::Provider,
                    signature: None,
                },
                kind,
                schema: schema_id(schema),
                data: encode(payload).unwrap(),
                refs,
            },
            rules,
            state,
        )
        .unwrap();
    assert_eq!(
        verdict.result == VerdictResult::Accept,
        expect_accept,
        "unexpected verdict for {kind:?}: {:?}",
        verdict.reason
    );
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    records: Vec<Record>,
    rules: VerifierRules,
    c0: RecordId,
    bench0: RecordId,
    s0: RecordId,
    c1: RecordId,
    c2: RecordId,
    c2b: RecordId,
    c3: RecordId,
    c4: RecordId,
    c5: RecordId,
    review0: RecordId,
    s1: RecordId,
    rejected: RecordId,
}

/// The broken-benchmark story plus a derivation sibling (c2b) and one
/// rejected record (a cross-author retraction attempt).
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let space = default_space();
    let rules = VerifierRules::new(space, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("benchmark", AuthorType::Provider)
        .with_author_role("reviewer", AuthorType::Provider);
    let mut w = LogWriter::open(dir.path(), &rules).unwrap();
    let mut st = State::default();

    let cand = |src: &str, basis: CandidateBasis, parent: Option<RecordId>| CandidateData {
        artifacts: None,
        source: source(src),
        basis,
        parent,
        note: None,
    };

    let c0 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &cand(
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            CandidateBasis::Root,
            None,
        ),
        vec![],
        space,
        true,
    );
    let bench0 = commit(
        &mut w,
        &rules,
        &mut st,
        "benchmark",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        &EvaluationData {
            candidate: c0,
            criterion: "bench-suite".into(),
            procedure: None,
            outcome: EvaluationOutcome::Passed,
        },
        vec![use_ref(c0)],
        space,
        true,
    );
    let s0 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        &SelectionData {
            objective: "adopt-baseline".into(),
            considered: vec![c0],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c0],
            },
            rationale: None,
        },
        vec![require_ref(c0), use_ref(bench0)],
        space,
        true,
    );
    let c1 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &cand(
            "1111111111111111111111111111111111111111",
            CandidateBasis::Continuation,
            Some(c0),
        ),
        vec![cause_ref(s0)],
        space,
        true,
    );
    let c2 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &cand(
            "2222222222222222222222222222222222222222",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause_ref(c1)],
        space,
        true,
    );
    // A sibling of c2: same derivation cause set {c1}.
    let c2b = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &cand(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause_ref(c1)],
        space,
        true,
    );
    let c3 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &cand(
            "3333333333333333333333333333333333333333",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause_ref(c2)],
        space,
        true,
    );
    // The motivated-by repair: derives from sound c0, Cause to the benchmark.
    let c4 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &cand(
            "4444444444444444444444444444444444444444",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause_ref(c0), cause_ref(bench0)],
        space,
        true,
    );
    // The benchmark retracts its own evaluation.
    commit(
        &mut w,
        &rules,
        &mut st,
        "benchmark",
        Kind::Retraction,
        SCHEMA_RETRACTION,
        &RetractionData {
            target_id: bench0,
            reason: "harness measured the wrong thing".into(),
        },
        vec![cause_ref(bench0)],
        space,
        true,
    );
    // Work continues under compromise.
    let c5 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &cand(
            "5555555555555555555555555555555555555555",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause_ref(c3)],
        space,
        true,
    );
    // Recovery: surviving evidence plus a reaffirming Selection.
    let review0 = commit(
        &mut w,
        &rules,
        &mut st,
        "reviewer",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        &EvaluationData {
            candidate: c0,
            criterion: "manual-review".into(),
            procedure: None,
            outcome: EvaluationOutcome::Passed,
        },
        vec![use_ref(c0)],
        space,
        true,
    );
    let s1 = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        &SelectionData {
            objective: "adopt-baseline".into(),
            considered: vec![c0],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c0],
            },
            rationale: None,
        },
        vec![require_ref(c0), use_ref(review0), replace_ref(s0)],
        space,
        true,
    );
    // A rejected record: the agent may not retract the reviewer's record.
    let rejected = commit(
        &mut w,
        &rules,
        &mut st,
        "agent",
        Kind::Retraction,
        SCHEMA_RETRACTION,
        &RetractionData {
            target_id: review0,
            reason: "not mine to retract".into(),
        },
        vec![cause_ref(review0)],
        space,
        false,
    );

    Fixture {
        records: w.records().to_vec(),
        _dir: dir,
        rules,
        c0,
        bench0,
        s0,
        c1,
        c2,
        c2b,
        c3,
        c4,
        c5,
        review0,
        s1,
        rejected,
    }
}

fn hex(id: &RecordId) -> String {
    hex_encode(id)
}

#[test]
fn queries_refuse_an_unverified_log() {
    let f = fixture();
    // The same records under rules that never registered the authors: the
    // replay rejects, and so must the query context.
    let wrong = VerifierRules::new(default_space(), 200);
    match Queries::new(&f.records, &wrong) {
        Err(QueryError::LogInvalid(_)) => {}
        Err(other) => panic!("expected LogInvalid, got {other:?}"),
        Ok(_) => panic!("expected LogInvalid, got a query context"),
    }
}

#[test]
fn descent_walks_continuations_and_derivations_with_annotations() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    let d = q.descent(f.c5).unwrap();
    let line: Vec<(String, String)> = d
        .line
        .iter()
        .map(|s| (s.node.id.clone(), s.via.clone()))
        .collect();
    assert_eq!(
        line,
        vec![
            (hex(&f.c3), "derivation".into()),
            (hex(&f.c2), "derivation".into()),
            (hex(&f.c1), "derivation".into()),
            (hex(&f.s0), "continuation-anchor".into()),
            (hex(&f.c0), "parent".into()),
        ]
    );
    // Annotations at the final state: the line is restored (nothing
    // compromised), s0 stays unsound and tainted, permanently.
    let s0_step = d.line.iter().find(|s| s.node.id == hex(&f.s0)).unwrap();
    assert_eq!(s0_step.node.standing, "unsound");
    assert!(s0_step.node.tainted);
    let c2_step = d.line.iter().find(|s| s.node.id == hex(&f.c2)).unwrap();
    assert_eq!(c2_step.node.standing, "sound");
}

#[test]
fn descent_of_a_motivated_repair_excludes_the_evaluation() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();
    // c4 derives from c0 and names the benchmark evaluation as motivation;
    // structure follows candidates only.
    let d = q.descent(f.c4).unwrap();
    let ids: Vec<String> = d.line.iter().map(|s| s.node.id.clone()).collect();
    assert_eq!(ids, vec![hex(&f.c0)]);
}

#[test]
fn descendants_are_the_forward_closure_in_log_order() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    let of_s0 = q.descendants(f.s0).unwrap();
    let ids: Vec<String> = of_s0.descendants.iter().map(|n| n.id.clone()).collect();
    assert_eq!(
        ids,
        vec![hex(&f.c1), hex(&f.c2), hex(&f.c2b), hex(&f.c3), hex(&f.c5)]
    );

    let of_c0 = q.descendants(f.c0).unwrap();
    let ids: Vec<String> = of_c0.descendants.iter().map(|n| n.id.clone()).collect();
    assert_eq!(
        ids,
        vec![
            hex(&f.c1),
            hex(&f.c2),
            hex(&f.c2b),
            hex(&f.c3),
            hex(&f.c4),
            hex(&f.c5)
        ]
    );
}

#[test]
fn siblings_share_the_exact_cause_target_set() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    let s = q.siblings(f.c2).unwrap();
    let ids: Vec<String> = s.siblings.iter().map(|n| n.id.clone()).collect();
    assert_eq!(ids, vec![hex(&f.c2b)]);

    // c4's cause set {c0, bench0} is unique; c1 is the only continuation.
    assert!(q.siblings(f.c4).unwrap().siblings.is_empty());
    assert!(q.siblings(f.c1).unwrap().siblings.is_empty());
    // A root has no generation.
    assert!(q.siblings(f.c0).unwrap().siblings.is_empty());
}

#[test]
fn frontier_reports_unconsidered_work_without_filtering() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    let fr = q.frontier();
    let ids: Vec<(String, String)> = fr
        .frontier
        .iter()
        .map(|e| (e.node.id.clone(), e.reason.clone()))
        .collect();
    // c0 was considered, chosen, and continued: not frontier. Everything
    // else was never considered by any selection.
    let expect: Vec<(String, String)> = [&f.c1, &f.c2, &f.c2b, &f.c3, &f.c4, &f.c5]
        .iter()
        .map(|id| (hex(id), "unconsidered".to_string()))
        .collect();
    assert_eq!(ids, expect);
}

#[test]
fn standing_is_kind_aware_and_names_restorations() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    let s0 = q.standing(f.s0).unwrap();
    assert_eq!(s0.node.standing, "unsound");
    assert!(s0.node.tainted);
    assert_eq!(s0.restorations, vec![hex(&f.s1)]);

    let c2 = q.standing(f.c2).unwrap();
    assert_eq!(c2.node.standing, "sound");
    assert!(!c2.node.tainted);
    assert!(c2.restorations.is_empty());

    let bench = q.standing(f.bench0).unwrap();
    assert_eq!(bench.node.standing, "n/a");
    assert!(bench.node.retracted);
}

#[test]
fn evidence_shows_what_a_line_rests_on() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    // A selection rests on its own Use-refs.
    let e = q.evidence(f.s1).unwrap();
    assert_eq!(e.rests_on.len(), 1);
    assert_eq!(e.rests_on[0].selection.id, hex(&f.s1));
    assert_eq!(e.rests_on[0].evidence.len(), 1);
    let entry = &e.rests_on[0].evidence[0];
    assert_eq!(entry.node.id, hex(&f.review0));
    assert_eq!(entry.criterion, "manual-review");
    assert_eq!(entry.outcome, "passed");

    // A candidate rests on the evidence of the anchors along its descent -
    // and the report shows that c3's line rests on a retracted evaluation.
    let e = q.evidence(f.c3).unwrap();
    assert_eq!(e.rests_on.len(), 1);
    assert_eq!(e.rests_on[0].selection.id, hex(&f.s0));
    let entry = &e.rests_on[0].evidence[0];
    assert_eq!(entry.node.id, hex(&f.bench0));
    assert!(entry.node.retracted);
}

#[test]
fn selected_matches_the_objective_exactly_and_never_ranks() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    let sel = q.selected("adopt-baseline");
    assert_eq!(
        sel.selections.len(),
        2,
        "s0 and s1, unsound and sound alike"
    );
    assert_eq!(sel.selections[0].selection.id, hex(&f.s0));
    assert_eq!(sel.selections[0].selection.standing, "unsound");
    assert_eq!(sel.selections[1].selection.id, hex(&f.s1));
    assert_eq!(sel.selections[1].selection.standing, "sound");
    for entry in &sel.selections {
        assert_eq!(entry.chosen.len(), 1);
        assert_eq!(entry.chosen[0].id, hex(&f.c0));
    }
    assert_eq!(sel.selections[0].evidence[0].node.id, hex(&f.bench0));
    assert_eq!(sel.selections[1].evidence[0].node.id, hex(&f.review0));

    // Exact match only: near-misses return nothing, never patterns.
    assert!(q.selected("adopt-baseline ").selections.is_empty());
    assert!(q.selected("adopt").selections.is_empty());
}

#[test]
fn query_errors_are_specific() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();

    match q.standing([0xfe; 32]) {
        Err(QueryError::NotFound(_)) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
    match q.descent(f.bench0) {
        Err(QueryError::KindMismatch { .. }) => {}
        other => panic!("expected KindMismatch, got {other:?}"),
    }
    // A rejected record made no claim: queries do not address it.
    match q.standing(f.rejected) {
        Err(QueryError::NotAccepted(_)) => {}
        other => panic!("expected NotAccepted, got {other:?}"),
    }
    match q.evidence(f.bench0) {
        Err(QueryError::KindMismatch { .. }) => {}
        other => panic!("expected KindMismatch, got {other:?}"),
    }
}

#[test]
fn reports_serialize_to_stable_json() {
    let f = fixture();
    let q = Queries::new(&f.records, &f.rules).unwrap();
    // Every report is Serialize with deny_unknown_fields: the JSON shapes
    // are the cross-surface contract, so a round-trip must be lossless.
    let d = q.descent(f.c5).unwrap();
    let json = serde_json::to_string(&d).unwrap();
    let back: DescentReport = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);

    let sel = q.selected("adopt-baseline");
    let json = serde_json::to_string(&sel).unwrap();
    let back: SelectedReport = serde_json::from_str(&json).unwrap();
    assert_eq!(sel, back);
}
