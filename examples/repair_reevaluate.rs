//! Single-candidate repair-and-reevaluate (issue #67): the third proving
//! workload (VISION, RFC-0001 §3), alongside best-of-N selection and iterative
//! evolution.
//!
//! The loop is small: a candidate fails an evaluation, a repair produces a
//! successor, re-evaluate, accept. What this example exists to show is the
//! *taint-vs-standing distinction* in isolation - the point external users
//! most often get wrong:
//!
//!   The repair is *motivated by* the failing evaluation (a `Cause` edge to
//!   it) but *derives its content from* the original candidate, which still
//!   stands. When the failing evaluation is later retracted, the repair is
//!   NOT tainted: kernel taint follows `Use` and `Require`, never `Cause`.
//!   Motivation is not contamination.
//!
//! Run with: `cargo run --example repair_reevaluate`

use bellbook::*;

fn main() {
    let dir = tempfile::tempdir().unwrap();

    let space = default_space();
    let rules = VerifierRules::new(space, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider);
    let thread = sha256_utf8("repair-thread");

    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let source = |tree: &str| SourceBinding {
        git: GitSource {
            algo: SourceAlgo::Sha1,
            tree: tree.into(),
            commit: None,
        },
        manifest_hash: None,
        binding: BindingMode::Reported,
    };

    // c0: the original candidate.
    let c0 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate c0 (original)",
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            source: source("1111111111111111111111111111111111111111"),
            basis: CandidateBasis::Root,
            parent: None,
            note: Some("original".into()),
        },
        vec![],
        space,
        thread,
    );

    // e0: it fails an evaluation - the trigger for a repair.
    let e0 = commit(
        &mut writer,
        &rules,
        &mut state,
        "evaluation of c0 -> FAILED",
        "evaluator",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        &EvaluationData {
            candidate: c0,
            criterion: "test-suite".into(),
            procedure: Some("ci".into()),
            outcome: EvaluationOutcome::Failed,
        },
        vec![use_ref(c0)],
        space,
        thread,
    );

    // c1: the repair. It derives its content from c0 (a sound candidate) and is
    // *motivated by* the failing evaluation - recorded as a Cause edge to e0,
    // not a Use. This edge is the whole point: it carries intent, not evidence.
    let c1 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate c1 (repair: derives from c0, motivated by the failure)",
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            source: source("2222222222222222222222222222222222222222"),
            basis: CandidateBasis::Derivation,
            parent: None,
            note: Some("repair of c0".into()),
        },
        vec![cause_ref(c0), cause_ref(e0)],
        space,
        thread,
    );

    // e1: the repaired candidate passes.
    let e1 = commit(
        &mut writer,
        &rules,
        &mut state,
        "evaluation of c1 -> PASSED",
        "evaluator",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        &EvaluationData {
            candidate: c1,
            criterion: "test-suite".into(),
            procedure: Some("ci".into()),
            outcome: EvaluationOutcome::Passed,
        },
        vec![use_ref(c1)],
        space,
        thread,
    );

    // s1: accept the repair. It rests only on e1 (the passing evaluation of the
    // chosen candidate); it does not Use e0.
    let s1 = commit(
        &mut writer,
        &rules,
        &mut state,
        "selection s1 (accept the repair c1)",
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        &SelectionData {
            objective: "green-test-suite".into(),
            considered: vec![c0, c1],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c1],
            },
            rationale: Some("repair passes; supersedes the original".into()),
        },
        vec![require_ref(c1), use_ref(e1)],
        space,
        thread,
    );

    println!("\n--- Phase 1: repaired and accepted, all sound ---");
    let phase1 = print_standing(writer.records(), &rules);
    assert!(
        phase1.is_empty(),
        "the repaired line must be entirely sound"
    );

    // --- The failing evaluation is itself retracted. -----------------------

    // Suppose the failing test suite is later found to have been broken, and
    // the evaluator retracts it. Taint reaches whatever *Used* e0 - nothing
    // here does. The repair c1 only *Caused* it.
    let _retraction = commit(
        &mut writer,
        &rules,
        &mut state,
        "retraction of e0 (the failing evaluation was itself broken)",
        "evaluator",
        Kind::Retraction,
        SCHEMA_RETRACTION,
        &RetractionData {
            target_id: e0,
            reason: "the failing test suite was measuring the wrong thing".into(),
        },
        vec![cause_ref(e0)],
        space,
        thread,
    );

    println!("\n--- Phase 2: e0 retracted; the repair is untouched ---");
    let report = validate_offline(writer.records(), &rules);

    // A retracted record is present, so the receipt is Tainted, not Clean...
    assert_eq!(report.status, ValidationStatus::Tainted);
    // ...but exactly e0 is retracted, and the taint set is *empty*: because the
    // only edge pointing at e0 is a Cause (from the repair), nothing downstream
    // depends on it, so nothing is tainted at all.
    assert_eq!(
        report.retracted_records,
        [e0].into_iter().collect(),
        "exactly e0 is retracted"
    );
    assert!(
        report.tainted_records.is_empty(),
        "the retraction taints nothing: only a Cause edge points at e0"
    );
    // Standing confirms it: no candidate is compromised, no selection unsound.
    assert!(
        report.standing.compromised.is_empty() && report.standing.unsound.is_empty(),
        "motivation is not contamination: the repair line stands"
    );
    // The repair and its acceptance are neither retracted nor tainted.
    assert!(!report.tainted_records.contains(&c1) && !report.retracted_records.contains(&c1));
    assert!(!report.tainted_records.contains(&s1) && !report.retracted_records.contains(&s1));

    println!(
        "\nthe repair c1 and its acceptance s1 stand, though the evaluation\n\
         that motivated the repair was retracted. Cause carries intent, not taint."
    );
}

// --- Helpers (kept local so the example reads standalone). -----------------

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

/// Commit one record, print its id and verdict, and assert it was accepted.
#[allow(clippy::too_many_arguments)]
fn commit<T: serde::Serialize>(
    writer: &mut LogWriter,
    rules: &VerifierRules,
    state: &mut State,
    label: &str,
    author_id: &str,
    kind: Kind,
    schema: &str,
    payload: &T,
    refs: Vec<Ref>,
    space: SpaceId,
    thread: ThreadId,
) -> RecordId {
    let (id, verdict) = writer
        .commit(
            Proposal {
                space,
                thread,
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
    println!(
        "  {:<8} {}  {label}",
        format!("{:?}", verdict.result),
        hex_encode(&id)
    );
    assert_eq!(
        verdict.result,
        VerdictResult::Accept,
        "{label} was rejected"
    );
    id
}

/// Replay the log, print a compact standing summary, and return the standing.
fn print_standing(records: &[Record], rules: &VerifierRules) -> StandingSection {
    let verdict = verify_log(records, rules, None);
    assert_eq!(verdict.result, VerdictResult::Accept);
    if verdict.standing.is_empty() {
        println!("  standing: entirely sound");
    } else {
        println!(
            "  standing: {} compromised, {} unsound, {} restoration(s)",
            verdict.standing.compromised.len(),
            verdict.standing.unsound.len(),
            verdict.standing.restorations.len()
        );
    }
    verdict.standing
}

/// Export a portable receipt and validate it offline, printing the report.
fn validate_offline(records: &[Record], rules: &VerifierRules) -> Report {
    let receipt = Receipt::new(records, rules);
    let bytes = receipt.to_bytes().unwrap();
    let report = validate(&bytes);
    print!("{report}");
    report
}
