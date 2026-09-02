//! The flagship evolution demo (RFC-0001 §10): a broken benchmark, the
//! compromise it casts over a line of work, and the single-Selection
//! recovery.
//!
//! The story, all on one append-only log:
//!
//!   1. A baseline is imported and chosen on the strength of a benchmark
//!      evaluation. Work continues: a generation continues from that choice,
//!      then repairs derive from it, at increasing depth.
//!   2. The benchmark harness is discovered to be broken. Its evaluation is
//!      retracted. Kernel taint reaches the Selection that `Use`d it, exactly
//!      as v0.2 defines, and the replay report's `standing` section now shows
//!      every descendant of that Selection compromised, transitively, at any
//!      depth. A repair that only *derives from a sound candidate* stays
//!      sound, even though it was motivated by the broken benchmark:
//!      evaluation motivation alone never compromises.
//!   3. Work never stops: the line keeps recording, visibly compromised.
//!   4. The team re-runs a surviving evaluation and commits one reaffirming
//!      Selection. The next replay shows the line's standing restored, with
//!      the retraction, the taint, the compromise, and the recovery all
//!      permanently, verifiably on the record.
//!
//! Run with: `cargo run --example broken_benchmark`

use bellbook::*;

fn main() {
    let dir = tempfile::tempdir().unwrap();

    // Identities are bound to roles here; the declared author type on a record
    // is never trusted by itself. The benchmark harness authors its own
    // evaluations as a Provider, so it can retract them when it is found
    // broken (RFC-0001 §4.0). A separate reviewer authors the surviving
    // evaluation used for recovery.
    let space = default_space();
    let rules = VerifierRules::new(space, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("benchmark", AuthorType::Provider)
        .with_author_role("reviewer", AuthorType::Provider);

    let thread = sha256_utf8("evolution-thread");

    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // A reported source binding over a Git tree OID (the canonical empty tree
    // stands in for real content here; identity is the tree, provenance the
    // commit). Manifest bindings are exercised elsewhere.
    let source = |tree: &str| SourceBinding {
        git: GitSource {
            algo: SourceAlgo::Sha1,
            tree: tree.into(),
            commit: None,
        },
        manifest_hash: None,
        binding: BindingMode::Reported,
    };

    // --- Build the line of work, all sound. --------------------------------

    // C0: the imported baseline (a Root candidate starts a line).
    let c0 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate C0 (baseline)",
        "agent",
        AuthorType::Provider,
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            artifacts: None,
            source: source("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
            basis: CandidateBasis::Root,
            parent: None,
            note: Some("imported baseline".into()),
        },
        vec![],
        space,
        thread,
    );

    // The benchmark evaluates the baseline and reports a pass.
    let bench0 = commit(
        &mut writer,
        &rules,
        &mut state,
        "evaluation (benchmark) of C0",
        "benchmark",
        AuthorType::Provider,
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        &EvaluationData {
            candidate: c0,
            criterion: "bench-suite".into(),
            procedure: Some("benchmark-harness v3".into()),
            outcome: EvaluationOutcome::Passed,
        },
        vec![use_ref(c0)],
        space,
        thread,
    );

    // S0: the pivotal Selection. It chooses the baseline on the strength of
    // the benchmark evaluation. Every later record hangs off this decision.
    let s0 = commit(
        &mut writer,
        &rules,
        &mut state,
        "selection S0 (choose C0, on the benchmark)",
        "agent",
        AuthorType::Provider,
        Kind::Selection,
        SCHEMA_SELECTION,
        &SelectionData {
            objective: "adopt-baseline".into(),
            considered: vec![c0],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c0],
            },
            rationale: Some("benchmark passed".into()),
        },
        vec![require_ref(c0), use_ref(bench0)],
        space,
        thread,
    );

    // C1: generation 1 continues from the chosen baseline.
    let c1 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate C1 (continues S0)",
        "agent",
        AuthorType::Provider,
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            artifacts: None,
            source: source("1111111111111111111111111111111111111111"),
            basis: CandidateBasis::Continuation,
            parent: Some(c0),
            note: Some("generation 1".into()),
        },
        vec![cause_ref(s0)],
        space,
        thread,
    );

    // C2, C3: repairs derived from the line, at increasing depth.
    let c2 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate C2 (derives from C1)",
        "agent",
        AuthorType::Provider,
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            artifacts: None,
            source: source("2222222222222222222222222222222222222222"),
            basis: CandidateBasis::Derivation,
            parent: None,
            note: Some("repair of generation 1".into()),
        },
        vec![cause_ref(c1)],
        space,
        thread,
    );
    let c3 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate C3 (derives from C2)",
        "agent",
        AuthorType::Provider,
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            artifacts: None,
            source: source("3333333333333333333333333333333333333333"),
            basis: CandidateBasis::Derivation,
            parent: None,
            note: Some("further repair".into()),
        },
        vec![cause_ref(c2)],
        space,
        thread,
    );

    // C4: a repair that derives from the *sound* baseline C0, motivated by the
    // benchmark evaluation (a Cause ref to it) but not resting on the pivotal
    // Selection. It will stay sound through the retraction: only a compromised
    // *candidate* it derives from could compromise it, and Cause never carries
    // kernel taint.
    let c4 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate C4 (derives from C0, motivated by the benchmark)",
        "agent",
        AuthorType::Provider,
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            artifacts: None,
            source: source("4444444444444444444444444444444444444444"),
            basis: CandidateBasis::Derivation,
            parent: None,
            note: Some("independent repair off the baseline".into()),
        },
        vec![cause_ref(c0), cause_ref(bench0)],
        space,
        thread,
    );

    println!("\n--- Phase 1: the line is built, all sound ---");
    let phase1 = print_standing(writer.records(), &rules);
    assert!(
        phase1.is_empty(),
        "the freshly built line must be entirely sound"
    );

    // --- The benchmark is discovered broken. -------------------------------

    // The benchmark harness retracts its own evaluation of the baseline.
    let _retraction = commit(
        &mut writer,
        &rules,
        &mut state,
        "retraction of the benchmark evaluation",
        "benchmark",
        AuthorType::Provider,
        Kind::Retraction,
        SCHEMA_RETRACTION,
        &RetractionData {
            target_id: bench0,
            reason: "benchmark harness was measuring the wrong thing".into(),
        },
        vec![cause_ref(bench0)],
        space,
        thread,
    );

    // Work never stops: a deeper repair is recorded on the (now compromised)
    // line, and commits without objection.
    let c5 = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate C5 (derives from C3, recorded after the break)",
        "agent",
        AuthorType::Provider,
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            artifacts: None,
            source: source("5555555555555555555555555555555555555555"),
            basis: CandidateBasis::Derivation,
            parent: None,
            note: Some("work continues under compromise".into()),
        },
        vec![cause_ref(c3)],
        space,
        thread,
    );

    println!("\n--- Phase 2: benchmark retracted; the line is compromised ---");
    println!("(C4 derives from the sound baseline, so it stays sound.)");
    // Export a portable receipt and validate it offline, exactly as a third
    // party would. The report's standing section is re-derived from scratch.
    let report = validate_offline(writer.records(), &rules);
    // The whole descendant subtree of S0 - C1, C2, C3, and the post-break C5 -
    // is compromised at every depth. C0 (the root), and crucially C4 (a repair
    // derived from the sound baseline, merely motivated by the broken
    // benchmark), stay sound: evaluation motivation alone never compromises.
    // S0 is the one unsound Selection, with no restoration yet. Pin the exact
    // sets, not just their sizes, so a standing regression that swapped a
    // member could not pass.
    assert_eq!(report.status, ValidationStatus::Tainted);
    assert_eq!(
        report.standing.compromised,
        [c1, c2, c3, c5].into_iter().collect(),
        "the compromised set must be exactly the descendant subtree of S0"
    );
    assert!(
        !report.standing.compromised.contains(&c4),
        "C4 derives from the sound baseline and must stay sound"
    );
    assert!(!report.standing.compromised.contains(&c0));
    assert_eq!(report.standing.unsound, [s0].into_iter().collect());
    assert!(report.standing.restorations.is_empty());

    // --- Recovery: one reaffirming Selection on surviving evidence. --------

    // A reviewer re-runs a surviving evaluation of the baseline (a different
    // criterion the broken harness never touched).
    let review0 = commit(
        &mut writer,
        &rules,
        &mut state,
        "evaluation (manual review) of C0",
        "reviewer",
        AuthorType::Provider,
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        &EvaluationData {
            candidate: c0,
            criterion: "manual-review".into(),
            procedure: Some("human sign-off".into()),
            outcome: EvaluationOutcome::Passed,
        },
        vec![use_ref(c0)],
        space,
        thread,
    );

    // One reaffirming Selection: it Replaces S0, re-selecting the baseline on
    // the surviving evidence. Standing restores the whole descendant subtree.
    let s1 = commit(
        &mut writer,
        &rules,
        &mut state,
        "selection S1 (reaffirm C0 via Replace of S0)",
        "agent",
        AuthorType::Provider,
        Kind::Selection,
        SCHEMA_SELECTION,
        &SelectionData {
            objective: "adopt-baseline".into(),
            considered: vec![c0],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c0],
            },
            rationale: Some("reaffirmed on surviving manual review".into()),
        },
        vec![require_ref(c0), use_ref(review0), replace_ref(s0)],
        space,
        thread,
    );

    println!("\n--- Phase 3: reaffirmed; the line's standing is restored ---");
    println!("(The retraction and taint stay on the record permanently.)");
    let report = validate_offline(writer.records(), &rules);
    // One reaffirming Selection cleared the whole compromise: no candidate is
    // compromised now. S0 stays permanently unsound (its taint never leaves
    // the record), but the restoration names S1 as the sound decision the line
    // now rests on.
    assert!(report.standing.compromised.is_empty());
    assert_eq!(report.standing.unsound, [s0].into_iter().collect());
    let expected_restoration = [(s0, [s1].into_iter().collect())].into_iter().collect();
    assert_eq!(report.standing.restorations, expected_restoration);
}

// --- Small helpers so the story above reads without ceremony. --------------

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

/// Commit one record, print its id and verdict, and assert it was accepted
/// (every step in this story is a valid record; a rejection is a bug in the
/// example, not an expected outcome).
#[allow(clippy::too_many_arguments)]
fn commit<T: serde::Serialize>(
    writer: &mut LogWriter,
    rules: &VerifierRules,
    state: &mut State,
    label: &str,
    author_id: &str,
    author_type: AuthorType,
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
                    type_: author_type,
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
        "  {:<10} {}  {label}",
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

/// Replay the whole log in memory, print a compact standing summary, and
/// return the standing section for assertions.
fn print_standing(records: &[Record], rules: &VerifierRules) -> StandingSection {
    let verdict = verify_log(records, rules, None);
    assert_eq!(verdict.result, VerdictResult::Accept);
    let s = &verdict.standing;
    if s.is_empty() {
        println!("  standing: entirely sound (no compromise, no unsound selections)");
        return verdict.standing;
    }
    println!(
        "  standing: {} compromised candidate(s), {} unsound selection(s), {} restoration(s)",
        s.compromised.len(),
        s.unsound.len(),
        s.restorations.len()
    );
    for id in &s.compromised {
        println!("    compromised candidate  {}", hex_encode(id));
    }
    for id in &s.unsound {
        println!("    unsound selection      {}", hex_encode(id));
    }
    for (target, replacers) in &s.restorations {
        for r in replacers {
            println!(
                "    restored               {} by {}",
                hex_encode(target),
                hex_encode(r)
            );
        }
    }
    verdict.standing
}

/// Export a portable receipt and validate it offline, printing the full
/// report (which renders the standing section) and returning it. This is the
/// same path `bellbook validate` takes, and the standing section is re-derived
/// by the validator, not carried in the receipt.
fn validate_offline(records: &[Record], rules: &VerifierRules) -> Report {
    let receipt = Receipt::new(records, rules);
    let bytes = receipt.to_bytes().unwrap();
    let report = validate(&bytes);
    print!("{report}");
    report
}
