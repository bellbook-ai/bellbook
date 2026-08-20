//! Autoresearch-style iterative evolution (issue #66): one of the three
//! proving workloads Bellbook's evolution semantics must serve (VISION,
//! RFC-0001 §3). Where `broken_benchmark` centers a single pivotal selection
//! and its recovery, this example centers the *loop*:
//!
//!   state -> fork N candidates -> evaluate -> rank -> select -> continue
//!
//! Each generation forks two candidates that continue from the previous
//! winner, scores both, and records one Selection that chooses the higher
//! score. The next generation continues from that choice. After several
//! generations the whole line is exported as a receipt, validated offline, and
//! its lineage - the continuation chain of survivors - is read back from the
//! records.
//!
//! Bellbook records the decision; it never makes it. The host compares the
//! scores and picks the winner here; the log just captures which candidates
//! were considered, the evaluation evidence, and the choice, verifiably.
//!
//! Run with: `cargo run --example iterative_evolution`

use bellbook::*;

/// How many generations of fork-evaluate-select to run.
const GENERATIONS: u64 = 4;

fn main() {
    let dir = tempfile::tempdir().unwrap();

    // The agent proposes and selects; a separate evaluator scores candidates.
    // Roles are bound in the rules; a record's declared author type is never
    // trusted by itself.
    let space = default_space();
    let rules = VerifierRules::new(space, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider);
    let thread = sha256_utf8("autoresearch-thread");

    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // A distinct reported Git-tree binding per candidate; identity is the tree.
    let mut tree_counter: u64 = 0;
    let mut next_source = || {
        tree_counter += 1;
        SourceBinding {
            git: GitSource {
                algo: SourceAlgo::Sha1,
                tree: format!("{tree_counter:040x}"),
                commit: None,
            },
            manifest_hash: None,
            binding: BindingMode::Reported,
        }
    };

    // --- Seed: a Root candidate, evaluated and selected. -------------------

    let root = commit(
        &mut writer,
        &rules,
        &mut state,
        "candidate gen0 (root baseline)",
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        &CandidateData {
            source: next_source(),
            basis: CandidateBasis::Root,
            parent: None,
            note: Some("generation 0".into()),
        },
        vec![],
        space,
        thread,
    );
    let root_eval = commit(
        &mut writer,
        &rules,
        &mut state,
        "evaluation of gen0",
        "evaluator",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        &EvaluationData {
            candidate: root,
            criterion: "fitness".into(),
            procedure: Some("harness".into()),
            outcome: EvaluationOutcome::Scored(ScoredValue {
                value: 50,
                scale: 0,
            }),
        },
        vec![use_ref(root)],
        space,
        thread,
    );
    let mut prev_winner = root;
    let mut prev_selection = commit(
        &mut writer,
        &rules,
        &mut state,
        "selection gen0 (adopt the baseline)",
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        &SelectionData {
            objective: "evolve-fitness".into(),
            considered: vec![root],
            outcome: SelectionOutcome::Selected {
                candidates: vec![root],
            },
            rationale: Some("baseline".into()),
        },
        vec![require_ref(root), use_ref(root_eval)],
        space,
        thread,
    );

    // The survivor lineage: generation winners, oldest first.
    let mut lineage = vec![root];
    // A cheap deterministic score generator, so the run is reproducible.
    let mut score_state: u64 = 0x51ED;
    let mut next_score = || {
        score_state = score_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        (score_state >> 33) as i64 % 100
    };

    // --- The loop: fork two, score both, select the better, continue. ------

    for gen in 1..=GENERATIONS {
        // Two candidates continue from the previous winner, caused by the
        // previous selection - the decision they build on.
        let cand_a = commit(
            &mut writer,
            &rules,
            &mut state,
            &format!("candidate gen{gen}-A (continues)"),
            "agent",
            Kind::Candidate,
            SCHEMA_CANDIDATE,
            &CandidateData {
                source: next_source(),
                basis: CandidateBasis::Continuation,
                parent: Some(prev_winner),
                note: Some(format!("generation {gen}, variant A")),
            },
            vec![cause_ref(prev_selection)],
            space,
            thread,
        );
        let cand_b = commit(
            &mut writer,
            &rules,
            &mut state,
            &format!("candidate gen{gen}-B (continues)"),
            "agent",
            Kind::Candidate,
            SCHEMA_CANDIDATE,
            &CandidateData {
                source: next_source(),
                basis: CandidateBasis::Continuation,
                parent: Some(prev_winner),
                note: Some(format!("generation {gen}, variant B")),
            },
            vec![cause_ref(prev_selection)],
            space,
            thread,
        );

        let score_a = next_score();
        let score_b = next_score();
        let eval_a = commit(
            &mut writer,
            &rules,
            &mut state,
            &format!("evaluation gen{gen}-A (score {score_a})"),
            "evaluator",
            Kind::Evaluation,
            SCHEMA_EVALUATION,
            &EvaluationData {
                candidate: cand_a,
                criterion: "fitness".into(),
                procedure: Some("harness".into()),
                outcome: EvaluationOutcome::Scored(ScoredValue {
                    value: score_a,
                    scale: 0,
                }),
            },
            vec![use_ref(cand_a)],
            space,
            thread,
        );
        let eval_b = commit(
            &mut writer,
            &rules,
            &mut state,
            &format!("evaluation gen{gen}-B (score {score_b})"),
            "evaluator",
            Kind::Evaluation,
            SCHEMA_EVALUATION,
            &EvaluationData {
                candidate: cand_b,
                criterion: "fitness".into(),
                procedure: Some("harness".into()),
                outcome: EvaluationOutcome::Scored(ScoredValue {
                    value: score_b,
                    scale: 0,
                }),
            },
            vec![use_ref(cand_b)],
            space,
            thread,
        );

        // The host ranks and picks; Bellbook records the choice and its
        // evidence. Ties go to A.
        let (winner, winner_score) = if score_a >= score_b {
            (cand_a, score_a)
        } else {
            (cand_b, score_b)
        };
        let selection = commit(
            &mut writer,
            &rules,
            &mut state,
            &format!("selection gen{gen} (winner scored {winner_score})"),
            "agent",
            Kind::Selection,
            SCHEMA_SELECTION,
            &SelectionData {
                objective: "evolve-fitness".into(),
                considered: vec![cand_a, cand_b],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![winner],
                },
                rationale: Some(format!("higher fitness ({winner_score})")),
            },
            // Require the winner; Use both evaluations - the comparison
            // evidence the decision rests on.
            vec![require_ref(winner), use_ref(eval_a), use_ref(eval_b)],
            space,
            thread,
        );

        lineage.push(winner);
        prev_winner = winner;
        prev_selection = selection;
    }

    // --- Validate offline and read the surviving lineage back. -------------

    println!("\n--- Replay-verify the whole run offline ---");
    let report = validate_offline(writer.records(), &rules);
    // Nothing was retracted and no selection is unsound, so the run is Clean
    // and its standing is entirely sound.
    assert_eq!(
        report.status,
        ValidationStatus::Clean,
        "the run must be Clean"
    );
    assert!(
        report.standing.compromised.is_empty() && report.standing.unsound.is_empty(),
        "an unretracted iterative run must have entirely sound standing"
    );

    // The lineage read back from the records must be the continuation chain we
    // built: each winner's parent is the previous winner.
    println!("\n--- Surviving lineage (continuation chain) ---");
    for (gen, id) in lineage.iter().enumerate() {
        println!("  generation {gen}: {}", hex_encode(id));
    }
    assert_eq!(
        lineage.len() as u64,
        GENERATIONS + 1,
        "one survivor per generation plus the root"
    );
    for window in lineage.windows(2) {
        let [parent, child] = window else { continue };
        let child_data = find_candidate(writer.records(), *child)
            .expect("each survivor is a candidate in the log");
        assert_eq!(
            child_data.parent,
            Some(*parent),
            "each generation's winner must continue from the previous winner"
        );
    }
    println!(
        "\nlineage verified: {} generations, all sound.",
        GENERATIONS
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

fn find_candidate(records: &[Record], id: RecordId) -> Option<CandidateData> {
    records
        .iter()
        .find(|r| r.id == id && r.kind == Kind::Candidate)
        .and_then(|r| decode::<CandidateData>(&r.data).ok())
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

/// Export a portable receipt and validate it offline, printing the report.
fn validate_offline(records: &[Record], rules: &VerifierRules) -> Report {
    let receipt = Receipt::new(records, rules);
    let bytes = receipt.to_bytes().unwrap();
    let report = validate(&bytes);
    print!("{report}");
    report
}
