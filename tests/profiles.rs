//! `bellbook-core-v1` (RFC-0003 section 4.5, SPEC section 12.2): the
//! content-addressed baseline profile, evaluated over receipts on request.
//! Profile conformance is a report alongside the verdict - these tests pin
//! that it never changes `status` or `reason`, that each clause judges what
//! it says, that the profile hash is stable, and that unknown ids are
//! reported, never errors.

#![cfg(feature = "persist")]

use bellbook::*;

const SPACE: [u8; 32] = [3u8; 32];
const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

fn baseline_rules() -> VerifierRules {
    VerifierRules::new(SPACE, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider)
        .with_baseline_thresholds()
}

/// A small verifying log: one candidate, one evaluation, one selection.
fn receipt_under(rules: &VerifierRules) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let mut w = LogWriter::open(dir.path(), rules).unwrap();
    let mut st = State::default();
    let author = |id: &str| Author {
        id: id.into(),
        type_: AuthorType::Provider,
        signature: None,
    };
    let (c0, v) = w
        .commit(
            Proposal {
                space: SPACE,
                thread: SPACE,
                author: author("agent"),
                kind: Kind::Candidate,
                schema: schema_id(SCHEMA_CANDIDATE),
                data: encode(&CandidateData {
                    source: SourceBinding {
                        git: GitSource {
                            algo: SourceAlgo::Sha1,
                            tree: TREE.into(),
                            commit: None,
                        },
                        manifest_hash: None,
                        binding: BindingMode::Reported,
                    },
                    basis: CandidateBasis::Root,
                    parent: None,
                    note: None,
                })
                .unwrap(),
                refs: vec![],
            },
            rules,
            &mut st,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (e0, v) = w
        .commit(
            Proposal {
                space: SPACE,
                thread: SPACE,
                author: author("evaluator"),
                kind: Kind::Evaluation,
                schema: schema_id(SCHEMA_EVALUATION),
                data: encode(&EvaluationData {
                    candidate: c0,
                    criterion: "unit-tests".into(),
                    procedure: None,
                    outcome: EvaluationOutcome::Passed,
                })
                .unwrap(),
                refs: vec![Ref {
                    type_: RefType::Use,
                    target: c0,
                }],
            },
            rules,
            &mut st,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_s0, v) = w
        .commit(
            Proposal {
                space: SPACE,
                thread: SPACE,
                author: author("agent"),
                kind: Kind::Selection,
                schema: schema_id(SCHEMA_SELECTION),
                data: encode(&SelectionData {
                    objective: "ship".into(),
                    considered: vec![c0],
                    outcome: SelectionOutcome::Selected {
                        candidates: vec![c0],
                    },
                    rationale: None,
                })
                .unwrap(),
                refs: vec![
                    Ref {
                        type_: RefType::Require,
                        target: c0,
                    },
                    Ref {
                        type_: RefType::Use,
                        target: e0,
                    },
                ],
            },
            rules,
            &mut st,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    Receipt::new(w.records(), rules).to_bytes().unwrap()
}

fn clause<'a>(r: &'a ProfileResult, id: &str) -> &'a ClauseResult {
    r.clauses.iter().find(|c| c.id == id).unwrap()
}

#[test]
fn baseline_rules_conform_and_verdict_is_untouched() {
    let rules = baseline_rules();
    let bytes = receipt_under(&rules);
    let plain = validate(&bytes);
    let with = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);

    // The verdict fields are exactly what validate() returns.
    assert_eq!(plain.status, ValidationStatus::Clean);
    assert_eq!(with.status, plain.status);
    assert_eq!(with.reason, plain.reason);
    assert_eq!(with.head_hash, plain.head_hash);
    assert_eq!(with.rules_hash, plain.rules_hash);
    assert!(plain.profiles.is_empty());

    assert_eq!(with.profiles.len(), 1);
    let p = &with.profiles[0];
    assert_eq!(p.id, BELLBOOK_CORE_V1);
    assert_eq!(p.status, ProfileStatus::Conformant);
    assert_eq!(p.hash, profile_hash(&core_v1_table()));
    let ids: Vec<&str> = p.clauses.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["B1", "B2", "B3", "B4", "B5", "B6"]);
    assert!(p.clauses.iter().all(|c| c.passed));
    assert!(clause(p, "B6").detail.contains("1 reported"));
}

#[test]
fn missing_thresholds_fail_b3_only() {
    // Rules without baseline thresholds are perfectly valid rules - the log
    // verifies Clean - but they are not comparable under the baseline.
    let rules = VerifierRules::new(SPACE, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider);
    let bytes = receipt_under(&rules);
    let r = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
    assert_eq!(r.status, ValidationStatus::Clean, "verdict unaffected");
    let p = &r.profiles[0];
    assert_eq!(p.status, ProfileStatus::NonConformant);
    assert!(!clause(p, "B3").passed);
    assert!(clause(p, "B3").detail.contains("Candidate=missing"));
    for id in ["B1", "B2", "B4", "B5", "B6"] {
        assert!(clause(p, id).passed, "{id} should pass");
    }
}

#[test]
fn weaker_than_base_threshold_fails_b3() {
    // A threshold that admits Assumed-class candidates is weaker than the
    // schema base class and fails the clause even though it is "present".
    let rules = baseline_rules().with_evidence_threshold(Kind::Candidate, Evidence::Assumed);
    let bytes = receipt_under(&rules);
    let r = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
    let p = &r.profiles[0];
    assert_eq!(p.status, ProfileStatus::NonConformant);
    assert!(clause(p, "B3").detail.contains("weaker than Reported"));
}

#[test]
fn context_bound_outside_range_fails_b4() {
    let rules = VerifierRules::new(SPACE, 0)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider)
        .with_baseline_thresholds();
    let bytes = receipt_under(&rules);
    let r = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
    let p = &r.profiles[0];
    assert_eq!(p.status, ProfileStatus::NonConformant);
    assert!(!clause(p, "B4").passed);
    assert!(clause(p, "B3").passed);
}

#[test]
fn invalid_receipt_fails_b1_and_verdict_still_invalid() {
    let rules = baseline_rules();
    let bytes = receipt_under(&rules);
    // Payloads travel as byte arrays, so corrupt one numerically: bump a
    // byte of the second record's data. The receipt still parses; that
    // record's id no longer recomputes; replay rejects.
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let byte = &mut v["records"][1]["data"][0];
    let n = byte.as_u64().unwrap();
    *byte = serde_json::Value::from((n + 1) % 256);
    let bytes = serde_json::to_vec(&v).unwrap();
    let r = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
    assert_eq!(r.status, ValidationStatus::Invalid);
    let p = &r.profiles[0];
    assert_eq!(p.status, ProfileStatus::NonConformant);
    assert!(!clause(p, "B1").passed);
    // B6 counts nothing for an invalid log: no record made an accepted claim.
    assert!(clause(p, "B6")
        .detail
        .contains("0 manifest-bound, 0 reported"));
}

#[test]
fn unknown_profile_is_reported_not_an_error() {
    let rules = baseline_rules();
    let bytes = receipt_under(&rules);
    let r = validate_with_profiles(
        &bytes,
        &ValidationLimits::default(),
        &["no-such-profile-v9", BELLBOOK_CORE_V1],
    );
    assert_eq!(r.status, ValidationStatus::Clean);
    assert_eq!(r.profiles.len(), 2, "request order is preserved");
    assert_eq!(r.profiles[0].status, ProfileStatus::Unknown);
    assert_eq!(r.profiles[0].hash, [0u8; 32]);
    assert!(r.profiles[0].clauses.is_empty());
    assert_eq!(r.profiles[1].status, ProfileStatus::Conformant);
}

#[test]
fn structural_failure_evaluates_nothing() {
    let r = validate_with_profiles(
        b"not a receipt",
        &ValidationLimits::default(),
        &[BELLBOOK_CORE_V1],
    );
    assert_eq!(r.status, ValidationStatus::Invalid);
    assert!(r.problem.is_some());
    assert!(r.profiles.is_empty(), "nothing to evaluate against");
}

#[test]
fn profile_hash_is_the_canonical_clause_table() {
    // The hash commits to the clause table and nothing else: two calls agree,
    // a changed statement changes it, and the table round-trips as JSON.
    let t = core_v1_table();
    assert_eq!(profile_hash(&t), profile_hash(&core_v1_table()));
    assert_eq!(profile_table(BELLBOOK_CORE_V1).unwrap(), t);
    assert!(profile_table("nope").is_none());
    assert_eq!(known_profiles(), &[BELLBOOK_CORE_V1]);
    let mut changed = t.clone();
    changed.clauses[0].statement.push('.');
    assert_ne!(profile_hash(&changed), profile_hash(&t));
    let json = serde_json::to_string(&t).unwrap();
    let back: ProfileTable = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn report_with_profiles_round_trips_and_old_reports_still_parse() {
    let rules = baseline_rules();
    let bytes = receipt_under(&rules);
    let r = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
    let json = serde_json::to_string(&r).unwrap();
    let back: Report = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
    // A report serialized before the field existed has no `profiles` key.
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v.as_object_mut().unwrap().remove("profiles");
    let old: Report = serde_json::from_value(v).unwrap();
    assert!(old.profiles.is_empty());
    // The human rendering names the profile and every clause.
    let text = r.to_string();
    assert!(text.contains("profile bellbook-core-v1: CONFORMANT"));
    for id in ["B1", "B2", "B3", "B4", "B5", "B6"] {
        assert!(text.contains(&format!("ok   {id}:")), "{text}");
    }
}
