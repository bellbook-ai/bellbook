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
                    artifacts: None,
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
    assert_eq!(known_profiles(), &[BELLBOOK_CORE_V1, DELIVERY_RECEIPT_V1]);
    assert_eq!(
        profile_table(DELIVERY_RECEIPT_V1).unwrap(),
        delivery_v1_table()
    );
    assert_eq!(profile_ref(DELIVERY_RECEIPT_V1).unwrap().version, 1);
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
    // A 0.7.0 profile result has no declaration fields: it parses as a
    // required (undeclared) evaluation.
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let p = v["profiles"][0].as_object_mut().unwrap();
    p.remove("declared");
    p.remove("declaration_matches");
    let old: Report = serde_json::from_value(v).unwrap();
    assert!(!old.profiles[0].declared);
    assert_eq!(old.profiles[0].declaration_matches, None);
    // The human rendering names the profile and every clause.
    let text = r.to_string();
    assert!(text.contains("profile bellbook-core-v1: CONFORMANT"));
    for id in ["B1", "B2", "B3", "B4", "B5", "B6"] {
        assert!(text.contains(&format!("ok   {id}:")), "{text}");
    }
}

// --- receipt profile declarations (spec 0.4, SPEC 12) ---

fn declaring(bytes: &[u8], ids: &[&str]) -> Receipt {
    Receipt::from_bytes(bytes)
        .unwrap()
        .with_declared_profiles(ids)
        .unwrap()
}

#[test]
fn a_declared_profile_is_evaluated_by_plain_validate_and_never_trusted() {
    let rules = baseline_rules();
    let receipt = declaring(&receipt_under(&rules), &[BELLBOOK_CORE_V1]);
    assert_eq!(
        receipt.profiles,
        vec![profile_ref(BELLBOOK_CORE_V1).unwrap()]
    );
    assert_eq!(receipt.profiles[0].version, core_v1_table().version);
    assert_eq!(receipt.profiles[0].hash, profile_hash(&core_v1_table()));
    let bytes = receipt.to_bytes().unwrap();

    // No profile request: the declaration alone makes the validator evaluate.
    let r = validate(&bytes);
    assert_eq!(r.status, ValidationStatus::Clean);
    assert_eq!(r.profiles.len(), 1);
    let p = &r.profiles[0];
    assert_eq!(p.id, BELLBOOK_CORE_V1);
    assert_eq!(p.status, ProfileStatus::Conformant);
    assert!(p.declared);
    assert_eq!(p.declaration_matches, Some(true));
    assert!(p.met());
    assert!(r
        .to_string()
        .contains("profile bellbook-core-v1: CONFORMANT (declared, declaration matches)"));

    // Requiring the declared id evaluates it once, as declared.
    let with = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
    assert_eq!(with.profiles, r.profiles);

    // A false claim: rules without thresholds declaring the baseline. The
    // declaration is honest about which table it names, and the evaluation
    // still says NonConformant - the verdict stays Clean.
    let loose = VerifierRules::new(SPACE, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider);
    let bytes = declaring(&receipt_under(&loose), &[BELLBOOK_CORE_V1])
        .to_bytes()
        .unwrap();
    let r = validate(&bytes);
    assert_eq!(r.status, ValidationStatus::Clean);
    let p = &r.profiles[0];
    assert_eq!(p.status, ProfileStatus::NonConformant);
    assert!(p.declared);
    assert_eq!(p.declaration_matches, Some(true));
    assert!(!p.met());
    assert!(!clause(p, "B3").passed);
}

#[test]
fn a_declaration_naming_another_revision_is_a_mismatch_and_not_met() {
    let rules = baseline_rules();
    let mut receipt = Receipt::from_bytes(&receipt_under(&rules)).unwrap();
    let real = profile_hash(&core_v1_table());

    // Wrong hash: the evaluation runs against this validator's table, whose
    // hash is what the result carries; the declaration is reported false.
    receipt.profiles = vec![ProfileRef {
        id: BELLBOOK_CORE_V1.into(),
        version: 1,
        hash: [0xAB; 32],
    }];
    let r = validate(&receipt.to_bytes().unwrap());
    assert_eq!(r.status, ValidationStatus::Clean, "verdict unaffected");
    let p = &r.profiles[0];
    assert_eq!(p.status, ProfileStatus::Conformant);
    assert_eq!(p.hash, real, "the evaluated hash, not the declared one");
    assert_eq!(p.declaration_matches, Some(false));
    assert!(!p.met());
    assert!(r.to_string().contains("(declared, DECLARATION MISMATCH)"));

    // Right hash, wrong version: still a mismatch.
    receipt.profiles = vec![ProfileRef {
        id: BELLBOOK_CORE_V1.into(),
        version: 2,
        hash: real,
    }];
    let r = validate(&receipt.to_bytes().unwrap());
    assert_eq!(r.profiles[0].declaration_matches, Some(false));
    assert!(!r.profiles[0].met());

    // An unknown declared profile is reported Unknown with nothing to
    // compare; a required profile the receipt did not declare follows it.
    receipt.profiles = vec![ProfileRef {
        id: "made-up-v1".into(),
        version: 1,
        hash: [0u8; 32],
    }];
    let r = validate_with_profiles(
        &receipt.to_bytes().unwrap(),
        &ValidationLimits::default(),
        &[BELLBOOK_CORE_V1],
    );
    assert_eq!(r.profiles.len(), 2);
    assert_eq!(r.profiles[0].status, ProfileStatus::Unknown);
    assert!(r.profiles[0].declared);
    assert_eq!(r.profiles[0].declaration_matches, None);
    assert!(!r.profiles[0].met());
    assert_eq!(r.profiles[1].status, ProfileStatus::Conformant);
    assert!(!r.profiles[1].declared);
    assert_eq!(r.profiles[1].declaration_matches, None);
    assert!(r.profiles[1].met());
    let text = r.to_string();
    assert!(
        text.contains("profile made-up-v1: UNKNOWN (declared)"),
        "{text}"
    );
    assert!(
        text.contains("profile bellbook-core-v1: CONFORMANT (required)"),
        "{text}"
    );
}

#[test]
fn declarations_are_structural_on_an_earlier_epoch_or_when_malformed() {
    let rules = baseline_rules();
    let receipt = declaring(&receipt_under(&rules), &[BELLBOOK_CORE_V1]);
    let value = || serde_json::to_value(&receipt).unwrap();

    // Declarations are a 0.4 field: a 0.3 receipt carrying one is Invalid
    // before replay, with nothing evaluated.
    let mut v = value();
    v["spec_version"] = "0.3".into();
    let r = validate(&serde_json::to_vec(&v).unwrap());
    assert_eq!(r.status, ValidationStatus::Invalid);
    assert!(r
        .problem
        .as_deref()
        .unwrap()
        .contains("profile declarations require spec 0.4"));
    assert!(r.profiles.is_empty());

    // An empty list is omitted from the wire form and is not a declaration,
    // so a 0.3 receipt written with `"profiles": []` still validates.
    let mut v = value();
    v["spec_version"] = "0.3".into();
    v["profiles"] = serde_json::json!([]);
    assert!(validate(&serde_json::to_vec(&v).unwrap()).problem.is_none());
    let plain = Receipt::new(&[], &rules).to_bytes().unwrap();
    assert!(!String::from_utf8_lossy(&plain).contains("\"profiles\""));

    // Duplicate id.
    let mut v = value();
    let first = v["profiles"][0].clone();
    v["profiles"].as_array_mut().unwrap().push(first);
    let r = validate(&serde_json::to_vec(&v).unwrap());
    assert!(r
        .problem
        .as_deref()
        .unwrap()
        .contains("declared more than once"));

    // Empty id.
    let mut v = value();
    v["profiles"][0]["id"] = "".into();
    let r = validate(&serde_json::to_vec(&v).unwrap());
    assert!(r.problem.as_deref().unwrap().contains("has an empty id"));

    // Strict decoding covers the declaration object too.
    let mut v = value();
    v["profiles"][0]["extra"] = true.into();
    let r = validate(&serde_json::to_vec(&v).unwrap());
    assert!(r
        .problem
        .as_deref()
        .unwrap()
        .contains("unparseable receipt"));
    let mut v = value();
    v["profiles"][0]["hash"] = serde_json::json!([1, 2, 3]);
    let r = validate(&serde_json::to_vec(&v).unwrap());
    assert!(r
        .problem
        .as_deref()
        .unwrap()
        .contains("unparseable receipt"));

    // The builder refuses what it cannot declare honestly.
    assert!(Receipt::new(&[], &rules)
        .with_declared_profiles(&["no-such-profile-v9"])
        .is_err());
    assert!(Receipt::new(&[], &rules)
        .with_declared_profiles(&[BELLBOOK_CORE_V1, BELLBOOK_CORE_V1])
        .is_err());
    assert!(profile_ref("no-such-profile-v9").is_none());
}
