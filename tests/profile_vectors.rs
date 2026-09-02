//! Profile vectors for `bellbook-core-v1` (RFC-0003 section 4.5, SPEC section
//! 12.2), generated from and checked against the reference implementation.
//!
//! Writes `spec/profiles/bellbook-core-v1/profile.json` (the clause table the
//! profile hash commits to) and `cases.json` (receipts paired with the exact
//! profile result each must yield) with `UPDATE_CONFORMANCE=1`; otherwise
//! checks the committed files for drift and re-derives every stored result
//! from the stored receipt - the contract an independent implementation
//! follows. Profile vectors live apart from the core conformance corpus so
//! that a profile can never destabilize core conformance (RFC-0003 C5).

#![cfg(feature = "persist")]

use bellbook::*;
use std::path::PathBuf;

const SPACE: [u8; 32] = [11u8; 32];
const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

fn author(id: &str) -> Author {
    Author {
        id: id.into(),
        type_: AuthorType::Provider,
        signature: None,
    }
}

/// Candidate, passing evaluation, selection - optionally followed by the
/// evaluator retracting its evaluation (a Tainted, still-conformant log).
fn line(rules: &VerifierRules, retract: bool) -> Vec<Record> {
    let dir = tempfile::tempdir().unwrap();
    let mut w = LogWriter::open(dir.path(), rules).unwrap();
    let mut st = State::default();
    let commit = |w: &mut LogWriter,
                  st: &mut State,
                  who: &str,
                  kind: Kind,
                  schema: &str,
                  data: Vec<u8>,
                  refs: Vec<Ref>| {
        let (id, v) = w
            .commit(
                Proposal {
                    space: SPACE,
                    thread: SPACE,
                    author: author(who),
                    kind,
                    schema: schema_id(schema),
                    data,
                    refs,
                },
                rules,
                st,
            )
            .unwrap();
        assert_eq!(v.result, VerdictResult::Accept, "{kind:?} must commit");
        id
    };
    let c0 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        encode(&CandidateData {
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
        vec![],
    );
    let e0 = commit(
        &mut w,
        &mut st,
        "evaluator",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        encode(&EvaluationData {
            candidate: c0,
            criterion: "unit-tests".into(),
            procedure: None,
            outcome: EvaluationOutcome::Passed,
        })
        .unwrap(),
        vec![Ref {
            type_: RefType::Use,
            target: c0,
        }],
    );
    commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        encode(&SelectionData {
            objective: "ship".into(),
            considered: vec![c0],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c0],
            },
            rationale: None,
        })
        .unwrap(),
        vec![
            Ref {
                type_: RefType::Require,
                target: c0,
            },
            Ref {
                type_: RefType::Use,
                target: e0,
            },
        ],
    );
    if retract {
        commit(
            &mut w,
            &mut st,
            "evaluator",
            Kind::Retraction,
            SCHEMA_RETRACTION,
            encode(&RetractionData {
                target_id: e0,
                reason: "harness measured the wrong thing".into(),
            })
            .unwrap(),
            vec![Ref {
                type_: RefType::Cause,
                target: e0,
            }],
        );
    }
    w.records().to_vec()
}

fn roles(rules: VerifierRules) -> VerifierRules {
    rules
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("evaluator", AuthorType::Provider)
}

/// Bump one payload byte of the second record so the receipt still parses
/// but the record's id no longer recomputes: replay rejects it.
fn corrupt(receipt: &Receipt) -> Receipt {
    let mut v: serde_json::Value = serde_json::to_value(receipt).unwrap();
    let byte = &mut v["records"][1]["data"][0];
    let n = byte.as_u64().unwrap();
    *byte = serde_json::Value::from((n + 1) % 256);
    serde_json::from_value(v).unwrap()
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ClauseExpect {
    id: String,
    passed: bool,
}

/// One profile result as the vectors pin it: the surface an independent
/// implementation must reproduce (details are free text and not pinned).
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ProfileExpect {
    id: String,
    status: ProfileStatus,
    declared: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    declaration_matches: Option<bool>,
    clauses: Vec<ClauseExpect>,
}

/// Every profile result validation reports for the case: the receipt's
/// declarations in order, then `bellbook-core-v1` required if not declared.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct CaseExpect {
    profiles: Vec<ProfileExpect>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ProfileCase {
    name: String,
    description: String,
    receipt: Receipt,
    expect: CaseExpect,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct CasesFile {
    profile: String,
    hash: Hash256,
    description: String,
    cases: Vec<ProfileCase>,
}

fn surface(p: &ProfileResult) -> ProfileExpect {
    ProfileExpect {
        id: p.id.clone(),
        status: p.status,
        declared: p.declared,
        declaration_matches: p.declaration_matches,
        clauses: p
            .clauses
            .iter()
            .map(|c| ClauseExpect {
                id: c.id.clone(),
                passed: c.passed,
            })
            .collect(),
    }
}

fn expect_for(receipt: &Receipt) -> CaseExpect {
    let bytes = receipt.to_bytes().unwrap();
    let report = validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
    CaseExpect {
        profiles: report.profiles.iter().map(surface).collect(),
    }
}

fn declaring(receipt: Receipt) -> Receipt {
    receipt.with_declared_profiles(&[BELLBOOK_CORE_V1]).unwrap()
}

fn declaring_ref(mut receipt: Receipt, decl: ProfileRef) -> Receipt {
    receipt.profiles = vec![decl];
    receipt
}

fn build_cases() -> Vec<ProfileCase> {
    let mut cases = Vec::new();
    let mut push = |name: &str, description: &str, receipt: Receipt| {
        let expect = expect_for(&receipt);
        cases.push(ProfileCase {
            name: name.into(),
            description: description.into(),
            receipt,
            expect,
        });
    };

    let baseline = roles(VerifierRules::new(SPACE, 200)).with_baseline_thresholds();
    push(
        "clean-baseline-conformant",
        "A Clean line committed under rules with the baseline thresholds: every clause holds.",
        Receipt::new(&line(&baseline, false), &baseline),
    );
    push(
        "tainted-still-conformant",
        "The evaluator retracts its evaluation: the receipt is Tainted, and Tainted conforms (B1 admits it). Conformance is about the rule shape, not the absence of retractions.",
        Receipt::new(&line(&baseline, true), &baseline),
    );

    let no_thresholds = roles(VerifierRules::new(SPACE, 200));
    push(
        "missing-thresholds-fails-b3",
        "Valid rules without evidence thresholds: the log verifies Clean, but the rules admit assumption-class evolution records, so B3 fails and nothing else does.",
        Receipt::new(&line(&no_thresholds, false), &no_thresholds),
    );

    let weak = baseline
        .clone()
        .with_evidence_threshold(Kind::Selection, Evidence::Assumed);
    push(
        "weaker-than-base-threshold-fails-b3",
        "A Selection threshold of Assumed is present but weaker than the schema base class (Inferred): B3 fails.",
        Receipt::new(&line(&weak, false), &weak),
    );

    let unbounded = roles(VerifierRules::new(SPACE, 0)).with_baseline_thresholds();
    push(
        "context-bound-zero-fails-b4",
        "max_context_records of 0 is outside the declared range: B4 fails while the thresholds (B3) hold.",
        Receipt::new(&line(&unbounded, false), &unbounded),
    );

    let empty_roles = VerifierRules::new(SPACE, 200).with_baseline_thresholds();
    push(
        "empty-log-empty-roles-fails-b2",
        "An empty log validates Clean, but rules that register no author role compare nothing: B2 fails.",
        Receipt::new(&[], &empty_roles),
    );

    push(
        "invalid-receipt-fails-b1",
        "One payload byte altered: the receipt parses, replay rejects it, and B1 fails. B6 reports no accepted candidates because a rejected log made no claims.",
        corrupt(&Receipt::new(&line(&baseline, false), &baseline)),
    );

    // Declarations (spec 0.4, SPEC 12): the receipt claims the profile; the
    // validator evaluates the claim and reports whether the declaration
    // names the table it applied. Never trusted.
    push(
        "declared-conformant",
        "The receipt declares bellbook-core-v1 with the published version and hash, under baseline rules: evaluated without any request, Conformant, declaration matches.",
        declaring(Receipt::new(&line(&baseline, false), &baseline)),
    );
    push(
        "declared-but-nonconformant",
        "A false claim: rules without thresholds declare the baseline. The declaration names the right table, the evaluation says NonConformant, and the verdict stays Clean.",
        declaring(Receipt::new(&line(&no_thresholds, false), &no_thresholds)),
    );
    push(
        "declared-stale-hash",
        "The declaration carries a hash that is not the published clause table's: the profile is evaluated against this validator's table (Conformant) and the declaration is reported as not matching. Not met.",
        declaring_ref(
            Receipt::new(&line(&baseline, false), &baseline),
            ProfileRef {
                id: BELLBOOK_CORE_V1.into(),
                version: 1,
                hash: [0xAB; 32],
            },
        ),
    );
    push(
        "declared-wrong-version",
        "The right hash under a version the profile does not have: a declaration must name both, so it does not match.",
        declaring_ref(
            Receipt::new(&line(&baseline, false), &baseline),
            ProfileRef {
                id: BELLBOOK_CORE_V1.into(),
                version: 2,
                hash: profile_hash(&core_v1_table()),
            },
        ),
    );
    push(
        "declared-unknown-profile",
        "The receipt declares a profile id no validator knows: reported Unknown with nothing to compare, never an error; the required baseline follows it as an undeclared evaluation.",
        declaring_ref(
            Receipt::new(&line(&baseline, false), &baseline),
            ProfileRef {
                id: "made-up-v1".into(),
                version: 1,
                hash: [0u8; 32],
            },
        ),
    );

    cases
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("spec")
        .join("profiles")
        .join(BELLBOOK_CORE_V1)
}

fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap() + "\n").unwrap();
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> T {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} (regenerate with UPDATE_CONFORMANCE=1)",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

#[test]
fn profile_vectors() {
    let table = core_v1_table();
    let file = CasesFile {
        profile: BELLBOOK_CORE_V1.into(),
        hash: profile_hash(&table),
        description: "bellbook-core-v1 profile vectors: each receipt paired with the exact profile result (status and per-clause pass flags) the profile must yield; every failable clause has a rejecting case.".into(),
        cases: build_cases(),
    };
    let d = dir();

    if std::env::var("UPDATE_CONFORMANCE").is_ok() {
        std::fs::create_dir_all(&d).unwrap();
        write_json(&d.join("profile.json"), &table);
        write_json(&d.join("cases.json"), &file);
        return;
    }

    // Drift: the committed files must match what the current code generates.
    let stored_table: ProfileTable = read_json(&d.join("profile.json"));
    assert_eq!(
        stored_table, table,
        "profile table drifted; regenerate with UPDATE_CONFORMANCE=1"
    );
    let stored: CasesFile = read_json(&d.join("cases.json"));
    assert_eq!(
        stored, file,
        "profile vectors drifted; regenerate with UPDATE_CONFORMANCE=1"
    );

    // Correctness: re-derive each stored result from the stored receipt.
    assert_eq!(stored.hash, profile_hash(&stored_table));
    let mut outcomes = std::collections::BTreeSet::new();
    let mut failing = std::collections::BTreeSet::new();
    let mut declarations = std::collections::BTreeSet::new();
    for c in &stored.cases {
        let bytes = c.receipt.to_bytes().unwrap();
        let report =
            validate_with_profiles(&bytes, &ValidationLimits::default(), &[BELLBOOK_CORE_V1]);
        let got: Vec<ProfileExpect> = report.profiles.iter().map(surface).collect();
        assert_eq!(got, c.expect.profiles, "case {}", c.name);
        for p in &report.profiles {
            if p.status == ProfileStatus::Unknown {
                assert_eq!(p.hash, [0u8; 32], "case {}", c.name);
            } else {
                assert_eq!(p.hash, stored.hash, "case {}", c.name);
            }
            outcomes.insert(p.status);
            failing.extend(p.clauses.iter().filter(|k| !k.passed).map(|k| k.id.clone()));
            declarations.insert((p.declared, p.declaration_matches));
        }
        // The declared profiles come first, in declaration order, and the
        // required baseline appears exactly once.
        let declared_ids: Vec<&str> = c.receipt.profiles.iter().map(|d| d.id.as_str()).collect();
        let reported_ids: Vec<&str> = report.profiles.iter().map(|p| p.id.as_str()).collect();
        assert!(reported_ids.starts_with(&declared_ids), "case {}", c.name);
        assert_eq!(
            reported_ids
                .iter()
                .filter(|id| **id == BELLBOOK_CORE_V1)
                .count(),
            1,
            "case {}",
            c.name
        );
    }
    // Coverage: every outcome, a rejecting vector for every failable clause
    // (B5 and B6 are reporting clauses and always hold), and every
    // declaration situation: required, declared and matching, declared with
    // a mismatch, and declared but unknown.
    assert!(outcomes.contains(&ProfileStatus::Conformant));
    assert!(outcomes.contains(&ProfileStatus::NonConformant));
    assert!(outcomes.contains(&ProfileStatus::Unknown));
    for id in ["B1", "B2", "B3", "B4"] {
        assert!(failing.contains(id), "no rejecting vector for {id}");
    }
    for situation in [
        (false, None),
        (true, Some(true)),
        (true, Some(false)),
        (true, None),
    ] {
        assert!(
            declarations.contains(&situation),
            "no vector for declaration situation {situation:?}"
        );
    }
}
