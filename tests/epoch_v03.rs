//! Epoch 0.3 under the current validator (SPEC.md §14, RFC-0003 C6).
//!
//! The backward-validity guarantee is that a receipt valid under spec 0.3
//! stays verifiable under 0.3's rules forever - and that this validator,
//! which implements 0.4, reaches the *identical* decision on it by replaying
//! under the 0.3 schema set. This test re-derives every outcome stored in
//! the frozen 0.3 corpus from its stored inputs with the current code:
//! per-record verdicts, whole-receipt reports (status, reason, hashes,
//! retracted and tainted sets, standing), malformed-document rejection, and
//! the named query set. Nothing here regenerates anything; the bytes are
//! pinned by `tests/frozen_v03.rs`.
//!
//! The comparison is field-by-field on the stored `expect` object, so this
//! file needs no knowledge of the corpus's case structs: every key the 0.3
//! generator recorded must reproduce.

use bellbook::*;
use serde_json::Value;
use std::path::PathBuf;

fn corpus(file: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("spec/conformance/v0.3")
        .join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("frozen 0.3 corpus {} missing: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

/// Every key in `expect` must be present with an equal value in `got`.
fn assert_expect_reproduced(got: &Value, expect: &Value, context: &str) {
    for (key, want) in expect.as_object().unwrap() {
        assert_eq!(
            got.get(key),
            Some(want),
            "{context}: field {key:?} diverged under the 0.4 validator"
        );
    }
}

#[test]
fn v03_receipts_validate_identically() {
    let doc = corpus("receipt-cases.json");
    assert_eq!(doc["spec_version"], "0.3");
    let cases = doc["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    let mut clean = 0;
    for case in cases {
        let bytes = serde_json::to_vec(&case["receipt"]).unwrap();
        let report = validate(&bytes);
        assert_eq!(report.spec_version, "0.3");
        assert!(
            report.problem.is_none(),
            "case {}: {:?}",
            case["name"],
            report.problem
        );
        let got = serde_json::to_value(&report).unwrap();
        // The generator stored the report's sets under shorter keys.
        let mut got = got;
        let obj = got.as_object_mut().unwrap();
        let retracted = obj.remove("retracted_records").unwrap();
        let tainted = obj.remove("tainted_records").unwrap();
        obj.insert("retracted".into(), retracted);
        obj.insert("tainted".into(), tainted);
        assert_expect_reproduced(
            &got,
            &case["expect"],
            &format!("receipt case {}", case["name"]),
        );
        if report.status == ValidationStatus::Clean {
            clean += 1;
        }
    }
    assert!(
        clean > 0,
        "the frozen corpus has Clean receipts to reproduce"
    );
}

#[test]
fn v03_record_cases_verify_identically() {
    let doc = corpus("record-cases.json");
    assert_eq!(doc["spec_version"], "0.3");
    let cases = doc["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let rules: VerifierRules = serde_json::from_value(case["rules"].clone()).unwrap();
        let prior: Vec<Record> = serde_json::from_value(case["prior"].clone()).unwrap();
        let candidate: Record = serde_json::from_value(case["candidate"].clone()).unwrap();
        let expect: VerdictData = serde_json::from_value(case["expect"].clone()).unwrap();
        let state = build_state_unchecked(&prior).unwrap();
        let got = verify_record(&candidate, &prior, &rules, &state);
        assert_eq!(got, expect, "record case {}", case["name"]);
    }
}

#[test]
fn v03_malformed_documents_still_reject() {
    let doc = corpus("malformed-cases.json");
    assert_eq!(doc["spec_version"], "0.3");
    let cases = doc["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let input = case["input"].as_str().unwrap();
        let report = match case.get("limits").filter(|l| !l.is_null()) {
            Some(l) => {
                let mut limits = ValidationLimits::default();
                if let Some(v) = l["max_bytes"].as_u64() {
                    limits.max_bytes = v as usize;
                }
                if let Some(v) = l["max_records"].as_u64() {
                    limits.max_records = v as usize;
                }
                if let Some(v) = l["max_payload_bytes"].as_u64() {
                    limits.max_payload_bytes = v as usize;
                }
                if let Some(v) = l["max_refs_per_record"].as_u64() {
                    limits.max_refs_per_record = v as usize;
                }
                validate_with_limits(input.as_bytes(), &limits)
            }
            None => validate(input.as_bytes()),
        };
        let expect = &case["expect"];
        let got = serde_json::to_value(&report).unwrap();
        assert_eq!(
            got["status"], expect["status"],
            "malformed case {} status",
            case["name"]
        );
        assert_eq!(
            got["reason"], expect["reason"],
            "malformed case {} reason",
            case["name"]
        );
        if let Some(sub) = expect["problem_contains"].as_str() {
            let problem = report.problem.clone().unwrap_or_default();
            assert!(
                problem.contains(sub),
                "malformed case {}: problem {:?} does not contain {:?}",
                case["name"],
                report.problem,
                sub
            );
        }
    }
}

fn hex_to_id(hex: &str) -> RecordId {
    let bytes = hex_decode(hex).expect("query vector id must be valid hex");
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    id
}

fn run_named_query(q: &Queries<'_>, name: &str, args: &Value) -> Value {
    let id = || hex_to_id(args["id"].as_str().expect("args.id"));
    match name {
        "descent" => serde_json::to_value(q.descent(id()).unwrap()).unwrap(),
        "descendants" => serde_json::to_value(q.descendants(id()).unwrap()).unwrap(),
        "siblings" => serde_json::to_value(q.siblings(id()).unwrap()).unwrap(),
        "frontier" => serde_json::to_value(q.frontier()).unwrap(),
        "standing" => serde_json::to_value(q.standing(id()).unwrap()).unwrap(),
        "evidence" => serde_json::to_value(q.evidence(id()).unwrap()).unwrap(),
        "selected" => {
            let objective = args["objective"].as_str().expect("args.objective");
            serde_json::to_value(q.selected(objective)).unwrap()
        }
        other => panic!("unknown query {other:?}"),
    }
}

#[test]
fn v03_query_answers_are_identical() {
    let doc = corpus("query-cases.json");
    assert_eq!(doc["spec_version"], "0.3");
    let cases = doc["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let receipt: Receipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let q = Queries::new(&receipt.records, &receipt.rules)
            .unwrap_or_else(|e| panic!("query case {}: receipt must verify: {e}", case["name"]));
        for v in case["queries"].as_array().unwrap() {
            let got = run_named_query(&q, v["query"].as_str().unwrap(), &v["args"]);
            assert_eq!(
                got, v["expect"],
                "query case {}: {} answer differs",
                case["name"], v["query"]
            );
        }
    }
}

#[test]
fn v03_receipt_cannot_carry_a_later_epoch_schema() {
    // Epoch dispatch is not a courtesy: a receipt that declares 0.3 replays
    // with the 0.3 schema set, so its embedded rules cannot smuggle in a
    // schema the epoch never had. A 0.3 receipt keeps its rules_hash as
    // embedded either way.
    let doc = corpus("receipt-cases.json");
    let case = &doc["cases"][0];
    let bytes = serde_json::to_vec(&case["receipt"]).unwrap();
    let report = validate(&bytes);
    let rules: VerifierRules = serde_json::from_value(case["receipt"]["rules"].clone()).unwrap();
    assert_eq!(report.rules_hash, sha256_canonical(&rules).unwrap());
    for s in SCHEMAS_V03 {
        assert!(ALL_SCHEMAS.contains(s), "0.4 dropped a 0.3 schema: {s}");
    }
    assert_eq!(schemas_for_epoch("0.3"), Some(SCHEMAS_V03));
    assert!(!SCHEMAS_V03.contains(&SCHEMA_REQUIREMENT));
}

/// The same invariant exercised end to end: a 0.4 log that carries a
/// Requirement validates Clean as 0.4, and the identical bytes relabeled
/// `spec_version: "0.3"` reject the Requirement as `UnknownSchema` even
/// though the embedded rules map its schema, because 0.3 never had it.
#[test]
#[cfg(feature = "persist")]
fn relabeling_a_v04_receipt_as_v03_rejects_the_new_kind() {
    let space = default_space();
    let rules = VerifierRules::new(space, 200).with_author_role("human", AuthorType::User);
    let dir = tempfile::tempdir().unwrap();
    let mut w = LogWriter::open(dir.path(), &rules).unwrap();
    let mut st = State::default();
    let author = || Author {
        id: "human".into(),
        type_: AuthorType::User,
        signature: None,
    };
    let (rid, v) = w
        .commit(
            Proposal {
                space,
                thread: space,
                author: author(),
                kind: Kind::Request,
                schema: schema_id(SCHEMA_REQUEST),
                data: encode(&RequestData {
                    objective: "epoch dispatch".into(),
                    scope: space,
                    attachments: vec![],
                    parent_request_id: None,
                })
                .unwrap(),
                refs: vec![],
            },
            &rules,
            &mut st,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (_, v) = w
        .commit(
            Proposal {
                space,
                thread: space,
                author: author(),
                kind: Kind::Requirement,
                schema: schema_id(SCHEMA_REQUIREMENT),
                data: encode(&RequirementData {
                    key: "r1".into(),
                    description: "the first requirement".into(),
                    required: true,
                    expected_evidence: None,
                    provenance: Provenance::UserAuthored,
                })
                .unwrap(),
                refs: vec![Ref {
                    type_: RefType::Cause,
                    target: rid,
                }],
            },
            &rules,
            &mut st,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept, "{:?}", v.reason);

    let receipt = Receipt::new(w.records(), &rules);
    let as_v04 = validate(&receipt.to_bytes().unwrap());
    assert_eq!(as_v04.status, ValidationStatus::Clean);

    let mut relabeled = serde_json::to_value(&receipt).unwrap();
    relabeled["spec_version"] = Value::String("0.3".into());
    let as_v03 = validate(&serde_json::to_vec(&relabeled).unwrap());
    assert_eq!(as_v03.status, ValidationStatus::Invalid);
    assert_eq!(as_v03.reason, Some(ReasonCode::UnknownSchema));
    assert_eq!(as_v03.spec_version, "0.3");
    // The rules hash is over the rules as embedded, in both readings.
    assert_eq!(as_v03.rules_hash, as_v04.rules_hash);
}
