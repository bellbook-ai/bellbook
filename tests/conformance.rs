//! Conformance corpus for the current Bellbook spec epoch.
//!
//! This test builds a machine-readable corpus of verification cases and writes
//! it to `spec/conformance/v0.3/` (regenerate with `UPDATE_CONFORMANCE=1`). Each
//! case pairs a portable input (records + rules, or a raw receipt document) with
//! the expected verification outcome. The runner re-derives every outcome from
//! the *stored* corpus, so an independent implementation (see issue #5) can
//! reproduce the same behavior byte for byte.
//!
//! Three case families:
//!   * record cases   - `verify_record(candidate, prior, rules, state)` == expected verdict.
//!   * receipt cases  - `validate(receipt_bytes)` report status/reason/hashes.
//!   * malformed cases - hostile raw documents that fail structurally.
//!
//! Coverage is asserted: every emitted `ReasonCode` that is expressible in the
//! portable wire format has at least one triggering case.

use bellbook::*;
use std::collections::BTreeSet;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Fixed identifiers (SHA-256-sized values chosen for the corpus).
// ---------------------------------------------------------------------------

const SPACE: [u8; 32] = [1u8; 32];
const THREAD: [u8; 32] = [2u8; 32];
const SCOPE: [u8; 32] = [10u8; 32];
const ACTOR: &str = "agent";

const HUMAN_SEED: [u8; 32] = [21u8; 32];
const WRONG_SEED: [u8; 32] = [22u8; 32];

fn base_rules() -> VerifierRules {
    let mut rules = VerifierRules::new(SPACE, 200)
        .with_author_role("human", AuthorType::User)
        .with_author_role(ACTOR, AuthorType::Provider)
        .with_author_role("tool_executor", AuthorType::Executor)
        .with_author_role("host", AuthorType::System);
    rules.admin_retraction_actors.insert("human".into());
    rules
}

fn pinned_rules() -> VerifierRules {
    let signer = Ed25519Signer::from_secret_bytes(&HUMAN_SEED);
    let mut rules = base_rules();
    rules
        .author_keys
        .insert("human".into(), [signer.public_key()].into_iter().collect());
    rules
}

// ---------------------------------------------------------------------------
// Author + proposal builders (ported so this test crate is self-contained).
// ---------------------------------------------------------------------------

fn author(id: &str, type_: AuthorType) -> Author {
    Author {
        id: id.into(),
        type_,
        signature: None,
    }
}

fn human_author() -> Author {
    author("human", AuthorType::User)
}
fn provider_author() -> Author {
    author(ACTOR, AuthorType::Provider)
}
fn executor_author() -> Author {
    author("tool_executor", AuthorType::Executor)
}

fn request_proposal() -> Proposal {
    let data = encode(&RequestData {
        objective: "conformance objective".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data,
        refs: vec![],
    }
}

fn capability_proposal(
    actor: &str,
    class: &str,
    mode: CapabilityMode,
    expiry: Option<Time>,
) -> Proposal {
    let data = encode(&CapabilityData {
        actor_id: actor.into(),
        action_class: class.into(),
        scope: SCOPE,
        mode,
        expiry,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Capability,
        schema: schema_id(SCHEMA_CAPABILITY),
        data,
        refs: vec![],
    }
}

fn action_data(request_id: RecordId, class: &str, scope: [u8; 32]) -> ActionData {
    ActionData {
        request_id,
        action_class: class.into(),
        scope,
        exec_mode: ExecMode::Internal,
        params: serde_json::json!({}),
    }
}

fn action_proposal_with_authority(
    request_id: RecordId,
    class: &str,
    authority: &[RecordId],
) -> Proposal {
    let data = encode(&action_data(request_id, class, SCOPE)).unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: provider_author(),
        kind: Kind::Action,
        schema: schema_id(SCHEMA_ACTION),
        data,
        refs: authority
            .iter()
            .copied()
            .map(|target| Ref {
                type_: RefType::Require,
                target,
            })
            .collect(),
    }
}

fn external_action_proposal(request_id: RecordId, class: &str, authority: &[RecordId]) -> Proposal {
    let mut data = action_data(request_id, class, SCOPE);
    data.exec_mode = ExecMode::External;
    let data = encode(&data).unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: provider_author(),
        kind: Kind::Action,
        schema: schema_id(SCHEMA_ACTION),
        data,
        refs: authority
            .iter()
            .copied()
            .map(|target| Ref {
                type_: RefType::Require,
                target,
            })
            .collect(),
    }
}

fn result_proposal(action_id: RecordId) -> Proposal {
    let data = encode(&ResultData {
        artifacts: None,
        action_id,
        status: ResultStatus::Success,
        output: "done".into(),
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: executor_author(),
        kind: Kind::Result,
        schema: schema_id(SCHEMA_RESULT),
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: action_id,
        }],
    }
}

fn candidate_proposal(author_: Author) -> Proposal {
    let data = encode(&CandidateData {
        artifacts: None,
        source: SourceBinding {
            git: GitSource {
                algo: SourceAlgo::Sha1,
                tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
                commit: None,
            },
            manifest_hash: None,
            binding: BindingMode::Reported,
        },
        basis: CandidateBasis::Root,
        parent: None,
        note: None,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Candidate,
        schema: schema_id(SCHEMA_CANDIDATE),
        data,
        refs: vec![],
    }
}

fn evaluation_proposal(candidate_id: RecordId, author_: Author) -> Proposal {
    let data = encode(&EvaluationData {
        candidate: candidate_id,
        criterion: "unit-tests".into(),
        procedure: None,
        outcome: EvaluationOutcome::Passed,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Evaluation,
        schema: schema_id(SCHEMA_EVALUATION),
        data,
        refs: vec![Ref {
            type_: RefType::Use,
            target: candidate_id,
        }],
    }
}

fn selection_proposal(
    candidate_id: RecordId,
    evaluation_id: RecordId,
    author_: Author,
) -> Proposal {
    let data = encode(&SelectionData {
        objective: "tests green".into(),
        considered: vec![candidate_id],
        outcome: SelectionOutcome::Selected {
            candidates: vec![candidate_id],
        },
        rationale: None,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Selection,
        schema: schema_id(SCHEMA_SELECTION),
        data,
        refs: vec![
            Ref {
                type_: RefType::Use,
                target: evaluation_id,
            },
            Ref {
                type_: RefType::Require,
                target: candidate_id,
            },
        ],
    }
}

// --- Requirement builders (spec 0.4). ---

/// A Requirement for `request_id` with the given key, provenance, author,
/// and refs (normally the single Cause to the request).
fn requirement_proposal(
    key: &str,
    provenance: Provenance,
    author_: Author,
    refs: Vec<Ref>,
) -> Proposal {
    let data = encode(&RequirementData {
        key: key.into(),
        description: if key.is_empty() {
            "an unlabeled requirement".into()
        } else {
            format!("requirement {key}")
        },
        required: true,
        expected_evidence: None,
        provenance,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Requirement,
        schema: schema_id(SCHEMA_REQUIREMENT),
        data,
        refs,
    }
}

/// Commit a Request and return its id.
fn setup_request(w: &mut LogWriter, rules: &VerifierRules, st: &mut State) -> RecordId {
    let (rid, v) = w.commit(request_proposal(), rules, st).unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    rid
}

// --- Extended evaluation builders (spec 0.4). ---

fn decider(id: &str) -> DeciderBinding {
    DeciderBinding {
        id: id.into(),
        version: Some("1.0".into()),
        procedure_hash: Some(sha256_utf8("cargo test --release")),
        input_hash: None,
    }
}

/// An extended evaluation of `candidate_id` under `schema`, judging against
/// `requirements` (payload ids, written exactly as given) with `refs` as
/// given, so binding and ordering failures reach the verifier.
#[allow(clippy::too_many_arguments)]
fn evaluation_v2_proposal(
    schema: &str,
    candidate_id: RecordId,
    outcome: EvaluationOutcomeV2,
    evaluator: DeciderBinding,
    evidence: Vec<ArtifactRef>,
    requirements: Vec<RecordId>,
    author_: Author,
    refs: Vec<Ref>,
) -> Proposal {
    let data = encode(&EvaluationDataV2 {
        candidate: candidate_id,
        criterion: "tests".into(),
        procedure: Some("cargo test --release".into()),
        outcome,
        evaluator,
        basis: Basis::Recomputed,
        evidence,
        requirements,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Evaluation,
        schema: schema_id(schema),
        data,
        refs,
    }
}

/// Commit a Request, a user-authored Requirement under it, and a root
/// Candidate; returns (requirement, candidate) ids.
fn setup_requirement_and_candidate(
    w: &mut LogWriter,
    rules: &VerifierRules,
    st: &mut State,
) -> (RecordId, RecordId) {
    let rid = setup_request(w, rules, st);
    let (req, v) = w
        .commit(
            requirement_proposal(
                "tests-pass",
                Provenance::UserAuthored,
                human_author(),
                vec![cause_ref(rid)],
            ),
            rules,
            st,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (cid, v) = w
        .commit(candidate_proposal(provider_author()), rules, st)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    (req, cid)
}

/// As [`setup_requirement_and_candidate`], but under pinned rules: the
/// human's Request and Requirement are signed with `signer`, as every
/// record of a key-pinned actor must be.
fn setup_requirement_and_candidate_signed(
    w: &mut LogWriter,
    rules: &VerifierRules,
    st: &mut State,
    signer: &Ed25519Signer,
) -> (RecordId, RecordId) {
    let (rid, v) = w
        .commit_signed(request_proposal(), rules, st, signer)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept, "{:?}", v.reason);
    let (req, v) = w
        .commit_signed(
            requirement_proposal(
                "tests-pass",
                Provenance::UserAuthored,
                human_author(),
                vec![cause_ref(rid)],
            ),
            rules,
            st,
            signer,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept, "{:?}", v.reason);
    let (cid, v) = w
        .commit(candidate_proposal(provider_author()), rules, st)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept, "{:?}", v.reason);
    (req, cid)
}

// --- Artifact identity builders (spec 0.4). ---

fn artifact(scheme: &str, digest: &str, name: Option<&str>) -> ArtifactRef {
    ArtifactRef {
        scheme: scheme.into(),
        digest: digest.into(),
        name: name.map(|s| s.to_string()),
    }
}

/// A root Candidate (reported binding) carrying the given artifact list
/// exactly as written, so malformed and unordered lists reach the verifier.
fn candidate_with_artifacts(artifacts: Vec<ArtifactRef>) -> Proposal {
    let mut p = candidate_proposal(provider_author());
    let data = CandidateData {
        source: default_source(),
        basis: CandidateBasis::Root,
        parent: None,
        note: None,
        artifacts: Some(artifacts),
    };
    p.data = encode(&data).unwrap();
    p
}

/// A Result for `action_id` carrying the given artifact list.
fn result_with_artifacts(action_id: RecordId, artifacts: Vec<ArtifactRef>) -> Proposal {
    let mut p = result_proposal(action_id);
    p.data = encode(&ResultData {
        action_id,
        status: ResultStatus::Success,
        output: "done".into(),
        artifacts: Some(artifacts),
    })
    .unwrap();
    p
}

// --- Flexible evolution builders (for the lineage/selection rule battery). ---

fn default_source() -> SourceBinding {
    SourceBinding {
        git: GitSource {
            algo: SourceAlgo::Sha1,
            // The canonical empty-tree SHA-1 OID (40 lowercase hex).
            tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
            commit: None,
        },
        manifest_hash: None,
        binding: BindingMode::Reported,
    }
}

fn candidate_custom(
    source: SourceBinding,
    basis: CandidateBasis,
    parent: Option<RecordId>,
    note: Option<&str>,
    author_: Author,
    refs: Vec<Ref>,
) -> Proposal {
    let data = encode(&CandidateData {
        artifacts: None,
        source,
        basis,
        parent,
        note: note.map(|s| s.to_string()),
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Candidate,
        schema: schema_id(SCHEMA_CANDIDATE),
        data,
        refs,
    }
}

/// A distinct root candidate (the `note` gives it a unique id).
fn candidate_root_note(note: &str, author_: Author) -> Proposal {
    candidate_custom(
        default_source(),
        CandidateBasis::Root,
        None,
        Some(note),
        author_,
        vec![],
    )
}

fn evaluation_custom(candidate_id: RecordId, author_: Author, refs: Vec<Ref>) -> Proposal {
    let data = encode(&EvaluationData {
        candidate: candidate_id,
        criterion: "unit-tests".into(),
        procedure: None,
        outcome: EvaluationOutcome::Passed,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Evaluation,
        schema: schema_id(SCHEMA_EVALUATION),
        data,
        refs,
    }
}

fn selection_custom(
    objective: &str,
    considered: Vec<RecordId>,
    outcome: SelectionOutcome,
    author_: Author,
    refs: Vec<Ref>,
) -> Proposal {
    let data = encode(&SelectionData {
        objective: objective.into(),
        considered,
        outcome,
        rationale: None,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Selection,
        schema: schema_id(SCHEMA_SELECTION),
        data,
        refs,
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
fn cause_ref(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Cause,
        target,
    }
}
fn replace_ref(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Replace,
        target,
    }
}

/// Rule variants for the selection knobs.
fn rules_min_binding_manifest() -> VerifierRules {
    let mut r = base_rules();
    r.min_binding = BindingMode::Manifest;
    r
}
fn rules_max_considered(n: u32) -> VerifierRules {
    let mut r = base_rules();
    r.max_considered = n;
    r
}
fn rules_reaffirmation_actors(actors: &[&str]) -> VerifierRules {
    let mut r = base_rules();
    r.reaffirmation_actors = actors.iter().map(|s| s.to_string()).collect();
    r
}

fn rules_reject_compromised_continuation() -> VerifierRules {
    let mut r = base_rules();
    r.reject_compromised_continuation = true;
    r
}

/// Commit a clean best-of-one lineage: a root candidate, an evaluation of
/// it, and a Selection that selects it. Returns (candidate, evaluation,
/// selection) ids for building continuation/reaffirmation cases on top.
fn setup_selected_line(
    w: &mut LogWriter,
    r: &VerifierRules,
    s: &mut State,
    objective: &str,
) -> (RecordId, RecordId, RecordId) {
    let (cid, v) = w
        .commit(candidate_proposal(provider_author()), r, s)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (eid, v) = w
        .commit(evaluation_proposal(cid, executor_author()), r, s)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (sid, v) = w
        .commit(
            selection_custom(
                objective,
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(eid), require_ref(cid)],
            ),
            r,
            s,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    (cid, eid, sid)
}

// --- Selection approval builders (spec 0.3 delta D5). ---

fn rules_selection_requires_approval() -> VerifierRules {
    let mut r = base_rules();
    r.selection_requires_approval = true;
    r
}

/// A User-granted exact approval whose subject is a Selection's subject hash.
fn selection_approval_proposal(
    subject_hash: Hash256,
    actor: &str,
    expiry: Option<Time>,
) -> Proposal {
    let data = encode(&ApprovalData {
        target_action: Some(subject_hash),
        action_class: None,
        scope: SCOPE,
        actor_id: Some(actor.into()),
        expiry,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Approval,
        schema: schema_id(SCHEMA_APPROVAL),
        data,
        refs: vec![],
    }
}

/// Build a Selection proposal directly from a `SelectionData`, so the same
/// value can seed both the subject-hash computation and the record.
fn selection_from_data(sd: &SelectionData, author_: Author, refs: Vec<Ref>) -> Proposal {
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: author_,
        kind: Kind::Selection,
        schema: schema_id(SCHEMA_SELECTION),
        data: encode(sd).unwrap(),
        refs,
    }
}

/// Commit a candidate, an evaluation, an approval, and an approved Selection
/// over them under `selection_requires_approval`. Returns (candidate, eval,
/// selection) ids for reaffirmation cases.
fn setup_approved_selected_line(
    w: &mut LogWriter,
    r: &VerifierRules,
    s: &mut State,
    objective: &str,
) -> (RecordId, RecordId, RecordId) {
    let (cid, v) = w
        .commit(candidate_proposal(provider_author()), r, s)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (eid, v) = w
        .commit(evaluation_proposal(cid, executor_author()), r, s)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let sd = SelectionData {
        objective: objective.into(),
        considered: vec![cid],
        outcome: SelectionOutcome::Selected {
            candidates: vec![cid],
        },
        rationale: None,
    };
    let hash = selection_approval_subject_hash(ACTOR, None, &sd).unwrap();
    let (aid, v) = w
        .commit(selection_approval_proposal(hash, ACTOR, None), r, s)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    let (sid, v) = w
        .commit(
            selection_from_data(
                &sd,
                provider_author(),
                vec![use_ref(eid), require_ref(cid), require_ref(aid)],
            ),
            r,
            s,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);
    (cid, eid, sid)
}

fn approval_class_proposal(class: &str, actor: Option<&str>, expiry: Option<Time>) -> Proposal {
    let data = encode(&ApprovalData {
        target_action: None,
        action_class: Some(class.into()),
        scope: SCOPE,
        actor_id: actor.map(|s| s.into()),
        expiry,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Approval,
        schema: schema_id(SCHEMA_APPROVAL),
        data,
        refs: vec![],
    }
}

fn approval_exact_proposal(actor: &str, ad: &ActionData) -> Proposal {
    let target_hash = sha256_canonical(&(&actor.to_string(), ad)).unwrap();
    let data = encode(&ApprovalData {
        target_action: Some(target_hash),
        action_class: None,
        scope: SCOPE,
        actor_id: Some(actor.into()),
        expiry: None,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Approval,
        schema: schema_id(SCHEMA_APPROVAL),
        data,
        refs: vec![],
    }
}

fn response_proposal(request_id: RecordId, turn: u32, closes: bool) -> Proposal {
    let data = encode(&ResponseData {
        request_id,
        content: format!("response turn {}", turn),
        turn_index: turn,
        closes_request: closes,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: provider_author(),
        kind: Kind::Response,
        schema: schema_id(SCHEMA_RESPONSE),
        data,
        refs: vec![],
    }
}

fn summary_proposal(source_ids: &[RecordId]) -> Proposal {
    let subject = sha256_canonical(&(&THREAD, &SummaryType::StateSnapshot)).unwrap();
    let data = encode(&SummaryData {
        summary_type: SummaryType::StateSnapshot,
        subject,
        scope: SCOPE,
        claim_payload: b"compact state summary".to_vec(),
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: provider_author(),
        kind: Kind::Summary,
        schema: schema_id(SCHEMA_SUMMARY),
        data,
        refs: source_ids
            .iter()
            .copied()
            .map(|target| Ref {
                type_: RefType::Use,
                target,
            })
            .collect(),
    }
}

fn refusal_action_proposal(action_id: RecordId) -> Proposal {
    let data = encode(&RefusalData {
        target_id: action_id,
        target_kind: RefusalTarget::Action,
        reason_code: None,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Refusal,
        schema: schema_id(SCHEMA_REFUSAL),
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: action_id,
        }],
    }
}

fn retraction_proposal(target_id: RecordId) -> Proposal {
    let data = encode(&RetractionData {
        target_id,
        reason: "content was wrong".into(),
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

fn plan_proposal(request_id: RecordId) -> Proposal {
    let data = encode(&PlanData {
        request_id,
        tasks: vec![PlanTask {
            id: "t1".into(),
            description: "first task".into(),
            kind: PlanTaskKind::Generic,
            tool_hint: None,
            inputs_from: vec![],
            produces: None,
            done_when: TaskDoneWhen::ToolSuccess,
            status: TaskStatus::Pending,
            result_record_id: None,
            depends_on: vec![],
            on_failure: FailurePolicy::Abort,
        }],
        status: PlanStatus::Running,
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

// ---------------------------------------------------------------------------
// Case containers.
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct RecordCase {
    name: String,
    description: String,
    rules: VerifierRules,
    prior: Vec<Record>,
    candidate: Record,
    expect: VerdictData,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ExpectReport {
    status: ValidationStatus,
    reason: Option<ReasonCode>,
    record_count: u64,
    head_hash: Hash256,
    rules_hash: Hash256,
    retracted: Vec<RecordId>,
    tainted: Vec<RecordId>,
    standing: StandingSection,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ReceiptCase {
    name: String,
    description: String,
    receipt: Receipt,
    expect: ExpectReport,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct CaseLimits {
    max_bytes: usize,
    max_records: usize,
    max_payload_bytes: usize,
    max_refs_per_record: usize,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct MalformedExpect {
    status: ValidationStatus,
    reason: Option<ReasonCode>,
    problem_contains: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct MalformedCase {
    name: String,
    description: String,
    input: String,
    limits: Option<CaseLimits>,
    expect: MalformedExpect,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct Corpus {
    spec_version: String,
    record_cases: Vec<RecordCase>,
    receipt_cases: Vec<ReceiptCase>,
    malformed_cases: Vec<MalformedCase>,
}

fn expect_from_report(r: &Report) -> ExpectReport {
    ExpectReport {
        status: r.status,
        reason: r.reason,
        record_count: r.record_count,
        head_hash: r.head_hash,
        rules_hash: r.rules_hash,
        retracted: r.retracted_records.iter().copied().collect(),
        tainted: r.tainted_records.iter().copied().collect(),
        standing: r.standing.clone(),
    }
}

// ---------------------------------------------------------------------------
// Record-case builder: commit a scripted prior, then commit the candidate and
// capture the verdict the verifier assigns it.
// ---------------------------------------------------------------------------

struct Cand {
    proposal: Proposal,
    signer: Option<Ed25519Signer>,
}
fn cand(proposal: Proposal) -> Cand {
    Cand {
        proposal,
        signer: None,
    }
}
fn signed(proposal: Proposal, signer: Ed25519Signer) -> Cand {
    Cand {
        proposal,
        signer: Some(signer),
    }
}

fn record_case<F>(name: &str, description: &str, rules: VerifierRules, build: F) -> RecordCase
where
    F: FnOnce(&mut LogWriter, &VerifierRules, &mut State) -> Cand,
{
    let dir = tempfile::tempdir().unwrap();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    let c = build(&mut writer, &rules, &mut state);
    let prior_len = writer.records().len();
    let (_, verdict) = match c.signer {
        Some(ref s) => writer
            .commit_signed(c.proposal, &rules, &mut state, s)
            .unwrap(),
        None => writer.commit(c.proposal, &rules, &mut state).unwrap(),
    };
    let prior = writer.records()[..prior_len].to_vec();
    let candidate = writer.records()[prior_len].clone();
    RecordCase {
        name: name.into(),
        description: description.into(),
        rules,
        prior,
        candidate,
        expect: verdict,
    }
}

/// Commit an accepted request + Auto capability, returning their ids.
fn setup_request_cap(
    w: &mut LogWriter,
    rules: &VerifierRules,
    st: &mut State,
    class: &str,
    mode: CapabilityMode,
) -> (RecordId, RecordId) {
    let (rid, v1) = w.commit(request_proposal(), rules, st).unwrap();
    assert_eq!(v1.result, VerdictResult::Accept);
    let (cid, v2) = w
        .commit(capability_proposal(ACTOR, class, mode, None), rules, st)
        .unwrap();
    assert_eq!(v2.result, VerdictResult::Accept);
    (rid, cid)
}

fn build_record_cases() -> Vec<RecordCase> {
    let mut cases = Vec::new();

    // --- Author-role acceptance (the natural author for each kind). ---
    cases.push(record_case(
        "accept-request",
        "A User authors a Request from genesis.",
        base_rules(),
        |_w, _r, _s| cand(request_proposal()),
    ));
    cases.push(record_case(
        "accept-capability",
        "A User grants a Capability after a Request.",
        base_rules(),
        |w, r, s| {
            let _ = w.commit(request_proposal(), r, s).unwrap();
            cand(capability_proposal(
                ACTOR,
                "tool",
                CapabilityMode::Auto,
                None,
            ))
        },
    ));
    cases.push(record_case(
        "accept-action",
        "A Provider acts under an Auto capability it names via a Require ref.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            cand(action_proposal_with_authority(rid, "tool", &[cid]))
        },
    ));
    cases.push(record_case(
        "accept-result",
        "An Executor reports a Result for an accepted Action.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            let (aid, v) = w
                .commit(action_proposal_with_authority(rid, "tool", &[cid]), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(result_proposal(aid))
        },
    ));
    cases.push(record_case(
        "accept-response",
        "A Provider responds within a Request's turn sequence.",
        base_rules(),
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            cand(response_proposal(rid, 0, false))
        },
    ));
    cases.push(record_case(
        "accept-approval",
        "A User grants a class Approval.",
        base_rules(),
        |w, r, s| {
            let _ = w.commit(request_proposal(), r, s).unwrap();
            cand(approval_class_proposal("tool", Some(ACTOR), None))
        },
    ));
    cases.push(record_case(
        "accept-refusal",
        "A User refuses an accepted Action.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            let (aid, _) = w
                .commit(action_proposal_with_authority(rid, "tool", &[cid]), r, s)
                .unwrap();
            cand(refusal_action_proposal(aid))
        },
    ));
    cases.push(record_case(
        "accept-plan",
        "A Provider records an advisory Plan for a Request.",
        base_rules(),
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            cand(plan_proposal(rid))
        },
    ));
    cases.push(record_case(
        "accept-retraction",
        "The admin User retracts an earlier Summary.",
        base_rules(),
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            let (sid, v) = w.commit(summary_proposal(&[rid]), r, s).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(retraction_proposal(sid))
        },
    ));
    cases.push(record_case(
        "accept-signed-pinned",
        "A key-pinned User authors a validly signed Request.",
        pinned_rules(),
        |_w, _r, _s| {
            signed(
                request_proposal(),
                Ed25519Signer::from_secret_bytes(&HUMAN_SEED),
            )
        },
    ));

    // --- Author-role rejection: the natural author with the wrong type. ---
    cases.push(record_case(
        "reject-request-wrong-role",
        "A Request whose author claims Provider instead of User.",
        base_rules(),
        |_w, _r, _s| {
            let mut p = request_proposal();
            p.author = author("human", AuthorType::Provider);
            cand(p)
        },
    ));
    cases.push(record_case(
        "reject-unregistered-author",
        "A Request from an actor not registered in author_roles.",
        base_rules(),
        |_w, _r, _s| {
            let mut p = request_proposal();
            p.author = author("stranger", AuthorType::User);
            cand(p)
        },
    ));

    // --- Signatures. ---
    cases.push(record_case(
        "reject-signature-missing",
        "A key-pinned actor authors an unsigned record.",
        pinned_rules(),
        |_w, _r, _s| cand(request_proposal()),
    ));
    cases.push(record_case(
        "reject-signature-invalid",
        "A key-pinned actor signs with a key that is not pinned.",
        pinned_rules(),
        |_w, _r, _s| {
            signed(
                request_proposal(),
                Ed25519Signer::from_secret_bytes(&WRONG_SEED),
            )
        },
    ));

    // --- Schema. ---
    cases.push(record_case(
        "reject-unknown-schema",
        "A record whose schema is absent from the rules' schema map.",
        base_rules(),
        |_w, _r, _s| {
            let mut p = request_proposal();
            p.schema = sha256_utf8("bellbook.not-a-real-schema.v1");
            cand(p)
        },
    ));
    cases.push(record_case(
        "reject-kind-schema-mismatch",
        "A Request record carrying the Capability schema id.",
        base_rules(),
        |_w, _r, _s| {
            let mut p = request_proposal();
            p.schema = schema_id(SCHEMA_CAPABILITY);
            cand(p)
        },
    ));

    // --- Payload canonicality. ---
    cases.push(record_case(
        "reject-non-canonical-payload",
        "A Request whose data bytes are valid JSON but not the exact JCS form.",
        base_rules(),
        |_w, _r, _s| {
            let mut p = request_proposal();
            let mut bytes = vec![b' '];
            bytes.extend_from_slice(&p.data);
            p.data = bytes;
            cand(p)
        },
    ));

    // --- Lifecycle / references. ---
    cases.push(record_case(
        "reject-request-missing",
        "A Response referencing a request id that is not in the log.",
        base_rules(),
        |w, r, s| {
            let _ = w.commit(request_proposal(), r, s).unwrap();
            cand(response_proposal([9u8; 32], 0, false))
        },
    ));
    cases.push(record_case(
        "reject-authority-ref-missing",
        "An Action that does not name any capability via a Require ref.",
        base_rules(),
        |w, r, s| {
            let (rid, _cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            cand(action_proposal_with_authority(rid, "tool", &[]))
        },
    ));
    cases.push(record_case(
        "reject-capability-denied",
        "An Action naming a Deny-mode capability.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Deny);
            cand(action_proposal_with_authority(rid, "tool", &[cid]))
        },
    ));
    cases.push(record_case(
        "reject-approval-missing",
        "An Ask-mode Action with no matching approval.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Ask);
            cand(action_proposal_with_authority(rid, "tool", &[cid]))
        },
    ));
    cases.push(record_case(
        "reject-ref-unresolved",
        "An Action naming a capability that was retracted before the action.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            let (_ret, v) = w.commit(retraction_proposal(cid), r, s).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(action_proposal_with_authority(rid, "tool", &[cid]))
        },
    ));
    cases.push(record_case(
        "reject-external-receipt-required",
        "A Result for an External-mode action that uses the internal Result schema instead of the external-receipt schema.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            let (aid, v) = w
                .commit(external_action_proposal(rid, "tool", &[cid]), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept, "external action should be accepted");
            cand(result_proposal(aid))
        },
    ));
    cases.push(record_case(
        "reject-evidence-below-threshold",
        "A Summary whose derived evidence is weaker than the per-kind threshold.",
        {
            let mut rules = base_rules();
            rules
                .evidence_thresholds
                .insert(Kind::Summary, Evidence::Verified);
            rules
        },
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            cand(summary_proposal(&[rid]))
        },
    ));
    cases.push(record_case(
        "reject-capability-missing",
        "An Action for a class with no matching capability (a capability exists for a different class).",
        base_rules(),
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            let (cid, v) = w
                .commit(capability_proposal(ACTOR, "read", CapabilityMode::Auto, None), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(action_proposal_with_authority(rid, "tool", &[cid]))
        },
    ));
    // Shares the CapabilityMissing reason with reject-capability-missing (there
    // is no CapabilityExpired code) but exercises the expiry branch.
    cases.push(record_case(
        "reject-capability-expired",
        "An Action naming a capability whose expiry time has passed.",
        base_rules(),
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            // request=1, capability=3 (expiry 4, valid at creation), action=5 >= 4 -> expired.
            let (cid, v) = w
                .commit(
                    capability_proposal(ACTOR, "tool", CapabilityMode::Auto, Some(4)),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(action_proposal_with_authority(rid, "tool", &[cid]))
        },
    ));
    cases.push(record_case(
        "reject-approval-expired",
        "An Ask-mode Action naming a class approval whose expiry time has passed.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Ask);
            // request=1, capability=3, approval=5 (expiry 6, valid at creation), action=7 >= 6.
            let (apid, v) = w
                .commit(approval_class_proposal("tool", Some(ACTOR), Some(6)), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(action_proposal_with_authority(rid, "tool", &[cid, apid]))
        },
    ));
    cases.push(record_case(
        "reject-action-closed",
        "A Result whose action id refers to a record that is not an open action.",
        base_rules(),
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            cand(result_proposal(rid))
        },
    ));
    cases.push(record_case(
        "reject-replacement-invalid",
        "A Capability carrying a Replace ref to a Request (a different kind).",
        base_rules(),
        |w, r, s| {
            let (rid, _) = w.commit(request_proposal(), r, s).unwrap();
            let mut p = capability_proposal(ACTOR, "tool", CapabilityMode::Auto, None);
            p.refs = vec![Ref {
                type_: RefType::Replace,
                target: rid,
            }];
            cand(p)
        },
    ));
    // Shares the ApprovalMissing reason with reject-approval-missing but
    // exercises the single-use consumption path (the approval was spent).
    cases.push(record_case(
        "reject-exact-approval-single-use",
        "A second Action reusing an exact approval that a first Action already consumed.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Ask);
            let ad = action_data(rid, "tool", SCOPE);
            let (apid, v0) = w.commit(approval_exact_proposal(ACTOR, &ad), r, s).unwrap();
            assert_eq!(v0.result, VerdictResult::Accept);
            // First action consumes the single-use exact approval.
            let (_a1, v1) = w
                .commit(
                    action_proposal_with_authority(rid, "tool", &[cid, apid]),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v1.result, VerdictResult::Accept);
            // Second, identical action can no longer resolve the consumed approval.
            cand(action_proposal_with_authority(rid, "tool", &[cid, apid]))
        },
    ));

    // Evolution kinds (spec 0.3): accepted baselines shaped to stay valid
    // under the full lineage battery, plus one author-machinery rejection
    // per kind, each exercising a different leg (unregistered author,
    // registered-role mismatch, kind-to-author-type table).
    cases.push(record_case(
        "accept-candidate-root",
        "A root Candidate with a reported Git binding.",
        base_rules(),
        |_w, _r, _s| cand(candidate_proposal(provider_author())),
    ));
    // --- Requirement (spec 0.4): binding, key uniqueness, provenance. ---
    cases.push(record_case(
        "accept-requirement-user-authored",
        "The human principal states a requirement for an accepted Request: one Cause to the request, provenance user_authored from a User author.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::UserAuthored,
                human_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "accept-requirement-derived",
        "The agent derives a requirement from the request: provenance derived from a Provider author.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            cand(requirement_proposal(
                "lint-clean",
                Provenance::Derived,
                provider_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-provenance-not-a-user",
        "Provenance is bound to authorship: a Provider claiming user_authored rejects with AuthorRoleInvalid.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::UserAuthored,
                provider_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-derived-by-user",
        "The other direction of the binding: a User writing a derived requirement rejects with AuthorRoleInvalid.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::Derived,
                human_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-executor-author",
        "The role that performs work never states what the work must satisfy: an Executor-authored Requirement rejects with AuthorRoleInvalid.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::Derived,
                executor_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-duplicate-key",
        "A second Requirement with a key already held under the same request rejects with RequirementInvalid.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            let (_, v) = w
                .commit(
                    requirement_proposal(
                        "tests-pass",
                        Provenance::UserAuthored,
                        human_author(),
                        vec![cause_ref(rid)],
                    ),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::Derived,
                provider_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "accept-requirement-key-reused-after-retraction",
        "Amendment is retract-and-record: after the principal retracts a requirement, a corrected one may carry the same key.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            let (req1, v) = w
                .commit(
                    requirement_proposal(
                        "tests-pass",
                        Provenance::UserAuthored,
                        human_author(),
                        vec![cause_ref(rid)],
                    ),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (_, v) = w.commit(retraction_proposal(req1), r, s).unwrap();
            assert_eq!(v.result, VerdictResult::Accept, "{:?}", v.reason);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::UserAuthored,
                human_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-empty-key",
        "A Requirement needs a handle: an empty key rejects with RequirementInvalid.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            cand(requirement_proposal(
                "",
                Provenance::UserAuthored,
                human_author(),
                vec![cause_ref(rid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-no-cause",
        "A Requirement belongs to a request: with no Cause ref it rejects with RequirementInvalid.",
        base_rules(),
        |w, r, s| {
            let _rid = setup_request(w, r, s);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::UserAuthored,
                human_author(),
                vec![],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-cause-not-a-request",
        "The single Cause must target an accepted Request: a Cause to a Capability rejects with RequirementInvalid.",
        base_rules(),
        |w, r, s| {
            let (_rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            cand(requirement_proposal(
                "tests-pass",
                Provenance::UserAuthored,
                human_author(),
                vec![cause_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-requirement-replace",
        "Requirements are never replaced (amendment is retract-and-record): a Replace ref rejects with ReplacementInvalid.",
        base_rules(),
        |w, r, s| {
            let rid = setup_request(w, r, s);
            let (req1, v) = w
                .commit(
                    requirement_proposal(
                        "tests-pass",
                        Provenance::UserAuthored,
                        human_author(),
                        vec![cause_ref(rid)],
                    ),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(requirement_proposal(
                "tests-pass-v2",
                Provenance::UserAuthored,
                human_author(),
                vec![cause_ref(rid), replace_ref(req1)],
            ))
        },
    ));

    // --- Extended evaluation (spec 0.4): decider binding, evidence,
    // requirement binding, fail-closed outcomes, the attested schema. ---
    cases.push(record_case(
        "accept-evaluation-v2",
        "An extended Evaluation: a bound decider, recomputed basis, one evidence artifact, and one Requirement it speaks to, mirrored by Use refs to both the candidate and the requirement.",
        base_rules(),
        |w, r, s| {
            let (req, cid) = setup_requirement_and_candidate(w, r, s);
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_V2,
                cid,
                EvaluationOutcomeV2::Passed,
                decider("ci-harness"),
                vec![artifact("sha256-bytes", &"ab".repeat(32), Some("junit.xml"))],
                vec![req],
                provider_author(),
                vec![use_ref(cid), use_ref(req)],
            ))
        },
    ));
    cases.push(record_case(
        "accept-evaluation-v2-blocked",
        "A fail-closed outcome: the evaluator could not proceed and says so (blocked), with no requirements and no evidence. Recorded as what it is, never as a pass.",
        base_rules(),
        |w, r, s| {
            let (_req, cid) = setup_requirement_and_candidate(w, r, s);
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_V2,
                cid,
                EvaluationOutcomeV2::Blocked,
                decider("ci-harness"),
                vec![],
                vec![],
                provider_author(),
                vec![use_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-evaluation-v2-empty-evaluator-id",
        "A decider binding needs an identity: an empty evaluator.id rejects with EvaluationInvalid.",
        base_rules(),
        |w, r, s| {
            let (_req, cid) = setup_requirement_and_candidate(w, r, s);
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_V2,
                cid,
                EvaluationOutcomeV2::Passed,
                decider(""),
                vec![],
                vec![],
                provider_author(),
                vec![use_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-evaluation-v2-requirement-not-used",
        "Each bound requirement must be mirrored by a Use ref (so a retracted requirement taints the evaluation): the payload names the requirement but the refs do not; EvaluationInvalid.",
        base_rules(),
        |w, r, s| {
            let (req, cid) = setup_requirement_and_candidate(w, r, s);
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_V2,
                cid,
                EvaluationOutcomeV2::Passed,
                decider("ci-harness"),
                vec![],
                vec![req],
                provider_author(),
                vec![use_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-evaluation-v2-requirement-not-a-requirement",
        "A bound requirement must resolve to an accepted Requirement: naming the candidate itself rejects with EvaluationInvalid.",
        base_rules(),
        |w, r, s| {
            let (_req, cid) = setup_requirement_and_candidate(w, r, s);
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_V2,
                cid,
                EvaluationOutcomeV2::Passed,
                decider("ci-harness"),
                vec![],
                vec![cid],
                provider_author(),
                vec![use_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-evaluation-v2-requirements-unordered",
        "The requirements list is strictly increasing: two accepted requirements in the wrong order reject with EvaluationInvalid.",
        base_rules(),
        |w, r, s| {
            let (req1, cid) = setup_requirement_and_candidate(w, r, s);
            let rid = {
                // The request is the Cause of req1.
                let rec = w.records().iter().find(|x| x.id == req1).unwrap();
                rec.refs[0].target
            };
            let (req2, v) = w
                .commit(
                    requirement_proposal(
                        "lint-clean",
                        Provenance::UserAuthored,
                        human_author(),
                        vec![cause_ref(rid)],
                    ),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (lo, hi) = if req1 < req2 {
                (req1, req2)
            } else {
                (req2, req1)
            };
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_V2,
                cid,
                EvaluationOutcomeV2::Passed,
                decider("ci-harness"),
                vec![],
                vec![hi, lo],
                provider_author(),
                vec![use_ref(cid), use_ref(lo), use_ref(hi)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-evaluation-v2-evidence-malformed",
        "The evidence list follows the artifact rules: a registered scheme with the wrong digest length rejects with ArtifactRefInvalid.",
        base_rules(),
        |w, r, s| {
            let (_req, cid) = setup_requirement_and_candidate(w, r, s);
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_V2,
                cid,
                EvaluationOutcomeV2::Passed,
                decider("ci-harness"),
                vec![artifact("git-tree-sha1", &"ab".repeat(32), None)],
                vec![],
                provider_author(),
                vec![use_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "accept-evaluation-attested-signed-pinned",
        "The attested schema earns Verified: a key-pinned User signs an extended evaluation; the signature verifies under the pinned key.",
        pinned_rules(),
        |w, r, s| {
            let signer = Ed25519Signer::from_secret_bytes(&HUMAN_SEED);
            let (req, cid) = setup_requirement_and_candidate_signed(w, r, s, &signer);
            signed(
                evaluation_v2_proposal(
                    SCHEMA_EVALUATION_ATTESTED,
                    cid,
                    EvaluationOutcomeV2::Passed,
                    decider("reviewer-desk"),
                    vec![],
                    vec![req],
                    human_author(),
                    vec![use_ref(cid), use_ref(req)],
                ),
                Ed25519Signer::from_secret_bytes(&HUMAN_SEED),
            )
        },
    ));
    cases.push(record_case(
        "reject-evaluation-attested-unsigned",
        "Verified is earned, never asserted: an unsigned record under the attested schema rejects with SignatureMissing even though nothing pins its author.",
        base_rules(),
        |w, r, s| {
            let (_req, cid) = setup_requirement_and_candidate(w, r, s);
            cand(evaluation_v2_proposal(
                SCHEMA_EVALUATION_ATTESTED,
                cid,
                EvaluationOutcomeV2::Passed,
                decider("ci-harness"),
                vec![],
                vec![],
                provider_author(),
                vec![use_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "reject-evaluation-attested-unpinned-signer",
        "A valid signature from an author with no pinned keys proves key possession, not identity: the attested schema rejects it with SignatureInvalid.",
        base_rules(),
        |w, r, s| {
            let (_req, cid) = setup_requirement_and_candidate(w, r, s);
            signed(
                evaluation_v2_proposal(
                    SCHEMA_EVALUATION_ATTESTED,
                    cid,
                    EvaluationOutcomeV2::Passed,
                    decider("reviewer-desk"),
                    vec![],
                    vec![],
                    human_author(),
                    vec![use_ref(cid)],
                ),
                Ed25519Signer::from_secret_bytes(&HUMAN_SEED),
            )
        },
    ));
    cases.push(record_case(
        "accept-selection-uses-v2-evaluation",
        "A Selection may Use an extended evaluation as its evidence: the subject rule reads the v2 shape.",
        base_rules(),
        |w, r, s| {
            let (req, cid) = setup_requirement_and_candidate(w, r, s);
            let (eid, v) = w
                .commit(
                    evaluation_v2_proposal(
                        SCHEMA_EVALUATION_V2,
                        cid,
                        EvaluationOutcomeV2::Passed,
                        decider("ci-harness"),
                        vec![],
                        vec![req],
                        provider_author(),
                        vec![use_ref(cid), use_ref(req)],
                    ),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept, "{:?}", v.reason);
            cand(selection_proposal(cid, eid, provider_author()))
        },
    ));

    // --- Artifact identity (spec 0.4): the additive `artifacts` list. ---
    cases.push(record_case(
        "accept-candidate-with-artifacts",
        "A root Candidate binding two artifacts beyond its source: a registered scheme with a label and an unregistered scheme under the generic digest rule, in (scheme, digest, name) order.",
        base_rules(),
        |_w, _r, _s| {
            cand(candidate_with_artifacts(vec![
                artifact("git-archive-tar-v1", &"ab".repeat(32), Some("src.tar")),
                artifact("x-custom-digest", &"cd".repeat(24), None),
            ]))
        },
    ));
    cases.push(record_case(
        "reject-candidate-artifact-digest-length",
        "A registered scheme fixes its digest length: a git-tree-sha1 digest of 32 bytes rejects with ArtifactRefInvalid.",
        base_rules(),
        |_w, _r, _s| {
            cand(candidate_with_artifacts(vec![artifact(
                "git-tree-sha1",
                &"ab".repeat(32),
                None,
            )]))
        },
    ));
    cases.push(record_case(
        "reject-candidate-artifact-digest-uppercase",
        "Digests are lowercase hex; an uppercase digit rejects with ArtifactRefInvalid.",
        base_rules(),
        |_w, _r, _s| {
            cand(candidate_with_artifacts(vec![artifact(
                "sha256-bytes",
                &format!("AB{}", "ab".repeat(31)),
                None,
            )]))
        },
    ));
    cases.push(record_case(
        "reject-candidate-artifact-scheme-token",
        "A scheme is a lowercase token; an uppercase or slash-bearing scheme rejects with ArtifactRefInvalid.",
        base_rules(),
        |_w, _r, _s| {
            cand(candidate_with_artifacts(vec![artifact(
                "OCI/manifest",
                &"ab".repeat(32),
                None,
            )]))
        },
    ));
    cases.push(record_case(
        "reject-candidate-artifacts-unordered",
        "The list is strictly sorted by (scheme, digest, name); two well-formed entries in the wrong order reject with ArtifactRefInvalid.",
        base_rules(),
        |_w, _r, _s| {
            cand(candidate_with_artifacts(vec![
                artifact("sha256-bytes", &"ab".repeat(32), None),
                artifact("git-tree-sha256", &"ab".repeat(32), None),
            ]))
        },
    ));
    cases.push(record_case(
        "reject-candidate-artifacts-duplicate",
        "Deduplicated means strictly increasing: a repeated entry rejects with ArtifactRefInvalid.",
        base_rules(),
        |_w, _r, _s| {
            cand(candidate_with_artifacts(vec![
                artifact("sha256-bytes", &"ab".repeat(32), Some("a")),
                artifact("sha256-bytes", &"ab".repeat(32), Some("a")),
            ]))
        },
    ));
    cases.push(record_case(
        "reject-candidate-artifact-unregistered-too-short",
        "An unregistered scheme takes the generic rule: a 16-byte digest is below the 20-byte floor and rejects with ArtifactRefInvalid.",
        base_rules(),
        |_w, _r, _s| {
            cand(candidate_with_artifacts(vec![artifact(
                "x-custom-digest",
                &"ab".repeat(16),
                None,
            )]))
        },
    ));
    cases.push(record_case(
        "accept-result-with-artifacts",
        "A Result naming the artifact it produced: the same additive list on the executor's record.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            let (aid, v) = w
                .commit(action_proposal_with_authority(rid, "tool", &[cid]), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(result_with_artifacts(
                aid,
                vec![artifact("sha256-bytes", &"ef".repeat(32), Some("out.bin"))],
            ))
        },
    ));
    cases.push(record_case(
        "reject-result-artifact-odd-hex",
        "A Result's artifact digest must be even-length hex; an odd-length digest rejects with ArtifactRefInvalid.",
        base_rules(),
        |w, r, s| {
            let (rid, cid) = setup_request_cap(w, r, s, "tool", CapabilityMode::Auto);
            let (aid, v) = w
                .commit(action_proposal_with_authority(rid, "tool", &[cid]), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(result_with_artifacts(
                aid,
                vec![artifact("x-custom-digest", &format!("{}a", "ab".repeat(20)), None)],
            ))
        },
    ));
    cases.push(record_case(
        "accept-evaluation",
        "An Evaluation that Uses its accepted candidate.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(evaluation_proposal(cid, executor_author()))
        },
    ));
    cases.push(record_case(
        "accept-selection",
        "A Selection that Requires its winner and Uses its evaluation.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_proposal(cid, eid, provider_author()))
        },
    ));
    cases.push(record_case(
        "reject-author-role-candidate-unregistered",
        "A Candidate whose author id is not registered in author_roles.",
        base_rules(),
        |_w, _r, _s| cand(candidate_proposal(author("stranger", AuthorType::User))),
    ));
    cases.push(record_case(
        "reject-author-role-evaluation-mismatch",
        "An Evaluation whose author is registered as System but declares Executor.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(evaluation_proposal(
                cid,
                author("host", AuthorType::Executor),
            ))
        },
    ));
    cases.push(record_case(
        "reject-author-role-selection-executor",
        "An Executor-authored Selection: decisions are not for the role that performs work.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_proposal(cid, eid, executor_author()))
        },
    ));

    // --- Evolution lineage/selection battery (spec 0.3, delta D3/D4). ---

    // Accepts covering continuation, derivation, none, and reaffirmation.
    cases.push(record_case(
        "accept-candidate-continuation",
        "A Continuation candidate anchored on a Selection, parent in its selected set.",
        base_rules(),
        |w, r, s| {
            let (cid, _eid, sid) = setup_selected_line(w, r, s, "tests green");
            cand(candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(cid),
                Some("next"),
                provider_author(),
                vec![cause_ref(sid)],
            ))
        },
    ));
    cases.push(record_case(
        "accept-candidate-derivation",
        "A Derivation candidate whose Cause targets a prior accepted candidate.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(candidate_custom(
                default_source(),
                CandidateBasis::Derivation,
                None,
                Some("repair"),
                provider_author(),
                vec![cause_ref(cid)],
            ))
        },
    ));
    cases.push(record_case(
        "accept-selection-none",
        "A Selection that considers a candidate but selects none (a prune).",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::None,
                provider_author(),
                vec![],
            ))
        },
    ));
    cases.push(record_case(
        "accept-selection-reaffirmation",
        "A Selection that Replaces a prior Selection under the same objective.",
        base_rules(),
        |w, r, s| {
            let (cid, eid, sid) = setup_selected_line(w, r, s, "tests green");
            cand(selection_custom(
                "tests green",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(eid), require_ref(cid), replace_ref(sid)],
            ))
        },
    ));

    // SourceBindingInvalid: manifest hash present without the manifest mode.
    cases.push(record_case(
        "reject-candidate-source-binding-manifest-mismatch",
        "A Candidate whose manifest_hash is present while binding is reported.",
        base_rules(),
        |_w, _r, _s| {
            let mut src = default_source();
            src.manifest_hash = Some([9u8; 32]); // present, but binding stays reported
            cand(candidate_custom(
                src,
                CandidateBasis::Root,
                None,
                Some("bad-binding"),
                provider_author(),
                vec![],
            ))
        },
    ));
    // SourceBindingInvalid: tree OID length does not match its algo.
    cases.push(record_case(
        "reject-candidate-source-binding-tree-length",
        "A Candidate declaring sha256 with a 40-hex (sha1-length) tree OID.",
        base_rules(),
        |_w, _r, _s| {
            let src = SourceBinding {
                git: GitSource {
                    algo: SourceAlgo::Sha256,
                    tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(), // 40 hex
                    commit: None,
                },
                manifest_hash: None,
                binding: BindingMode::Reported,
            };
            cand(candidate_custom(
                src,
                CandidateBasis::Root,
                None,
                Some("bad-len"),
                provider_author(),
                vec![],
            ))
        },
    ));
    // LineageInvalid: a Root candidate that carries a parent.
    cases.push(record_case(
        "reject-candidate-root-with-parent",
        "A Root candidate naming a parent, which Root forbids.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(candidate_custom(
                default_source(),
                CandidateBasis::Root,
                Some(cid),
                Some("root-parent"),
                provider_author(),
                vec![],
            ))
        },
    ));
    // LineageInvalid: a Continuation whose parent is not in the selected set.
    cases.push(record_case(
        "reject-candidate-continuation-parent-not-selected",
        "A Continuation whose parent resolves but is not in its anchor's selected set.",
        base_rules(),
        |w, r, s| {
            let (_cid, _eid, sid) = setup_selected_line(w, r, s, "tests green");
            // A second accepted candidate, never selected by the anchor.
            let (other, v) = w
                .commit(candidate_root_note("other", provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(other),
                Some("wrong-parent"),
                provider_author(),
                vec![cause_ref(sid)],
            ))
        },
    ));
    // LineageInvalid: a Derivation whose Cause targets a Selection.
    cases.push(record_case(
        "reject-candidate-derivation-selection-cause",
        "A Derivation whose Cause targets a Selection, which derivation forbids.",
        base_rules(),
        |w, r, s| {
            let (_cid, _eid, sid) = setup_selected_line(w, r, s, "tests green");
            cand(candidate_custom(
                default_source(),
                CandidateBasis::Derivation,
                None,
                Some("bad-derivation"),
                provider_author(),
                vec![cause_ref(sid)],
            ))
        },
    ));
    // PayloadRefUnresolved: an Evaluation whose candidate is not a Candidate.
    cases.push(record_case(
        "reject-evaluation-payload-ref-wrong-kind",
        "An Evaluation whose candidate id resolves to a Request, not a Candidate.",
        base_rules(),
        |w, r, s| {
            let (rid, v) = w.commit(request_proposal(), r, s).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(evaluation_custom(
                rid,
                executor_author(),
                vec![use_ref(rid)],
            ))
        },
    ));
    // EvaluationInvalid: an Evaluation missing the Use ref to its candidate.
    cases.push(record_case(
        "reject-evaluation-missing-use",
        "An Evaluation that resolves its candidate but does not Use it.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(evaluation_custom(cid, executor_author(), vec![]))
        },
    ));
    // SelectionInvalid: an empty considered list.
    cases.push(record_case(
        "reject-selection-considered-empty",
        "A Selection with an empty considered list.",
        base_rules(),
        |_w, _r, _s| {
            cand(selection_custom(
                "latency",
                vec![],
                SelectionOutcome::None,
                provider_author(),
                vec![],
            ))
        },
    ));
    // SelectionInvalid: a winner not named by a Require ref.
    cases.push(record_case(
        "reject-selection-winner-not-required",
        "A Selected winner that is not named by a Require ref.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(eid)], // no Require winner
            ))
        },
    ));
    // SelectionInvalid: a None decision carrying a candidate Require ref.
    cases.push(record_case(
        "reject-selection-none-with-require",
        "A None Selection that still Requires a candidate.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::None,
                provider_author(),
                vec![require_ref(cid)],
            ))
        },
    ));
    // SelectionInvalid: a Selected decision with no Used evaluation.
    cases.push(record_case(
        "reject-selection-requires-evaluation",
        "A Selected Selection that Uses no Evaluation (default requires one).",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![require_ref(cid)], // no Use of any evaluation
            ))
        },
    ));
    // SelectionInvalid: a Used evaluation whose candidate is not considered.
    cases.push(record_case(
        "reject-selection-used-eval-not-considered",
        "A Selection Using an Evaluation whose candidate is absent from considered.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (other, v) = w
                .commit(candidate_root_note("other", provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid_other, v) = w
                .commit(evaluation_proposal(other, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(eid_other), require_ref(cid)],
            ))
        },
    ));
    // SelectionInvalid: a Used but *rejected* Evaluation does not count as
    // evidence (and its payload is never decoded during the selection check).
    cases.push(record_case(
        "reject-selection-rejected-eval-does-not-count",
        "A Selection whose only Used Evaluation was itself rejected.",
        base_rules(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            // An Evaluation with no Use ref to its candidate is rejected
            // (EvaluationInvalid) but stays in the log with valid payload bytes.
            let (bad_eid, v) = w
                .commit(evaluation_custom(cid, executor_author(), vec![]), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Reject);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(bad_eid), require_ref(cid)],
            ))
        },
    ));
    // SelectionInvalid: considered longer than max_considered.
    cases.push(record_case(
        "reject-selection-max-considered",
        "A Selection whose considered list exceeds max_considered.",
        rules_max_considered(1),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (other, v) = w
                .commit(candidate_root_note("other", provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid, other],
                SelectionOutcome::None,
                provider_author(),
                vec![],
            ))
        },
    ));
    // Accept: a comparative Selection exactly at max_considered, Using one
    // evaluation per considered candidate plus the winner Require. This is the
    // shape whose ref count (Used evaluations + winners) approaches the receipt
    // ref limit while the verifier accepts it; the malformed corpus pins the
    // receipt ref bound biting on the same shape (spec 0.3, delta D3).
    cases.push(record_case(
        "accept-selection-comparative-at-max-considered",
        "A comparative Selection at max_considered, one evaluation per candidate.",
        rules_max_considered(4),
        |w, r, s| {
            let mut cids = Vec::new();
            let mut eids = Vec::new();
            for i in 0..4 {
                let (cid, v) = w
                    .commit(
                        candidate_root_note(&format!("c{i}"), provider_author()),
                        r,
                        s,
                    )
                    .unwrap();
                assert_eq!(v.result, VerdictResult::Accept);
                let (eid, v) = w
                    .commit(evaluation_proposal(cid, executor_author()), r, s)
                    .unwrap();
                assert_eq!(v.result, VerdictResult::Accept);
                cids.push(cid);
                eids.push(eid);
            }
            let mut refs: Vec<Ref> = eids.iter().map(|&e| use_ref(e)).collect();
            refs.push(require_ref(cids[0]));
            cand(selection_custom(
                "latency",
                cids.clone(),
                SelectionOutcome::Selected {
                    candidates: vec![cids[0]],
                },
                provider_author(),
                refs,
            ))
        },
    ));
    // SelectionInvalid: a winner below the configured min_binding.
    cases.push(record_case(
        "reject-selection-min-binding",
        "A Selection whose winner is reported-bound under min_binding = manifest.",
        rules_min_binding_manifest(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(eid), require_ref(cid)],
            ))
        },
    ));
    // ReaffirmationInvalid: a reaffirmation targeting a different objective.
    cases.push(record_case(
        "reject-selection-reaffirm-objective",
        "A reaffirming Selection whose objective differs from its Replace target.",
        base_rules(),
        |w, r, s| {
            let (cid, eid, sid) = setup_selected_line(w, r, s, "tests green");
            cand(selection_custom(
                "different-objective",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(eid), require_ref(cid), replace_ref(sid)],
            ))
        },
    ));
    // ReaffirmationInvalid: a reaffirmation author outside the allowlist.
    cases.push(record_case(
        "reject-selection-reaffirm-actor",
        "A reaffirming Selection whose author is not in reaffirmation_actors.",
        rules_reaffirmation_actors(&["human"]),
        |w, r, s| {
            let (cid, eid, sid) = setup_selected_line(w, r, s, "tests green");
            cand(selection_custom(
                "tests green",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(), // not "human"
                vec![use_ref(eid), require_ref(cid), replace_ref(sid)],
            ))
        },
    ));

    // LineageInvalid: a continuation of an unsound anchor rejects at commit
    // when reject_compromised_continuation is set (spec 0.3, delta D6).
    cases.push(record_case(
        "reject-continuation-compromised-anchor",
        "A Continuation of a retracted anchor Selection under reject_compromised_continuation.",
        rules_reject_compromised_continuation(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (sid, v) = w
                .commit(
                    selection_custom(
                        "obj",
                        vec![cid],
                        SelectionOutcome::Selected {
                            candidates: vec![cid],
                        },
                        provider_author(),
                        vec![use_ref(eid), require_ref(cid)],
                    ),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (_ret, v) = w.commit(retraction_proposal(sid), r, s).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            // The anchor sid is now retracted; the continuation rejects.
            cand(candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(cid),
                Some("late"),
                provider_author(),
                vec![cause_ref(sid)],
            ))
        },
    ));

    // --- Selection approval binding battery (spec 0.3, delta D5). ---

    // Accept: a Selection Requiring a valid approval that binds its subject.
    cases.push(record_case(
        "accept-selection-approved",
        "A Selection carrying the approval its subject hash binds.",
        rules_selection_requires_approval(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let sd = SelectionData {
                objective: "latency".into(),
                considered: vec![cid],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                rationale: None,
            };
            let hash = selection_approval_subject_hash(ACTOR, None, &sd).unwrap();
            let (aid, v) = w
                .commit(selection_approval_proposal(hash, ACTOR, None), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_from_data(
                &sd,
                provider_author(),
                vec![use_ref(eid), require_ref(cid), require_ref(aid)],
            ))
        },
    ));
    // ApprovalMissing: rules require an approval but none is present.
    cases.push(record_case(
        "reject-selection-approval-missing",
        "A Selection under selection_requires_approval with no approval.",
        rules_selection_requires_approval(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_custom(
                "latency",
                vec![cid],
                SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                provider_author(),
                vec![use_ref(eid), require_ref(cid)],
            ))
        },
    ));
    // ApprovalMissing: the approval binds a different subject actor.
    cases.push(record_case(
        "reject-selection-approval-wrong-actor",
        "A Selection whose bound approval declares a different subject actor.",
        rules_selection_requires_approval(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let sd = SelectionData {
                objective: "latency".into(),
                considered: vec![cid],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                rationale: None,
            };
            let hash = selection_approval_subject_hash(ACTOR, None, &sd).unwrap();
            // Correct subject hash, but the approval's actor_id is "host".
            let (aid, v) = w
                .commit(selection_approval_proposal(hash, "host", None), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_from_data(
                &sd,
                provider_author(),
                vec![use_ref(eid), require_ref(cid), require_ref(aid)],
            ))
        },
    ));
    // ApprovalExpired: the bound approval lapsed before the Selection.
    cases.push(record_case(
        "reject-selection-approval-expired",
        "A Selection whose bound approval expired at its commit time.",
        rules_selection_requires_approval(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let sd = SelectionData {
                objective: "latency".into(),
                considered: vec![cid],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                rationale: None,
            };
            let hash = selection_approval_subject_hash(ACTOR, None, &sd).unwrap();
            let (aid, v) = w
                .commit(selection_approval_proposal(hash, ACTOR, Some(1)), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_from_data(
                &sd,
                provider_author(),
                vec![use_ref(eid), require_ref(cid), require_ref(aid)],
            ))
        },
    ));
    // ApprovalMissing: the approval was already consumed by a prior Selection.
    cases.push(record_case(
        "reject-selection-approval-consumed",
        "A Selection reusing an approval a prior identical Selection consumed.",
        rules_selection_requires_approval(),
        |w, r, s| {
            let (cid, v) = w
                .commit(candidate_proposal(provider_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let (eid, v) = w
                .commit(evaluation_proposal(cid, executor_author()), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            let sd = SelectionData {
                objective: "latency".into(),
                considered: vec![cid],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                rationale: None,
            };
            let hash = selection_approval_subject_hash(ACTOR, None, &sd).unwrap();
            let (aid, v) = w
                .commit(selection_approval_proposal(hash, ACTOR, None), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            // First Selection consumes the approval (accepted).
            let refs = vec![use_ref(eid), require_ref(cid), require_ref(aid)];
            let (_s1, v) = w
                .commit(
                    selection_from_data(&sd, provider_author(), refs.clone()),
                    r,
                    s,
                )
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            // A byte-identical Selection at a later time reuses the same hash.
            cand(selection_from_data(&sd, provider_author(), refs))
        },
    ));
    // ApprovalMissing: a fresh-decision approval cannot authorize a
    // reaffirmation (the Replace target is inside the subject hash).
    cases.push(record_case(
        "reject-selection-approval-diverted-reaffirmation",
        "A reaffirmation Requiring an approval granted for the fresh decision.",
        rules_selection_requires_approval(),
        |w, r, s| {
            let (cid, eid, sid) = setup_approved_selected_line(w, r, s, "latency");
            // The reaffirmation's data (a distinct rationale keeps its
            // fresh-decision hash from colliding with the original approval).
            let sd1 = SelectionData {
                objective: "latency".into(),
                considered: vec![cid],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                rationale: Some("reaffirm".into()),
            };
            // An approval bound to the FRESH decision (replace_target = null).
            let fresh_hash = selection_approval_subject_hash(ACTOR, None, &sd1).unwrap();
            let (aid, v) = w
                .commit(selection_approval_proposal(fresh_hash, ACTOR, None), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            // The reaffirmation binds replace_target = sid, so this approval
            // does not match.
            cand(selection_from_data(
                &sd1,
                provider_author(),
                vec![
                    use_ref(eid),
                    require_ref(cid),
                    require_ref(aid),
                    replace_ref(sid),
                ],
            ))
        },
    ));
    // Accept: a reaffirmation carrying the approval its Replace-bound subject
    // hash demands.
    cases.push(record_case(
        "accept-selection-approved-reaffirmation",
        "A reaffirmation carrying the approval its Replace-bound subject binds.",
        rules_selection_requires_approval(),
        |w, r, s| {
            let (cid, eid, sid) = setup_approved_selected_line(w, r, s, "latency");
            let sd1 = SelectionData {
                objective: "latency".into(),
                considered: vec![cid],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![cid],
                },
                rationale: Some("reaffirm".into()),
            };
            // Approval bound to the reaffirmation (replace_target = sid).
            let reaff_hash = selection_approval_subject_hash(ACTOR, Some(sid), &sd1).unwrap();
            let (aid, v) = w
                .commit(selection_approval_proposal(reaff_hash, ACTOR, None), r, s)
                .unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            cand(selection_from_data(
                &sd1,
                provider_author(),
                vec![
                    use_ref(eid),
                    require_ref(cid),
                    require_ref(aid),
                    replace_ref(sid),
                ],
            ))
        },
    ));

    cases
}

// ---------------------------------------------------------------------------
// Receipt-case builders: whole-log validation outcomes.
// ---------------------------------------------------------------------------

/// Build a clean, multi-kind scripted log and return its records.
fn scripted_clean_log() -> (Vec<Record>, VerifierRules) {
    let rules = base_rules();
    let dir = tempfile::tempdir().unwrap();
    let mut w = LogWriter::open(dir.path(), &rules).unwrap();
    let mut st = State::default();

    let commit = |w: &mut LogWriter, st: &mut State, p: Proposal| {
        let (id, v) = w.commit(p, &rules, st).unwrap();
        assert_eq!(
            v.result,
            VerdictResult::Accept,
            "scripted log must stay clean"
        );
        id
    };

    let rid = commit(&mut w, &mut st, request_proposal());
    let cid = commit(
        &mut w,
        &mut st,
        capability_proposal(ACTOR, "tool", CapabilityMode::Auto, None),
    );
    let aid = commit(
        &mut w,
        &mut st,
        action_proposal_with_authority(rid, "tool", &[cid]),
    );
    let _res = commit(&mut w, &mut st, result_proposal(aid));
    let _sum = commit(&mut w, &mut st, summary_proposal(&[rid]));
    let _resp = commit(&mut w, &mut st, response_proposal(rid, 0, false));

    (w.records().to_vec(), rules)
}

fn build_receipt_cases() -> Vec<ReceiptCase> {
    let mut cases = Vec::new();

    // --- Clean full log. ---
    {
        let (records, rules) = scripted_clean_log();
        let receipt = Receipt::new(&records, &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Clean);
        cases.push(ReceiptCase {
            name: "clean-full-log".into(),
            description: "A scripted log exercising request, capability, action, result, summary, and response.".into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    // --- Tainted: retract a summary source; the summary that used it taints. ---
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let commit = |w: &mut LogWriter, st: &mut State, p: Proposal| {
            let (id, v) = w.commit(p, &rules, st).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            id
        };
        let rid = commit(&mut w, &mut st, request_proposal());
        // A summary that epistemically uses the request.
        let _sum = commit(&mut w, &mut st, summary_proposal(&[rid]));
        // Retract the request; the summary that Used it is tainted.
        let _ret = commit(&mut w, &mut st, retraction_proposal(rid));
        let receipt = Receipt::new(w.records(), &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Tainted);
        cases.push(ReceiptCase {
            name: "tainted-retraction".into(),
            description: "Retracting a Summary's Use source taints the dependent Summary; the log still verifies.".into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    // --- Invalid: forge a stored verdict result. ---
    {
        let (mut records, rules) = scripted_clean_log();
        // Find the first Verdict record and flip its stored Accept to Reject.
        let idx = records
            .iter()
            .position(|r| r.kind == Kind::Verdict)
            .expect("a verdict exists");
        let mut vd: VerdictData = decode(&records[idx].data).unwrap();
        vd.result = VerdictResult::Reject;
        vd.reason = Some(ReasonCode::InvalidPayload);
        records[idx].data = encode(&vd).unwrap();
        records[idx] = records[idx].clone().with_computed_id().unwrap();
        let receipt = Receipt::new(&records, &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(ReceiptCase {
            name: "invalid-forged-verdict".into(),
            description: "A stored Verdict is changed to Reject; replay re-derives Accept and the mismatch is caught.".into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    // --- Invalid: tamper a record id (break the chain). ---
    {
        let (mut records, rules) = scripted_clean_log();
        records[0].id[0] ^= 0xff;
        let receipt = Receipt::new(&records, &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(ReceiptCase {
            name: "invalid-tampered-id".into(),
            description: "The genesis record id is corrupted; the recomputed id no longer matches."
                .into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    // --- Invalid: drop a verdict, breaking subject/verdict pairing. ---
    {
        let (mut records, rules) = scripted_clean_log();
        let idx = records
            .iter()
            .position(|r| r.kind == Kind::Verdict)
            .unwrap();
        records.remove(idx);
        let receipt = Receipt::new(&records, &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(ReceiptCase {
            name: "invalid-missing-verdict".into(),
            description:
                "A Verdict record is removed; a non-verdict record is no longer immediately judged."
                    .into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    // --- Taint follows Use/Require but not Cause. ---
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let commit = |w: &mut LogWriter, st: &mut State, p: Proposal| {
            let (id, v) = w.commit(p, &rules, st).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            id
        };
        let rid = commit(&mut w, &mut st, request_proposal());
        // A Summary epistemically Uses the request (taint propagates here).
        let _sum = commit(&mut w, &mut st, summary_proposal(&[rid]));
        // A Plan only Causally references the request (taint must NOT propagate here).
        let _plan = commit(&mut w, &mut st, plan_proposal(rid));
        let _ret = commit(&mut w, &mut st, retraction_proposal(rid));
        let receipt = Receipt::new(w.records(), &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Tainted);
        cases.push(ReceiptCase {
            name: "tainted-use-not-cause".into(),
            description: "Retracting a record taints its Use dependent (a Summary) but not its Cause dependent (a Plan). The tainted set is the ground truth for non-propagation through Cause.".into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    // --- Taint propagates through the Require leg (no Use leg present). ---
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let commit = |w: &mut LogWriter, st: &mut State, p: Proposal| {
            let (id, v) = w.commit(p, &rules, st).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            id
        };
        let (rid, cid) = {
            let (rid, v1) = w.commit(request_proposal(), &rules, &mut st).unwrap();
            assert_eq!(v1.result, VerdictResult::Accept);
            let (cid, v2) = w
                .commit(
                    capability_proposal(ACTOR, "tool", CapabilityMode::Auto, None),
                    &rules,
                    &mut st,
                )
                .unwrap();
            assert_eq!(v2.result, VerdictResult::Accept);
            (rid, cid)
        };
        // The action's only edge to the capability is a Require ref.
        let aid = commit(
            &mut w,
            &mut st,
            action_proposal_with_authority(rid, "tool", &[cid]),
        );
        // A Result referencing the action by Cause only: taint must not reach it.
        let _res = commit(&mut w, &mut st, result_proposal(aid));
        // A Summary that Uses the action: taint must reach it transitively.
        let _sum = commit(&mut w, &mut st, summary_proposal(&[aid]));
        // Retract the capability. The action taints solely through Require,
        // the Summary transitively through Use, the Result (Cause) stays clean.
        let _ret = commit(&mut w, &mut st, retraction_proposal(cid));
        let receipt = Receipt::new(w.records(), &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Tainted);
        cases.push(ReceiptCase {
            name: "tainted-require-leg".into(),
            description: "Retracting a capability taints the Action whose only edge to it is a Require ref, and transitively the Summary that Used the action; the Cause-only Result stays untainted. The tainted set is the ground truth for propagation through Require.".into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    // --- A record Requiring an already-tainted target is rejected at commit. ---
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let commit = |w: &mut LogWriter, st: &mut State, p: Proposal| {
            let (id, v) = w.commit(p, &rules, st).unwrap();
            assert_eq!(v.result, VerdictResult::Accept);
            id
        };
        let rid = commit(&mut w, &mut st, request_proposal());
        // A capability that epistemically Uses the request.
        let cid = {
            let mut p = capability_proposal(ACTOR, "tool", CapabilityMode::Auto, None);
            p.refs = vec![Ref {
                type_: RefType::Use,
                target: rid,
            }];
            commit(&mut w, &mut st, p)
        };
        // Retract the request: the capability taints through its Use leg.
        let _ret = commit(&mut w, &mut st, retraction_proposal(rid));
        // An Action Requiring the now-tainted capability must reject at its
        // commit position; the rejected record and its verdict stay in the log.
        let (_, v) = w
            .commit(
                action_proposal_with_authority(rid, "tool", &[cid]),
                &rules,
                &mut st,
            )
            .unwrap();
        assert_eq!(v.result, VerdictResult::Reject);
        assert_eq!(v.reason, Some(ReasonCode::RefUnresolved));
        let receipt = Receipt::new(w.records(), &rules);
        let report = validate(&receipt.to_bytes().unwrap());
        assert_eq!(report.status, ValidationStatus::Tainted);
        cases.push(ReceiptCase {
            name: "tainted-require-target-rejected".into(),
            description: "An Action Requiring an already-tainted capability is rejected at commit position with RefUnresolved; the rejected record stays in the log with its Reject verdict and replay agrees.".into(),
            receipt,
            expect: expect_from_report(&report),
        });
    }

    cases.extend(build_standing_receipt_cases());
    cases
}

/// Commit a proposal into a scripted receipt log, asserting the expected
/// verdict result. Returns the committed record id.
fn commit_expect(
    w: &mut LogWriter,
    rules: &VerifierRules,
    st: &mut State,
    p: Proposal,
    expect: VerdictResult,
) -> RecordId {
    let (id, v) = w.commit(p, rules, st).unwrap();
    assert_eq!(v.result, expect, "scripted standing log verdict mismatch");
    id
}

/// Standing (SPEC §7.2) receipt cases: whole-log validation whose report
/// carries a `standing` section. Each builds an evolution log, validates it,
/// and stores the report Rust derived; the Python validator must reproduce
/// the same `standing` bytes.
fn build_standing_receipt_cases() -> Vec<ReceiptCase> {
    let mut cases = Vec::new();

    let mut push = |name: &str, description: &str, records: &[Record], rules: &VerifierRules| {
        let receipt = Receipt::new(records, rules);
        let report = validate(&receipt.to_bytes().unwrap());
        cases.push(ReceiptCase {
            name: name.into(),
            description: description.into(),
            receipt,
            expect: expect_from_report(&report),
        });
    };

    // A: continuation compromise cascade - retracting the anchor Selection
    // compromises the continuation whose lineage rests on it.
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let _c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(s0),
            VerdictResult::Accept,
        );
        push(
            "standing-continuation-cascade",
            "Retracting an anchor Selection compromises the continuation resting on it.",
            w.records(),
            &rules,
        );
    }

    // B: derivation with only an Evaluation motivation stays sound even when
    // that evaluation is retracted (evaluation targets carry no standing).
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let _d1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Derivation,
                None,
                Some("d1"),
                provider_author(),
                vec![cause_ref(e0)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(e0),
            VerdictResult::Accept,
        );
        push("standing-derivation-evaluation-only", "A derivation motivated only by an Evaluation stays sound when that evaluation is retracted.", w.records(), &rules);
    }

    // C: derivation cascade - a derivation over a compromised candidate is
    // itself compromised.
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _d2 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Derivation,
                None,
                Some("d2"),
                provider_author(),
                vec![cause_ref(c1)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(s0),
            VerdictResult::Accept,
        );
        push(
            "standing-derivation-cascade",
            "A derivation over a compromised candidate is itself compromised.",
            w.records(),
            &rules,
        );
    }

    // D: deep reaffirmation recovery - one reaffirmation re-selecting the
    // parent restores the entire descendant subtree.
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let e1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c1, executor_author()),
            VerdictResult::Accept,
        );
        let s1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj2",
                vec![c1],
                SelectionOutcome::Selected {
                    candidates: vec![c1],
                },
                provider_author(),
                vec![use_ref(e1), require_ref(c1)],
            ),
            VerdictResult::Accept,
        );
        let _c2 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c1),
                Some("c2"),
                provider_author(),
                vec![cause_ref(s1)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(s0),
            VerdictResult::Accept,
        );
        // Reaffirm S0 (same objective), re-selecting C0.
        let _s2 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0), replace_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        push(
            "standing-deep-reaffirmation-recovery",
            "One reaffirmation re-selecting the parent restores the whole descendant subtree.",
            w.records(),
            &rules,
        );
    }

    // E: a None-decision reaffirmation restores nothing (the parent is not in
    // any selected set), though it is still a sound replacer.
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let _c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(s0),
            VerdictResult::Accept,
        );
        let _s2 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::None,
                provider_author(),
                vec![replace_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        push(
            "standing-none-reaffirmation-restores-nothing",
            "A None-decision reaffirmation is a sound replacer but restores no descendant.",
            w.records(),
            &rules,
        );
    }

    // G: a replacement chain through an accepted-but-unsound intermediate
    // still restores (intermediates need only be accepted).
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let _c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let s1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0), replace_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _s2 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0), replace_ref(s1)],
            ),
            VerdictResult::Accept,
        );
        // Retract both S0 and the intermediate S1; only S2 stays sound.
        let _r0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(s0),
            VerdictResult::Accept,
        );
        let _r1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(s1),
            VerdictResult::Accept,
        );
        push("standing-chain-through-unsound-intermediate", "A sound reaffirmation restores through an accepted-but-unsound intermediate replacement.", w.records(), &rules);
    }

    // H: a retracted candidate is compromised unconditionally, and its
    // continuation stays compromised (unrestorable base case).
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let _c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(c0),
            VerdictResult::Accept,
        );
        push("standing-retracted-candidate-unrestorable", "A retracted candidate is compromised unconditionally, and its continuation stays compromised.", w.records(), &rules);
    }

    // I: competing reaffirmations - two reaffirmations of one anchor each
    // restore only the subtree whose parent they re-select; restorations
    // lists both replacers.
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let cx = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_root_note("cx", provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let ex = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(cx, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0, cx],
                SelectionOutcome::Selected {
                    candidates: vec![c0, cx],
                },
                provider_author(),
                vec![use_ref(e0), use_ref(ex), require_ref(c0), require_ref(cx)],
            ),
            VerdictResult::Accept,
        );
        let _c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _cx1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(cx),
                Some("cx1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(s0),
            VerdictResult::Accept,
        );
        let _s2 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0), replace_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let _s3 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![cx],
                SelectionOutcome::Selected {
                    candidates: vec![cx],
                },
                provider_author(),
                vec![use_ref(ex), require_ref(cx), replace_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        push("standing-competing-reaffirmations", "Two reaffirmations of one anchor each restore only the parent they re-select; restorations lists both.", w.records(), &rules);
    }

    // J: retracted parent (middle of a chain) - the descendant is compromised
    // and unrestorable while the root stays sound.
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let e0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c0, executor_author()),
            VerdictResult::Accept,
        );
        let s0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj",
                vec![c0],
                SelectionOutcome::Selected {
                    candidates: vec![c0],
                },
                provider_author(),
                vec![use_ref(e0), require_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let c1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c0),
                Some("c1"),
                provider_author(),
                vec![cause_ref(s0)],
            ),
            VerdictResult::Accept,
        );
        let e1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(c1, executor_author()),
            VerdictResult::Accept,
        );
        let s1 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            selection_custom(
                "obj2",
                vec![c1],
                SelectionOutcome::Selected {
                    candidates: vec![c1],
                },
                provider_author(),
                vec![use_ref(e1), require_ref(c1)],
            ),
            VerdictResult::Accept,
        );
        let _c2 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                default_source(),
                CandidateBasis::Continuation,
                Some(c1),
                Some("c2"),
                provider_author(),
                vec![cause_ref(s1)],
            ),
            VerdictResult::Accept,
        );
        // Retract the middle parent candidate C1: base-case compromise, and it
        // taints S1 (which Requires it), so the leaf's anchor is unsound too.
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(c1),
            VerdictResult::Accept,
        );
        push("standing-retracted-parent-unrestorable", "Retracting a middle-of-chain parent candidate compromises the descendant unrestorably while the root stays sound.", w.records(), &rules);
    }

    // K: binding-upgrade idiom, sound before retraction - a manifest-binding
    // derivation upgrade of a reported-binding candidate carries sound
    // standing.
    let manifest_source = SourceBinding {
        git: GitSource {
            algo: SourceAlgo::Sha1,
            tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
            commit: None,
        },
        manifest_hash: Some([7u8; 32]),
        binding: BindingMode::Manifest,
    };
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let _u = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                manifest_source.clone(),
                CandidateBasis::Derivation,
                None,
                Some("upgrade"),
                provider_author(),
                vec![cause_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        push("standing-binding-upgrade-sound", "A manifest-binding derivation upgrade of a reported candidate is standing-sound before any retraction.", w.records(), &rules);
    }

    // L: binding-upgrade idiom, compromised after retraction - retracting the
    // original reported candidate compromises the upgrade; the idiom cannot
    // launder a retracted state.
    {
        let rules = base_rules();
        let dir = tempfile::tempdir().unwrap();
        let mut w = LogWriter::open(dir.path(), &rules).unwrap();
        let mut st = State::default();
        let c0 = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_proposal(provider_author()),
            VerdictResult::Accept,
        );
        let _u = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_custom(
                manifest_source,
                CandidateBasis::Derivation,
                None,
                Some("upgrade"),
                provider_author(),
                vec![cause_ref(c0)],
            ),
            VerdictResult::Accept,
        );
        let _ret = commit_expect(
            &mut w,
            &rules,
            &mut st,
            retraction_proposal(c0),
            VerdictResult::Accept,
        );
        push("standing-binding-upgrade-compromised", "Retracting the original candidate compromises its manifest-binding upgrade; the idiom cannot launder a retracted state.", w.records(), &rules);
    }

    cases
}

/// Standing is a pure function of the accepted records at replay end:
/// re-deriving it is deterministic, and the `verify_log` and `validate`
/// entry points agree. At least one scenario must exercise a non-empty
/// section so the property is not vacuous.
#[test]
fn standing_is_deterministic_and_consistent() {
    let mut saw_nonempty = false;
    for case in build_standing_receipt_cases() {
        let bytes = case.receipt.to_bytes().unwrap();
        let r1 = validate(&bytes);
        let r2 = validate(&bytes);
        assert_eq!(
            r1.standing, r2.standing,
            "standing not deterministic for {}",
            case.name
        );
        let v = verify_log(&case.receipt.records, &case.receipt.rules, None);
        assert_eq!(
            v.standing, r1.standing,
            "verify_log and validate disagree on standing for {}",
            case.name
        );
        if !r1.standing.is_empty() {
            saw_nonempty = true;
        }
    }
    assert!(
        saw_nonempty,
        "standing property test exercised no compromise"
    );
}

// ---------------------------------------------------------------------------
// Malformed-case builders: hostile raw documents.
// ---------------------------------------------------------------------------

fn build_malformed_cases() -> Vec<MalformedCase> {
    let mut cases = Vec::new();

    let (records, rules) = scripted_clean_log();
    let clean_receipt = Receipt::new(&records, &rules);
    let clean_json = String::from_utf8(clean_receipt.to_bytes().unwrap()).unwrap();

    // Sanity: the clean document validates before we corrupt copies of it.
    assert_eq!(
        validate(clean_json.as_bytes()).status,
        ValidationStatus::Clean
    );

    // Build a malformed case from a validate() report. `problem_substr` is a
    // short, stable fragment of the structural-failure message - deliberately
    // NOT the whole `problem` string, which carries volatile serde offsets and
    // generated sizes. The generator asserts the fragment is actually present.
    fn malformed(
        name: &str,
        description: &str,
        input: String,
        limits: Option<CaseLimits>,
        report: &Report,
        problem_substr: &str,
    ) -> MalformedCase {
        let problem = report.problem.clone().unwrap_or_default();
        assert!(
            problem.contains(problem_substr),
            "malformed `{name}`: problem {problem:?} does not contain {problem_substr:?}"
        );
        assert_eq!(
            report.status,
            ValidationStatus::Invalid,
            "malformed `{name}` status"
        );
        MalformedCase {
            name: name.into(),
            description: description.into(),
            input,
            limits,
            expect: MalformedExpect {
                status: report.status,
                reason: report.reason,
                problem_contains: Some(problem_substr.into()),
            },
        }
    }

    // Extra top-level field -> strict decoding rejects.
    {
        let mut v: serde_json::Value = serde_json::from_str(&clean_json).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!(true));
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "strict-decode-extra-top-level-field",
            "A receipt document with an unknown top-level field.",
            input,
            None,
            &report,
            "unparseable receipt: unknown field `extra`",
        ));
    }

    // Wrong spec version: a prior-epoch (v0.2) receipt must be rejected by
    // this validator with a clear unsupported-version report; v0.2 receipts
    // stay valid under v0.2 rules via the pinned published v0.2 validator
    // (SPEC §14).
    {
        let mut v: serde_json::Value = serde_json::from_str(&clean_json).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("spec_version".into(), serde_json::json!("0.2"));
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "wrong-spec-version",
            "A receipt declaring another epoch's spec version (0.2); a conforming v0.3 validator rejects it with an unsupported-version report.",
            input,
            None,
            &report,
            "unsupported spec version",
        ));
    }

    // Profile declarations (spec 0.4, SPEC §12) are structural: an earlier
    // epoch's receipt cannot carry one, ids are non-empty and unique, and
    // the declaration object decodes strictly. The version and hash inside
    // a declaration are claims, compared during evaluation, never rejected
    // here - so none of these cases is about a wrong hash.
    {
        let declared = Receipt::new(&records, &rules)
            .with_declared_profiles(&[BELLBOOK_CORE_V1])
            .unwrap();
        let declared_json = String::from_utf8(declared.to_bytes().unwrap()).unwrap();
        assert_eq!(
            validate(declared_json.as_bytes()).status,
            ValidationStatus::Clean
        );
        let base = || -> serde_json::Value { serde_json::from_str(&declared_json).unwrap() };

        let mut v = base();
        v["spec_version"] = serde_json::json!("0.3");
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "profile-declaration-on-earlier-epoch",
            "A receipt declaring spec 0.3 that carries a profile declaration; declarations exist from spec 0.4, so the receipt is structurally Invalid before replay.",
            input,
            None,
            &report,
            "profile declarations require spec 0.4",
        ));

        let mut v = base();
        let first = v["profiles"][0].clone();
        v["profiles"].as_array_mut().unwrap().push(first);
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "profile-declared-twice",
            "The same profile id declared twice; a declaration list is a set of claims and a repeat is structurally Invalid.",
            input,
            None,
            &report,
            "declared more than once",
        ));

        let mut v = base();
        v["profiles"][0]["id"] = serde_json::json!("");
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "profile-declaration-empty-id",
            "A profile declaration with an empty id.",
            input,
            None,
            &report,
            "has an empty id",
        ));

        let mut v = base();
        v["profiles"][0]["extra"] = serde_json::json!(true);
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "profile-declaration-unknown-field",
            "A profile declaration carrying an unknown field; the declaration object decodes as strictly as every other wire object.",
            input,
            None,
            &report,
            "unparseable receipt: unknown field `extra`",
        ));

        let mut v = base();
        v["profiles"][0]["hash"] = serde_json::json!([1, 2, 3]);
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "profile-declaration-short-hash",
            "A profile declaration whose hash is not 32 bytes.",
            input,
            None,
            &report,
            "unparseable receipt",
        ));
    }

    // Not JSON at all.
    {
        let input = "this is not a receipt".to_string();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "not-json",
            "Arbitrary bytes that do not parse as JSON.",
            input,
            None,
            &report,
            "unparseable receipt",
        ));
    }

    // Truncated JSON.
    {
        let input = clean_json[..clean_json.len() / 2].to_string();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "truncated-json",
            "The receipt document cut in half.",
            input,
            None,
            &report,
            "unparseable receipt",
        ));
    }

    // Duplicate top-level field: a genuine repeated key (which serde_json::Value
    // would collapse) is injected as raw text. Serde's derived decoder rejects
    // the repeat with "duplicate field", part of the reference's strict decoding.
    {
        let input = format!("{{\"spec_version\":\"0.2\",{}", &clean_json[1..]);
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "duplicate-top-level-field",
            "A receipt document that declares `spec_version` twice; strict decoding rejects the duplicate key.",
            input,
            None,
            &report,
            "duplicate field",
        ));
    }

    // Mistyped nested signature fields: a numeric `key_id` and a non-byte-array
    // `sig`. The typed `Signature` decoder rejects them at decode, before any id
    // recomputation could observe the tampering.
    {
        let mut v: serde_json::Value = serde_json::from_str(&clean_json).unwrap();
        v["records"][0]["author"]["signature"] =
            serde_json::json!({ "key_id": 123, "sig": "notbytes" });
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(malformed(
            "malformed-signature-field-types",
            "A record whose signature carries a numeric key_id and a non-byte sig; strict decoding rejects the mistyped fields.",
            input,
            None,
            &report,
            "invalid type",
        ));
    }

    // Exceeds max_bytes.
    {
        let limits = CaseLimits {
            max_bytes: 32,
            max_records: 1_000_000,
            max_payload_bytes: 16 << 20,
            max_refs_per_record: 4096,
        };
        let report = validate_with_limits(clean_json.as_bytes(), &to_limits(&limits));
        cases.push(malformed(
            "exceeds-max-bytes",
            "A valid receipt rejected because it exceeds a tiny byte budget.",
            clean_json.clone(),
            Some(limits),
            &report,
            "receipt exceeds size limit",
        ));
    }

    // Exceeds max_records.
    {
        let limits = CaseLimits {
            max_bytes: 64 << 20,
            max_records: 1,
            max_payload_bytes: 16 << 20,
            max_refs_per_record: 4096,
        };
        let report = validate_with_limits(clean_json.as_bytes(), &to_limits(&limits));
        cases.push(malformed(
            "exceeds-max-records",
            "A valid multi-record receipt rejected under a one-record budget.",
            clean_json.clone(),
            Some(limits),
            &report,
            "receipt exceeds record limit",
        ));
    }

    // The receipt ref bound bites on a comparative Selection: the verifier
    // accepts it at max_considered (see accept-selection-comparative-at-max-
    // considered), but its Used evaluations plus its winner Require exceed a
    // tight max_refs_per_record and are rejected structurally before replay
    // (spec 0.3, delta D3; the effective bound on Used evaluations is the
    // receipt ref limit).
    {
        let json = scripted_comparative_selection_receipt();
        let limits = CaseLimits {
            max_bytes: 64 << 20,
            max_records: 1_000_000,
            max_payload_bytes: 16 << 20,
            // The Selection carries 4 Use refs plus 1 winner Require (5); a
            // budget of 4 rejects it.
            max_refs_per_record: 4,
        };
        let report = validate_with_limits(json.as_bytes(), &to_limits(&limits));
        cases.push(malformed(
            "exceeds-max-refs-comparative-selection",
            "A comparative Selection accepted by the verifier at max_considered, but its ref count exceeds a tight receipt ref budget.",
            json,
            Some(limits),
            &report,
            "exceeds ref-count limit",
        ));
    }

    cases
}

/// Script a clean log ending in a comparative Selection (four candidates, one
/// evaluation each, one winner) under `max_considered = 4`, and return its
/// receipt as a JSON string. The Selection carries five refs (four `Use`, one
/// winner `Require`).
fn scripted_comparative_selection_receipt() -> String {
    let rules = rules_max_considered(4);
    let dir = tempfile::tempdir().unwrap();
    let mut w = LogWriter::open(dir.path(), &rules).unwrap();
    let mut st = State::default();
    let mut cids = Vec::new();
    let mut refs: Vec<Ref> = Vec::new();
    for i in 0..4 {
        let cid = commit_expect(
            &mut w,
            &rules,
            &mut st,
            candidate_root_note(&format!("c{i}"), provider_author()),
            VerdictResult::Accept,
        );
        let eid = commit_expect(
            &mut w,
            &rules,
            &mut st,
            evaluation_proposal(cid, executor_author()),
            VerdictResult::Accept,
        );
        cids.push(cid);
        refs.push(use_ref(eid));
    }
    refs.push(require_ref(cids[0]));
    commit_expect(
        &mut w,
        &rules,
        &mut st,
        selection_custom(
            "latency",
            cids.clone(),
            SelectionOutcome::Selected {
                candidates: vec![cids[0]],
            },
            provider_author(),
            refs,
        ),
        VerdictResult::Accept,
    );
    let receipt = Receipt::new(w.records(), &rules);
    String::from_utf8(receipt.to_bytes().unwrap()).unwrap()
}

fn to_limits(l: &CaseLimits) -> ValidationLimits {
    ValidationLimits {
        max_bytes: l.max_bytes,
        max_records: l.max_records,
        max_payload_bytes: l.max_payload_bytes,
        max_refs_per_record: l.max_refs_per_record,
    }
}

// ---------------------------------------------------------------------------
// Assemble, generate, and verify the corpus.
// ---------------------------------------------------------------------------

fn build_corpus() -> Corpus {
    Corpus {
        spec_version: SPEC_VERSION.to_string(),
        record_cases: build_record_cases(),
        receipt_cases: build_receipt_cases(),
        malformed_cases: build_malformed_cases(),
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("spec/conformance/v{SPEC_VERSION}"))
}

fn write_json<T: serde::Serialize>(path: &std::path::Path, value: &T) {
    let mut out = serde_json::to_string_pretty(value).unwrap();
    out.push('\n');
    std::fs::write(path, out).unwrap();
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "read {}: {} (regenerate with UPDATE_CONFORMANCE=1)",
            path.display(),
            e
        )
    });
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct RecordFile {
    spec_version: String,
    description: String,
    cases: Vec<RecordCase>,
}
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct ReceiptFile {
    spec_version: String,
    description: String,
    cases: Vec<ReceiptCase>,
}
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct MalformedFile {
    spec_version: String,
    description: String,
    cases: Vec<MalformedCase>,
}

#[test]
fn conformance_corpus() {
    let corpus = build_corpus();
    let dir = corpus_dir();

    let record_file = RecordFile {
        spec_version: corpus.spec_version.clone(),
        description: "Per-record verification cases: verify_record(candidate, prior, rules, state) equals the expected verdict.".into(),
        cases: corpus.record_cases.clone(),
    };
    let receipt_file = ReceiptFile {
        spec_version: corpus.spec_version.clone(),
        description: "Whole-log receipt validation cases: validate(receipt bytes) yields the expected status, reason, and hashes.".into(),
        cases: corpus.receipt_cases.clone(),
    };
    let malformed_file = MalformedFile {
        spec_version: corpus.spec_version.clone(),
        description: "Hostile documents that fail structurally before or during verification."
            .into(),
        cases: corpus.malformed_cases.clone(),
    };

    let query_file = QueryFile {
        spec_version: corpus.spec_version.clone(),
        description: "Read-side query cases (RFC-0002): the named set q1-q7 answered over a receipt; expect is the exact surface JSON every implementation must emit.".into(),
        cases: build_query_cases(),
    };

    if std::env::var("UPDATE_CONFORMANCE").is_ok() {
        std::fs::create_dir_all(&dir).unwrap();
        write_json(&dir.join("record-cases.json"), &record_file);
        write_json(&dir.join("receipt-cases.json"), &receipt_file);
        write_json(&dir.join("malformed-cases.json"), &malformed_file);
        write_json(&dir.join("query-cases.json"), &query_file);
        return;
    }

    // Drift: the committed corpus must match what the current code generates.
    let stored_records: RecordFile = read_json(&dir.join("record-cases.json"));
    let stored_receipts: ReceiptFile = read_json(&dir.join("receipt-cases.json"));
    let stored_malformed: MalformedFile = read_json(&dir.join("malformed-cases.json"));
    assert_eq!(
        record_file, stored_records,
        "record corpus drifted; regenerate with UPDATE_CONFORMANCE=1"
    );
    assert_eq!(
        receipt_file, stored_receipts,
        "receipt corpus drifted; regenerate with UPDATE_CONFORMANCE=1"
    );
    assert_eq!(
        malformed_file, stored_malformed,
        "malformed corpus drifted; regenerate with UPDATE_CONFORMANCE=1"
    );
    let stored_queries: QueryFile = read_json(&dir.join("query-cases.json"));
    assert_eq!(
        query_file, stored_queries,
        "query corpus drifted; regenerate with UPDATE_CONFORMANCE=1"
    );

    // Correctness: re-derive every outcome from the STORED inputs (the contract
    // an independent implementation follows).
    for c in &stored_records.cases {
        let state = build_state_unchecked(&c.prior).unwrap();
        let got = verify_record(&c.candidate, &c.prior, &c.rules, &state);
        assert_eq!(got, c.expect, "record case `{}`", c.name);
    }
    for c in &stored_receipts.cases {
        let report = validate(&c.receipt.to_bytes().unwrap());
        assert_eq!(
            expect_from_report(&report),
            c.expect,
            "receipt case `{}`",
            c.name
        );
    }
    for c in &stored_malformed.cases {
        let report = match &c.limits {
            Some(l) => validate_with_limits(c.input.as_bytes(), &to_limits(l)),
            None => validate(c.input.as_bytes()),
        };
        assert_eq!(
            report.status, c.expect.status,
            "malformed case `{}` status",
            c.name
        );
        assert_eq!(
            report.reason, c.expect.reason,
            "malformed case `{}` reason",
            c.name
        );
        if let Some(sub) = &c.expect.problem_contains {
            let problem = report.problem.clone().unwrap_or_default();
            assert!(
                problem.contains(sub),
                "malformed case `{}`: problem {:?} does not contain {:?}",
                c.name,
                report.problem,
                sub
            );
        }
    }

    for c in &stored_queries.cases {
        let q = Queries::new(&c.receipt.records, &c.receipt.rules)
            .unwrap_or_else(|e| panic!("query case `{}`: receipt must verify: {e}", c.name));
        for v in &c.queries {
            let got = run_named_query(&q, &v.query, &v.args);
            assert_eq!(
                got, v.expect,
                "query case `{}`: {} {} answer differs",
                c.name, v.query, v.args
            );
        }
    }

    // Coverage: every wire-expressible reason code has at least one case.
    let mut covered: BTreeSet<ReasonCode> = BTreeSet::new();
    for c in &stored_records.cases {
        if let Some(r) = c.expect.reason {
            covered.insert(r);
        }
    }
    for c in &stored_receipts.cases {
        if let Some(r) = c.expect.reason {
            covered.insert(r);
        }
    }
    let required: BTreeSet<ReasonCode> = wire_expressible_reasons().into_iter().collect();
    let missing: Vec<ReasonCode> = required.difference(&covered).copied().collect();
    assert!(
        missing.is_empty(),
        "reason codes not triggered by any corpus case: {:?}",
        missing
    );
}

/// Every verdict `ReasonCode` that is expressible through the portable wire
/// format. Three of the 26 variants are excluded and documented in the corpus
/// README:
///   - `Refused` is a reason a `Refusal` record cites in its payload; the
///     verifier never emits it as a verdict.
///   - `InvalidCheckpoint` arises only on the trusted-checkpoint replay path;
///     checkpoints are opaque and never travel inside a receipt.
///   - `RefCrossSpace` needs a reference into a second space, which a
///     single-space receipt cannot carry.
///
/// The latter two are genuine verdict reasons; they are exercised by the
/// crate's own integration suite instead.
fn wire_expressible_reasons() -> Vec<ReasonCode> {
    vec![
        ReasonCode::UnknownSchema,
        ReasonCode::KindSchemaMismatch,
        ReasonCode::SignatureMissing,
        ReasonCode::SignatureInvalid,
        ReasonCode::RefUnresolved,
        ReasonCode::RequestMissing,
        ReasonCode::CapabilityMissing,
        ReasonCode::CapabilityDenied,
        ReasonCode::ApprovalMissing,
        ReasonCode::ApprovalExpired,
        ReasonCode::ActionClosed,
        ReasonCode::ReplacementInvalid,
        ReasonCode::ExternalReceiptRequired,
        ReasonCode::EvidenceBelowThreshold,
        ReasonCode::InvalidPayload,
        ReasonCode::AuthorRoleInvalid,
        ReasonCode::AuthorityRefMissing,
        ReasonCode::SourceBindingInvalid,
        ReasonCode::LineageInvalid,
        ReasonCode::PayloadRefUnresolved,
        ReasonCode::EvaluationInvalid,
        ReasonCode::SelectionInvalid,
        ReasonCode::ReaffirmationInvalid,
        ReasonCode::ArtifactRefInvalid,
        ReasonCode::RequirementInvalid,
    ]
}

// ---------------------------------------------------------------------------
// Query cases (RFC-0002): the named set q1-q7 as cross-implementation
// vectors. Each case pairs a receipt with a battery of (query, args) calls
// and the exact surface JSON the reference answers - the same shapes the
// CLI and the Python binding emit, so an independent implementation is held
// to the full read-side contract, not just verdicts.
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct QueryFile {
    spec_version: String,
    description: String,
    cases: Vec<QueryCase>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct QueryCase {
    name: String,
    description: String,
    receipt: Receipt,
    queries: Vec<QueryVector>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct QueryVector {
    /// One of `descent | descendants | siblings | frontier | standing |
    /// evidence | selected`.
    query: String,
    /// `{ "id": "<hex>" }` for record-addressed queries, `{ "objective":
    /// "<exact string>" }` for `selected`, `{}` for `frontier`.
    args: serde_json::Value,
    /// The exact report JSON (the shared surface shape).
    expect: serde_json::Value,
}

fn hex_to_id(hex: &str) -> RecordId {
    let bytes = hex_decode(hex).expect("query vector id must be valid hex");
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    id
}

/// Dispatch one named query against a verified context. Shared by the
/// generator and the stored-corpus checker so both sides run the same code.
fn run_named_query(q: &Queries<'_>, name: &str, args: &serde_json::Value) -> serde_json::Value {
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

/// The broken-benchmark shape (RFC-0001 section 10) plus a derivation
/// sibling: root, benchmark evaluation, pivotal selection, a continuation,
/// derivations at depth, a motivated-by repair, the retraction, post-break
/// work, and a restoring reaffirmation. One log exercises every annotation
/// a query can emit.
fn build_query_cases() -> Vec<QueryCase> {
    let dir = tempfile::tempdir().unwrap();
    let space = SPACE;
    let rules = VerifierRules::new(space, 200)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("benchmark", AuthorType::Provider)
        .with_author_role("reviewer", AuthorType::Provider)
        .with_author_role("human", AuthorType::User);
    let mut w = LogWriter::open(dir.path(), &rules).unwrap();
    let mut st = State::default();

    let commit = |w: &mut LogWriter,
                  st: &mut State,
                  author: &str,
                  kind: Kind,
                  schema: &str,
                  data: Vec<u8>,
                  refs: Vec<Ref>|
     -> RecordId {
        let (id, verdict) = w
            .commit(
                Proposal {
                    space,
                    thread: space,
                    author: Author {
                        id: author.into(),
                        type_: rules.author_roles[author],
                        signature: None,
                    },
                    kind,
                    schema: schema_id(schema),
                    data,
                    refs,
                },
                &rules,
                st,
            )
            .unwrap();
        assert_eq!(verdict.result, VerdictResult::Accept, "{kind:?} rejected");
        id
    };
    let cause = |t: RecordId| Ref {
        type_: RefType::Cause,
        target: t,
    };
    let use_r = |t: RecordId| Ref {
        type_: RefType::Use,
        target: t,
    };
    let require = |t: RecordId| Ref {
        type_: RefType::Require,
        target: t,
    };
    let replace = |t: RecordId| Ref {
        type_: RefType::Replace,
        target: t,
    };
    let src = |tree: &str| SourceBinding {
        git: GitSource {
            algo: SourceAlgo::Sha1,
            tree: tree.into(),
            commit: None,
        },
        manifest_hash: None,
        binding: BindingMode::Reported,
    };
    let cand = |tree: &str, basis: CandidateBasis, parent: Option<RecordId>| {
        encode(&CandidateData {
            artifacts: None,
            source: src(tree),
            basis,
            parent,
            note: None,
        })
        .unwrap()
    };

    let c0 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        cand(
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            CandidateBasis::Root,
            None,
        ),
        vec![],
    );
    let bench0 = commit(
        &mut w,
        &mut st,
        "benchmark",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        encode(&EvaluationData {
            candidate: c0,
            criterion: "bench-suite".into(),
            procedure: None,
            outcome: EvaluationOutcome::Passed,
        })
        .unwrap(),
        vec![use_r(c0)],
    );
    let s0 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        encode(&SelectionData {
            objective: "adopt-baseline".into(),
            considered: vec![c0],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c0],
            },
            rationale: None,
        })
        .unwrap(),
        vec![require(c0), use_r(bench0)],
    );
    let c1 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        cand(
            "1111111111111111111111111111111111111111",
            CandidateBasis::Continuation,
            Some(c0),
        ),
        vec![cause(s0)],
    );
    let c2 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        cand(
            "2222222222222222222222222222222222222222",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause(c1)],
    );
    let _c2b = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        cand(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause(c1)],
    );
    let c3 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        cand(
            "3333333333333333333333333333333333333333",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause(c2)],
    );
    let c4 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        cand(
            "4444444444444444444444444444444444444444",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause(c0), cause(bench0)],
    );
    commit(
        &mut w,
        &mut st,
        "benchmark",
        Kind::Retraction,
        SCHEMA_RETRACTION,
        encode(&RetractionData {
            target_id: bench0,
            reason: "harness measured the wrong thing".into(),
        })
        .unwrap(),
        vec![cause(bench0)],
    );
    let _c5 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        cand(
            "5555555555555555555555555555555555555555",
            CandidateBasis::Derivation,
            None,
        ),
        vec![cause(c3)],
    );
    let review0 = commit(
        &mut w,
        &mut st,
        "reviewer",
        Kind::Evaluation,
        SCHEMA_EVALUATION,
        encode(&EvaluationData {
            candidate: c0,
            criterion: "manual-review".into(),
            procedure: None,
            outcome: EvaluationOutcome::Passed,
        })
        .unwrap(),
        vec![use_r(c0)],
    );
    let _s1 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        encode(&SelectionData {
            objective: "adopt-baseline".into(),
            considered: vec![c0],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c0],
            },
            rationale: None,
        })
        .unwrap(),
        vec![require(c0), use_r(review0), replace(s0)],
    );

    // Spec 0.4 bindings: a request with a user-authored requirement, a
    // candidate binding an artifact, an extended evaluation that judged
    // that artifact against the requirement, and a selection resting on it.
    // The nodes these reach carry `artifacts` and `requirements`
    // annotations; every other node stays 0.3-shaped.
    let req = commit(
        &mut w,
        &mut st,
        "human",
        Kind::Request,
        SCHEMA_REQUEST,
        encode(&RequestData {
            objective: "ship the bound build".into(),
            scope: space,
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap(),
        vec![],
    );
    let r1 = commit(
        &mut w,
        &mut st,
        "human",
        Kind::Requirement,
        SCHEMA_REQUIREMENT,
        encode(&RequirementData {
            key: "R1".into(),
            description: "unit tests pass on the bound tree".into(),
            required: true,
            expected_evidence: None,
            provenance: Provenance::UserAuthored,
        })
        .unwrap(),
        vec![cause(req)],
    );
    let bound_tree = ArtifactRef {
        scheme: "git-tree-sha1".into(),
        digest: "6666666666666666666666666666666666666666".into(),
        name: Some("src".into()),
    };
    let c6 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Candidate,
        SCHEMA_CANDIDATE,
        encode(&CandidateData {
            artifacts: Some(vec![bound_tree.clone()]),
            source: src("6666666666666666666666666666666666666666"),
            basis: CandidateBasis::Root,
            parent: None,
            note: None,
        })
        .unwrap(),
        vec![],
    );
    let bound0 = commit(
        &mut w,
        &mut st,
        "benchmark",
        Kind::Evaluation,
        SCHEMA_EVALUATION_V2,
        encode(&EvaluationDataV2 {
            candidate: c6,
            criterion: "unit-tests".into(),
            procedure: None,
            outcome: EvaluationOutcomeV2::Passed,
            evaluator: DeciderBinding {
                id: "bench-harness".into(),
                version: Some("2.1".into()),
                procedure_hash: None,
                input_hash: None,
            },
            basis: Basis::Recomputed,
            evidence: vec![bound_tree],
            requirements: vec![r1],
        })
        .unwrap(),
        vec![use_r(c6), use_r(r1)],
    );
    let _s2 = commit(
        &mut w,
        &mut st,
        "agent",
        Kind::Selection,
        SCHEMA_SELECTION,
        encode(&SelectionData {
            objective: "ship-bound".into(),
            considered: vec![c6],
            outcome: SelectionOutcome::Selected {
                candidates: vec![c6],
            },
            rationale: None,
        })
        .unwrap(),
        vec![require(c6), use_r(bound0)],
    );

    let receipt = Receipt::new(w.records(), &rules);
    let q = Queries::new(w.records(), &rules).unwrap();
    let hx = hex_encode;
    let id_args = |id: &RecordId| serde_json::json!({ "id": hx(id) });
    let battery: Vec<(&str, serde_json::Value)> = vec![
        ("descent", id_args(&_c5)),
        ("descent", id_args(&c4)),
        ("descendants", id_args(&s0)),
        ("descendants", id_args(&c0)),
        ("siblings", id_args(&c2)),
        ("frontier", serde_json::json!({})),
        ("standing", id_args(&s0)),
        ("standing", id_args(&bench0)),
        ("evidence", id_args(&c3)),
        ("evidence", id_args(&_s1)),
        (
            "selected",
            serde_json::json!({ "objective": "adopt-baseline" }),
        ),
        ("selected", serde_json::json!({ "objective": "adopt" })),
        // Spec 0.4 annotations: the bound candidate's evidence carries the
        // evaluation's artifacts and requirements, and the chosen node its
        // artifacts.
        ("evidence", id_args(&c6)),
        ("selected", serde_json::json!({ "objective": "ship-bound" })),
    ];
    let queries = battery
        .into_iter()
        .map(|(name, args)| QueryVector {
            expect: run_named_query(&q, name, &args),
            query: name.to_string(),
            args,
        })
        .collect();

    vec![QueryCase {
        name: "broken-benchmark-line".into(),
        description: "The RFC-0001 section 10 flagship shape plus a derivation sibling: every query answered over a line that was built, compromised at depth by a retraction (with a motivated-by repair staying sound), and restored by a reaffirmation.".into(),
        receipt,
        queries,
    }]
}
