//! Conformance corpus for Bellbook spec version 0.2.
//!
//! This test builds a machine-readable corpus of verification cases and writes
//! it to `spec/conformance/v0.2/` (regenerate with `UPDATE_CONFORMANCE=1`). Each
//! case pairs a portable input (records + rules, or a raw receipt document) with
//! the expected verification outcome. The runner re-derives every outcome from
//! the *stored* corpus, so an independent implementation (see issue #5) can
//! reproduce the same behavior byte for byte.
//!
//! Two case families:
//!   * record cases   - `verify_record(candidate, prior, rules, state)` == expected verdict.
//!   * receipt cases  - `validate(receipt_bytes)` report status/reason/hashes.
//!   * malformed cases - hostile raw documents that fail structurally.
//!
//! Coverage is asserted: every emitted `ReasonCode` that is expressible in the
//! portable wire format has at least one triggering case.

#![allow(clippy::type_complexity)]

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

    cases
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

    let structural = |status: ValidationStatus, problem: &str| MalformedExpect {
        status,
        reason: None,
        problem_contains: Some(problem.into()),
    };

    // Extra top-level field -> strict decoding rejects.
    {
        let mut v: serde_json::Value = serde_json::from_str(&clean_json).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!(true));
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        cases.push(MalformedCase {
            name: "strict-decode-extra-top-level-field".into(),
            description: "A receipt document with an unknown top-level field.".into(),
            input,
            limits: None,
            expect: MalformedExpect {
                status: report.status,
                reason: report.reason,
                problem_contains: report.problem.clone(),
            },
        });
    }

    // Wrong spec version.
    {
        let mut v: serde_json::Value = serde_json::from_str(&clean_json).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("spec_version".into(), serde_json::json!("0.3"));
        let input = serde_json::to_string(&v).unwrap();
        let report = validate(input.as_bytes());
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(MalformedCase {
            name: "wrong-spec-version".into(),
            description: "A receipt declaring an unsupported spec version.".into(),
            input,
            limits: None,
            expect: MalformedExpect {
                status: report.status,
                reason: report.reason,
                problem_contains: report.problem.clone(),
            },
        });
    }

    // Not JSON at all.
    {
        let input = "this is not a receipt".to_string();
        let report = validate(input.as_bytes());
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(MalformedCase {
            name: "not-json".into(),
            description: "Arbitrary bytes that do not parse as JSON.".into(),
            input,
            limits: None,
            expect: MalformedExpect {
                status: report.status,
                reason: report.reason,
                problem_contains: report.problem.clone(),
            },
        });
    }

    // Truncated JSON.
    {
        let input = clean_json[..clean_json.len() / 2].to_string();
        let report = validate(input.as_bytes());
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(MalformedCase {
            name: "truncated-json".into(),
            description: "The receipt document cut in half.".into(),
            input,
            limits: None,
            expect: MalformedExpect {
                status: report.status,
                reason: report.reason,
                problem_contains: report.problem.clone(),
            },
        });
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
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(MalformedCase {
            name: "exceeds-max-bytes".into(),
            description: "A valid receipt rejected because it exceeds a tiny byte budget.".into(),
            input: clean_json.clone(),
            limits: Some(limits),
            expect: MalformedExpect {
                status: report.status,
                reason: report.reason,
                problem_contains: report.problem.clone(),
            },
        });
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
        assert_eq!(report.status, ValidationStatus::Invalid);
        cases.push(MalformedCase {
            name: "exceeds-max-records".into(),
            description: "A valid multi-record receipt rejected under a one-record budget.".into(),
            input: clean_json.clone(),
            limits: Some(limits),
            expect: MalformedExpect {
                status: report.status,
                reason: report.reason,
                problem_contains: report.problem.clone(),
            },
        });
    }

    let _ = structural; // keep helper available for future cases
    cases
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance/v0.2")
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

    if std::env::var("UPDATE_CONFORMANCE").is_ok() {
        std::fs::create_dir_all(&dir).unwrap();
        write_json(&dir.join("record-cases.json"), &record_file);
        write_json(&dir.join("receipt-cases.json"), &receipt_file);
        write_json(&dir.join("malformed-cases.json"), &malformed_file);
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

/// Every `ReasonCode` that can be produced through the portable wire format.
/// `InvalidCheckpoint` and `RefCrossSpace` are excluded and documented in the
/// corpus README: checkpoints are opaque and never travel in a receipt, and a
/// cross-space reference needs a multi-space log the single-space wire form
/// cannot carry. Both are exercised by the crate's own integration suite.
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
    ]
}
