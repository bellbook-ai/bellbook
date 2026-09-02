//! Comprehensive integration tests for the bellbook crate.
//!
//! Covers verifier ReasonCode variants, state lifecycle, context building,
//! commit flow, and verify_log scenarios per SPEC.md.

use bellbook::*;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const SPACE: [u8; 32] = [1u8; 32];
const THREAD: [u8; 32] = [2u8; 32];
const SCOPE: [u8; 32] = [10u8; 32];
const ACTOR: &str = "agent";

fn test_rules() -> VerifierRules {
    let mut rules = VerifierRules::new(SPACE, 200)
        .with_author_role("human", AuthorType::User)
        .with_author_role(ACTOR, AuthorType::Provider)
        .with_author_role("tool_executor", AuthorType::Executor)
        .with_author_role("host", AuthorType::System);
    // The human principal may retract records it did not author.
    rules.admin_retraction_actors.insert("human".into());
    rules
}

fn human_author() -> Author {
    Author {
        id: "human".into(),
        type_: AuthorType::User,
        signature: None,
    }
}

fn provider_author() -> Author {
    Author {
        id: ACTOR.into(),
        type_: AuthorType::Provider,
        signature: None,
    }
}

fn executor_author() -> Author {
    Author {
        id: "tool_executor".into(),
        type_: AuthorType::Executor,
        signature: None,
    }
}

fn request_proposal() -> Proposal {
    let data = encode(&RequestData {
        objective: "test objective".into(),
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

fn capability_proposal(actor: &str, class: &str, mode: CapabilityMode) -> Proposal {
    let data = encode(&CapabilityData {
        actor_id: actor.into(),
        action_class: class.into(),
        scope: SCOPE,
        mode,
        expiry: None,
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

/// An Action proposal carrying `Require` refs to the authority records
/// (capability, and approval for Ask mode) that allow it - mandatory
/// since the authority-binding rules (`AuthorityRefMissing`).
fn action_proposal_with_authority(
    request_id: RecordId,
    class: &str,
    authority: &[RecordId],
) -> Proposal {
    let data = encode(&ActionData {
        request_id,
        action_class: class.into(),
        scope: SCOPE,
        exec_mode: ExecMode::Internal,
        params: serde_json::json!({}),
    })
    .unwrap();
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

fn action_proposal(request_id: RecordId, class: &str) -> Proposal {
    action_proposal_with_authority(request_id, class, &[])
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

fn external_result_proposal(action_id: RecordId) -> Proposal {
    let data = encode(&ResultData {
        artifacts: None,
        action_id,
        status: ResultStatus::Success,
        output: "external done".into(),
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: executor_author(),
        kind: Kind::Result,
        schema: schema_id(SCHEMA_RESULT_EXTERNAL),
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: action_id,
        }],
    }
}

/// An exact approval binds the acting author together with the action
/// content: target = SHA-256(canonical((actor, ActionData))), and the
/// actor must be declared in the payload.
fn approval_exact_proposal(actor: &str, action_data: &ActionData) -> Proposal {
    let target_hash = sha256_canonical(&(&actor.to_string(), action_data)).unwrap();
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

fn response_proposal(request_id: RecordId, turn: u32) -> Proposal {
    let data = encode(&ResponseData {
        request_id,
        content: format!("response turn {}", turn),
        turn_index: turn,
        closes_request: false,
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

/// A Response that explicitly completes its request (the terminal event).
fn closing_response_proposal(request_id: RecordId, turn: u32) -> Proposal {
    let mut p = response_proposal(request_id, turn);
    p.data = encode(&ResponseData {
        request_id,
        content: format!("final response turn {}", turn),
        turn_index: turn,
        closes_request: true,
    })
    .unwrap();
    p
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

fn refusal_request_proposal(request_id: RecordId) -> Proposal {
    let data = encode(&RefusalData {
        target_id: request_id,
        target_kind: RefusalTarget::Request,
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
            target: request_id,
        }],
    }
}

fn usage_proposal(
    used_record: RecordId,
    consuming_record: RecordId,
    outcome: UsageOutcome,
) -> Proposal {
    let data = encode(&UsageData {
        actor: ACTOR.into(),
        used_record,
        consuming_record,
        role: "context".into(),
        outcome,
    })
    .unwrap();
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: provider_author(),
        kind: Kind::Usage,
        schema: schema_id(SCHEMA_USAGE),
        data,
        refs: vec![Ref {
            type_: RefType::Use,
            target: used_record,
        }],
    }
}

/// Commit an request and an Auto capability for the agent actor, returning
/// (request_id, capability_id) - actions must Require-ref the capability.
fn setup_request_and_capability(
    writer: &mut LogWriter,
    rules: &VerifierRules,
    state: &mut State,
    class: &str,
) -> (RecordId, RecordId) {
    let (request_id, v) = writer.commit(request_proposal(), rules, state).unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, class, CapabilityMode::Auto),
            rules,
            state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    (request_id, cap_id)
}

/// Commit an request, capability, action, and return (request_id, action_id).
fn setup_open_action(
    writer: &mut LogWriter,
    rules: &VerifierRules,
    state: &mut State,
    class: &str,
) -> (RecordId, RecordId) {
    let (request_id, cap_id) = setup_request_and_capability(writer, rules, state, class);

    let (action_id, v) = writer
        .commit(
            action_proposal_with_authority(request_id, class, &[cap_id]),
            rules,
            state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    (request_id, action_id)
}

include!("integration/rejection_structure.rs");
include!("integration/rejection_authority.rs");
include!("integration/state_context.rs");
include!("integration/commit_replay.rs");
include!("integration/response_signatures.rs");
include!("integration/signature_checkpoint.rs");
include!("integration/hardening.rs");
include!("integration/plans_evidence.rs");
include!("integration/retraction.rs");
include!("integration/appender.rs");
include!("integration/verdict_hostile.rs");
include!("integration/checkpoint_performance.rs");
include!("integration/authority_lifecycle.rs");
include!("integration/identity_authority.rs");
include!("integration/actor_scope.rs");
include!("integration/pinned_identity.rs");
include!("integration/recovery.rs");
include!("integration/signature_context_parent.rs");
