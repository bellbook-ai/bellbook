use bellbook::receipt::{validate, Receipt, ValidationStatus};
use bellbook::*;

const SPACE: [u8; 32] = [1u8; 32];
const THREAD: [u8; 32] = [2u8; 32];
const SCOPE: [u8; 32] = [10u8; 32];

fn rules() -> VerifierRules {
    let mut rules = VerifierRules::new(SPACE, 200)
        .with_author_role("human", AuthorType::User)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("exec", AuthorType::Executor);
    rules.admin_retraction_actors.insert("human".into());
    rules
}

fn human() -> Author {
    Author {
        id: "human".into(),
        type_: AuthorType::User,
        signature: None,
    }
}

fn request_proposal() -> Proposal {
    Proposal {
        space: SPACE,
        thread: THREAD,
        author: human(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data: encode(&RequestData {
            objective: "receipt demo".into(),
            scope: SCOPE,
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap(),
        refs: vec![],
    }
}

/// Build a small accepted log: request, capability, action, result,
/// summary (Use-ref on the result). Returns (records, rules, result_id).
fn small_log(dir: &std::path::Path, retract_result: bool) -> (Vec<Record>, VerifierRules) {
    let rules = rules();
    let mut writer = LogWriter::open(dir, &rules).unwrap();
    let mut state = State::default();

    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (cap_id, _) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: human(),
                kind: Kind::Capability,
                schema: schema_id(SCHEMA_CAPABILITY),
                data: encode(&CapabilityData {
                    actor_id: "agent".into(),
                    action_class: "tool".into(),
                    scope: SCOPE,
                    mode: CapabilityMode::Auto,
                    expiry: None,
                })
                .unwrap(),
                refs: vec![],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    let (aid, _) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: Author {
                    id: "agent".into(),
                    type_: AuthorType::Provider,
                    signature: None,
                },
                kind: Kind::Action,
                schema: schema_id(SCHEMA_ACTION),
                data: encode(&ActionData {
                    request_id: rid,
                    action_class: "tool".into(),
                    scope: SCOPE,
                    exec_mode: ExecMode::Internal,
                    params: serde_json::json!({}),
                })
                .unwrap(),
                refs: vec![Ref {
                    type_: RefType::Require,
                    target: cap_id,
                }],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    let (res_id, _) = writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: Author {
                    id: "exec".into(),
                    type_: AuthorType::Executor,
                    signature: None,
                },
                kind: Kind::Result,
                schema: schema_id(SCHEMA_RESULT),
                data: encode(&ResultData {
                    artifacts: None,
                    action_id: aid,
                    status: ResultStatus::Success,
                    output: "done".into(),
                })
                .unwrap(),
                refs: vec![Ref {
                    type_: RefType::Cause,
                    target: aid,
                }],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    writer
        .commit(
            Proposal {
                space: SPACE,
                thread: THREAD,
                author: Author {
                    id: "agent".into(),
                    type_: AuthorType::Provider,
                    signature: None,
                },
                kind: Kind::Summary,
                schema: schema_id(SCHEMA_SUMMARY),
                data: encode(&SummaryData {
                    summary_type: SummaryType::Lesson,
                    subject: [3u8; 32],
                    scope: SCOPE,
                    claim_payload: b"it worked".to_vec(),
                })
                .unwrap(),
                refs: vec![
                    Ref {
                        type_: RefType::Cause,
                        target: res_id,
                    },
                    Ref {
                        type_: RefType::Use,
                        target: res_id,
                    },
                ],
            },
            &rules,
            &mut state,
        )
        .unwrap();

    if retract_result {
        writer
            .commit(
                Proposal {
                    space: SPACE,
                    thread: THREAD,
                    author: human(),
                    kind: Kind::Retraction,
                    schema: schema_id(SCHEMA_RETRACTION),
                    data: encode(&RetractionData {
                        target_id: res_id,
                        reason: "contradicted".into(),
                    })
                    .unwrap(),
                    refs: vec![Ref {
                        type_: RefType::Cause,
                        target: res_id,
                    }],
                },
                &rules,
                &mut state,
            )
            .unwrap();
    }

    (writer.records().to_vec(), rules)
}

