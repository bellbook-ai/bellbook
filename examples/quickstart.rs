//! Quickstart: one real flow end to end.
//!
//! Request -> Capability -> Action -> Result -> closing Response,
//! then replay verification, receipt export + offline validation, and a
//! tamper demonstration.
//!
//! Run with: `cargo run --example quickstart`

use bellbook::*;

fn main() {
    let dir = tempfile::tempdir().unwrap();

    // A space is the trust boundary; rules are the verifier's static
    // configuration. Actor identities are bound to roles here - the
    // declared author type on a record is never trusted by itself.
    let space = default_space();
    let rules = VerifierRules::new(space, 200)
        .with_author_role("human", AuthorType::User)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("tool-executor", AuthorType::Executor);

    let thread = sha256_utf8("demo-thread");
    let scope = sha256_utf8("demo-scope");

    let author = |id: &str, type_: AuthorType| Author {
        id: id.into(),
        type_,
        signature: None,
    };

    // Open the log (exclusive lock + crash recovery).
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // 1. The human states an objective.
    let (request_id, v) = writer
        .commit(
            Proposal {
                space,
                thread,
                author: author("human", AuthorType::User),
                kind: Kind::Request,
                schema: schema_id(SCHEMA_REQUEST),
                data: encode(&RequestData {
                    objective: "summarize the quarterly report".into(),
                    scope,
                    attachments: vec![],
                    parent_request_id: None,
                })
                .unwrap(),
                refs: vec![],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    println!("request   {} -> {:?}", hex_encode(&request_id), v.result);

    // 2. The human grants the agent a capability (Auto: no per-action
    //    approval needed).
    let (capability_id, v) = writer
        .commit(
            Proposal {
                space,
                thread,
                author: author("human", AuthorType::User),
                kind: Kind::Capability,
                schema: schema_id(SCHEMA_CAPABILITY),
                data: encode(&CapabilityData {
                    actor_id: "agent".into(),
                    action_class: "read_file".into(),
                    scope,
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
    println!(
        "capability {} -> {:?}",
        hex_encode(&capability_id),
        v.result
    );

    // 3. The agent acts, naming the request it serves and the exact
    //    authority that allows it (the Require ref is mandatory).
    let (action_id, v) = writer
        .commit(
            Proposal {
                space,
                thread,
                author: author("agent", AuthorType::Provider),
                kind: Kind::Action,
                schema: schema_id(SCHEMA_ACTION),
                data: encode(&ActionData {
                    request_id,
                    action_class: "read_file".into(),
                    scope,
                    exec_mode: ExecMode::Internal,
                    params: serde_json::json!({"path": "q3-report.txt"}),
                })
                .unwrap(),
                refs: vec![Ref {
                    type_: RefType::Require,
                    target: capability_id,
                }],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    println!("action    {} -> {:?}", hex_encode(&action_id), v.result);

    // 4. The executor closes the action with what actually came back.
    let (result_id, v) = writer
        .commit(
            Proposal {
                space,
                thread,
                author: author("tool-executor", AuthorType::Executor),
                kind: Kind::Result,
                schema: schema_id(SCHEMA_RESULT),
                data: encode(&ResultData {
                    artifacts: None,
                    action_id,
                    status: ResultStatus::Success,
                    output: "Revenue grew 12% quarter over quarter.".into(),
                })
                .unwrap(),
                refs: vec![Ref {
                    type_: RefType::Cause,
                    target: action_id,
                }],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    println!("result    {} -> {:?}", hex_encode(&result_id), v.result);

    // 5. The agent answers and explicitly completes the request
    //    (completion is never inferred).
    let (response_id, v) = writer
        .commit(
            Proposal {
                space,
                thread,
                author: author("agent", AuthorType::Provider),
                kind: Kind::Response,
                schema: schema_id(SCHEMA_RESPONSE),
                data: encode(&ResponseData {
                    request_id,
                    content: "Summary: revenue grew 12% quarter over quarter.".into(),
                    turn_index: 0,
                    closes_request: true,
                })
                .unwrap(),
                refs: vec![],
            },
            &rules,
            &mut state,
        )
        .unwrap();
    println!("response  {} -> {:?}", hex_encode(&response_id), v.result);

    // Replay-verify the entire log: ids, gap-free time, and every verdict
    // recompute from scratch.
    let report = verify_log(writer.records(), &rules, None);
    println!(
        "\nverify_log: {:?} ({} records checked)",
        report.result, report.checked_records
    );
    assert_eq!(report.result, VerdictResult::Accept);

    // Export a portable receipt and validate it offline, exactly as a
    // third party would (`bellbook validate` wraps the same call).
    let receipt = Receipt::new(writer.records(), &rules);
    let bytes = receipt.to_bytes().unwrap();
    let validation = validate(&bytes);
    println!(
        "receipt:    {} bytes, status {:?}, rules hash {}",
        bytes.len(),
        validation.status,
        hex_encode(&validation.rules_hash)
    );
    assert_eq!(validation.status, ValidationStatus::Clean);

    // Tamper with history: flip one byte of a committed payload. Replay
    // catches it - the content address no longer matches.
    let mut forged: Vec<Record> = writer.records().to_vec();
    forged[0].data[0] ^= 0xff;
    let bad = verify_log(&forged, &rules, None);
    println!("tampered:   {:?} ({:?})", bad.result, bad.reason);
    assert_eq!(bad.result, VerdictResult::Reject);
}
