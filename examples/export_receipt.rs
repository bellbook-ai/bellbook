//! Emit the canonical example receipt to stdout.
//!
//! Builds the same deterministic flow as the quickstart (Request ->
//! Capability -> Action -> Result -> closing Response) and prints the
//! canonical (JCS) receipt bytes. The committed copy lives at
//! `spec/examples/receipt.json`; regenerate it with:
//!
//! `cargo run --example export_receipt > spec/examples/receipt.json`
//!
//! A guard test in `tests/receipt_tests.rs` validates the committed copy,
//! so format drift is caught by CI.

use bellbook::*;

fn main() {
    let dir = tempfile::tempdir().unwrap();
    let space = default_space();
    let rules = VerifierRules::new(space, 200)
        .with_author_role("human", AuthorType::User)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("tool-executor", AuthorType::Executor);

    let thread = sha256_utf8("bellbook.example.thread");
    let scope = sha256_utf8("bellbook.example.scope");
    let author = |id: &str, type_: AuthorType| Author {
        id: id.into(),
        type_,
        signature: None,
    };

    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    let commit = |p: Proposal, writer: &mut LogWriter, state: &mut State| -> RecordId {
        let (id, v) = writer.commit(p, &rules, state).unwrap();
        assert_eq!(
            v.result,
            VerdictResult::Accept,
            "example log commit rejected"
        );
        id
    };

    let request_id = commit(
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
        &mut writer,
        &mut state,
    );

    let capability_id = commit(
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
        &mut writer,
        &mut state,
    );

    let action_id = commit(
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
        &mut writer,
        &mut state,
    );

    commit(
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
        &mut writer,
        &mut state,
    );

    commit(
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
        &mut writer,
        &mut state,
    );

    let receipt = Receipt::new(writer.records(), &rules);
    let bytes = receipt.to_bytes().unwrap();
    assert_eq!(validate(&bytes).status, ValidationStatus::Clean);

    use std::io::Write;
    std::io::stdout().write_all(&bytes).unwrap();
    println!();
}
