//! Golden test vectors for the current spec epoch's canonical form (SPEC §3.1).
//!
//! Builds a fixed, fully deterministic log containing at least one record of
//! every kind, and asserts one record of each non-evolution kind plus every
//! evolution-kind subject (so the richer v0.3 canonical forms are each pinned)
//! against `spec/test-vectors-v0.3.json`: canonical id form (the exact JCS
//! bytes fed to SHA-256) and the resulting id. A deterministic signed vector
//! also
//! fixes the signing form, key material, signature, final id form, and a
//! key-substitution case. Third-party implementations can reproduce every
//! byte and id without running Rust.
//!
//! Regenerate after an intentional format change with:
//! `UPDATE_VECTORS=1 cargo test --test spec_vectors`

use bellbook::*;
use std::collections::BTreeMap;

const SPACE_NAME: &str = "bellbook.spec.test-vectors.space";
const THREAD_NAME: &str = "bellbook.spec.test-vectors.thread";
const SCOPE_NAME: &str = "bellbook.spec.test-vectors.scope";

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn author(id: &str, type_: AuthorType) -> Author {
    Author {
        id: id.into(),
        type_,
        signature: None,
    }
}

fn proposal(kind: Kind, schema: &str, data: Vec<u8>, refs: Vec<Ref>, author_: Author) -> Proposal {
    Proposal {
        space: sha256_utf8(SPACE_NAME),
        thread: sha256_utf8(THREAD_NAME),
        author: author_,
        kind,
        schema: schema_id(schema),
        data,
        refs,
    }
}

fn cause(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Cause,
        target,
    }
}

fn require(target: RecordId) -> Ref {
    Ref {
        type_: RefType::Require,
        target,
    }
}

/// Build the scripted vector log. Every commit must be accepted.
fn scripted_log(dir: &std::path::Path) -> Vec<Record> {
    let space = sha256_utf8(SPACE_NAME);
    let scope = sha256_utf8(SCOPE_NAME);
    let mut rules = VerifierRules::new(space, 200)
        .with_author_role("human", AuthorType::User)
        .with_author_role("agent", AuthorType::Provider)
        .with_author_role("tool-executor", AuthorType::Executor)
        .with_author_role("host", AuthorType::System);
    rules.admin_retraction_actors.insert("human".into());
    let mut writer = LogWriter::open(dir, &rules).unwrap();
    let mut state = State::default();

    let commit = |p: Proposal, writer: &mut LogWriter, state: &mut State| -> RecordId {
        let (id, verdict) = writer.commit(p, &rules, state).unwrap();
        assert_eq!(
            verdict.result,
            VerdictResult::Accept,
            "vector log commit rejected: {:?}",
            verdict.reason
        );
        id
    };

    let request_id = commit(
        proposal(
            Kind::Request,
            SCHEMA_REQUEST,
            encode(&RequestData {
                objective: "demonstrate the bellbook record format".into(),
                scope,
                attachments: vec![],
                parent_request_id: None,
            })
            .unwrap(),
            vec![],
            author("human", AuthorType::User),
        ),
        &mut writer,
        &mut state,
    );

    // Spec 0.4: a Requirement stated by the principal for the request.
    let requirement_id = commit(
        proposal(
            Kind::Requirement,
            SCHEMA_REQUIREMENT,
            encode(&RequirementData {
                key: "demo-file-written".into(),
                description: "demo.txt exists after the run".into(),
                required: true,
                expected_evidence: Some("a Result naming demo.txt".into()),
                provenance: Provenance::UserAuthored,
            })
            .unwrap(),
            vec![cause(request_id)],
            author("human", AuthorType::User),
        ),
        &mut writer,
        &mut state,
    );

    let capability_id = commit(
        proposal(
            Kind::Capability,
            SCHEMA_CAPABILITY,
            encode(&CapabilityData {
                actor_id: "agent".into(),
                action_class: "tool".into(),
                scope,
                mode: CapabilityMode::Auto,
                expiry: None,
            })
            .unwrap(),
            vec![],
            author("human", AuthorType::User),
        ),
        &mut writer,
        &mut state,
    );

    commit(
        proposal(
            Kind::Approval,
            SCHEMA_APPROVAL,
            encode(&ApprovalData {
                target_action: None,
                action_class: Some("tool".into()),
                scope,
                actor_id: None,
                expiry: None,
            })
            .unwrap(),
            vec![],
            author("human", AuthorType::User),
        ),
        &mut writer,
        &mut state,
    );

    let response_id = commit(
        proposal(
            Kind::Response,
            SCHEMA_RESPONSE,
            encode(&ResponseData {
                request_id,
                content: "I will run the tool and summarize the outcome.".into(),
                turn_index: 0,
                closes_request: false,
            })
            .unwrap(),
            vec![],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    commit(
        proposal(
            Kind::Plan,
            SCHEMA_PLAN,
            encode(&PlanData {
                request_id,
                tasks: vec![PlanTask {
                    id: "t1".into(),
                    description: "run the tool".into(),
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
            .unwrap(),
            vec![cause(request_id)],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    let action1_id = commit(
        proposal(
            Kind::Action,
            SCHEMA_ACTION,
            encode(&ActionData {
                request_id,
                action_class: "tool".into(),
                scope,
                exec_mode: ExecMode::Internal,
                params: serde_json::json!({"path": "demo.txt"}),
            })
            .unwrap(),
            vec![require(capability_id)],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    let action2_id = commit(
        proposal(
            Kind::Action,
            SCHEMA_ACTION,
            encode(&ActionData {
                request_id,
                action_class: "tool".into(),
                scope,
                exec_mode: ExecMode::Internal,
                params: serde_json::json!({"path": "other.txt"}),
            })
            .unwrap(),
            vec![require(capability_id)],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    let result_id = commit(
        proposal(
            Kind::Result,
            SCHEMA_RESULT,
            encode(&ResultData {
                artifacts: Some(vec![ArtifactRef {
                    scheme: "sha256-bytes".into(),
                    digest: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                        .into(),
                    name: Some("demo.txt".into()),
                }]),
                action_id: action1_id,
                status: ResultStatus::Success,
                output: "wrote demo.txt".into(),
            })
            .unwrap(),
            vec![cause(action1_id)],
            author("tool-executor", AuthorType::Executor),
        ),
        &mut writer,
        &mut state,
    );

    let summary_id = commit(
        proposal(
            Kind::Summary,
            SCHEMA_SUMMARY,
            encode(&SummaryData {
                summary_type: SummaryType::Lesson,
                subject: sha256_utf8("demo.txt"),
                scope,
                claim_payload: b"demo.txt was written successfully".to_vec(),
            })
            .unwrap(),
            vec![
                cause(result_id),
                Ref {
                    type_: RefType::Use,
                    target: result_id,
                },
            ],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    commit(
        proposal(
            Kind::Usage,
            SCHEMA_USAGE,
            encode(&UsageData {
                actor: "host".into(),
                used_record: response_id,
                consuming_record: result_id,
                role: "input".into(),
                outcome: UsageOutcome::Done,
            })
            .unwrap(),
            vec![Ref {
                type_: RefType::Use,
                target: response_id,
            }],
            author("host", AuthorType::System),
        ),
        &mut writer,
        &mut state,
    );

    commit(
        proposal(
            Kind::Refusal,
            SCHEMA_REFUSAL,
            encode(&RefusalData {
                target_id: action2_id,
                target_kind: RefusalTarget::Action,
                reason_code: None,
            })
            .unwrap(),
            vec![cause(action2_id)],
            author("human", AuthorType::User),
        ),
        &mut writer,
        &mut state,
    );

    commit(
        proposal(
            Kind::Retraction,
            SCHEMA_RETRACTION,
            encode(&RetractionData {
                target_id: result_id,
                reason: "demo.txt was later found unchanged".into(),
            })
            .unwrap(),
            vec![cause(result_id)],
            author("human", AuthorType::User),
        ),
        &mut writer,
        &mut state,
    );

    // Evolution kinds (spec 0.3): a root candidate, an evaluation of it,
    // and a selection over it. Shaped to satisfy the full lineage battery
    // (SPEC §4.1) so these vectors stay stable as the evolution rules land.
    let candidate_id = commit(
        proposal(
            Kind::Candidate,
            SCHEMA_CANDIDATE,
            encode(&CandidateData {
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
                note: Some("initial state".into()),
            })
            .unwrap(),
            vec![],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    let evaluation_id = commit(
        proposal(
            Kind::Evaluation,
            SCHEMA_EVALUATION,
            encode(&EvaluationData {
                candidate: candidate_id,
                criterion: "unit-tests".into(),
                procedure: Some("cargo test".into()),
                outcome: EvaluationOutcome::Scored(ScoredValue {
                    value: 930,
                    scale: 3,
                }),
            })
            .unwrap(),
            vec![Ref {
                type_: RefType::Use,
                target: candidate_id,
            }],
            author("tool-executor", AuthorType::Executor),
        ),
        &mut writer,
        &mut state,
    );

    let selection_id = commit(
        proposal(
            Kind::Selection,
            SCHEMA_SELECTION,
            encode(&SelectionData {
                objective: "all tests green".into(),
                considered: vec![candidate_id],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![candidate_id],
                },
                rationale: Some("only candidate; criterion met".into()),
            })
            .unwrap(),
            vec![
                Ref {
                    type_: RefType::Use,
                    target: evaluation_id,
                },
                Ref {
                    type_: RefType::Require,
                    target: candidate_id,
                },
            ],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    // A continuation candidate with a full `manifest` binding: exercises the
    // SHA-256 object format, the `commit` provenance field, `manifest_hash`,
    // `basis: continuation`, and `parent` in the canonical form.
    let continuation_id = commit(
        proposal(
            Kind::Candidate,
            SCHEMA_CANDIDATE,
            encode(&CandidateData {
                artifacts: None,
                source: SourceBinding {
                    git: GitSource {
                        algo: SourceAlgo::Sha256,
                        tree: "a".repeat(64),
                        commit: Some("b".repeat(64)),
                    },
                    manifest_hash: Some([0x11u8; 32]),
                    binding: BindingMode::Manifest,
                },
                basis: CandidateBasis::Continuation,
                parent: Some(candidate_id),
                note: None,
            })
            .unwrap(),
            vec![cause(selection_id)],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    // A derivation candidate (repair/mutation over sibling material).
    commit(
        proposal(
            Kind::Candidate,
            SCHEMA_CANDIDATE,
            encode(&CandidateData {
                artifacts: Some(vec![
                    ArtifactRef {
                        scheme: "git-archive-tar-v1".into(),
                        digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            .into(),
                        name: Some("repair.tar".into()),
                    },
                    ArtifactRef {
                        scheme: "x-custom-digest".into(),
                        digest: "0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                        name: None,
                    },
                ]),
                source: SourceBinding {
                    git: GitSource {
                        algo: SourceAlgo::Sha1,
                        tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
                        commit: None,
                    },
                    manifest_hash: None,
                    binding: BindingMode::Reported,
                },
                basis: CandidateBasis::Derivation,
                parent: None,
                note: Some("repair".into()),
            })
            .unwrap(),
            vec![cause(continuation_id)],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    // A `passed` evaluation of the continuation: exercises the unit-variant
    // outcome canonical form (contrast the earlier `scored` evaluation).
    commit(
        proposal(
            Kind::Evaluation,
            SCHEMA_EVALUATION,
            encode(&EvaluationData {
                candidate: continuation_id,
                criterion: "lint".into(),
                procedure: None,
                outcome: EvaluationOutcome::Passed,
            })
            .unwrap(),
            vec![Ref {
                type_: RefType::Use,
                target: continuation_id,
            }],
            author("tool-executor", AuthorType::Executor),
        ),
        &mut writer,
        &mut state,
    );

    // Spec 0.4: an extended evaluation of the continuation, bound to a
    // decider and to the requirement, with one evidence artifact; pins the
    // v2 canonical form (DeciderBinding, basis, evidence, requirements).
    commit(
        proposal(
            Kind::Evaluation,
            SCHEMA_EVALUATION_V2,
            encode(&EvaluationDataV2 {
                candidate: continuation_id,
                criterion: "demo-file-written".into(),
                procedure: Some("test -f demo.txt".into()),
                outcome: EvaluationOutcomeV2::Passed,
                evaluator: DeciderBinding {
                    id: "ci-harness".into(),
                    version: Some("1.0".into()),
                    procedure_hash: Some(sha256_utf8("test -f demo.txt")),
                    input_hash: None,
                },
                basis: Basis::Recomputed,
                evidence: vec![ArtifactRef {
                    scheme: "sha256-bytes".into(),
                    digest: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                        .into(),
                    name: Some("demo.txt".into()),
                }],
                requirements: vec![requirement_id],
            })
            .unwrap(),
            {
                let mut refs = vec![
                    Ref {
                        type_: RefType::Use,
                        target: continuation_id,
                    },
                    Ref {
                        type_: RefType::Use,
                        target: requirement_id,
                    },
                ];
                sort_and_dedup_refs(&mut refs);
                refs
            },
            author("tool-executor", AuthorType::Executor),
        ),
        &mut writer,
        &mut state,
    );

    // A `none` selection (a prune): exercises the unit-variant outcome with no
    // candidate Require refs.
    commit(
        proposal(
            Kind::Selection,
            SCHEMA_SELECTION,
            encode(&SelectionData {
                objective: "latency budget".into(),
                considered: vec![continuation_id],
                outcome: SelectionOutcome::None,
                rationale: None,
            })
            .unwrap(),
            vec![],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    // A reaffirmation: a Selection that Replaces the earlier one under the same
    // objective, re-selecting the same candidate (exercises the Replace ref in
    // the canonical form).
    commit(
        proposal(
            Kind::Selection,
            SCHEMA_SELECTION,
            encode(&SelectionData {
                objective: "all tests green".into(),
                considered: vec![candidate_id],
                outcome: SelectionOutcome::Selected {
                    candidates: vec![candidate_id],
                },
                rationale: Some("reaffirmed".into()),
            })
            .unwrap(),
            vec![
                Ref {
                    type_: RefType::Use,
                    target: evaluation_id,
                },
                Ref {
                    type_: RefType::Require,
                    target: candidate_id,
                },
                Ref {
                    type_: RefType::Replace,
                    target: selection_id,
                },
            ],
            author("agent", AuthorType::Provider),
        ),
        &mut writer,
        &mut state,
    );

    // The scripted log must itself replay cleanly.
    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
    assert!(state.tainted_records.contains(&summary_id));

    writer.records().to_vec()
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct Vector {
    kind: String,
    schema: String,
    time: u64,
    canonical_hash_form: String,
    id: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct SignedVector {
    kind: String,
    schema: String,
    time: u64,
    secret_key_seed_hex: String,
    public_key_hex: String,
    signing_form: String,
    signature_hex: String,
    canonical_id_form: String,
    id: String,
    substitute_public_key_hex: String,
    substitute_signature_hex: String,
    substitute_canonical_id_form: String,
    substitute_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct VectorFile {
    spec_version: String,
    description: String,
    space_name: String,
    thread_name: String,
    scope_name: String,
    space: String,
    vectors: Vec<Vector>,
    signed_vector: SignedVector,
}

fn build_signed_vector(unsigned: &Record) -> SignedVector {
    let seed = [7u8; 32];
    let signer = Ed25519Signer::from_secret_bytes(&seed);
    let signing_form = String::from_utf8(unsigned.signing_bytes().unwrap()).unwrap();

    let mut signed = unsigned.clone();
    signed.author.signature = Some(signer.sign(&signed).unwrap());
    signed = signed.with_computed_id().unwrap();
    assert!(signature_verifies(&signed));

    // A different valid signer over the same signing form produces a valid
    // envelope with a different id; merely substituting its public key into
    // the original envelope must fail strict signature verification.
    let substitute_signer = Ed25519Signer::from_secret_bytes(&[8u8; 32]);
    let mut substitute = unsigned.clone();
    substitute.author.signature = Some(substitute_signer.sign(&substitute).unwrap());
    substitute = substitute.with_computed_id().unwrap();
    assert!(signature_verifies(&substitute));
    assert_ne!(signed.id, substitute.id);

    let mut key_only_substitution = signed.clone();
    key_only_substitution
        .author
        .signature
        .as_mut()
        .unwrap()
        .key_id = substitute_signer.public_key_hex();
    assert!(!signature_verifies(&key_only_substitution));

    SignedVector {
        kind: format!("{:?}", signed.kind),
        schema: schema_name_for_id(&signed.schema).unwrap().to_string(),
        time: signed.time,
        secret_key_seed_hex: hex_encode(&seed),
        public_key_hex: signer.public_key_hex(),
        signing_form,
        signature_hex: bytes_hex(&signed.author.signature.as_ref().unwrap().sig),
        canonical_id_form: String::from_utf8(signed.canonical_id_form().unwrap()).unwrap(),
        id: hex_encode(&signed.id),
        substitute_public_key_hex: substitute_signer.public_key_hex(),
        substitute_signature_hex: bytes_hex(&substitute.author.signature.as_ref().unwrap().sig),
        substitute_canonical_id_form: String::from_utf8(substitute.canonical_id_form().unwrap())
            .unwrap(),
        substitute_id: hex_encode(&substitute.id),
    }
}

fn build_vector_file(records: &[Record]) -> VectorFile {
    // One record of each non-evolution kind, plus *every* evolution-kind
    // subject record, so the richer v0.3 canonical forms (manifest binding,
    // scored vs passed, none vs selected, continuation/derivation, Replace)
    // are each pinned for cross-implementation byte agreement.
    let is_evolution = |k: Kind| matches!(k, Kind::Candidate | Kind::Evaluation | Kind::Selection);
    let mut seen: BTreeMap<Kind, ()> = BTreeMap::new();
    let mut vectors = Vec::new();
    for r in records {
        if !is_evolution(r.kind) {
            if seen.contains_key(&r.kind) {
                continue;
            }
            seen.insert(r.kind, ());
        }
        vectors.push(Vector {
            kind: format!("{:?}", r.kind),
            schema: schema_name_for_id(&r.schema).unwrap().to_string(),
            time: r.time,
            canonical_hash_form: String::from_utf8(r.canonical_id_form().unwrap()).unwrap(),
            id: hex_encode(&r.id),
        });
    }
    // Keep log order (not Kind order) for readability.
    vectors.sort_by_key(|v| v.time);
    VectorFile {
        spec_version: SPEC_VERSION.into(),
        description: "One unsigned record of each non-evolution kind plus every evolution-kind (Candidate/Evaluation/Selection) subject from a fixed scripted log, so the richer v0.3 canonical forms (manifest binding, scored vs passed, none vs selected, continuation/derivation, Replace) and the spec 0.4 `artifacts` list on a Candidate and a Result, a `Requirement`, and an extended `bellbook.evaluation.v2` Evaluation are each pinned; plus a deterministic signed Request and valid alternate-key substitution. id = SHA-256(canonical id form); the domain-separated signing form wraps the record with id and author.signature omitted, while a signed canonical id form omits only id. space/thread/scope ids are SHA-256 of the given UTF-8 names."
            .into(),
        space_name: SPACE_NAME.into(),
        thread_name: THREAD_NAME.into(),
        scope_name: SCOPE_NAME.into(),
        space: hex_encode(&sha256_utf8(SPACE_NAME)),
        vectors,
        signed_vector: build_signed_vector(&records[0]),
    }
}

#[test]
fn spec_vectors_match() {
    let dir = tempfile::tempdir().unwrap();
    let records = scripted_log(dir.path());
    assert_eq!(records.len(), 44); // 22 subjects + 22 verdicts

    let built = build_vector_file(&records);
    // One vector per non-evolution kind, plus every evolution-kind subject
    // (3 candidates, 3 evaluations, 3 selections).
    let evolution = built
        .vectors
        .iter()
        .filter(|v| matches!(v.kind.as_str(), "Candidate" | "Evaluation" | "Selection"))
        .count();
    assert_eq!(evolution, 9, "richer evolution shapes pinned");
    assert_eq!(built.vectors.len(), 22);

    // Every unsigned and signed vector must round-trip to its published id.
    for v in &built.vectors {
        let recomputed = hex_encode(&sha256(v.canonical_hash_form.as_bytes()));
        assert_eq!(recomputed, v.id, "id mismatch for {}", v.kind);
    }
    assert_eq!(
        hex_encode(&sha256(built.signed_vector.canonical_id_form.as_bytes())),
        built.signed_vector.id
    );
    assert_eq!(
        hex_encode(&sha256(
            built.signed_vector.substitute_canonical_id_form.as_bytes()
        )),
        built.signed_vector.substitute_id
    );
    assert_ne!(built.signed_vector.id, built.signed_vector.substitute_id);

    let rel = format!("spec/test-vectors-v{SPEC_VERSION}.json");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&rel);
    if std::env::var("UPDATE_VECTORS").is_ok() {
        let mut out = serde_json::to_string_pretty(&built).unwrap();
        out.push('\n');
        std::fs::write(&path, out).unwrap();
        return;
    }

    let stored: VectorFile =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{rel} missing ({e}) - run UPDATE_VECTORS=1 cargo test --test spec_vectors")
        }))
        .unwrap();
    assert_eq!(
        built, stored,
        "canonical form drifted from {rel}; if the change is an intentional \
         format change, regenerate with UPDATE_VECTORS=1 and document it in \
         CHANGELOG/SPEC"
    );
}
