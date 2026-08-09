// ---------------------------------------------------------------------------
// SignatureMissing - record on a kind that requires signature, but signature is None
// ---------------------------------------------------------------------------

#[test]
fn test_signature_missing() {
    let dir = tempfile::tempdir().unwrap();
    // Create rules that REQUIRE signatures on Request kind
    let mut rules = test_rules();
    rules.signature_required_kinds.insert(Kind::Request);

    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Submit an request without a signature - should be rejected with SignatureMissing
    let proposal = request_proposal(); // author.signature = None
    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();

    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::SignatureMissing));
}

// ---------------------------------------------------------------------------
// SignatureInvalid and Ed25519 signing - signatures are verified for real:
// any present signature must verify (strict Ed25519 over the canonical
// hash form), and rules.author_keys can pin which keys an actor may use.
// ---------------------------------------------------------------------------

fn signed_request_proposal(objective: &str) -> Proposal {
    let data = encode(&RequestData {
        objective: objective.into(),
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

/// A present-but-invalid signature rejects with SignatureInvalid even when
/// no signature is required for the kind (the reason code's triggering
/// test).
#[test]
fn test_signature_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules(); // no signature requirements
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let mut proposal = signed_request_proposal("garbage-signed request");
    proposal.author.signature = Some(Signature {
        key_id: "key-1".into(),
        sig: vec![1, 2, 3, 4],
    });
    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::SignatureInvalid));

    // The rejected record replays identically.
    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// commit_signed produces a record whose signature verifies; the signed
/// log replays cleanly, including when the kind requires a signature.
#[test]
fn test_signed_commit_accepted_and_replays() {
    let dir = tempfile::tempdir().unwrap();
    let mut rules = test_rules();
    rules.signature_required_kinds.insert(Kind::Request);
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let signer = Ed25519Signer::from_secret_bytes(&[42u8; 32]);
    let (id, verdict) = writer
        .commit_signed(
            signed_request_proposal("signed request"),
            &rules,
            &mut state,
            &signer,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);

    let record = writer.get(id).unwrap();
    assert!(signature_verifies(record));
    assert_eq!(verified_key(record), Some(signer.public_key()));

    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// author_keys binds actors to keys: a valid signature under a key the
/// rules do not pin for that actor rejects with SignatureInvalid.
#[test]
fn test_signature_wrong_key_for_pinned_actor() {
    let dir = tempfile::tempdir().unwrap();
    let pinned = Ed25519Signer::from_secret_bytes(&[1u8; 32]);
    let imposter = Ed25519Signer::from_secret_bytes(&[2u8; 32]);

    let mut rules = test_rules();
    rules
        .author_keys
        .entry("human".into())
        .or_default()
        .insert(pinned.public_key());
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (_, verdict) = writer
        .commit_signed(
            signed_request_proposal("imposter-signed"),
            &rules,
            &mut state,
            &imposter,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::SignatureInvalid));

    let (_, verdict2) = writer
        .commit_signed(
            signed_request_proposal("pinned-signed"),
            &rules,
            &mut state,
            &pinned,
        )
        .unwrap();
    assert_eq!(verdict2.result, VerdictResult::Accept);
}

// ---------------------------------------------------------------------------
// InvalidCheckpoint - verify_log with a checkpoint whose log_hash doesn't match
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit a few records
    let (_, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let all_records = writer.scan(0, u64::MAX);

    // Create a valid checkpoint first
    let mut checkpoint = create_checkpoint(all_records, &state).unwrap();
    // Tamper with the log_hash
    checkpoint.log_hash = [99u8; 32];

    // verify_log should reject with InvalidCheckpoint
    let log_verdict = verify_log(
        all_records,
        &rules,
        Some(&TrustedCheckpoint::assume_verified(checkpoint, &rules).unwrap()),
    );
    assert_eq!(log_verdict.result, VerdictResult::Reject);
    assert_eq!(log_verdict.reason, Some(ReasonCode::InvalidCheckpoint));
}

// ---------------------------------------------------------------------------
// Refused - a valid Refusal record with reason_code = Some(Refused)
// ---------------------------------------------------------------------------

#[test]
fn test_refused_reason_code() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Create request
    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Create capability
    let (cap_id, _) = writer
        .commit(
            capability_proposal(ACTOR, "read_file", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();

    // Create action
    let (action_id, _) = writer
        .commit(
            action_proposal_with_authority(request_id, "read_file", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();

    // Submit a programmatic refusal with Refused reason code targeting the action
    let data = encode(&RefusalData {
        target_id: action_id,
        target_kind: RefusalTarget::Action,
        reason_code: Some(ReasonCode::Refused),
    })
    .unwrap();
    let refusal_proposal = Proposal {
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
    };

    let (_, verdict) = writer.commit(refusal_proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Accept);
    assert!(verdict.reason.is_none()); // Accept has no reason

    // Verify the action is now closed
    assert!(!state.open_actions.contains(&action_id));
}

