// ---------------------------------------------------------------------------
// Forged-verdict envelope and hostile-input regressions
// signature key_ids must reject, never pass or panic.
// ---------------------------------------------------------------------------

fn forged_verdict(space: [u8; 32], evidence: Evidence, subject: RecordId) -> Record {
    Record {
        id: [0u8; 32],
        space,
        thread: THREAD,
        time: 1,
        author: Author {
            id: "verifier".into(),
            type_: AuthorType::Verifier,
            signature: None,
        },
        kind: Kind::Verdict,
        schema: schema_id(SCHEMA_VERDICT),
        data: encode(&VerdictData {
            result: VerdictResult::Accept,
            reason: None,
        })
        .unwrap(),
        refs: vec![Ref {
            type_: RefType::Cause,
            target: subject,
        }],
        evidence,
    }
    .with_computed_id()
    .unwrap()
}

/// A verdict whose Cause subject does not resolve is rejected - an
/// unresolved subject must never read as "no objection".
#[test]
fn test_forged_verdict_dangling_subject_rejected() {
    let rules = test_rules();
    let forged = forged_verdict(SPACE, Evidence::Deterministic, [0xAB; 32]);
    let v = verify_record(&forged, &[], &rules, &State::default());
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::RefUnresolved));
}

/// Verdict envelopes are fully verified: wrong space, non-Deterministic
/// evidence, a tampered id, and extra refs all reject.
#[test]
fn test_forged_verdict_envelope_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    let (rid, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    // Fresh subject with no verdict yet, so only the checked property fails.
    let subject = writer.get(rid).unwrap().clone();
    let prior = vec![subject];

    // Wrong space.
    let v = verify_record(
        &forged_verdict([9u8; 32], Evidence::Deterministic, rid),
        &prior,
        &rules,
        &state,
    );
    assert_eq!(v.result, VerdictResult::Reject);

    // Forged evidence class.
    let v = verify_record(
        &forged_verdict(SPACE, Evidence::Assumed, rid),
        &prior,
        &rules,
        &state,
    );
    assert_eq!(v.result, VerdictResult::Reject);

    // Tampered id.
    let mut bad_id = forged_verdict(SPACE, Evidence::Deterministic, rid);
    bad_id.id = [7u8; 32];
    let v = verify_record(&bad_id, &prior, &rules, &state);
    assert_eq!(v.result, VerdictResult::Reject);

    // Extra ref beyond the single Cause edge.
    let mut extra_ref = forged_verdict(SPACE, Evidence::Deterministic, rid);
    extra_ref.refs.push(Ref {
        type_: RefType::Use,
        target: rid,
    });
    let extra_ref = extra_ref.with_computed_id().unwrap();
    let v = verify_record(&extra_ref, &prior, &rules, &state);
    assert_eq!(v.result, VerdictResult::Reject);
}

/// Hostile key_id strings - non-ASCII multibyte content of the right byte
/// length, or uppercase hex - must reject with SignatureInvalid, not panic
/// and not verify.
#[test]
fn test_hostile_signature_key_ids() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // 64 BYTES of UTF-8 that is not 64 ASCII chars: slicing this at fixed
    // byte offsets used to panic inside hex_decode.
    let mut evil = String::from("a");
    for _ in 0..31 {
        evil.push('\u{00a1}');
    }
    evil.push('b');
    assert_eq!(evil.len(), 64);

    let mut p = request_proposal();
    p.author.signature = Some(Signature {
        key_id: evil,
        sig: vec![0u8; 64],
    });
    let (_, v) = writer.commit(p, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::SignatureInvalid));

    // Uppercase hex spelling of a valid key is rejected: key_id has
    // exactly one accepted spelling (lowercase), so conforming verifiers
    // agree byte-for-byte.
    let signer = Ed25519Signer::from_secret_bytes(&[5u8; 32]);
    let mut p = request_proposal();
    p.author.signature = Some(Signature {
        key_id: signer.public_key_hex().to_uppercase(),
        sig: vec![0u8; 64],
    });
    let (_, v) = writer.commit(p, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::SignatureInvalid));

    // The log with the rejected attempts still replays, and a receipt
    // containing them validates without panicking.
    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
    let receipt = bellbook::receipt::Receipt::new(writer.records(), &rules);
    let r = bellbook::receipt::validate(&receipt.to_bytes().unwrap());
    assert_eq!(r.status, bellbook::receipt::ValidationStatus::Clean);
}

