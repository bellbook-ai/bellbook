// ---------------------------------------------------------------------------
// Pinned-actor signature regressions
// ---------------------------------------------------------------------------

/// Claiming a key-pinned identity without its signature is impersonation
/// and rejects: the id string alone never authenticates. With the wrong
/// key it is SignatureInvalid; with the right key it authenticates.
#[test]
fn test_pinned_identity_cannot_be_claimed_unsigned() {
    let dir = tempfile::tempdir().unwrap();
    let human_signer = Ed25519Signer::from_secret_bytes(&[21u8; 32]);
    let imposter_signer = Ed25519Signer::from_secret_bytes(&[22u8; 32]);
    let mut rules = test_rules();
    rules.author_keys.insert(
        "human".into(),
        [human_signer.public_key()].into_iter().collect(),
    );
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // The provider claims author.id = "human" with no signature - the
    // impersonation attempt. Role check passes ("human" is a
    // registered User and the declared type matches); the mandatory
    // signature for pinned identities rejects it.
    let mut approval = approval_class_proposal("shell", None, None);
    approval.author = Author {
        id: "human".into(),
        type_: AuthorType::User,
        signature: None,
    };
    let (_, v) = writer.commit(approval, &rules, &mut state).unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::SignatureMissing));

    // Same claim signed with a key that is not pinned for "human".
    let approval = approval_class_proposal("shell", None, None);
    let (_, v) = writer
        .commit_signed(approval, &rules, &mut state, &imposter_signer)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::SignatureInvalid));

    // The genuine key authenticates the identity.
    let approval = approval_class_proposal("shell", None, None);
    let (_, v) = writer
        .commit_signed(approval, &rules, &mut state, &human_signer)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // The pinned-signature rule applies to every kind, not just
    // signature_required_kinds: an unsigned Request from "human" also
    // rejects now.
    let (_, v) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    assert_eq!(v.result, VerdictResult::Reject);
    assert_eq!(v.reason, Some(ReasonCode::SignatureMissing));
}

