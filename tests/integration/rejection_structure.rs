// ---------------------------------------------------------------------------
// Verifier tests - one per ReasonCode
// ---------------------------------------------------------------------------

#[test]
fn test_unknown_schema() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let bogus_schema = sha256_utf8("bogus.schema.v99");
    let data = encode(&RequestData {
        objective: "test".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();
    let proposal = Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Request,
        schema: bogus_schema,
        data,
        refs: vec![],
    };

    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::UnknownSchema));
}

#[test]
fn test_kind_schema_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Use the Request schema but claim it's an Action kind
    let data = encode(&RequestData {
        objective: "test".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();
    let proposal = Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Action, // wrong kind for SCHEMA_REQUEST
        schema: schema_id(SCHEMA_REQUEST),
        data,
        refs: vec![],
    };

    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::KindSchemaMismatch));
}

#[test]
fn test_ref_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let nonexistent_id = [99u8; 32];
    let data = encode(&RequestData {
        objective: "test".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();
    let proposal = Proposal {
        space: SPACE,
        thread: THREAD,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: nonexistent_id,
        }],
    };

    let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::RefUnresolved));
}

#[test]
fn test_ref_cross_space() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit a valid request
    let (_request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Now create a second rules set with a different space for a second writer
    let other_space = [77u8; 32];
    let other_rules = VerifierRules::new(other_space, 200);
    let dir2 = tempfile::tempdir().unwrap();
    let mut writer2 = LogWriter::open(dir2.path(), &other_rules).unwrap();
    let mut state2 = State::default();

    // Commit a record in the other space
    let data = encode(&RequestData {
        objective: "other space".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();
    let (_other_id, _) = writer2
        .commit(
            Proposal {
                space: other_space,
                thread: THREAD,
                author: human_author(),
                kind: Kind::Request,
                schema: schema_id(SCHEMA_REQUEST),
                data,
                refs: vec![],
            },
            &other_rules,
            &mut state2,
        )
        .unwrap();

    // Now manually append that other-space record into writer1's log to simulate cross-space ref
    // We need to use verify_record directly since LogWriter.commit only operates on its own log.
    // Instead, we construct a record that references the request_id (which is in SPACE)
    // but set the record's space to SPACE - the ref target has space SPACE so this won't trigger cross-space.
    // To actually test cross-space, we need a record in the prior log that has a different space.
    // The simplest approach: commit an request in the main writer, then create a proposal
    // that references it but we manually hack the target record's space in the prior.
    // Actually, cross-space is checked by looking up the target in prior and comparing spaces.
    // Since all records committed through our writer have the same space, we can't easily trigger
    // this through the normal commit flow. Instead, test verify_record directly.

    let data = encode(&RequestData {
        objective: "test".into(),
        scope: SCOPE,
        attachments: vec![],
        parent_request_id: None,
    })
    .unwrap();

    // Create a record in a different space, put it in prior
    let foreign_record = Record {
        id: [0u8; 32],
        space: other_space,
        thread: THREAD,
        time: 100,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data: data.clone(),
        refs: vec![],
        evidence: Evidence::Reported,
    }
    .with_computed_id()
    .unwrap();

    // Create a record in SPACE that references the foreign record
    let test_record = Record {
        id: [0u8; 32],
        space: SPACE,
        thread: THREAD,
        time: 101,
        author: human_author(),
        kind: Kind::Request,
        schema: schema_id(SCHEMA_REQUEST),
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: foreign_record.id,
        }],
        evidence: Evidence::Reported, // will be recomputed below
    };
    // Derive correct evidence
    let ref_evidences: Vec<Evidence> = vec![foreign_record.evidence];
    let evidence = derive_evidence(&test_record.schema, &ref_evidences);
    let test_record = Record {
        evidence,
        ..test_record
    }
    .with_computed_id()
    .unwrap();

    let prior = vec![foreign_record];
    let verdict = verify_record(&test_record, &prior, &rules, &State::default());
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::RefCrossSpace));
}

#[test]
fn test_request_missing() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit a capability so the action doesn't fail on CapabilityMissing first
    let (_cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    // Commit an action referencing a non-existent request
    let bogus_request = [88u8; 32];
    let (_, verdict) = writer
        .commit(action_proposal(bogus_request, "shell"), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::RequestMissing));
}

#[test]
fn test_capability_missing() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Commit an request but NO capability
    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Commit an action - should fail because there's no capability for (ACTOR, "shell", SCOPE)
    let (_, verdict) = writer
        .commit(action_proposal(request_id, "shell"), &rules, &mut state)
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::CapabilityMissing));
}

#[test]
fn test_capability_denied() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let (request_id, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Grant a Deny capability
    let (cap_id, v) = writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Deny),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(v.result, VerdictResult::Accept);

    let (_, verdict) = writer
        .commit(
            action_proposal_with_authority(request_id, "shell", &[cap_id]),
            &rules,
            &mut state,
        )
        .unwrap();
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::CapabilityDenied));
}
