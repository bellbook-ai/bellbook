// ---------------------------------------------------------------------------
// Hardening regressions
// ---------------------------------------------------------------------------

/// A checkpoint whose log_length exceeds the actual log must be rejected as
/// InvalidCheckpoint, not panic on the prefix slice.
#[test]
fn test_verify_log_rejects_oversized_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let hostile = Checkpoint {
        log_length: 999,
        last_time: 0,
        last_record_id: [0u8; 32],
        state_hash: [0u8; 32],
        log_hash: [0u8; 32],
    };
    let verdict = verify_log(
        writer.records(),
        &rules,
        Some(&TrustedCheckpoint::assume_verified(hostile, &rules).unwrap()),
    );
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidCheckpoint));
}

/// A torn trailing frame (crash mid-append) must be truncated on open so a
/// later append cannot bury garbage inside the file and corrupt the log.
#[test]
fn test_torn_trailing_write_then_append_stays_readable() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();

    {
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();
        writer
            .commit(request_proposal(), &rules, &mut state)
            .unwrap();
    }

    // Simulate a crash mid-append: length prefix promises 100 bytes, only 5 arrive.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("records.log"))
            .unwrap();
        f.write_all(&100u32.to_be_bytes()).unwrap();
        f.write_all(b"torn!").unwrap();
    }

    // Reopen (recovery) and append more records.
    {
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        assert_eq!(writer.records().len(), 2);
        let mut state = build_state_unchecked(writer.records()).unwrap();
        writer
            .commit(
                capability_proposal(ACTOR, "shell", CapabilityMode::Auto),
                &rules,
                &mut state,
            )
            .unwrap();
    }

    // The log must still be fully readable and verifiable after the append.
    let writer = LogWriter::open(dir.path(), &rules).unwrap();
    assert_eq!(writer.records().len(), 4);
    let verdict = verify_log(writer.records(), &rules, None);
    assert_eq!(verdict.result, VerdictResult::Accept);
}

/// checked_records counts every examined record exactly once: one commit
/// produces a subject + verdict pair, so a full replay reports 2.
#[test]
fn test_checked_records_counts_each_record_once() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let verdict = verify_log(writer.records(), &rules, None);
    assert_eq!(verdict.result, VerdictResult::Accept);
    assert_eq!(verdict.checked_records, 2);
}

/// Refs must be strictly sorted and deduplicated: identical content with
/// reordered refs would otherwise hash to a different id, breaking the
/// "equal content => equal id" property of content addressing.
#[test]
fn test_unsorted_refs_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    let (r1, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let (r2, _) = writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let (lo, hi) = if r1 < r2 { (r1, r2) } else { (r2, r1) };
    // A Summary over two sources is the canonical multi-ref record (a
    // Request may carry at most one parent Cause since the parentage
    // cardinality rules).
    let make = |refs: Vec<Ref>| {
        let summary_evidence = derive_evidence(
            &schema_id(SCHEMA_SUMMARY),
            &[Evidence::Reported, Evidence::Reported],
        );
        Record {
            id: [0u8; 32],
            space: SPACE,
            thread: THREAD,
            time: writer.next_time(),
            author: provider_author(),
            kind: Kind::Summary,
            schema: schema_id(SCHEMA_SUMMARY),
            data: encode(&SummaryData {
                summary_type: SummaryType::Lesson,
                subject: sha256_utf8("two-source summary"),
                scope: SCOPE,
                claim_payload: b"summary over two sources".to_vec(),
            })
            .unwrap(),
            refs,
            evidence: summary_evidence,
        }
        .with_computed_id()
        .unwrap()
    };

    let sorted = make(vec![
        Ref {
            type_: RefType::Use,
            target: lo,
        },
        Ref {
            type_: RefType::Use,
            target: hi,
        },
    ]);
    let unsorted = make(vec![
        Ref {
            type_: RefType::Use,
            target: hi,
        },
        Ref {
            type_: RefType::Use,
            target: lo,
        },
    ]);
    let duplicated = make(vec![
        Ref {
            type_: RefType::Use,
            target: lo,
        },
        Ref {
            type_: RefType::Use,
            target: lo,
        },
    ]);

    let prior = writer.records();
    let ok = verify_record(&sorted, prior, &rules, &state);
    assert_eq!(ok.result, VerdictResult::Accept);

    let bad = verify_record(&unsorted, prior, &rules, &state);
    assert_eq!(bad.result, VerdictResult::Reject);
    assert_eq!(bad.reason, Some(ReasonCode::InvalidPayload));

    let dup = verify_record(&duplicated, prior, &rules, &state);
    assert_eq!(dup.result, VerdictResult::Reject);
    assert_eq!(dup.reason, Some(ReasonCode::InvalidPayload));
}

/// Every checkpoint field is validated: a wrong state_hash, last_time, or
/// last_record_id must reject even when log_length/log_hash are correct.
#[test]
fn test_checkpoint_field_forgeries_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let genuine = create_checkpoint(writer.records(), &state).unwrap();
    writer
        .commit(
            capability_proposal(ACTOR, "shell", CapabilityMode::Auto),
            &rules,
            &mut state,
        )
        .unwrap();

    let ok = verify_log(
        writer.records(),
        &rules,
        Some(&TrustedCheckpoint::assume_verified(genuine.clone(), &rules).unwrap()),
    );
    assert_eq!(ok.result, VerdictResult::Accept);

    for forged in [
        Checkpoint {
            state_hash: [0xAB; 32],
            ..genuine.clone()
        },
        Checkpoint {
            last_time: genuine.last_time + 1,
            ..genuine.clone()
        },
        Checkpoint {
            last_record_id: [0xCD; 32],
            ..genuine.clone()
        },
    ] {
        let verdict = verify_log(
            writer.records(),
            &rules,
            Some(&TrustedCheckpoint::assume_verified(forged, &rules).unwrap()),
        );
        assert_eq!(verdict.result, VerdictResult::Reject);
        assert_eq!(verdict.reason, Some(ReasonCode::InvalidCheckpoint));
    }
}

/// A checkpoint whose boundary splits a subject/verdict pair is rejected, so
/// every verdict after the replay start is always re-derived.
#[test]
fn test_pair_splitting_checkpoint_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    // Boundary after the subject, before its verdict. log_hash is computed
    // honestly so the rejection is specifically about the split.
    let prefix = &writer.records()[..1];
    let split = Checkpoint {
        log_length: 1,
        last_time: prefix[0].time,
        last_record_id: prefix[0].id,
        state_hash: sha256_canonical(&build_state_unchecked(prefix).unwrap()).unwrap(),
        log_hash: sha256_concat_ids(&[prefix[0].id]),
    };
    let verdict = verify_log(
        writer.records(),
        &rules,
        Some(&TrustedCheckpoint::assume_verified(split, &rules).unwrap()),
    );
    assert_eq!(verdict.result, VerdictResult::Reject);
    assert_eq!(verdict.reason, Some(ReasonCode::InvalidCheckpoint));
}

/// Generative check of invariant 33 (apply_record == build_state_unchecked) and full
/// replay acceptance over pseudo-random commit sequences. Deterministic LCG,
/// no external dependency; each seed drives a different interleaving of
/// requests, capabilities, actions, results, refusals, and approvals -
/// including proposals the verifier rejects.
#[test]
fn test_generative_state_equivalence_and_replay() {
    for seed in [1u64, 0xDEADBEEF, 0x00C0FFEE] {
        let mut rng = seed;
        let mut next = move || {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (rng >> 33) as u32
        };

        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();
        let mut open_requests: Vec<RecordId> = Vec::new();
        let mut open_actions: Vec<RecordId> = Vec::new();

        for _ in 0..60 {
            let roll = next() % 6;
            let proposal = match roll {
                0 => request_proposal(),
                1 => capability_proposal(ACTOR, "shell", CapabilityMode::Auto),
                2 if !open_requests.is_empty() => {
                    let rid = open_requests[next() as usize % open_requests.len()];
                    action_proposal(rid, "shell")
                }
                3 if !open_actions.is_empty() => {
                    let aid = open_actions[next() as usize % open_actions.len()];
                    result_proposal(aid)
                }
                // Deliberately invalid: action for a request id that never existed.
                4 => action_proposal([0xEE; 32], "shell"),
                _ => capability_proposal(ACTOR, "git", CapabilityMode::Ask),
            };

            let kind = proposal.kind;
            let (id, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
            if verdict.result == VerdictResult::Accept {
                match kind {
                    Kind::Request => open_requests.push(id),
                    Kind::Action => open_actions.push(id),
                    Kind::Result => {}
                    _ => {}
                }
            }

            // Invariant 33: incremental state == full rebuild, every step.
            let rebuilt = build_state_unchecked(writer.records()).unwrap();
            assert_eq!(state, rebuilt, "state divergence at seed {seed}");
        }

        // The whole log - including rejected records - replays cleanly.
        let report = verify_log(writer.records(), &rules, None);
        assert_eq!(report.result, VerdictResult::Accept, "seed {seed}");
        assert_eq!(report.checked_records, writer.records().len() as u64);
    }
}

