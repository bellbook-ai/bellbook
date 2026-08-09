#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::schema::SCHEMA_REQUEST;
    use crate::record::payloads::RequestData;

    fn test_rules() -> VerifierRules {
        VerifierRules::new([1u8; 32], 200).with_author_role("human", AuthorType::User)
    }

    fn make_request_proposal(space: [u8; 32], thread: [u8; 32]) -> Proposal {
        let data = encode(&RequestData {
            objective: "test goal".into(),
            scope: [10u8; 32],
            attachments: vec![],
            parent_request_id: None,
        })
        .unwrap();
        Proposal {
            space,
            thread,
            author: Author {
                id: "human".into(),
                type_: AuthorType::User,
                signature: None,
            },
            kind: Kind::Request,
            schema: schema_id(SCHEMA_REQUEST),
            data,
            refs: vec![],
        }
    }

    #[test]
    fn test_commit_protocol() {
        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();

        let proposal = make_request_proposal(rules.space, [2u8; 32]);
        let (id, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();

        assert_eq!(verdict.result, VerdictResult::Accept);
        assert!(verdict.reason.is_none());
        assert!(state.accepted_records.contains(&id));
        assert!(state.active_requests.contains(&id));
        assert_eq!(writer.log.records.len(), 2); // subject + verdict
    }

    #[test]
    fn test_crash_recovery_missing_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();

        // Manually create a log with a subject but no verdict, and an intent file
        {
            let mut log = FileLog::open(dir.path(), u64::MAX).unwrap();
            let data = encode(&RequestData {
                objective: "test".into(),
                scope: [10u8; 32],
                attachments: vec![],
                parent_request_id: None,
            })
            .unwrap();
            let record = Record {
                id: [0u8; 32],
                space: rules.space,
                thread: [2u8; 32],
                time: 1,
                author: Author {
                    id: "human".into(),
                    type_: AuthorType::User,
                    signature: None,
                },
                kind: Kind::Request,
                schema: schema_id(SCHEMA_REQUEST),
                data,
                refs: vec![],
                evidence: Evidence::Reported,
            }
            .with_computed_id()
            .unwrap();

            let subject_id = record.id;
            log.append(record).unwrap();

            // Write intent file as if crash happened after subject append
            let intent = CommitIntent {
                subject_id,
                written: true,
            };
            intent.write_to_file(&dir.path().join(".intent")).unwrap();
        }

        // Open with recovery
        let writer = LogWriter::open(dir.path(), &rules).unwrap();
        // Should have 2 records: subject + recovered verdict
        assert_eq!(writer.log.records.len(), 2);
        assert_eq!(writer.log.records[1].kind, Kind::Verdict);
    }

    #[test]
    fn test_recovery_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();

        let proposal = make_request_proposal(rules.space, [2u8; 32]);
        writer.commit(proposal, &rules, &mut state).unwrap();

        drop(writer);

        // Reopen - recovery is a no-op on clean log
        let writer = LogWriter::open(dir.path(), &rules).unwrap();
        assert_eq!(writer.log.records.len(), 2);
    }

    #[test]
    fn test_lock_exclusion() {
        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let _writer1 = LogWriter::open(dir.path(), &rules).unwrap();

        // Second open should fail
        let result = LogWriter::open(dir.path(), &rules);
        assert!(matches!(result, Err(LogError::AlreadyLocked)));
    }

    #[test]
    fn capacity_preflight_error_does_not_consume_time() {
        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let mut writer = LogWriter::open_with_max_bytes(dir.path(), &rules, 4096).unwrap();
        let mut state = State::default();

        let mut oversized = make_request_proposal(rules.space, [2u8; 32]);
        oversized.data = vec![0; 8192];
        assert!(matches!(
            writer.commit(oversized, &rules, &mut state),
            Err(LogError::LogSizeLimitExceeded { .. })
        ));
        assert_eq!(writer.next_time(), 1);
        assert!(writer.records().is_empty());
        assert!(!dir.path().join(".intent").exists());

        let proposal = make_request_proposal(rules.space, [2u8; 32]);
        let (_, verdict) = writer.commit(proposal, &rules, &mut state).unwrap();
        assert_eq!(verdict.result, VerdictResult::Accept);
        assert_eq!(writer.records()[0].time, 1);
        assert_eq!(writer.records()[1].time, 2);
        assert_eq!(
            verify_log(writer.records(), &rules, None).result,
            VerdictResult::Accept
        );
    }

    #[test]
    fn capacity_preflight_reserves_subject_and_verdict_together() {
        let probe_dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let mut probe = LogWriter::open(probe_dir.path(), &rules).unwrap();
        let mut probe_state = State::default();
        probe
            .commit(
                make_request_proposal(rules.space, [2u8; 32]),
                &rules,
                &mut probe_state,
            )
            .unwrap();
        let subject_frame_bytes = 4u64 + canonical_json(&probe.records()[0]).unwrap().len() as u64;
        drop(probe);

        // The subject alone fits exactly, but the logical pair does not.
        let dir = tempfile::tempdir().unwrap();
        let mut writer =
            LogWriter::open_with_max_bytes(dir.path(), &rules, subject_frame_bytes).unwrap();
        let mut state = State::default();
        assert!(matches!(
            writer.commit(
                make_request_proposal(rules.space, [2u8; 32]),
                &rules,
                &mut state
            ),
            Err(LogError::LogSizeLimitExceeded { .. })
        ));
        assert!(writer.records().is_empty());
        assert_eq!(writer.next_time(), 1);
        assert!(!dir.path().join(".intent").exists());
    }

    #[test]
    fn durable_phase_failure_requires_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        writer.recovery_required = true;
        let mut state = State::default();

        assert!(matches!(
            writer.commit(
                make_request_proposal(rules.space, [2u8; 32]),
                &rules,
                &mut state
            ),
            Err(LogError::RecoveryRequired)
        ));
        assert!(writer.records().is_empty());
        assert_eq!(writer.next_time(), 1);
    }

    #[test]
    fn checked_batch_retry_binds_exact_signature() {
        let dir = tempfile::tempdir().unwrap();
        let rules = test_rules();
        let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
        let mut state = State::default();
        let mut proposal = make_request_proposal(rules.space, [2u8; 32]);
        proposal.author.signature = Some(crate::record::author::Signature {
            key_id: "11".repeat(32),
            sig: vec![1; 64],
        });

        let first = writer
            .checked_batch_commit(EMPTY_HEAD, vec![proposal.clone()], &rules, &mut state)
            .unwrap();
        assert_eq!(first.replayed, 0);
        assert_eq!(first.results[0].1.result, VerdictResult::Reject);

        let retry = writer
            .checked_batch_commit(EMPTY_HEAD, vec![proposal.clone()], &rules, &mut state)
            .unwrap();
        assert_eq!(retry.replayed, 1);
        assert_eq!(retry.head, first.head);
        assert_eq!(retry.results, first.results);

        let mut changed = proposal.clone();
        changed.author.signature.as_mut().unwrap().sig[0] ^= 1;
        assert!(matches!(
            writer.checked_batch_commit(EMPTY_HEAD, vec![changed], &rules, &mut state),
            Err(LogError::HeadConflict { .. })
        ));

        let mut removed = proposal;
        removed.author.signature = None;
        assert!(matches!(
            writer.checked_batch_commit(EMPTY_HEAD, vec![removed], &rules, &mut state),
            Err(LogError::HeadConflict { .. })
        ));
    }
}
