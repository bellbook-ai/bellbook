// ---------------------------------------------------------------------------
// Appender contract: idempotent compare-and-append (SPEC §5.1)
// ---------------------------------------------------------------------------

fn two_capability_batch() -> Vec<Proposal> {
    vec![
        capability_proposal("actor-a", "tool-a", CapabilityMode::Auto),
        capability_proposal("actor-b", "tool-b", CapabilityMode::Auto),
    ]
}

/// Retrying a committed batch is a success no-op returning the same head
/// and the same results, with nothing appended.
#[test]
fn test_checked_batch_commit_retry_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    assert_eq!(writer.head(), EMPTY_HEAD);
    let first = writer
        .checked_batch_commit(EMPTY_HEAD, two_capability_batch(), &rules, &mut state)
        .unwrap();
    assert_eq!(first.replayed, 0);
    assert_eq!(first.head, writer.head());
    let len_after = writer.records().len();
    assert_eq!(len_after, 4); // 2 subjects + 2 verdicts

    // Crash-retry: reopen, rebuild state, resend the identical batch.
    drop(writer);
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = build_state_unchecked(writer.records()).unwrap();
    let retry = writer
        .checked_batch_commit(EMPTY_HEAD, two_capability_batch(), &rules, &mut state)
        .unwrap();
    assert_eq!(retry.head, first.head);
    assert_eq!(retry.results, first.results);
    assert_eq!(retry.replayed, 2);
    assert_eq!(writer.records().len(), len_after); // nothing appended

    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// A batch retried after later unrelated appends still no-ops and returns
/// the head as of after the batch, not the current head.
#[test]
fn test_checked_batch_commit_retry_after_later_appends() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    let first = writer
        .checked_batch_commit(EMPTY_HEAD, two_capability_batch(), &rules, &mut state)
        .unwrap();
    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();

    let retry = writer
        .checked_batch_commit(EMPTY_HEAD, two_capability_batch(), &rules, &mut state)
        .unwrap();
    assert_eq!(retry.head, first.head);
    assert_ne!(retry.head, writer.head());
    assert_eq!(retry.replayed, 2);
}

/// A crash after part of the batch landed: the retry recognizes the landed
/// prefix and commits only the remainder, converging on the same head.
#[test]
fn test_checked_batch_commit_resumes_partial_batch() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    // Determine deterministic batch order, then land only the first
    // proposal (as a crash mid-batch would).
    let batch = two_capability_batch();
    let mut ordered = batch.clone();
    ordered.sort_unstable_by(|a, b| {
        sha256_canonical(a)
            .unwrap()
            .cmp(&sha256_canonical(b).unwrap())
    });
    writer
        .commit(ordered[0].clone(), &rules, &mut state)
        .unwrap();
    assert_eq!(writer.records().len(), 2);

    let outcome = writer
        .checked_batch_commit(EMPTY_HEAD, batch, &rules, &mut state)
        .unwrap();
    assert_eq!(outcome.replayed, 1);
    assert_eq!(outcome.results.len(), 2);
    assert_eq!(writer.records().len(), 4);
    assert_eq!(outcome.head, writer.head());

    let report = verify_log(writer.records(), &rules, None);
    assert_eq!(report.result, VerdictResult::Accept);
}

/// A mismatched head - the log moved on with records that are not this
/// batch - is a conflict, never a duplicate append.
#[test]
fn test_checked_batch_commit_head_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let rules = test_rules();
    let mut writer = LogWriter::open(dir.path(), &rules).unwrap();
    let mut state = State::default();

    writer
        .commit(request_proposal(), &rules, &mut state)
        .unwrap();
    let len_before = writer.records().len();

    // Built against the empty log, but a request landed in between.
    let result =
        writer.checked_batch_commit(EMPTY_HEAD, two_capability_batch(), &rules, &mut state);
    assert!(matches!(result, Err(LogError::HeadConflict { .. })));
    assert_eq!(writer.records().len(), len_before); // nothing appended

    // An unknown expected head is also a conflict.
    let result = writer.checked_batch_commit([9u8; 32], two_capability_batch(), &rules, &mut state);
    assert!(matches!(result, Err(LogError::HeadConflict { .. })));
}

