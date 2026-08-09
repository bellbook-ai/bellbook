use super::*;

/// Single-writer log handle with file lock.
pub struct LogWriter {
    /// The underlying append-only store. Kept private so all writes must
    /// pass through the verified commit protocol.
    pub(super) log: FileLog,
    /// Logical time counter, restored from the last committed record on
    /// open; each commit consumes two times (subject, then verdict).
    pub(super) time_source: TimeSource,
    /// Hash of the exact rules used to validate the log at open.
    pub(super) rules_hash: crate::base::hash::Hash256,
    /// Set before the first durable record write and cleared only after the
    /// complete subject/verdict pair, intent cleanup, and state fold succeed.
    /// A set flag makes all later writes fail until the handle is reopened.
    pub(super) recovery_required: bool,
    pub(super) _lock: std::fs::File,
}

/// Default maximum size of records.log opened by [LogWriter::open]:
/// 64 MiB. Use [LogWriter::open_with_max_bytes] for a trusted larger log.
pub const DEFAULT_MAX_LOG_BYTES: u64 = 64 << 20;

impl LogWriter {
    /// Open a log directory for writing with the default 64 MiB file limit.
    /// Acquires the exclusive file lock, verifies existing history, and runs
    /// crash recovery before accepting new commits.
    pub fn open(dir: &Path, rules: &VerifierRules) -> Result<Self, LogError> {
        Self::open_with_max_bytes(dir, rules, DEFAULT_MAX_LOG_BYTES)
    }

    /// Open a log directory with an explicit maximum records.log size.
    ///
    /// The bound is checked before the file is read and before every append,
    /// preventing a hostile or accidentally oversized file from demanding
    /// unbounded memory. Pass u64::MAX only for trusted storage.
    pub fn open_with_max_bytes(
        dir: &Path,
        rules: &VerifierRules,
        max_file_bytes: u64,
    ) -> Result<Self, LogError> {
        std::fs::create_dir_all(dir)?;
        let lock_path = dir.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;

        match fs4::FileExt::try_lock(&lock_file) {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(LogError::AlreadyLocked),
            Err(TryLockError::Error(error)) => return Err(LogError::Io(error)),
        }

        let mut log = FileLog::open(dir, max_file_bytes)?;

        // Before recovery, every complete subject/verdict pair must already
        // replay under these rules. An interrupted final subject is excluded
        // until recovery appends its deterministic verdict.
        let complete_prefix_len = match log.records.last() {
            Some(record) if record.kind != Kind::Verdict => log.records.len() - 1,
            _ => log.records.len(),
        };
        Self::require_valid_log(&log.records[..complete_prefix_len], rules)?;

        // Run crash recovery, then verify the resulting whole log. This
        // catches a malformed/tampered tail before a writable handle escapes.
        Self::recover(&mut log, rules)?;
        Self::require_valid_log(log.records(), rules)?;

        let time_source = TimeSource::from_last_time(log.last_time());
        let rules_hash = sha256_canonical(rules)?;

        Ok(Self {
            log,
            time_source,
            rules_hash,
            recovery_required: false,
            _lock: lock_file,
        })
    }

    fn require_valid_log(records: &[Record], rules: &VerifierRules) -> Result<(), LogError> {
        let verdict = verify_log(records, rules, None);
        if verdict.result == VerdictResult::Accept {
            Ok(())
        } else {
            Err(LogError::InvalidExistingLog {
                reason: verdict.reason,
            })
        }
    }

    /// The logical time the next subject would receive.
    pub fn next_time(&self) -> crate::base::time::Time {
        self.time_source.peek()
    }

    /// Read all committed records. Mutation remains behind the writer's
    /// verified commit methods.
    pub fn records(&self) -> &[Record] {
        self.log.records()
    }

    /// Find a committed record by id.
    pub fn get(&self, id: RecordId) -> Option<&Record> {
        self.log.get(id)
    }

    /// Scan committed records in the inclusive logical-time range.
    pub fn scan(&self, from: crate::base::time::Time, to: crate::base::time::Time) -> &[Record] {
        self.log.scan(from, to)
    }

    fn ensure_writable(&self) -> Result<(), LogError> {
        if self.recovery_required {
            Err(LogError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn ensure_rules_match(&self, rules: &VerifierRules) -> Result<(), LogError> {
        if sha256_canonical(rules)? == self.rules_hash {
            Ok(())
        } else {
            Err(LogError::RulesMismatch)
        }
    }

    fn ensure_state_matches(&self, state: &State) -> Result<(), LogError> {
        let expected = build_state_unchecked(self.log.records())?;
        if expected == *state {
            Ok(())
        } else {
            Err(LogError::StateMismatch)
        }
    }

    /// Crash recovery: restore the log to a valid state.
    ///
    /// The **log tail is the final recovery authority**, never the intent
    /// file: a commit appends the fsynced subject first and its verdict
    /// second, so the only interrupted-commit signature is a trailing
    /// non-verdict record. Whenever the final complete record is not a
    /// Verdict, its verdict is recomputed and appended - regardless of
    /// whether `.intent` is present, absent, empty, or torn (an unlucky
    /// crash could leave any of those, and none may change the outcome).
    /// The intent file is only a crash-marker; it is cleared afterwards.
    /// (A torn trailing subject *frame* is truncated by `FileLog::open`
    /// before recovery runs, exactly as before.)
    fn recover(log: &mut FileLog, rules: &VerifierRules) -> Result<(), LogError> {
        let unverdicted_tail = match log.records.last() {
            Some(r) if r.kind != Kind::Verdict => Some(r.clone()),
            _ => None,
        };

        if let Some(subject) = unverdicted_tail {
            let prior_records = &log.records[..log.records.len() - 1];
            let state = build_state_unchecked(prior_records)?;
            let verdict_data = verify_record(&subject, prior_records, rules, &state);

            let verdict_time = subject.time.checked_add(1).ok_or(LogError::TimeExhausted)?;
            let verdict_record = materialize_verdict(&subject, verdict_time, &verdict_data)?;
            log.append(verdict_record)?;
        }

        // The intent file carries no additional recovery information once
        // the tail is repaired; discard whatever state it is in.
        let intent_path = log.dir.join(".intent");
        CommitIntent::clear_file(&intent_path)?;
        Ok(())
    }

    /// Commit a single proposal through the full protocol.
    /// Returns the committed subject record id and the verdict.
    pub fn commit(
        &mut self,
        proposal: Proposal,
        rules: &VerifierRules,
        state: &mut State,
    ) -> Result<(RecordId, VerdictData), LogError> {
        self.commit_inner(proposal, rules, state, None)
    }

    /// Commit a proposal, signing the materialized record with the given
    /// Ed25519 signer before it is appended and verified. The signature
    /// covers the domain-separated id-free/signature-free signing form; the
    /// completed signature is then bound into the final record id. It must be produced
    /// here, after `time` and `evidence` are assigned.
    pub fn commit_signed(
        &mut self,
        proposal: Proposal,
        rules: &VerifierRules,
        state: &mut State,
        signer: &Ed25519Signer,
    ) -> Result<(RecordId, VerdictData), LogError> {
        self.commit_inner(proposal, rules, state, Some(signer))
    }

    fn commit_inner(
        &mut self,
        proposal: Proposal,
        rules: &VerifierRules,
        state: &mut State,
        signer: Option<&Ed25519Signer>,
    ) -> Result<(RecordId, VerdictData), LogError> {
        // Rules and derived state are caller-supplied conveniences, never
        // trust inputs. Refuse drift, staleness, fabrication, or reuse of a
        // handle whose prior durable commit phase did not finish.
        self.ensure_writable()?;
        self.ensure_rules_match(rules)?;
        self.ensure_state_matches(state)?;

        // A commit consumes two times (subject, verdict); refuse to start
        // one the counter cannot finish rather than saturate mid-commit.
        if self.time_source.exhausted() {
            return Err(LogError::TimeExhausted);
        }
        let intent_path = self.log.dir.join(".intent");

        // Step 1: Derive evidence for the record (SPEC §5). Only epistemic
        // refs (Use/Require) contribute; refs to retracted/tainted records
        // contribute the floor (SPEC §7.1).
        let ref_evidences: Vec<Evidence> = proposal
            .refs
            .iter()
            .filter_map(|r| {
                self.log
                    .get(r.target)
                    .and_then(|t| state.ref_evidence(r, t))
            })
            .collect();
        let evidence = crate::record::evidence::derive_evidence(&proposal.schema, &ref_evidences);

        // Step 2: Materialize the complete pair without mutating the logical
        // clock or storage. A failed preflight therefore consumes no time.
        let time = self.time_source.peek();
        let verdict_time = time.checked_add(1).ok_or(LogError::TimeExhausted)?;
        let mut refs = proposal.refs;
        sort_and_dedup_refs(&mut refs);

        let mut record = Record {
            id: [0u8; 32], // placeholder
            space: proposal.space,
            thread: proposal.thread,
            time,
            author: proposal.author,
            kind: proposal.kind,
            schema: proposal.schema,
            data: proposal.data,
            refs,
            evidence,
        };

        // Sign the domain-separated id-free signing form first, then bind the
        // completed detached signature into the final content-addressed record id.
        if let Some(signer) = signer {
            record.author.signature = Some(signer.sign(&record)?);
        }
        record = record.with_computed_id()?;
        let subject_id = record.id;

        // Verification depends only on the prior committed prefix and the
        // materialized subject, so derive the verdict before any write.
        let verdict_data = verify_record(&record, self.log.records(), rules, state);
        let verdict_record = materialize_verdict(&record, verdict_time, &verdict_data)?;

        // Reserve room for the indivisible logical pair. This prevents the
        // file-size ceiling from accepting a subject that recovery cannot
        // complete with its verdict.
        self.log.ensure_capacity_for(&[&record, &verdict_record])?;

        // Step 3: Write commit intent (written: false), fsync. Once this
        // succeeds, conservatively require reopen on any later error: an I/O
        // failure may have partially written a frame even when append returns
        // Err, and only open-time recovery is allowed to inspect/repair it.
        let intent = CommitIntent {
            subject_id,
            written: false,
        };
        intent.write_to_file(&intent_path)?;
        self.recovery_required = true;

        // Step 4: Append subject, then mark it durable in the intent.
        self.log.append(record)?;
        let intent = CommitIntent {
            subject_id,
            written: true,
        };
        intent.write_to_file(&intent_path)?;

        // Step 5: Append the already-derived deterministic verdict.
        self.log.append(verdict_record)?;

        // Step 6: Clear intent and fold the accepted pair into caller state.
        CommitIntent::clear_file(&intent_path)?;
        let subject = self
            .log
            .get(subject_id)
            .ok_or(LogError::CorruptedRecovery)?;
        crate::state::incremental::apply_record(state, subject, &verdict_data)?;
        state.applied_up_to = verdict_time;

        // Publish the two consumed times only after the complete durable pair
        // and state fold succeed. Before the durable phase, errors leave the
        // writer exactly reusable; during it, recovery_required stays set.
        self.time_source.next_time();
        self.time_source.next_time();
        self.recovery_required = false;

        Ok((subject_id, verdict_data))
    }

    /// Batch commit: sort proposals by canonical hash ascending, then commit each sequentially.
    ///
    /// Each subject/verdict pair is failure-atomic, but the batch as a whole
    /// is **not** a transaction: if a later commit returns an error, earlier
    /// pairs remain durable. Retry-sensitive hosts should use
    /// [`LogWriter::checked_batch_commit`] with an expected head instead of
    /// retrying this method blindly.
    pub fn batch_commit(
        &mut self,
        mut proposals: Vec<Proposal>,
        rules: &VerifierRules,
        state: &mut State,
    ) -> Result<Vec<(RecordId, VerdictData)>, LogError> {
        sort_batch(&mut proposals);
        let mut results = Vec::new();
        for proposal in proposals {
            let result = self.commit(proposal, rules, state)?;
            results.push(result);
        }
        Ok(results)
    }

    /// The current head: id of the last record, or [`EMPTY_HEAD`] for an
    /// empty log. This is the token [`checked_batch_commit`] compares
    /// against.
    ///
    /// [`checked_batch_commit`]: LogWriter::checked_batch_commit
    pub fn head(&self) -> RecordId {
        self.log.records.last().map(|r| r.id).unwrap_or(EMPTY_HEAD)
    }

    /// Idempotent compare-and-append (SPEC §5.1): commit a batch against
    /// the head the appender built it on.
    ///
    /// - If the log's head equals `expected_head`, the batch commits
    ///   normally.
    /// - If the batch (or a prefix of it, from a crash mid-batch) already
    ///   landed immediately after `expected_head`, the landed part is
    ///   recognized by content and **not appended again**; any remainder is
    ///   committed. A fully-landed batch is a success no-op returning the
    ///   same resulting head as the original append.
    /// - Anything else is [`LogError::HeadConflict`] - a conflict, never a
    ///   duplicate append.
    ///
    /// A retry must resend the identical batch. `state` must reflect the
    /// current log (e.g. rebuilt via `build_state_unchecked` after reopening); on a
    /// full no-op it is not touched.
    pub fn checked_batch_commit(
        &mut self,
        expected_head: RecordId,
        mut proposals: Vec<Proposal>,
        rules: &VerifierRules,
        state: &mut State,
    ) -> Result<BatchAppend, LogError> {
        // A full retry can return without calling `commit`, so enforce the
        // same recovery, rule, and state boundaries before inspecting landed
        // records.
        self.ensure_writable()?;
        self.ensure_rules_match(rules)?;
        self.ensure_state_matches(state)?;
        sort_batch(&mut proposals);

        // Position right after the expected head.
        let start = if expected_head == EMPTY_HEAD {
            0
        } else {
            match self.log.records.iter().position(|r| r.id == expected_head) {
                Some(pos) => pos + 1,
                None => {
                    return Err(LogError::HeadConflict {
                        expected: expected_head,
                        actual: self.head(),
                    })
                }
            }
        };

        // Match the longest batch prefix already landed after the head:
        // each landed subject must equal the proposal by content, with its
        // verdict immediately following.
        let mut landed = 0usize;
        let mut pos = start;
        let mut results: Vec<(RecordId, VerdictData)> = Vec::new();
        while landed < proposals.len() {
            let Some(subject) = self.log.records.get(pos) else {
                break;
            };
            if !proposal_matches_record(&proposals[landed], subject) {
                break;
            }
            let Some(verdict) = self.log.records.get(pos + 1) else {
                // Subject landed without its verdict - recovery on open
                // repairs this; reaching here means the caller skipped it.
                return Err(LogError::CorruptedRecovery);
            };
            let verdict_data: VerdictData = crate::record::record::decode(&verdict.data)?;
            results.push((subject.id, verdict_data));
            landed += 1;
            pos += 2;
        }

        if landed == proposals.len() {
            // Fully landed: success no-op with the head the original
            // append produced (records may have been appended after it).
            let head = if pos == 0 {
                EMPTY_HEAD
            } else {
                self.log.records[pos - 1].id
            };
            return Ok(BatchAppend {
                head,
                results,
                replayed: landed,
            });
        }

        // The unmatched remainder must begin at the end of the log -
        // otherwise the log diverged from this batch: conflict.
        if pos != self.log.records.len() {
            return Err(LogError::HeadConflict {
                expected: expected_head,
                actual: self.head(),
            });
        }

        for proposal in proposals.drain(landed..) {
            let result = self.commit(proposal, rules, state)?;
            results.push(result);
        }

        Ok(BatchAppend {
            head: self.head(),
            results,
            replayed: landed,
        })
    }
}

/// Head token of an empty log (all zeros).
pub const EMPTY_HEAD: RecordId = [0u8; 32];

/// Outcome of [`LogWriter::checked_batch_commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchAppend {
    /// The head after this batch - identical on the original append and on
    /// every retry of the same batch.
    pub head: RecordId,
    /// (subject id, verdict) per proposal, in deterministic batch order;
    /// replayed entries are read back from the log, not recomputed.
    pub results: Vec<(RecordId, VerdictData)>,
    /// How many of the batch's proposals had already landed and were not
    /// appended again (`== proposals.len()` for a full no-op).
    pub replayed: usize,
}
