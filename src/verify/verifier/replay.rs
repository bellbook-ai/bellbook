use super::*;

/// Verify an entire committed log.
///
/// # Checkpoint trust
///
/// Passing a [`TrustedCheckpoint`] skips verdict re-derivation and
/// per-record rule checks for the covered prefix - that is the
/// acceleration. The prefix's record ids are still recomputed from
/// content, and every checkpoint field is validated against the prefix,
/// but forged verdicts inside the prefix are attested by the checkpoint,
/// not detected. That is exactly why the parameter is
/// [`TrustedCheckpoint`] and not [`Checkpoint`](crate::checkpoint::Checkpoint): the type can only be
/// obtained from a prior successful verification under the same rules
/// (or an explicit, greppable [`TrustedCheckpoint::assume_verified`]
/// assertion). A checkpoint verified under different rules rejects with
/// `InvalidCheckpoint`. External anchoring never substitutes for
/// verification - see [`TrustedCheckpoint`]. Receipts always verify from
/// genesis (SPEC §12).
///
/// The checkpoint is validated before anything else, including the
/// empty-log case: an empty (or truncated) records slice presented
/// against a checkpoint covering more records rejects with
/// `InvalidCheckpoint` - deleted history is never Accept. A checkpoint
/// covering an empty prefix grants nothing: replay starts at genesis and
/// the first record must have time 1.
///
/// # Cost
///
/// Replay is linear in the number of records (ref resolution, subject
/// lookup, and duplicate-verdict detection go through an id index built
/// as replay advances), plus hashing proportional to total content size.
pub fn verify_log(
    records: &[Record],
    rules: &VerifierRules,
    checkpoint: Option<&TrustedCheckpoint>,
) -> LogVerdict {
    let start_index;
    let mut state;
    let mut index = PriorIndex::default();

    // Checkpoint validation runs before anything else - including the
    // empty-log case. An empty (or truncated) records slice presented
    // against a checkpoint covering more records means attested history
    // has been deleted, and must reject, never Accept.
    if let Some(trusted) = checkpoint {
        // The checkpoint must have been established under these exact
        // rules - verdict re-derivation is rule-dependent, so a prefix
        // verified under different rules attests nothing here.
        match sha256_canonical(rules) {
            Ok(h) if h == *trusted.rules_hash() => {}
            _ => return reject(ReasonCode::InvalidCheckpoint, 0, records),
        }
        let cp = trusted.checkpoint();

        // Even a trusted checkpoint's fields are validated against the
        // actual records: its claimed prefix length must fit the log
        // before it can be sliced. Compared in u64 so an oversized
        // length can never truncate on 32-bit targets.
        if cp.log_length > records.len() as u64 {
            return reject(ReasonCode::InvalidCheckpoint, 0, records);
        }

        // Verify log_hash against actual prefix
        let prefix = &records[..cp.log_length as usize];
        let ids: Vec<[u8; 32]> = prefix.iter().map(|r| r.id).collect();
        let computed_log_hash = crate::base::hash::sha256_concat_ids(&ids);
        if computed_log_hash != cp.log_hash {
            return reject(ReasonCode::InvalidCheckpoint, 0, records);
        }

        start_index = cp.log_length as usize;

        // The prefix boundary must not split a subject/verdict pair: if the
        // first replayed record is a Verdict, its subject sits inside the
        // prefix and its stored result could not be re-derived. Rejecting
        // here keeps "every replayed verdict re-derives" unconditional.
        if start_index < records.len() && records[start_index].kind == Kind::Verdict {
            return reject(ReasonCode::InvalidCheckpoint, 0, records);
        }

        // Rebuild state from the hash-verified prefix (prefix verdicts are
        // attested by the checkpoint rather than re-derived; prefix ids
        // are still recomputed below, so the hash binds content).
        state = match build_state_unchecked(prefix) {
            Ok(s) => s,
            Err(_) => {
                return reject(ReasonCode::InvalidPayload, 0, records);
            }
        };

        // The remaining checkpoint fields must agree with the verified
        // prefix and the state it rebuilds to.
        let (expect_time, expect_id) = prefix
            .last()
            .map(|r| (r.time, r.id))
            .unwrap_or((0, [0u8; 32]));
        let state_hash = match sha256_canonical(&state) {
            Ok(h) => h,
            Err(_) => {
                return reject(ReasonCode::InvalidPayload, 0, records);
            }
        };
        if cp.last_time != expect_time
            || cp.last_record_id != expect_id
            || cp.state_hash != state_hash
        {
            return reject(ReasonCode::InvalidCheckpoint, 0, records);
        }

        // Seed the lookup index with the hash-verified prefix.
        for (pos, record) in prefix.iter().enumerate() {
            index.insert(pos, record);
        }
    } else {
        start_index = 0;
        state = State::default();
    }

    let mut checked = 0u64;

    // Check time sequence. checked_add: a hostile time of u64::MAX must
    // reject, never overflow (panic in debug, wrap in release).
    for i in 1..records.len() {
        match records[i - 1].time.checked_add(1) {
            Some(expected) if records[i].time == expected => {}
            _ => return reject(ReasonCode::InvalidPayload, checked, records),
        }
    }

    // Genesis rule: logical time starts at 1. Enforced unconditionally -
    // in particular, a checkpoint covering an empty prefix must not
    // exempt a log from starting at time 1.
    if !records.is_empty() && records[0].time != 1 {
        return reject(ReasonCode::InvalidPayload, 0, records);
    }

    // Verify every record's id - including records inside a checkpoint
    // prefix. The checkpoint's log_hash covers *stored* ids; recomputing
    // them here makes it bind actual content, so a prefix record whose
    // bytes were swapped under a kept id is caught even when a checkpoint
    // is used.
    for record in records {
        let computed_id = match record.compute_id() {
            Ok(id) => id,
            Err(_) => {
                return reject(ReasonCode::InvalidPayload, checked, records);
            }
        };
        if record.id != computed_id {
            return reject(ReasonCode::InvalidPayload, checked, records);
        }
    }

    // Process records in pairs: each non-verdict must have a verdict
    // following it. The index grows as replay advances, so every lookup
    // below sees exactly the records before the one being checked and
    // costs O(1) - full-log replay stays linear in the number of records.
    let mut i = start_index;
    while i < records.len() {
        let record = &records[i];

        if record.kind == Kind::Verdict {
            // Verdict record - verify it
            let prior = index.view(records);
            if let Some(reason) = check_verdict_record(record, &prior, rules) {
                return reject(reason, checked, records);
            }

            let stored_verdict: VerdictData = match decode(&record.data) {
                Ok(v) => v,
                Err(_) => {
                    return reject(ReasonCode::InvalidPayload, checked, records);
                }
            };

            // Get subject from Cause ref
            let Some(subject_id) = record
                .refs
                .iter()
                .find(|r| r.type_ == RefType::Cause)
                .map(|r| r.target)
            else {
                return reject(ReasonCode::InvalidPayload, checked, records);
            };

            // Apply to state
            if let Some(subject) = prior.find(subject_id) {
                if crate::state::incremental::apply_record(&mut state, subject, &stored_verdict)
                    .is_err()
                {
                    return reject(ReasonCode::InvalidPayload, checked, records);
                }
            }
            state.applied_up_to = record.time;

            index.insert(i, record);
            checked += 1;
            i += 1;
            continue;
        }

        // Non-verdict record - the next record MUST be its verdict
        if i + 1 >= records.len() {
            return reject(ReasonCode::InvalidPayload, checked, records);
        }

        let next = &records[i + 1];
        if next.kind != Kind::Verdict {
            return reject(ReasonCode::InvalidPayload, checked, records);
        }

        // The subject enters the index first so its verdict's Cause ref
        // resolves. Its own checks below cannot be confused by this: no
        // record can reference its own id (the id is a hash over the
        // refs, so a self-reference is a hash fixpoint).
        index.insert(i, record);
        let prior = index.view(records);

        // The paired verdict's own envelope is verified in full (schema,
        // author type, space, evidence, payload round-trip, single Cause
        // ref to a resolving subject, no duplicate) - position alone does
        // not make a record a valid verdict.
        if let Some(reason) = check_verdict_record(next, &prior, rules) {
            return reject(reason, checked, records);
        }
        // And its Cause ref must name exactly the record it is paired
        // with, so verdicts cannot be re-pointed at other subjects.
        if next.refs[0].target != record.id {
            return reject(ReasonCode::InvalidPayload, checked, records);
        }

        // Verify the stored verdict matches recomputed
        let recomputed = match check_record(record, &prior, rules, &state) {
            Some(reason) => VerdictData {
                result: VerdictResult::Reject,
                reason: Some(reason),
            },
            None => VerdictData {
                result: VerdictResult::Accept,
                reason: None,
            },
        };
        let stored_verdict: VerdictData = match decode(&next.data) {
            Ok(v) => v,
            Err(_) => {
                return reject(ReasonCode::InvalidPayload, checked, records);
            }
        };

        if recomputed.result != stored_verdict.result || recomputed.reason != stored_verdict.reason
        {
            return reject(
                recomputed.reason.unwrap_or(ReasonCode::InvalidPayload),
                checked,
                records,
            );
        }

        // Apply both subject and verdict to state
        if crate::state::incremental::apply_record(&mut state, record, &stored_verdict).is_err() {
            return reject(ReasonCode::InvalidPayload, checked, records);
        }
        state.applied_up_to = next.time;

        index.insert(i + 1, next);
        checked += 2; // subject and verdict both replayed cleanly
        i += 2;
    }

    // Standing is derived at replay end from the accepted records and the
    // final retracted/tainted sets (SPEC §7.2). Computed before the sets are
    // moved out of `state`.
    let standing = crate::verify::standing::derive_standing(records, &state);

    LogVerdict {
        result: VerdictResult::Accept,
        reason: None,
        checked_records: checked,
        last_time: records.last().map(|r| r.time).unwrap_or(0),
        retracted_records: state.retracted_records,
        tainted_records: state.tainted_records,
        standing,
    }
}
