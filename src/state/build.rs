//! Full state build from SPEC.md.

use crate::record::kind::Kind;
use crate::record::payloads::VerdictData;
use crate::record::record::{decode, Record};
use crate::record::refs::RecordId;
use crate::state::incremental::apply_record;
use crate::state::state::State;
use std::collections::BTreeMap;

/// Build full state from a slice of records in ascending time order,
/// **trusting the log's stored verdicts without verification**.
///
/// This performs NO validation: record ids, time ordering,
/// subject/verdict pairing, verdict authorship, and verdict correctness
/// are all taken on faith. Calling it on an untrusted log derives
/// authoritative-looking state from forged verdicts. It exists for logs
/// that have **already passed** replay verification (the writer's own
/// log, a checkpoint prefix whose hash was validated) - for anything
/// else, use [`verify_and_build_state`].
pub fn build_state_unchecked(records: &[Record]) -> Result<State, serde_json::Error> {
    let mut state = State::default();

    if records.is_empty() {
        return Ok(state);
    }

    // Step 1: Build verdict map from Verdict records
    let mut verdict_map: BTreeMap<RecordId, VerdictData> = BTreeMap::new();
    for record in records {
        if record.kind == Kind::Verdict {
            // Subject is the Cause ref target
            if let Some(subject_id) = record
                .refs
                .iter()
                .find(|r| r.type_ == crate::record::kind::RefType::Cause)
                .map(|r| r.target)
            {
                let data: VerdictData = decode(&record.data)?;
                verdict_map.insert(subject_id, data);
            }
        }
    }

    // Step 2: Process non-verdict records in log order
    for record in records {
        if record.kind == Kind::Verdict {
            continue;
        }

        if let Some(verdict) = verdict_map.get(&record.id) {
            apply_record(&mut state, record, verdict)?;
        }
        // If no verdict exists, skip (record has no effect on state)
    }

    // Step 3: Set applied_up_to
    state.applied_up_to = records.last().map(|r| r.time).unwrap_or(0);

    Ok(state)
}

/// Verify the whole log from genesis and, only on Accept, build its
/// state. The safe way to derive state from records you did not commit
/// yourself: forged or invalid logs return the rejecting
/// [`LogVerdict`](crate::verify::verifier::LogVerdict)
/// instead of authoritative-looking state.
pub fn verify_and_build_state(
    records: &[Record],
    rules: &crate::verify::rules::VerifierRules,
) -> Result<State, Box<crate::verify::verifier::LogVerdict>> {
    let verdict = crate::verify::verifier::verify_log(records, rules, None);
    if verdict.result != crate::record::kind::VerdictResult::Accept {
        return Err(Box::new(verdict));
    }
    // A log that replays Accept has canonical, decodable payloads, so the
    // unchecked build cannot fail on it; surface the impossible case as a
    // reject rather than panic.
    build_state_unchecked(records).map_err(|_| {
        let mut v = verdict;
        v.result = crate::record::kind::VerdictResult::Reject;
        v.reason = Some(crate::record::kind::ReasonCode::InvalidPayload);
        Box::new(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_state_empty() {
        let state = build_state_unchecked(&[]).unwrap();
        assert_eq!(state.applied_up_to, 0);
        assert!(state.accepted_records.is_empty());
    }
}
