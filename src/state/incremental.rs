//! Incremental state application from SPEC.md.

use crate::base::hash::sha256_canonical;
use crate::record::kind::*;
use crate::record::payloads::*;
use crate::record::record::{decode, Record};
use crate::record::refs::{RecordId, Ref};
use crate::state::state::State;

/// Update state with a single record + verdict pair.
/// On Accept, record enters accepted_records and appropriate fold runs.
/// On Reject, no state changes.
pub fn apply_record(
    state: &mut State,
    record: &Record,
    verdict: &VerdictData,
) -> Result<(), serde_json::Error> {
    match verdict.result {
        VerdictResult::Accept => apply_accepted(state, record),
        VerdictResult::Reject => Ok(()), // no state changes
    }
}

/// Apply an accepted record to state.
fn apply_accepted(state: &mut State, record: &Record) -> Result<(), serde_json::Error> {
    state.accepted_records.insert(record.id);

    // Epistemic dependence: index Use/Require refs so a later retraction can
    // taint this record, and inherit taint immediately when a target is
    // already retracted or tainted.
    let mut inherits_taint = false;
    for r in &record.refs {
        if matches!(r.type_, RefType::Use | RefType::Require) {
            state
                .epistemic_dependents
                .entry(r.target)
                .or_default()
                .insert(record.id);
            if state.retracted_records.contains(&r.target)
                || state.tainted_records.contains(&r.target)
            {
                inherits_taint = true;
            }
        }
    }
    if inherits_taint {
        mark_tainted(state, record.id);
    }

    match record.kind {
        Kind::Request => {
            state.active_requests.insert(record.id);
        }
        Kind::Action => {
            let data: ActionData = decode(&record.data)?;
            // Exact approvals are single-use: an accepted action that was
            // authorized by one (it Require-refs the approval its exact
            // hash resolves to) consumes it. Class approvals stay
            // reusable - that is their explicit purpose.
            let exact_hash = sha256_canonical(&(&record.author.id, &data))?;
            if let Some(&approval_id) = state.valid_approvals.get(&exact_hash) {
                if record
                    .refs
                    .iter()
                    .any(|r| matches!(r.type_, RefType::Require) && r.target == approval_id)
                {
                    state.valid_approvals.remove(&exact_hash);
                    state.exact_approval_index.remove(&approval_id);
                }
            }
            state.open_actions.insert(record.id);
            state.action_to_request.insert(record.id, data.request_id);
            *state
                .request_open_action_count
                .entry(data.request_id)
                .or_insert(0) += 1;
        }
        Kind::Result => {
            let data: ResultData = decode(&record.data)?;
            state.open_actions.remove(&data.action_id);
            close_action_for_request(state, &data.action_id);
        }
        Kind::Refusal => {
            let data: RefusalData = decode(&record.data)?;
            match data.target_kind {
                RefusalTarget::Action => {
                    state.open_actions.remove(&data.target_id);
                    close_action_for_request(state, &data.target_id);
                }
                RefusalTarget::Request => {
                    state.active_requests.remove(&data.target_id);
                    // Also clean up any active plan for this request.
                    state.active_plans.remove(&data.target_id);
                }
                RefusalTarget::VerifiedEffect => {
                    // Verified-effect failures do not automatically close the request or action;
                    // the host decides retry/skip/stop after surfacing the failure.
                }
            }
        }
        Kind::Capability => {
            let data: CapabilityData = decode(&record.data)?;
            let key = (data.actor_id, data.action_class, data.scope);
            if let Some(replaced_id) = find_replace_ref(&record.refs) {
                state.replaced_records.insert(replaced_id);
            }
            state.capability_index.insert(record.id, key.clone());
            state.active_capabilities.insert(key, record.id);
        }
        Kind::Approval => {
            let data: ApprovalData = decode(&record.data)?;
            if let Some(replaced_id) = find_replace_ref(&record.refs) {
                state.replaced_records.insert(replaced_id);
            }
            // Exactly one of the two forms is set (the verifier enforces
            // this); each indexes into its own lookup map plus the reverse
            // index used for retraction-time deactivation.
            if let Some(target) = data.target_action {
                state.exact_approval_index.insert(record.id, target);
                state.valid_approvals.insert(target, record.id);
            }
            if let Some(action_class) = data.action_class {
                let key = (action_class, data.scope, data.actor_id);
                state.class_approval_index.insert(record.id, key.clone());
                state.class_approvals.insert(key, record.id);
            }
        }
        Kind::Summary => {
            let data: SummaryData = decode(&record.data)?;
            let key = sha256_canonical(&(&data.summary_type, &data.subject, &data.scope))?;
            if let Some(replaced_id) = find_replace_ref(&record.refs) {
                state.replaced_records.insert(replaced_id);
            }
            state.active_summaries.insert(key, record.id);
        }
        Kind::Usage => {
            let data: UsageData = decode(&record.data)?;
            let key = (data.used_record, data.role);
            let c = state.usage_counts.entry(key).or_default();
            match data.outcome {
                UsageOutcome::Done => c.done += 1,
                UsageOutcome::NotDone => c.not_done += 1,
                UsageOutcome::NoChange => c.no_change += 1,
            }
        }
        Kind::Plan => {
            let data: PlanData = decode(&record.data)?;
            if let Some(replaced_id) = find_replace_ref(&record.refs) {
                state.replaced_records.insert(replaced_id);
            }
            state.active_plans.insert(data.request_id, record.id);
            if matches!(data.status, PlanStatus::Completed | PlanStatus::Abandoned) {
                state.active_plans.remove(&data.request_id);
            }
        }
        Kind::Retraction => {
            let data: RetractionData = decode(&record.data)?;
            state.retracted_records.insert(data.target_id);
            // Everything epistemically downstream of the target is tainted.
            let dependents: Vec<RecordId> = state
                .epistemic_dependents
                .get(&data.target_id)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            for id in dependents {
                mark_tainted(state, id);
            }
            // Retracted authority is deactivated operationally, not just
            // epistemically: a grant whose content was wrong must stop
            // authorizing future actions. Only remove the active slot if it
            // still points at the retracted record (a replacement may have
            // taken the slot since).
            if let Some(key) = state.capability_index.get(&data.target_id) {
                if state.active_capabilities.get(key) == Some(&data.target_id) {
                    let key = key.clone();
                    state.active_capabilities.remove(&key);
                }
            }
            if let Some(hash) = state.exact_approval_index.get(&data.target_id) {
                if state.valid_approvals.get(hash) == Some(&data.target_id) {
                    let hash = *hash;
                    state.valid_approvals.remove(&hash);
                }
            }
            if let Some(key) = state.class_approval_index.get(&data.target_id) {
                if state.class_approvals.get(key) == Some(&data.target_id) {
                    let key = key.clone();
                    state.class_approvals.remove(&key);
                }
            }
        }
        Kind::Response => {
            let data: ResponseData = decode(&record.data)?;
            // Saturating: the verifier rejects a response once the counter
            // would pass u32::MAX (check_response), so saturation is
            // unreachable in a verified log; this just keeps the fold
            // arithmetically total.
            let turns = state.response_turns.entry(data.request_id).or_insert(0);
            *turns = turns.saturating_add(1);
            if data.closes_request {
                // The explicit terminal event for a request (the verifier
                // has already checked no actions are open).
                state.active_requests.remove(&data.request_id);
                state.active_plans.remove(&data.request_id);
            }
        }
        Kind::Verdict => {
            // Verdicts don't contribute to operational state
        }
    }
    Ok(())
}

/// Mark a record tainted and cascade through the epistemic-dependence index.
fn mark_tainted(state: &mut State, id: RecordId) {
    let mut stack = vec![id];
    while let Some(current) = stack.pop() {
        if !state.tainted_records.insert(current) {
            continue;
        }
        if let Some(dependents) = state.epistemic_dependents.get(&current) {
            stack.extend(dependents.iter().copied());
        }
    }
}

/// Returns the target of the first Replace ref in the list, if any.
pub fn find_replace_ref(refs: &[Ref]) -> Option<RecordId> {
    refs.iter()
        .find(|r| matches!(r.type_, RefType::Replace))
        .map(|r| r.target)
}

/// Decrement the request's open-action count. Reaching zero does NOT
/// complete the request: sequential workflows open further actions after
/// earlier ones close, so completion is only ever the explicit terminal
/// event (a closing Response or a request-targeting Refusal).
fn close_action_for_request(state: &mut State, action_id: &RecordId) {
    if let Some(request_id) = state.action_to_request.get(action_id).copied() {
        if let Some(count) = state.request_open_action_count.get_mut(&request_id) {
            *count -= 1;
            if *count == 0 {
                state.request_open_action_count.remove(&request_id);
            }
        }
    }
}
