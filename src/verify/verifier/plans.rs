use super::*;

pub(super) fn check_plan(record: &Record, prior: &Prior<'_>, state: &State) -> Option<ReasonCode> {
    let data: PlanData = dec!(&record.data, PlanData);

    // Must have exactly one Cause ref to an accepted active Request in same thread/space.
    let cause_refs: Vec<&Ref> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Cause)
        .collect();
    if cause_refs.len() != 1 {
        return Some(ReasonCode::RequestMissing);
    }
    let cause_id = cause_refs[0].target;
    if cause_id != data.request_id {
        return Some(ReasonCode::RequestMissing);
    }
    if !state.active_requests.contains(&data.request_id) {
        return Some(ReasonCode::RequestMissing);
    }
    let Some(request) = prior.find(data.request_id) else {
        return Some(ReasonCode::RequestMissing);
    };
    if request.thread != record.thread || request.space != record.space {
        return Some(ReasonCode::RequestMissing);
    }

    // At most one Replace ref; if present, target must be a prior Plan with same request_id.
    // (Replacement compatibility is already checked in check_replacement_compatibility above.)
    // Nothing additional needed here.

    // tasks must be non-empty.
    if data.tasks.is_empty() {
        return Some(ReasonCode::InvalidPayload);
    }

    // All task ids must be unique.
    let mut seen_ids: HashSet<&str> = HashSet::new();
    for task in &data.tasks {
        if !seen_ids.insert(task.id.as_str()) {
            return Some(ReasonCode::InvalidPayload);
        }
    }

    // All depends_on and inputs_from ids must exist in the task list.
    for task in &data.tasks {
        for dep_id in &task.depends_on {
            if !seen_ids.contains(dep_id.as_str()) {
                return Some(ReasonCode::InvalidPayload);
            }
        }
        for input_id in &task.inputs_from {
            if !seen_ids.contains(input_id.as_str()) {
                return Some(ReasonCode::InvalidPayload);
            }
        }
    }

    // Proof binding: a task's result_record_id, when present, must be real
    // proof - an accepted Result whose action belongs to this plan's
    // request - and only terminal-executed tasks (Done/Failed) may carry
    // one. A Completed plan can therefore never cite nonexistent or
    // foreign results.
    for task in &data.tasks {
        let Some(result_id) = task.result_record_id else {
            continue;
        };
        if !matches!(task.status, TaskStatus::Done | TaskStatus::Failed) {
            return Some(ReasonCode::InvalidPayload);
        }
        let Some(result_record) = prior.find(result_id) else {
            return Some(ReasonCode::InvalidPayload);
        };
        if result_record.kind != Kind::Result
            || !state.accepted_records.contains(&result_id)
            || result_record.thread != record.thread
            || result_record.space != record.space
        {
            return Some(ReasonCode::InvalidPayload);
        }
        let result_data: ResultData = dec!(&result_record.data, ResultData);
        let Some(action_record) = prior.find(result_data.action_id) else {
            return Some(ReasonCode::InvalidPayload);
        };
        let action_data: ActionData = dec!(&action_record.data, ActionData);
        if action_data.request_id != data.request_id {
            return Some(ReasonCode::InvalidPayload);
        }
    }

    // No cycles in depends_on (topological sort).
    if has_cycle(&data.tasks) {
        return Some(ReasonCode::InvalidPayload);
    }

    // Status consistency.
    let any_pending_or_running = data
        .tasks
        .iter()
        .any(|t| matches!(t.status, TaskStatus::Pending | TaskStatus::Running));
    let all_done = data.tasks.iter().all(|t| t.status == TaskStatus::Done);
    let all_terminal = data.tasks.iter().all(|t| {
        matches!(
            t.status,
            TaskStatus::Done | TaskStatus::Failed | TaskStatus::Skipped
        )
    });
    let any_failed_or_skipped = data
        .tasks
        .iter()
        .any(|t| matches!(t.status, TaskStatus::Failed | TaskStatus::Skipped));

    match data.status {
        PlanStatus::Running => {
            if !any_pending_or_running {
                return Some(ReasonCode::InvalidPayload);
            }
        }
        PlanStatus::Completed => {
            if !all_done {
                return Some(ReasonCode::InvalidPayload);
            }
        }
        PlanStatus::Abandoned => {
            if !all_terminal || !any_failed_or_skipped {
                return Some(ReasonCode::InvalidPayload);
            }
        }
    }

    None
}

/// Detect cycles in depends_on using DFS (Kahn's algorithm).
pub(super) fn has_cycle(tasks: &[PlanTask]) -> bool {
    use std::collections::HashMap;

    let n = tasks.len();
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

    for task in tasks {
        in_degree.entry(task.id.as_str()).or_insert(0);
        adj.entry(task.id.as_str()).or_default();
        for dep in &task.depends_on {
            // dep -> task.id edge
            *in_degree.entry(task.id.as_str()).or_insert(0) += 1;
            adj.entry(dep.as_str()).or_default().push(task.id.as_str());
        }
    }

    let mut queue: std::collections::VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut visited = 0usize;
    while let Some(id) = queue.pop_front() {
        visited += 1;
        if let Some(neighbors) = adj.get(id) {
            for &nb in neighbors {
                if let Some(d) = in_degree.get_mut(nb) {
                    *d -= 1;
                    if *d == 0 {
                        queue.push_back(nb);
                    }
                }
            }
        }
    }

    visited != n
}

/// Retraction checks.
pub(super) fn check_retraction(
    record: &Record,
    prior: &Prior<'_>,
    rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    let data: RetractionData = dec!(&record.data, RetractionData);

    // Must include exactly one Cause ref to target_id (so generic ref checks
    // have already resolved it in the same space).
    let cause_refs: Vec<&Ref> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Cause)
        .collect();
    if cause_refs.len() != 1 || cause_refs[0].target != data.target_id {
        return Some(ReasonCode::InvalidPayload);
    }

    // The Cause ref already resolved the target in the generic ref checks;
    // a miss here is a rejection, never a pass.
    let Some(target) = prior.find(data.target_id) else {
        return Some(ReasonCode::RefUnresolved);
    };

    // Only accepted records can be retracted - a rejected record never made
    // any claim to retract.
    if !state.accepted_records.contains(&data.target_id) {
        return Some(ReasonCode::InvalidPayload);
    }

    // Verdicts are the verifier's own deterministic output, and retracting a
    // retraction would un-assert wrongness; both are excluded.
    if matches!(target.kind, Kind::Verdict | Kind::Retraction) {
        return Some(ReasonCode::InvalidPayload);
    }

    // Retraction is ownership-bound: an author retracts its own records.
    // Anything else - one actor declaring another's record wrong - is
    // contrary evidence or a Refusal, unless the retractor is an
    // explicitly configured administrator (e.g. the human principal),
    // because retraction has operational teeth (authority deactivation).
    if record.author.id != target.author.id
        && !rules.admin_retraction_actors.contains(&record.author.id)
    {
        return Some(ReasonCode::AuthorRoleInvalid);
    }

    None
}

/// Approval structural check.
pub(super) fn check_approval(record: &Record) -> Option<ReasonCode> {
    let data: ApprovalData = dec!(&record.data, ApprovalData);

    // Exactly one of target_action (exact form) or action_class (class
    // form): an approval authorizes one thing. Carrying both would
    // silently broaden one human authorization into two.
    if data.target_action.is_some() == data.action_class.is_some() {
        return Some(ReasonCode::InvalidPayload);
    }

    // The exact form authorizes one actor's one action, so it must name
    // that actor (the target hash also binds it; the explicit field keeps
    // the approval auditable without reversing a hash).
    if data.target_action.is_some() && data.actor_id.is_none() {
        return Some(ReasonCode::InvalidPayload);
    }

    None
}

// Verify verdict records specifically (rules from §4.2 verify_record for
// verdict records). Verdicts take this path instead of the generic
// `check_record` checks, so the envelope must be re-verified here in
// full: a forged log can put anything in a verdict record.
