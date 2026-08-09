use super::*;

pub(super) fn check_kind_specific(
    record: &Record,
    prior: &Prior<'_>,
    rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    match record.kind {
        Kind::Request => check_request(record, prior, state),
        Kind::Action => check_action(record, prior, state),
        Kind::Result => check_result(record, prior, rules, state),
        Kind::Refusal => check_refusal(record, prior, state),
        Kind::Usage => check_usage(record, prior, state),
        Kind::Summary => check_summary(record, rules),
        Kind::Response => check_response(record, prior, state),
        Kind::Approval => check_approval(record),
        Kind::Plan => check_plan(record, prior, state),
        Kind::Retraction => check_retraction(record, prior, rules, state),
        // No kind-specific rules beyond the structural and replacement
        // checks above.
        Kind::Capability => None,
        // Verdicts take the check_verdict_record path before this match.
        Kind::Verdict => None,
    }
}

/// Request checks - delegated child requests must link to parent via `Cause` refs.
pub(super) fn check_request(
    record: &Record,
    prior: &Prior<'_>,
    state: &State,
) -> Option<ReasonCode> {
    let data: RequestData = dec!(&record.data, RequestData);
    let cause_targets: Vec<RecordId> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Cause)
        .map(|r| r.target)
        .collect();

    for target_id in &cause_targets {
        // Cause targets are refs, so the generic ref checks already
        // resolved them; a miss here is a rejection, never a pass.
        let Some(parent) = prior.find(*target_id) else {
            return Some(ReasonCode::RefUnresolved);
        };
        if parent.kind != Kind::Request {
            return Some(ReasonCode::InvalidPayload);
        }
        if parent.thread != record.thread {
            return Some(ReasonCode::InvalidPayload);
        }
        if !state.accepted_records.contains(target_id) {
            return Some(ReasonCode::RequestMissing);
        }
    }

    // Parentage is unambiguous: the declared parent and the Cause edges
    // must state the same delegation graph. No parent means zero Request
    // Cause refs; a declared parent means exactly one Cause ref, naming
    // exactly that parent - no undeclared or surplus parents.
    match data.parent_request_id {
        None => {
            if !cause_targets.is_empty() {
                return Some(ReasonCode::InvalidPayload);
            }
        }
        Some(pid) => {
            if cause_targets.len() != 1 || cause_targets[0] != pid {
                return Some(ReasonCode::InvalidPayload);
            }
        }
    }

    None
}

/// Action checks.
pub(super) fn check_action(
    record: &Record,
    prior: &Prior<'_>,
    state: &State,
) -> Option<ReasonCode> {
    let data: ActionData = dec!(&record.data, ActionData);

    // request_id must resolve to accepted active request in same thread/space
    if !state.active_requests.contains(&data.request_id) {
        return Some(ReasonCode::RequestMissing);
    }
    let Some(request) = prior.find(data.request_id) else {
        return Some(ReasonCode::RequestMissing);
    };
    if request.thread != record.thread || request.space != record.space {
        return Some(ReasonCode::RequestMissing);
    }

    // The action must operate in the request's scope: a capability held
    // for some other scope must not let a provider serve a scope-A
    // request with scope-B actions.
    let request_data: RequestData = dec!(&request.data, RequestData);
    if data.scope != request_data.scope {
        return Some(ReasonCode::InvalidPayload);
    }

    // Requires effective capability
    let cap_record_id = state.active_capabilities.get(&(
        record.author.id.clone(),
        data.action_class.clone(),
        data.scope,
    ));

    match cap_record_id {
        None => return Some(ReasonCode::CapabilityMissing),
        Some(&cap_id) => {
            let Some(cap_record) = prior.find(cap_id) else {
                return Some(ReasonCode::CapabilityMissing);
            };

            // Retracted or tainted authority never authorizes: its content
            // was asserted wrong (or rests on something that was), so
            // governance and epistemic state must agree.
            if state.retracted_records.contains(&cap_id) || state.tainted_records.contains(&cap_id)
            {
                return Some(ReasonCode::CapabilityMissing);
            }

            let cap_data: CapabilityData = dec!(&cap_record.data, CapabilityData);

            // Check expiry
            if let Some(expiry) = cap_data.expiry {
                if record.time >= expiry {
                    return Some(ReasonCode::CapabilityMissing);
                }
            }

            // Resolve the full authority chain first (so a missing or
            // expired approval reports its own precise reason), then
            // require the audit graph to show that authority: `Require`
            // refs naming the exact capability - and approval, for Ask
            // mode - are mandatory, so a later retraction of the authority
            // taints the action through the dependence index.
            let approval_id = match cap_data.mode {
                // Deny rejects
                CapabilityMode::Deny => return Some(ReasonCode::CapabilityDenied),
                // Auto allows without approval
                CapabilityMode::Auto => None,
                // Ask requires approval
                CapabilityMode::Ask => {
                    match check_approval_for_action(record, &data, prior, state) {
                        Err(reason) => return Some(reason),
                        Ok(approval_id) => Some(approval_id),
                    }
                }
            };
            if !has_require_ref(record, cap_id) {
                return Some(ReasonCode::AuthorityRefMissing);
            }
            if let Some(approval_id) = approval_id {
                if !has_require_ref(record, approval_id) {
                    return Some(ReasonCode::AuthorityRefMissing);
                }
            }
        }
    }

    None
}

/// Whether the record carries a `Require` ref to `target`.
pub(super) fn has_require_ref(record: &Record, target: RecordId) -> bool {
    record
        .refs
        .iter()
        .any(|r| r.type_ == RefType::Require && r.target == target)
}

/// Check approval resolution for Ask mode actions. Ok carries the id of
/// the approval that resolved (the caller requires a `Require` ref naming
/// exactly it); Err is the rejection reason. Retracted or tainted
/// approvals never authorize - they are skipped as if absent.
pub(super) fn check_approval_for_action(
    record: &Record,
    data: &ActionData,
    prior: &Prior<'_>,
    state: &State,
) -> Result<RecordId, ReasonCode> {
    // The exact-approval target binds the acting author together with the
    // action content: SHA-256(canonical((action_author_id, ActionData))).
    // Hashing ActionData alone would let a different Provider (or the
    // same one, repeatedly) reuse an approval granted for one specific
    // actor's one specific action.
    let action_hash = match sha256_canonical(&(&record.author.id, data)) {
        Ok(h) => h,
        Err(_) => return Err(ReasonCode::InvalidPayload),
    };

    let usable = |approval_id: RecordId| -> bool {
        state.accepted_records.contains(&approval_id)
            && !state.retracted_records.contains(&approval_id)
            && !state.tainted_records.contains(&approval_id)
    };

    // Priority 1: Exact match (single-use: an accepted action consumes
    // it, removing it from `valid_approvals` - see the incremental state
    // apply).
    if let Some(&approval_id) = state.valid_approvals.get(&action_hash) {
        if let Some(approval_record) = prior.find(approval_id) {
            if usable(approval_id) {
                let approval_data: ApprovalData =
                    match decode::<ApprovalData>(&approval_record.data) {
                        Ok(v) => v,
                        Err(_) => return Err(ReasonCode::InvalidPayload),
                    };
                // The approval's declared subject actor and scope must
                // match the action (the hash already binds both; a
                // mismatched declaration is malformed and unusable -
                // an approval must not visibly claim one scope while
                // authorizing another through its hash).
                if approval_data.actor_id.as_deref() == Some(record.author.id.as_str())
                    && approval_data.scope == data.scope
                {
                    match approval_data.expiry {
                        // Expired exact approval falls through to class match.
                        Some(expiry) if record.time >= expiry => {}
                        // Valid exact approval.
                        _ => return Ok(approval_id),
                    }
                }
            }
        }
    }

    // Priority 2: Class match with specific actor
    let class_key = (
        data.action_class.clone(),
        data.scope,
        Some(record.author.id.clone()),
    );
    if let Some(&approval_id) = state.class_approvals.get(&class_key) {
        if let Some(approval_record) = prior.find(approval_id) {
            if usable(approval_id) {
                let approval_data: ApprovalData =
                    match decode::<ApprovalData>(&approval_record.data) {
                        Ok(v) => v,
                        Err(_) => return Err(ReasonCode::InvalidPayload),
                    };
                if let Some(expiry) = approval_data.expiry {
                    if record.time >= expiry {
                        return Err(ReasonCode::ApprovalExpired);
                    }
                }
                return Ok(approval_id); // Valid class approval
            }
        }
    }

    // Priority 3: Class wildcard match
    let wildcard_key = (data.action_class.clone(), data.scope, None);
    if let Some(&approval_id) = state.class_approvals.get(&wildcard_key) {
        if let Some(approval_record) = prior.find(approval_id) {
            if usable(approval_id) {
                let approval_data: ApprovalData =
                    match decode::<ApprovalData>(&approval_record.data) {
                        Ok(v) => v,
                        Err(_) => return Err(ReasonCode::InvalidPayload),
                    };
                if let Some(expiry) = approval_data.expiry {
                    if record.time >= expiry {
                        return Err(ReasonCode::ApprovalExpired);
                    }
                }
                return Ok(approval_id); // Valid class wildcard approval
            }
        }
    }

    Err(ReasonCode::ApprovalMissing)
}

// Result checks.
