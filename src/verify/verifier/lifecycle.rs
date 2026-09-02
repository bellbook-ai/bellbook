use super::*;

pub(super) fn check_result(
    record: &Record,
    prior: &Prior<'_>,
    rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    let data: ResultData = dec!(&record.data, ResultData);

    // Artifact identities (spec 0.4): each well-formed, the list strictly
    // ordered and deduplicated.
    if let Some(artifacts) = &data.artifacts {
        if !artifact_refs_well_formed(artifacts) {
            return Some(ReasonCode::ArtifactRefInvalid);
        }
    }

    // Must reference an open action in same thread/space
    if !state.open_actions.contains(&data.action_id) {
        return Some(ReasonCode::ActionClosed);
    }

    let Some(action) = prior.find(data.action_id) else {
        return Some(ReasonCode::ActionClosed);
    };
    if action.thread != record.thread || action.space != record.space {
        return Some(ReasonCode::ActionClosed);
    }

    let action_data: ActionData = dec!(&action.data, ActionData);

    // Schema must match exec mode
    let external_schema = schema_id(SCHEMA_RESULT_EXTERNAL);

    match action_data.exec_mode {
        ExecMode::External => {
            if record.schema != external_schema {
                return Some(ReasonCode::ExternalReceiptRequired);
            }
            // `Verified` evidence is earned, never asserted: an external
            // result is Verified because it is a signed attestation from a
            // key-bound executor. It must carry a signature (verified
            // strictly by the generic checks above) and its author must
            // have pinned keys in `author_keys` - otherwise the signature
            // proves key possession, not executor identity, which is the
            // Reported class, and the record rejects.
            if record.author.signature.is_none() {
                return Some(ReasonCode::SignatureMissing);
            }
            if !rules.author_keys.contains_key(&record.author.id) {
                return Some(ReasonCode::SignatureInvalid);
            }
        }
        ExecMode::Internal => {
            if record.schema == external_schema {
                return Some(ReasonCode::InvalidPayload);
            }
        }
    }

    // Must include exactly one Cause ref to action_id
    let cause_refs: Vec<&Ref> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Cause)
        .collect();
    if cause_refs.len() != 1 || cause_refs[0].target != data.action_id {
        return Some(ReasonCode::InvalidPayload);
    }

    None
}

/// Refusal checks.
pub(super) fn check_refusal(
    record: &Record,
    prior: &Prior<'_>,
    state: &State,
) -> Option<ReasonCode> {
    let data: RefusalData = dec!(&record.data, RefusalData);

    let target = prior.find(data.target_id);
    match target {
        None => return Some(ReasonCode::RequestMissing),
        Some(t) => {
            // target_kind must match actual kind
            match data.target_kind {
                RefusalTarget::Action => {
                    if t.kind != Kind::Action {
                        return Some(ReasonCode::InvalidPayload);
                    }
                    // Must be open action in same thread/space
                    if !state.open_actions.contains(&data.target_id) {
                        return Some(ReasonCode::ActionClosed);
                    }
                    if t.thread != record.thread || t.space != record.space {
                        return Some(ReasonCode::ActionClosed);
                    }
                }
                RefusalTarget::Request => {
                    if t.kind != Kind::Request {
                        return Some(ReasonCode::InvalidPayload);
                    }
                    // Must be active request in same thread/space
                    if !state.active_requests.contains(&data.target_id) {
                        return Some(ReasonCode::RequestMissing);
                    }
                    if t.thread != record.thread || t.space != record.space {
                        return Some(ReasonCode::RequestMissing);
                    }
                }
                RefusalTarget::VerifiedEffect => {
                    if t.kind != Kind::Result
                        || t.schema != schema_id(SCHEMA_RESULT_EFFECT_CONFIRMATION)
                    {
                        return Some(ReasonCode::InvalidPayload);
                    }
                    if !state.accepted_records.contains(&data.target_id) {
                        return Some(ReasonCode::InvalidPayload);
                    }
                    if t.thread != record.thread || t.space != record.space {
                        return Some(ReasonCode::InvalidPayload);
                    }
                }
            }
        }
    }

    // Must include exactly one Cause ref to target_id
    let cause_refs: Vec<&Ref> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Cause)
        .collect();
    if cause_refs.len() != 1 || cause_refs[0].target != data.target_id {
        return Some(ReasonCode::InvalidPayload);
    }

    None
}

/// Usage checks.
pub(super) fn check_usage(record: &Record, prior: &Prior<'_>, state: &State) -> Option<ReasonCode> {
    let data: UsageData = dec!(&record.data, UsageData);

    // The payload's actor must be the envelope author: usage feedback is
    // attributed, and a record cannot report usage on another actor's
    // behalf.
    if data.actor != record.author.id {
        return Some(ReasonCode::InvalidPayload);
    }

    // used_record must resolve
    if prior.find(data.used_record).is_none() {
        return Some(ReasonCode::InvalidPayload);
    }

    // consuming_record must resolve
    let consuming = match prior.find(data.consuming_record) {
        None => return Some(ReasonCode::InvalidPayload),
        Some(r) => r,
    };

    // consuming_record must be accepted Result or Refusal in the same
    // thread as the usage report.
    if !state.accepted_records.contains(&data.consuming_record) {
        return Some(ReasonCode::InvalidPayload);
    }
    if consuming.kind != Kind::Result && consuming.kind != Kind::Refusal {
        return Some(ReasonCode::InvalidPayload);
    }
    if consuming.thread != record.thread {
        return Some(ReasonCode::InvalidPayload);
    }

    // Must include one Use ref to used_record
    let use_refs: Vec<&Ref> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Use)
        .collect();
    if use_refs.len() != 1 || use_refs[0].target != data.used_record {
        return Some(ReasonCode::InvalidPayload);
    }

    None
}

/// Summary checks.
pub(super) fn check_summary(record: &Record, rules: &VerifierRules) -> Option<ReasonCode> {
    let data: SummaryData = dec!(&record.data, SummaryData);

    // summary_type must be in allowed_summary_types
    if !rules.allowed_summary_types.contains(&data.summary_type) {
        return Some(ReasonCode::InvalidPayload);
    }

    // A summary *rests on* its sources, so it must say so with `Use` refs
    // (epistemic dependence): its evidence derives from the weakest source
    // and retraction of a source taints it. A summary with no sources at
    // all would be an unfounded claim.
    let use_count = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Use)
        .count();
    if use_count == 0 {
        return Some(ReasonCode::InvalidPayload);
    }

    None
}

/// Response checks.
pub(super) fn check_response(
    record: &Record,
    prior: &Prior<'_>,
    state: &State,
) -> Option<ReasonCode> {
    let data: ResponseData = dec!(&record.data, ResponseData);

    // request_id must resolve to accepted active request in same
    // thread/space. The prior-log lookup is mandatory, not best-effort: a
    // fabricated State containing a nonexistent request id must not let a
    // Response for that phantom request be accepted.
    if !state.active_requests.contains(&data.request_id) {
        return Some(ReasonCode::RequestMissing);
    }
    let Some(request) = prior.find(data.request_id) else {
        return Some(ReasonCode::RequestMissing);
    };
    if request.thread != record.thread || request.space != record.space {
        return Some(ReasonCode::RequestMissing);
    }

    // Turns are gap-free and in order: turn_index must equal the count of
    // previously accepted responses for this request, so a conversation
    // cannot be silently reordered or have turns dropped. The counter's
    // ceiling is a hard stop: at u32::MAX prior responses no further
    // response is accepted (a saturated counter must never let one
    // turn_index be accepted twice).
    let expected_turn = state
        .response_turns
        .get(&data.request_id)
        .copied()
        .unwrap_or(0);
    if expected_turn == u32::MAX || data.turn_index != expected_turn {
        return Some(ReasonCode::InvalidPayload);
    }

    // A closing response is the request's explicit terminal event; it is
    // only coherent when no actions remain open and no plan is still
    // running (a plan must reach Completed or Abandoned first - a final
    // response must not silently strand in-flight work).
    if data.closes_request {
        if state
            .request_open_action_count
            .get(&data.request_id)
            .copied()
            .unwrap_or(0)
            > 0
        {
            return Some(ReasonCode::InvalidPayload);
        }
        if state.active_plans.contains_key(&data.request_id) {
            return Some(ReasonCode::InvalidPayload);
        }
    }

    None
}

// Plan checks.
