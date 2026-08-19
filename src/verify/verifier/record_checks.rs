use super::*;

/// Verify a single non-verdict record against its prior committed prefix and derived state.
/// Returns the VerdictData that should be committed as the verdict record.
pub fn verify_record(
    record: &Record,
    prior: &[Record],
    rules: &VerifierRules,
    state: &State,
) -> VerdictData {
    // One-off index over the prior slice: costs a single O(prior) pass,
    // after which every lookup during this record's checks is O(1).
    // `verify_log` grows its index incrementally instead of calling this
    // wrapper, keeping full-log replay linear.
    let index = PriorIndex::of(prior);
    let prior = index.view(prior);
    if let Some(reason) = check_record(record, &prior, rules, state) {
        VerdictData {
            result: VerdictResult::Reject,
            reason: Some(reason),
        }
    } else {
        VerdictData {
            result: VerdictResult::Accept,
            reason: None,
        }
    }
}

/// Internal: returns Some(ReasonCode) if record should be rejected, None if accepted.
pub(super) fn check_record(
    record: &Record,
    prior: &Prior<'_>,
    rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    // For verdict records, use special verification
    if record.kind == Kind::Verdict {
        return check_verdict_record(record, prior, rules);
    }

    // Structural validity: id must match the canonical id form
    let computed_id = match record.compute_id() {
        Ok(id) => id,
        Err(_) => return Some(ReasonCode::InvalidPayload),
    };
    if record.id != computed_id {
        return Some(ReasonCode::InvalidPayload);
    }

    // Refs must be strictly sorted by (type ordinal, target) and
    // deduplicated, so identical content always hashes to the same id.
    if !record
        .refs
        .windows(2)
        .all(|w| (w[0].type_ as u8, &w[0].target) < (w[1].type_ as u8, &w[1].target))
    {
        return Some(ReasonCode::InvalidPayload);
    }

    // Space must match
    if record.space != rules.space {
        return Some(ReasonCode::InvalidPayload);
    }

    // Schema must be in kind_schema_map
    let expected_kind = match rules.kind_schema_map.get(&record.schema) {
        Some(k) => *k,
        None => return Some(ReasonCode::UnknownSchema),
    };
    if record.kind != expected_kind {
        return Some(ReasonCode::KindSchemaMismatch);
    }

    // Author role must be allowed for this kind (the normative table,
    // SPEC §2). Signatures cannot substitute: a validly signed actor can
    // still declare a forbidden author type or emit a forbidden kind.
    if !allowed_author_types(record.kind).contains(&record.author.type_) {
        return Some(ReasonCode::AuthorRoleInvalid);
    }

    // Identity-to-role binding: the declared `author.type` is
    // adversary-controlled (a governed agent could simply *claim* User on
    // an Approval), so a registered actor must declare exactly its
    // configured role on every kind, and authority-bearing/work-bearing
    // kinds require the actor to be registered at all.
    match rules.author_roles.get(&record.author.id) {
        Some(role) => {
            if record.author.type_ != *role {
                return Some(ReasonCode::AuthorRoleInvalid);
            }
        }
        None => {
            if requires_registered_author(record.kind) {
                return Some(ReasonCode::AuthorRoleInvalid);
            }
        }
    }

    // Signature checks: a required-but-absent signature is
    // SignatureMissing; any present signature - required or not - must
    // verify (Ed25519 over the domain-separated canonical signing form,
    // strict verification),
    // and when rules pin keys for this actor, the signing key must be one
    // of them. A key-pinned actor's records ALWAYS require a signature:
    // `author.id` is otherwise just a string anyone can write, so an
    // unsigned record claiming a pinned identity would bypass exactly the
    // authentication the pinning exists to provide.
    let sig_required = rules.signature_required_kinds.contains(&record.kind)
        || rules.author_keys.contains_key(&record.author.id);
    if sig_required && record.author.signature.is_none() {
        return Some(ReasonCode::SignatureMissing);
    }
    if record.author.signature.is_some() {
        match crate::record::sign::verified_key(record) {
            None => return Some(ReasonCode::SignatureInvalid),
            Some(key) => {
                if let Some(allowed) = rules.author_keys.get(&record.author.id) {
                    if !allowed.contains(&key) {
                        return Some(ReasonCode::SignatureInvalid);
                    }
                }
            }
        }
    }

    // Refs resolve to prior committed records in same space. `Require`
    // means "the target must be accepted state" (SPEC §2): a rejected,
    // retracted, or tainted target cannot satisfy a Require ref, for any
    // kind. (`Use` of such a record stays legal - an actor may genuinely
    // have consumed bad input - but contributes floor evidence, §7.)
    for r in &record.refs {
        let target = prior.find(r.target);
        match target {
            None => return Some(ReasonCode::RefUnresolved),
            Some(t) => {
                if t.space != record.space {
                    return Some(ReasonCode::RefCrossSpace);
                }
                if r.type_ == RefType::Require
                    && (!state.accepted_records.contains(&t.id)
                        || state.retracted_records.contains(&t.id)
                        || state.tainted_records.contains(&t.id))
                {
                    return Some(ReasonCode::RefUnresolved);
                }
            }
        }
    }

    // Replacement checks
    let replace_refs: Vec<&Ref> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Replace)
        .collect();

    if replace_refs.len() > 1 {
        return Some(ReasonCode::InvalidPayload);
    }

    if let Some(replace_ref) = replace_refs.first() {
        // Replace only on Summary, Capability, Approval, Plan
        match record.kind {
            Kind::Summary | Kind::Capability | Kind::Approval | Kind::Plan => {}
            _ => return Some(ReasonCode::ReplacementInvalid),
        }

        // Target must be prior accepted record of same kind
        let target = prior.find(replace_ref.target);
        match target {
            None => return Some(ReasonCode::ReplacementInvalid),
            Some(t) => {
                if !state.accepted_records.contains(&t.id) {
                    return Some(ReasonCode::ReplacementInvalid);
                }
                if t.kind != record.kind {
                    return Some(ReasonCode::ReplacementInvalid);
                }

                // Compatibility checks
                if let Some(reason) = check_replacement_compatibility(record, t) {
                    return Some(reason);
                }
            }
        }
    }

    // Evidence must match derived. Only epistemic refs (`Use`/`Require`)
    // contribute, degraded to the floor when their target is
    // retracted/tainted; `Cause`/`Replace` refs are provenance and do not
    // participate (State::ref_evidence returns None for them, SPEC §7).
    let ref_evidences: Vec<Evidence> = record
        .refs
        .iter()
        .filter_map(|r| prior.find(r.target).and_then(|t| state.ref_evidence(r, t)))
        .collect();
    let expected_evidence = derive_evidence(&record.schema, &ref_evidences);
    if record.evidence != expected_evidence {
        return Some(ReasonCode::InvalidPayload);
    }

    // Evidence threshold: derived evidence weaker than the configured
    // minimum for this kind rejects the record. Evidence orders strongest →
    // weakest, so "weaker" is Ord-greater.
    if let Some(threshold) = rules.evidence_thresholds.get(&record.kind) {
        if expected_evidence > *threshold {
            return Some(ReasonCode::EvidenceBelowThreshold);
        }
    }

    // Payload must decode correctly
    if let Some(reason) = check_payload_decode(record) {
        return Some(reason);
    }

    // Kind-specific checks
    check_kind_specific(record, prior, rules, state)
}

/// Check replacement compatibility based on kind.
fn check_replacement_compatibility(record: &Record, target: &Record) -> Option<ReasonCode> {
    match record.kind {
        Kind::Capability => {
            let new_data: CapabilityData = dec!(&record.data, CapabilityData);
            let old_data: CapabilityData = dec!(&target.data, CapabilityData);
            // identical (actor_id, action_class, scope)
            if new_data.actor_id != old_data.actor_id
                || new_data.action_class != old_data.action_class
                || new_data.scope != old_data.scope
            {
                return Some(ReasonCode::ReplacementInvalid);
            }
        }
        Kind::Approval => {
            let new_data: ApprovalData = dec!(&record.data, ApprovalData);
            let old_data: ApprovalData = dec!(&target.data, ApprovalData);
            // For exact approvals, identical (scope, target_action)
            // For class approvals, identical (action_class, scope, actor_id)
            if new_data.target_action.is_some() && old_data.target_action.is_some() {
                if new_data.scope != old_data.scope
                    || new_data.target_action != old_data.target_action
                {
                    return Some(ReasonCode::ReplacementInvalid);
                }
            } else if new_data.action_class.is_some() && old_data.action_class.is_some() {
                if new_data.action_class != old_data.action_class
                    || new_data.scope != old_data.scope
                    || new_data.actor_id != old_data.actor_id
                {
                    return Some(ReasonCode::ReplacementInvalid);
                }
            } else {
                return Some(ReasonCode::ReplacementInvalid);
            }
        }
        Kind::Summary => {
            let new_data: SummaryData = dec!(&record.data, SummaryData);
            let old_data: SummaryData = dec!(&target.data, SummaryData);
            // identical (summary_type, subject, scope)
            if new_data.summary_type != old_data.summary_type
                || new_data.subject != old_data.subject
                || new_data.scope != old_data.scope
            {
                return Some(ReasonCode::ReplacementInvalid);
            }
        }
        Kind::Plan => {
            let new_data: PlanData = dec!(&record.data, PlanData);
            let old_data: PlanData = dec!(&target.data, PlanData);
            // Plan replacement: must target a prior Plan with same request_id
            if new_data.request_id != old_data.request_id {
                return Some(ReasonCode::ReplacementInvalid);
            }
        }
        _ => {}
    }
    None
}

/// Canonical payload rule (SPEC §3): `data` must be exactly the JCS
/// canonical serialization of the schema's payload type. The payload is
/// decoded and re-encoded, and the bytes must match - which uniformly
/// rejects duplicate keys, unknown fields, non-canonical key order,
/// whitespace, and non-canonical number spellings, so independent
/// verifiers cannot diverge on permissive-parsing behavior.
pub(super) fn decodes_canonically<T: serde::de::DeserializeOwned + serde::Serialize>(
    data: &[u8],
) -> bool {
    match serde_json::from_slice::<T>(data) {
        Ok(value) => match crate::base::canonical::canonical_json(&value) {
            Ok(reencoded) => reencoded == data,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// Check that the payload is the canonical serialization for the record's
/// schema (see [`decodes_canonically`]).
fn check_payload_decode(record: &Record) -> Option<ReasonCode> {
    let schema = record.schema;
    let ok = match () {
        _ if schema == schema_id(SCHEMA_REQUEST) => {
            decodes_canonically::<RequestData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_ACTION) => decodes_canonically::<ActionData>(&record.data),
        _ if schema == schema_id(SCHEMA_RESPONSE) => {
            decodes_canonically::<ResponseData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_RESULT)
            || schema == schema_id(SCHEMA_RESULT_EXTERNAL)
            || schema == schema_id(SCHEMA_RESULT_EFFECT_CONFIRMATION) =>
        {
            decodes_canonically::<ResultData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_CAPABILITY) => {
            decodes_canonically::<CapabilityData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_APPROVAL) => {
            decodes_canonically::<ApprovalData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_SUMMARY) => {
            decodes_canonically::<SummaryData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_REFUSAL) => {
            decodes_canonically::<RefusalData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_USAGE) => decodes_canonically::<UsageData>(&record.data),
        _ if schema == schema_id(SCHEMA_VERDICT) => {
            decodes_canonically::<VerdictData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_PLAN) => decodes_canonically::<PlanData>(&record.data),
        _ if schema == schema_id(SCHEMA_RETRACTION) => {
            decodes_canonically::<RetractionData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_CANDIDATE) => {
            decodes_canonically::<CandidateData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_EVALUATION) => {
            decodes_canonically::<EvaluationData>(&record.data)
        }
        _ if schema == schema_id(SCHEMA_SELECTION) => {
            decodes_canonically::<SelectionData>(&record.data)
        }
        _ => return Some(ReasonCode::UnknownSchema),
    };
    if ok {
        None
    } else {
        Some(ReasonCode::InvalidPayload)
    }
}

// Kind-specific verification rules.
