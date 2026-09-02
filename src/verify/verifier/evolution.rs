//! Per-kind verification rules for the evolution kinds (spec 0.3, delta D3
//! and D4): `Candidate`, `Evaluation`, and `Selection`.
//!
//! These run after the generic structural checks (id, refs, author role,
//! evidence, canonical payload) in `check_record`, so everything below may
//! assume the payload decoded and every ref resolved to a prior record in
//! the same space. Lineage edges that are *payload ids* rather than refs
//! (`CandidateData.parent`, `SelectionData.considered`,
//! `EvaluationData.candidate`) are resolved here, since the generic ref
//! machinery never sees them.

use super::*;
use std::collections::BTreeSet;

/// Hex length of a Git OID under each object format.
fn oid_hex_len(algo: SourceAlgo) -> usize {
    match algo {
        SourceAlgo::Sha1 => 40,
        SourceAlgo::Sha256 => 64,
    }
}

/// Whether `s` is exactly `len` lowercase-hex characters. Git OIDs are
/// canonically lowercase hex; requiring that keeps the two implementations'
/// decision byte-identical on any input (an uppercase or short OID rejects
/// in both).
fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether a `SourceBinding` is well-formed: `tree` (and `commit`, if
/// present) are lowercase-hex of the length its `algo` dictates, and
/// `manifest_hash` is present exactly when `binding == Manifest`.
fn source_binding_well_formed(sb: &SourceBinding) -> bool {
    let len = oid_hex_len(sb.git.algo);
    if !is_lower_hex(&sb.git.tree, len) {
        return false;
    }
    if let Some(commit) = &sb.git.commit {
        if !is_lower_hex(commit, len) {
            return false;
        }
    }
    sb.manifest_hash.is_some() == (sb.binding == BindingMode::Manifest)
}

/// Resolve a lineage payload id to a prior accepted `Candidate` in the same
/// space (the shared payload-id rule, delta D3). Retracted or tainted
/// targets still resolve: those conditions surface through refs, evidence,
/// and standing, never through payload lookup.
fn resolve_candidate<'a>(
    id: RecordId,
    record: &Record,
    prior: &Prior<'a>,
    state: &State,
) -> Result<&'a Record, ReasonCode> {
    match prior.find(id) {
        Some(t)
            if t.space == record.space
                && t.kind == Kind::Candidate
                && state.accepted_records.contains(&t.id) =>
        {
            Ok(t)
        }
        _ => Err(ReasonCode::PayloadRefUnresolved),
    }
}

/// `Candidate` rules (delta D3): well-formed source binding, and basis
/// obligations over `Cause` targets and `parent`.
pub(super) fn check_candidate(
    record: &Record,
    prior: &Prior<'_>,
    rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    let data: CandidateData = dec!(&record.data, CandidateData);

    if !source_binding_well_formed(&data.source) {
        return Some(ReasonCode::SourceBindingInvalid);
    }
    // Artifact identities (spec 0.4): each well-formed, the list strictly
    // ordered and deduplicated.
    if let Some(artifacts) = &data.artifacts {
        if !artifact_refs_well_formed(artifacts) {
            return Some(ReasonCode::ArtifactRefInvalid);
        }
    }

    // A present `parent` must resolve to an accepted Candidate (the basis
    // rules below decide whether a parent is allowed at all).
    if let Some(parent) = data.parent {
        if let Err(reason) = resolve_candidate(parent, record, prior, state) {
            return Some(reason);
        }
    }

    // Cause targets are refs, so the generic checks already resolved them;
    // a miss here is defensive, never a pass.
    let mut causes: Vec<&Record> = Vec::new();
    for r in &record.refs {
        if r.type_ == RefType::Cause {
            match prior.find(r.target) {
                Some(t) => causes.push(t),
                None => return Some(ReasonCode::RefUnresolved),
            }
        }
    }

    match data.basis {
        CandidateBasis::Root => {
            // At most one Cause, targeting an accepted Request; no parent.
            if data.parent.is_some() || causes.len() > 1 {
                return Some(ReasonCode::LineageInvalid);
            }
            if let Some(c) = causes.first() {
                if c.kind != Kind::Request || !state.accepted_records.contains(&c.id) {
                    return Some(ReasonCode::LineageInvalid);
                }
            }
        }
        CandidateBasis::Continuation => {
            // Exactly one Cause to an accepted Selection whose outcome is
            // Selected; parent names a member of that selected set.
            if causes.len() != 1 {
                return Some(ReasonCode::LineageInvalid);
            }
            let anchor = causes[0];
            if anchor.kind != Kind::Selection || !state.accepted_records.contains(&anchor.id) {
                return Some(ReasonCode::LineageInvalid);
            }
            // Optional commit-time strictness (delta D6): reject a
            // continuation whose anchor is already unsound (retracted or
            // tainted) at this position. Off by default so the ledger can
            // always record ongoing work; the standing report (SPEC §7.2)
            // carries the lineage consequence otherwise.
            if rules.reject_compromised_continuation
                && (state.retracted_records.contains(&anchor.id)
                    || state.tainted_records.contains(&anchor.id))
            {
                return Some(ReasonCode::LineageInvalid);
            }
            let Some(parent) = data.parent else {
                return Some(ReasonCode::LineageInvalid);
            };
            let anchor_data: SelectionData = dec!(&anchor.data, SelectionData);
            match anchor_data.outcome {
                SelectionOutcome::Selected { candidates } if candidates.contains(&parent) => {}
                _ => return Some(ReasonCode::LineageInvalid),
            }
        }
        CandidateBasis::Derivation => {
            // At least one Cause, each an accepted Candidate or Evaluation,
            // none a Selection; no parent.
            if data.parent.is_some() || causes.is_empty() {
                return Some(ReasonCode::LineageInvalid);
            }
            for c in &causes {
                if !state.accepted_records.contains(&c.id) {
                    return Some(ReasonCode::LineageInvalid);
                }
                if !matches!(c.kind, Kind::Candidate | Kind::Evaluation) {
                    return Some(ReasonCode::LineageInvalid);
                }
            }
        }
    }

    None
}

/// `Evaluation` rules (delta D3): the judged candidate resolves to an
/// accepted Candidate and is named by a `Use` ref (the epistemic subject
/// edge). `criterion` non-empty and `outcome` bounds are decode-enforced.
pub(super) fn check_evaluation(
    record: &Record,
    prior: &Prior<'_>,
    _rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    let data: EvaluationData = dec!(&record.data, EvaluationData);

    if let Err(reason) = resolve_candidate(data.candidate, record, prior, state) {
        return Some(reason);
    }

    let uses_candidate = record
        .refs
        .iter()
        .any(|r| r.type_ == RefType::Use && r.target == data.candidate);
    if !uses_candidate {
        return Some(ReasonCode::EvaluationInvalid);
    }

    None
}

/// `Selection` rules (delta D3/D4): `considered` well-formed and resolving,
/// outcome/winner discipline, used-evaluation subject constraint, and
/// reaffirmation validity when a `Replace` ref is present.
pub(super) fn check_selection(
    record: &Record,
    prior: &Prior<'_>,
    rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    let data: SelectionData = dec!(&record.data, SelectionData);

    // considered: non-empty, unique, within max_considered.
    if data.considered.is_empty() || data.considered.len() > rules.max_considered as usize {
        return Some(ReasonCode::SelectionInvalid);
    }
    let considered: BTreeSet<RecordId> = data.considered.iter().copied().collect();
    if considered.len() != data.considered.len() {
        return Some(ReasonCode::SelectionInvalid);
    }
    // Each considered member resolves to an accepted Candidate.
    for &cid in &data.considered {
        if let Err(reason) = resolve_candidate(cid, record, prior, state) {
            return Some(reason);
        }
    }

    // Every Used *accepted* Evaluation's candidate must appear in
    // `considered`; count them for `selection_requires_evaluation`. The
    // acceptance gate is load-bearing: a Selection may `Use` a rejected
    // Evaluation-kind record (it stays in the log and merely degrades the
    // Selection's evidence to the floor, like any `Use` of bad content), and
    // a rejected record's bytes need not decode as `EvaluationData`. Decoding
    // one would let a repudiated judgment satisfy the evaluation requirement,
    // and its payload is not guaranteed well-formed. Only an accepted
    // Evaluation passed the canonical-payload check, so only it is real
    // evidence and safe to decode.
    let mut used_evaluations = 0usize;
    for r in &record.refs {
        if r.type_ == RefType::Use {
            if let Some(t) = prior.find(r.target) {
                if t.kind == Kind::Evaluation && state.accepted_records.contains(&t.id) {
                    used_evaluations += 1;
                    let ev: EvaluationData = dec!(&t.data, EvaluationData);
                    if !considered.contains(&ev.candidate) {
                        return Some(ReasonCode::SelectionInvalid);
                    }
                }
            }
        }
    }

    let require_targets: BTreeSet<RecordId> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Require)
        .map(|r| r.target)
        .collect();

    // Winner set (the candidate Require targets the outcome demands), with
    // per-outcome winner validity.
    let winners: BTreeSet<RecordId> = match &data.outcome {
        SelectionOutcome::Selected { candidates } => {
            let selected: BTreeSet<RecordId> = candidates.iter().copied().collect();
            // Non-empty, unique, subset of considered.
            if selected.is_empty()
                || selected.len() != candidates.len()
                || !selected.is_subset(&considered)
            {
                return Some(ReasonCode::SelectionInvalid);
            }
            // min_binding: every winner must meet the configured minimum
            // source binding. Winners are in `considered`, already resolved
            // to accepted Candidates above.
            if rules.min_binding == BindingMode::Manifest {
                for c in &selected {
                    let Some(t) = prior.find(*c) else {
                        return Some(ReasonCode::SelectionInvalid);
                    };
                    let cd: CandidateData = dec!(&t.data, CandidateData);
                    if cd.source.binding != BindingMode::Manifest {
                        return Some(ReasonCode::SelectionInvalid);
                    }
                }
            }
            // selection_requires_evaluation: at least one Evaluation Used.
            if rules.selection_requires_evaluation && used_evaluations == 0 {
                return Some(ReasonCode::SelectionInvalid);
            }
            selected
        }
        // A None decision names no winners.
        SelectionOutcome::None => BTreeSet::new(),
    };

    // Selection approval binding (delta D5): when the rules demand it, the
    // Selection must `Require` a valid, unconsumed approval whose subject hash
    // binds the author, the Replace target, and the SelectionData. This is the
    // only authority `Require` a Selection may carry.
    let approval_require = match resolve_selection_approval(record, &data, prior, rules, state) {
        Ok(id) => id,
        Err(reason) => return Some(reason),
    };

    // Require-target exactness: exactly the winners plus the required approval
    // (if any). No other `Require` targets are allowed (V3-S2). This is the
    // single place the require set is pinned, so a None decision with an
    // authority approval is expressible while a stray Require still rejects.
    let mut allowed = winners;
    if let Some(a) = approval_require {
        allowed.insert(a);
    }
    if require_targets != allowed {
        return Some(ReasonCode::SelectionInvalid);
    }

    // Reaffirmation (delta D4): a Replace ref makes this a new decision over
    // the same objective. The generic Replace machinery already required the
    // target to be a prior accepted Selection (same kind); here the objective
    // must match and the author must be allowlisted when one is configured.
    if let Some(replace) = record.refs.iter().find(|r| r.type_ == RefType::Replace) {
        if let Some(target) = prior.find(replace.target) {
            let target_data: SelectionData = dec!(&target.data, SelectionData);
            if target_data.objective != data.objective {
                return Some(ReasonCode::ReaffirmationInvalid);
            }
        }
        if !rules.reaffirmation_actors.is_empty()
            && !rules.reaffirmation_actors.contains(&record.author.id)
        {
            return Some(ReasonCode::ReaffirmationInvalid);
        }
    }

    None
}

/// `Requirement` rules (spec 0.4, RFC-0003 section 4.1): non-empty key and
/// description, exactly one `Cause` to an accepted Request in the same
/// thread and space, a key not already held under that request, and
/// provenance bound to the author's role. The generic checks have already
/// applied the author-role table (no Executor) and rejected any `Replace`
/// (a Requirement is never replaceable: amendment is retract-and-record).
pub(super) fn check_requirement(
    record: &Record,
    prior: &Prior<'_>,
    state: &State,
) -> Option<ReasonCode> {
    let data: RequirementData = dec!(&record.data, RequirementData);

    if data.key.is_empty() || data.description.is_empty() {
        return Some(ReasonCode::RequirementInvalid);
    }

    // Provenance is bound to authorship: "confirmed by a person" is a fact
    // about who wrote the record, never a flag (RFC-0003 decision 1).
    let provenance_ok = match data.provenance {
        Provenance::UserAuthored => record.author.type_ == AuthorType::User,
        Provenance::Derived => matches!(
            record.author.type_,
            AuthorType::Provider | AuthorType::System
        ),
    };
    if !provenance_ok {
        return Some(ReasonCode::AuthorRoleInvalid);
    }

    // Exactly one Cause, to an accepted Request in the same thread and space.
    let causes: Vec<&Ref> = record
        .refs
        .iter()
        .filter(|r| r.type_ == RefType::Cause)
        .collect();
    if causes.len() != 1 {
        return Some(ReasonCode::RequirementInvalid);
    }
    let request_id = causes[0].target;
    let Some(request) = prior.find(request_id) else {
        return Some(ReasonCode::RequirementInvalid);
    };
    if request.kind != Kind::Request
        || !state.accepted_records.contains(&request_id)
        || request.thread != record.thread
        || request.space != record.space
    {
        return Some(ReasonCode::RequirementInvalid);
    }

    // The key is unique among accepted, unretracted Requirements under the
    // request (a retraction releases its key, so retract-and-record can
    // reuse it).
    if state
        .requirement_keys
        .get(&request_id)
        .is_some_and(|keys| keys.contains(&data.key))
    {
        return Some(ReasonCode::RequirementInvalid);
    }

    None
}

/// Resolve the approval a Selection is required to carry (delta D5). Returns
/// `Ok(None)` when the rules do not require Selection approvals, `Ok(Some(id))`
/// with the approving record's id when a valid approval is `Require`-referenced,
/// and `Err(ApprovalMissing | ApprovalExpired)` otherwise. Modeled on the
/// Action exact-approval path: the subject hash is looked up in
/// `valid_approvals`, the approval must be `Require`-referenced, usable
/// (accepted, not retracted or tainted), declare the selecting author as its
/// subject actor, and be unexpired.
fn resolve_selection_approval(
    record: &Record,
    data: &SelectionData,
    prior: &Prior<'_>,
    rules: &VerifierRules,
    state: &State,
) -> Result<Option<RecordId>, ReasonCode> {
    if !rules.selection_requires_approval {
        return Ok(None);
    }
    let replace_target = record
        .refs
        .iter()
        .find(|r| r.type_ == RefType::Replace)
        .map(|r| r.target);
    let subject_hash = selection_approval_subject_hash(&record.author.id, replace_target, data)
        .map_err(|_| ReasonCode::InvalidPayload)?;

    // Looked up by subject hash (parallel to the Action exact path) and must
    // be `Require`-referenced by this Selection.
    let Some(&approval_id) = state.valid_approvals.get(&subject_hash) else {
        return Err(ReasonCode::ApprovalMissing);
    };
    let require_matches = record
        .refs
        .iter()
        .any(|r| r.type_ == RefType::Require && r.target == approval_id);
    if !require_matches {
        return Err(ReasonCode::ApprovalMissing);
    }
    // Usable: accepted, not retracted or tainted.
    if !state.accepted_records.contains(&approval_id)
        || state.retracted_records.contains(&approval_id)
        || state.tainted_records.contains(&approval_id)
    {
        return Err(ReasonCode::ApprovalMissing);
    }
    let Some(approval_record) = prior.find(approval_id) else {
        return Err(ReasonCode::ApprovalMissing);
    };
    let approval_data: ApprovalData = match decode::<ApprovalData>(&approval_record.data) {
        Ok(v) => v,
        Err(_) => return Err(ReasonCode::InvalidPayload),
    };
    // The declared subject actor must equal the selecting author. The subject
    // hash already binds the author, so this is the parallel of the Action
    // path's explicit `actor_id` check: it rejects an approval that visibly
    // claims a different subject than the one its hash authorizes.
    if approval_data.actor_id.as_deref() != Some(record.author.id.as_str()) {
        return Err(ReasonCode::ApprovalMissing);
    }
    if let Some(expiry) = approval_data.expiry {
        if record.time >= expiry {
            return Err(ReasonCode::ApprovalExpired);
        }
    }
    Ok(Some(approval_id))
}
