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
    _rules: &VerifierRules,
    state: &State,
) -> Option<ReasonCode> {
    let data: CandidateData = dec!(&record.data, CandidateData);

    if !source_binding_well_formed(&data.source) {
        return Some(ReasonCode::SourceBindingInvalid);
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

    match &data.outcome {
        SelectionOutcome::Selected { candidates } => {
            let selected: BTreeSet<RecordId> = candidates.iter().copied().collect();
            // Non-empty, unique, subset of considered.
            if selected.is_empty()
                || selected.len() != candidates.len()
                || !selected.is_subset(&considered)
            {
                return Some(ReasonCode::SelectionInvalid);
            }
            // The winner Require refs must be exactly the selected set: each
            // winner is Required, and no other record is Required (Selection
            // approval authority lands in delta D5 / #25).
            if require_targets != selected {
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
        }
        SelectionOutcome::None => {
            // A None decision carries no candidate Require refs, and no
            // authority Require refs exist for Selections yet (delta D5).
            if !require_targets.is_empty() {
                return Some(ReasonCode::SelectionInvalid);
            }
        }
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
