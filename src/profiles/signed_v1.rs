//! `bellbook-core-signed-v1` (RFC-0003 section 4.5, SPEC section 12.2): the
//! signed tier above the content-addressed baseline.
//!
//! The baseline requires no signatures, because a baseline nobody can meet
//! compares nothing. The signed tier is what a consumer names when it wants
//! the evolution record authenticated as well as consistent: the rules must
//! demand a signature on every evolution kind, every actor who authored one
//! must have pinned keys (so the signature binds a key to an identity, not
//! just to a string), and every evaluation a claim rests on must carry the
//! attested schema, whose `Verified` base class the verifier only admits
//! under a pinned signature. A baseline-conformant receipt reaches this
//! tier by adding signatures and switching evaluation schema ids; no
//! payload changes shape.
//!
//! Every clause is fail-closed and, like every profile, this is a report
//! alongside the verdict: it never changes `status` or `reason`.

use std::collections::{BTreeMap, BTreeSet};

use crate::base::hash::hex_encode;
use crate::base::schema::{schema_id, SCHEMA_EVALUATION_ATTESTED};
use crate::receipt::{Receipt, Report, ValidationStatus};
use crate::record::kind::{Kind, RefType};
use crate::record::payloads::{SelectionData, SelectionOutcome};
use crate::record::record::{decode, Record};
use crate::record::refs::RecordId;

use super::{
    evaluate_declared, evaluate_profile, profile_hash, Clause, ClauseResult, ProfileResult,
    ProfileStatus, ProfileTable, BELLBOOK_CORE_SIGNED_V1, BELLBOOK_CORE_V1,
};

/// The evolution kinds the signed tier requires signatures for (S1) and
/// pinned authors of (S2).
pub const SIGNED_KINDS: [Kind; 5] = [
    Kind::Candidate,
    Kind::Evaluation,
    Kind::Selection,
    Kind::Retraction,
    Kind::Requirement,
];

/// The clause table of `bellbook-core-signed-v1`. The statements are the
/// normative text; `docs/profiles/bellbook-core-signed-v1.md` quotes them.
pub fn table() -> ProfileTable {
    ProfileTable {
        id: BELLBOOK_CORE_SIGNED_V1.to_string(),
        version: 1,
        clauses: vec![
            Clause {
                id: "S0".into(),
                statement: "The receipt conforms to bellbook-core-v1, and if it declares that profile the declaration names the evaluated table.".into(),
            },
            Clause {
                id: "S1".into(),
                statement: "signature_required_kinds includes Candidate, Evaluation, Selection, Retraction, and Requirement.".into(),
            },
            Clause {
                id: "S2".into(),
                statement: "author_keys pins every actor that authored an accepted Candidate, Evaluation, Selection, Retraction, or Requirement.".into(),
            },
            Clause {
                id: "S3".into(),
                statement: "Every evaluation Used by an accepted Selection with outcome Selected carries the schema bellbook.evaluation.attested.v1.".into(),
            },
        ],
    }
}

const CLAUSE_IDS: [&str; 4] = ["S0", "S1", "S2", "S3"];

fn short(id: &RecordId) -> String {
    hex_encode(id)[..12].to_string()
}

fn finish(clauses: Vec<ClauseResult>) -> ProfileResult {
    let status = if clauses.iter().all(|c| c.passed) {
        ProfileStatus::Conformant
    } else {
        ProfileStatus::NonConformant
    };
    ProfileResult {
        id: BELLBOOK_CORE_SIGNED_V1.to_string(),
        hash: profile_hash(&table()),
        status,
        clauses,
        declared: false,
        declaration_matches: None,
    }
}

/// Every clause failed for one reason that precedes the record itself.
fn all_failed(reason: &str) -> ProfileResult {
    finish(
        CLAUSE_IDS
            .iter()
            .map(|id| ClauseResult {
                id: (*id).into(),
                passed: false,
                detail: reason.into(),
            })
            .collect(),
    )
}

/// Evaluate the profile over a validated receipt. `report` must be the
/// result of validating `receipt`.
pub fn evaluate(receipt: &Receipt, report: &Report) -> ProfileResult {
    if report.status == ValidationStatus::Invalid {
        return all_failed("receipt is Invalid");
    }
    // An accepting log has canonical payloads; the unchecked build cannot
    // fail. Surface the impossible case as a non-conformance, never a panic.
    let Ok(state) = crate::state::build::build_state_unchecked(&receipt.records) else {
        return all_failed("state could not be rebuilt");
    };
    let accepted = &state.accepted_records;
    let rules = &receipt.rules;
    let by_id: BTreeMap<RecordId, &Record> = receipt.records.iter().map(|r| (r.id, r)).collect();
    let is_accepted = |id: &RecordId| accepted.contains(id) && by_id.contains_key(id);

    // S0: the baseline, declared or evaluated as the fallback (as
    // delivery-receipt-v1 D6 does).
    let core = match receipt.profiles.iter().find(|p| p.id == BELLBOOK_CORE_V1) {
        Some(decl) => evaluate_declared(decl, receipt, report),
        None => evaluate_profile(BELLBOOK_CORE_V1, receipt, report),
    };
    let s0 = ClauseResult {
        id: "S0".into(),
        passed: core.met(),
        detail: format!(
            "{}: {:?}{}",
            BELLBOOK_CORE_V1,
            core.status,
            match (core.declared, core.declaration_matches) {
                (true, Some(true)) => " (declared, declaration matches)",
                (true, Some(false)) => " (declared, DECLARATION MISMATCH)",
                (true, None) => " (declared)",
                (false, _) => " (not declared; evaluated as the fallback)",
            }
        ),
    };

    // S1: the rules demand a signature on every evolution kind.
    let missing: Vec<String> = SIGNED_KINDS
        .iter()
        .filter(|k| !rules.signature_required_kinds.contains(k))
        .map(|k| format!("{k:?}"))
        .collect();
    let s1 = ClauseResult {
        id: "S1".into(),
        passed: missing.is_empty(),
        detail: if missing.is_empty() {
            "signatures required for Candidate, Evaluation, Selection, Retraction, Requirement"
                .into()
        } else {
            format!("signature not required for {}", missing.join(", "))
        },
    };

    // S2: every author of an accepted evolution record has pinned keys.
    // Replay has already verified each such signature against those keys
    // (`SignatureInvalid` otherwise), so under S0 this is what binds the
    // signatures to identities.
    let mut pinned: BTreeSet<&str> = BTreeSet::new();
    let mut unpinned: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for rec in &receipt.records {
        if !SIGNED_KINDS.contains(&rec.kind) || !is_accepted(&rec.id) {
            continue;
        }
        let author: &str = &rec.author.id;
        if rules.author_keys.contains_key(&rec.author.id) {
            pinned.insert(author);
        } else {
            unpinned
                .entry(author)
                .or_default()
                .insert(format!("{:?}", rec.kind));
        }
    }
    let s2 = ClauseResult {
        id: "S2".into(),
        passed: unpinned.is_empty(),
        detail: if unpinned.is_empty() {
            format!(
                "{} pinned author(s) of evolution records: [{}]",
                pinned.len(),
                pinned.iter().copied().collect::<Vec<_>>().join(", ")
            )
        } else {
            format!(
                "unpinned: {}",
                unpinned
                    .iter()
                    .map(|(a, kinds)| format!(
                        "{a:?} ({})",
                        kinds.iter().cloned().collect::<Vec<_>>().join(", ")
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    };

    // S3: every evaluation a claim rests on is attested. A claim here is any
    // accepted Selection with outcome Selected; the evaluations it Uses are
    // the ones a consumer is asked to rely on. Evaluations no selection uses
    // may carry any schema.
    let attested = schema_id(SCHEMA_EVALUATION_ATTESTED);
    let mut used_total = 0usize;
    let mut not_attested: Vec<String> = Vec::new();
    for rec in &receipt.records {
        if rec.kind != Kind::Selection || !is_accepted(&rec.id) {
            continue;
        }
        let Ok(sd) = decode::<SelectionData>(&rec.data) else {
            continue;
        };
        if !matches!(sd.outcome, SelectionOutcome::Selected { .. }) {
            continue;
        }
        for f in rec.refs.iter().filter(|f| f.type_ == RefType::Use) {
            let Some(target) = by_id.get(&f.target) else {
                continue;
            };
            if target.kind != Kind::Evaluation || !is_accepted(&target.id) {
                continue;
            }
            used_total += 1;
            if target.schema != attested {
                not_attested.push(short(&target.id));
            }
        }
    }
    not_attested.sort();
    not_attested.dedup();
    let s3 = ClauseResult {
        id: "S3".into(),
        passed: not_attested.is_empty(),
        detail: if not_attested.is_empty() {
            format!("{used_total} evaluation(s) used by selections, all attested")
        } else {
            format!(
                "not attested: {} of {used_total} used evaluation(s): [{}]",
                not_attested.len(),
                not_attested.join(", ")
            )
        },
    };

    finish(vec![s0, s1, s2, s3])
}
