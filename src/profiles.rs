//! Profiles (RFC-0003 section 4.5, SPEC section 12.2): separately versioned
//! predicates a validator evaluates over a receipt on request and reports
//! alongside the verdict.
//!
//! A profile has a stable id, a canonical hash of its clause table, and a
//! predicate over the embedded rules, the records, and the validation
//! [`Report`]. Evaluating one yields a [`ProfileResult`]: `Conformant`,
//! `NonConformant` (naming the failing clauses), or `Unknown` (the id is not
//! known to this validator). Profile conformance never changes the
//! validation verdict and is never a verdict reason code: it is a report
//! about what a consumer may conclude from Clean, Tainted, and Invalid
//! under a declared rule shape.
//!
//! The first profile, [`BELLBOOK_CORE_V1`], is the content-addressed
//! baseline: what two parties agree on when they both name it. It fixes the
//! rule shape (roles registered, evidence thresholds present and no weaker
//! than the schema base classes, a declared context bound) and requires no
//! signatures - a baseline nobody can meet compares nothing. The signed
//! tier is a separate profile (RFC-0003 section 4.5).

use serde::{Deserialize, Serialize};

use crate::base::hash::{sha256_canonical, Hash256};
use crate::receipt::{Receipt, Report, ValidationStatus};
use crate::record::evidence::Evidence;
use crate::record::kind::Kind;
use crate::record::payloads::{BindingMode, CandidateData};
use crate::record::record::decode;

/// Stable id of the content-addressed baseline profile.
pub const BELLBOOK_CORE_V1: &str = "bellbook-core-v1";

/// Every profile id this validator knows how to evaluate.
pub fn known_profiles() -> &'static [&'static str] {
    &[BELLBOOK_CORE_V1]
}

/// Outcome of evaluating one profile over one receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProfileStatus {
    /// Every clause held.
    Conformant,
    /// At least one clause failed; see the clause results.
    NonConformant,
    /// This validator does not know the profile id; nothing was evaluated.
    Unknown,
}

/// One clause of a profile, evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClauseResult {
    /// Clause id as the profile document names it, e.g. `"B3"`.
    pub id: String,
    /// Whether the clause held.
    pub passed: bool,
    /// What was observed - the facts the clause judged, for a reader.
    pub detail: String,
}

/// The evaluation of one profile over one receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileResult {
    /// The profile id as requested.
    pub id: String,
    /// SHA-256 of the canonical clause table this validator evaluated, so a
    /// consumer can confirm which revision of the profile was applied.
    /// All zero for an unknown profile.
    pub hash: Hash256,
    /// The outcome.
    pub status: ProfileStatus,
    /// Per-clause results, in profile order; empty for an unknown profile.
    pub clauses: Vec<ClauseResult>,
}

/// One row of a profile's clause table: the normative statement a clause
/// checks. The table is what the profile hash commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clause {
    /// Clause id, e.g. `"B1"`.
    pub id: String,
    /// The normative statement, verbatim from the profile document.
    pub statement: String,
}

/// A profile's identity: id, version, and its clause table. Serializing
/// this canonically and hashing it yields the profile hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileTable {
    /// The stable id.
    pub id: String,
    /// The profile document version this table belongs to.
    pub version: u32,
    /// The clauses, in evaluation order.
    pub clauses: Vec<Clause>,
}

/// The clause table of `bellbook-core-v1`. The statements here are the
/// normative text; `docs/profiles/bellbook-core-v1.md` quotes them.
pub fn core_v1_table() -> ProfileTable {
    ProfileTable {
        id: BELLBOOK_CORE_V1.to_string(),
        version: 1,
        clauses: vec![
            Clause {
                id: "B1".into(),
                statement: "The receipt validates Clean or Tainted; an Invalid receipt never conforms.".into(),
            },
            Clause {
                id: "B2".into(),
                statement: "author_roles is non-empty, and every accepted record's author is registered in it.".into(),
            },
            Clause {
                id: "B3".into(),
                statement: "evidence_thresholds carries entries for Candidate, Evaluation, and Selection, each no weaker than the schema base class (Reported, Reported, Inferred).".into(),
            },
            Clause {
                id: "B4".into(),
                statement: "max_context_records is declared within 1..=100000.".into(),
            },
            Clause {
                id: "B5".into(),
                statement: "Retraction and reaffirmation authority are readable from the rules: admin_retraction_actors and reaffirmation_actors are reported.".into(),
            },
            Clause {
                id: "B6".into(),
                statement: "The source binding mode of every accepted Candidate (Manifest or Reported) is reported; neither is required.".into(),
            },
        ],
    }
}

/// The clause table for a known profile id.
pub fn profile_table(id: &str) -> Option<ProfileTable> {
    match id {
        BELLBOOK_CORE_V1 => Some(core_v1_table()),
        _ => None,
    }
}

/// SHA-256 over the canonical JSON of a profile's clause table.
pub fn profile_hash(table: &ProfileTable) -> Hash256 {
    // The table is plain strings and integers; canonicalization cannot fail
    // for it, and a failure here would be a bug, not an input problem.
    sha256_canonical(table).unwrap_or([0u8; 32])
}

/// Evaluate a profile over a validated receipt. `report` must be the result
/// of validating `receipt` (the caller holds both; this function does not
/// replay). An unknown `id` yields `Unknown` with no clauses.
pub fn evaluate_profile(id: &str, receipt: &Receipt, report: &Report) -> ProfileResult {
    match id {
        BELLBOOK_CORE_V1 => evaluate_core_v1(receipt, report),
        _ => ProfileResult {
            id: id.to_string(),
            hash: [0u8; 32],
            status: ProfileStatus::Unknown,
            clauses: Vec::new(),
        },
    }
}

fn evaluate_core_v1(receipt: &Receipt, report: &Report) -> ProfileResult {
    let rules = &receipt.rules;
    let mut clauses = Vec::with_capacity(6);

    // B1: replay outcome.
    let b1 = report.status != ValidationStatus::Invalid;
    clauses.push(ClauseResult {
        id: "B1".into(),
        passed: b1,
        detail: format!("status {:?}", report.status),
    });

    // B2: roles registered. Replay already rejects an unregistered author
    // (AuthorRoleInvalid), so under B1 the second half holds; the clause
    // states it for consumers and checks the map is not empty.
    let b2 = !rules.author_roles.is_empty();
    clauses.push(ClauseResult {
        id: "B2".into(),
        passed: b2,
        detail: format!("{} registered author role(s)", rules.author_roles.len()),
    });

    // B3: evidence thresholds present and no weaker than the base class.
    // A threshold admits records whose derived evidence is at most that
    // strong; "no weaker than base" means the threshold is at least as
    // strict as the schema base class (Evidence orders strongest first).
    let required: [(Kind, Evidence); 3] = [
        (Kind::Candidate, Evidence::Reported),
        (Kind::Evaluation, Evidence::Reported),
        (Kind::Selection, Evidence::Inferred),
    ];
    let mut b3 = true;
    let mut b3_detail = Vec::new();
    for (kind, base) in required {
        match rules.evidence_thresholds.get(&kind) {
            Some(t) if *t <= base => b3_detail.push(format!("{kind:?}={t:?}")),
            Some(t) => {
                b3 = false;
                b3_detail.push(format!("{kind:?}={t:?} (weaker than {base:?})"));
            }
            None => {
                b3 = false;
                b3_detail.push(format!("{kind:?}=missing"));
            }
        }
    }
    clauses.push(ClauseResult {
        id: "B3".into(),
        passed: b3,
        detail: b3_detail.join(", "),
    });

    // B4: a declared, bounded context size.
    let b4 = (1..=100_000).contains(&rules.max_context_records);
    clauses.push(ClauseResult {
        id: "B4".into(),
        passed: b4,
        detail: format!("max_context_records {}", rules.max_context_records),
    });

    // B5: authority is readable. Always holds; the value is the detail.
    clauses.push(ClauseResult {
        id: "B5".into(),
        passed: true,
        detail: format!(
            "admin_retraction_actors [{}], reaffirmation_actors [{}]",
            join_ids(rules.admin_retraction_actors.iter()),
            join_ids(rules.reaffirmation_actors.iter()),
        ),
    });

    // B6: binding modes reported. Only accepted Candidates count; a
    // rejected record made no claim. Always holds; the value is the detail.
    let mut manifest = 0usize;
    let mut reported = 0usize;
    if report.status != ValidationStatus::Invalid {
        let accepted = crate::state::build::build_state_unchecked(&receipt.records)
            .map(|s| s.accepted_records)
            .unwrap_or_default();
        for r in &receipt.records {
            if r.kind != Kind::Candidate || !accepted.contains(&r.id) {
                continue;
            }
            if let Ok(cd) = decode::<CandidateData>(&r.data) {
                match cd.source.binding {
                    BindingMode::Manifest => manifest += 1,
                    BindingMode::Reported => reported += 1,
                }
            }
        }
    }
    clauses.push(ClauseResult {
        id: "B6".into(),
        passed: true,
        detail: format!("candidates: {manifest} manifest-bound, {reported} reported"),
    });

    let status = if clauses.iter().all(|c| c.passed) {
        ProfileStatus::Conformant
    } else {
        ProfileStatus::NonConformant
    };
    ProfileResult {
        id: BELLBOOK_CORE_V1.to_string(),
        hash: profile_hash(&core_v1_table()),
        status,
        clauses,
    }
}

fn join_ids<'a>(ids: impl Iterator<Item = &'a String>) -> String {
    ids.map(String::as_str).collect::<Vec<_>>().join(", ")
}
