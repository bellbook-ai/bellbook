//! Evidence enum and derivation.

use crate::base::hash::Hash256;
use crate::base::schema::*;
use serde::{Deserialize, Serialize};

/// Trust class of a record's content. Ordered strongest → weakest, so the
/// derived class of a record is the `max` (weakest) of its base class and
/// the classes of the records it epistemically depends on (`Use`/`Require`
/// refs; `Cause`/`Replace` are provenance and do not participate) -
/// evidence can never be inflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Evidence {
    /// Strongest (ordinal 0, ≈"proven"): derived by the verifier itself
    /// (Verdict records).
    Deterministic,
    /// ≈"attested": a signed attestation from a key-pinned external party
    /// (`bellbook.result.external_receipt.v1` - the verifier enforces the
    /// signature and key binding). Origin is verified, never the claimed
    /// real-world effect.
    Verified,
    /// An external party (user, provider, executor, host) asserted it;
    /// checkable in principle but not checked.
    Reported,
    /// Derived by reasoning from other records (summaries, plans) rather
    /// than asserted first-hand.
    Inferred,
    /// Weakest (ordinal 4): proceeded on an unverified assumption. No core
    /// schema has this as its base class; it is the floor reserved for
    /// host-declared assumptions and evidence degradation.
    Assumed,
}

/// Base evidence by schema (SPEC.md §7).
///
/// Every frozen schema is classified explicitly - no catch-all arm - so
/// registering a new schema forces a classification decision here. Unknown
/// schemas (which the verifier rejects with `UnknownSchema` anyway) get the
/// weakest class rather than an invented stronger one.
pub fn base_evidence(schema: &Hash256) -> Evidence {
    match schema_name_for_id(schema) {
        Some(SCHEMA_VERDICT) => Evidence::Deterministic,
        Some(SCHEMA_RESULT_EXTERNAL) => Evidence::Verified,
        Some(SCHEMA_REQUEST) => Evidence::Reported,
        Some(SCHEMA_ACTION) => Evidence::Reported,
        Some(SCHEMA_RESPONSE) => Evidence::Reported,
        Some(SCHEMA_RESULT) => Evidence::Reported,
        Some(SCHEMA_RESULT_EFFECT_CONFIRMATION) => Evidence::Reported,
        Some(SCHEMA_CAPABILITY) => Evidence::Reported,
        Some(SCHEMA_APPROVAL) => Evidence::Reported,
        Some(SCHEMA_REFUSAL) => Evidence::Reported,
        Some(SCHEMA_USAGE) => Evidence::Reported,
        Some(SCHEMA_RETRACTION) => Evidence::Reported,
        // A candidate's binding and an evaluation's outcome are
        // host-asserted; a selection is a judgment derived by reasoning.
        // Under these bases evaluations derive at most Reported and
        // selections at most Inferred (SPEC §7).
        Some(SCHEMA_CANDIDATE) => Evidence::Reported,
        Some(SCHEMA_EVALUATION) => Evidence::Reported,
        Some(SCHEMA_SUMMARY) => Evidence::Inferred,
        Some(SCHEMA_PLAN) => Evidence::Inferred,
        Some(SCHEMA_SELECTION) => Evidence::Inferred,
        Some(_) | None => Evidence::Assumed,
    }
}

/// Return the weakest evidence from a slice. If empty, returns Deterministic.
pub fn weakest(evidences: &[Evidence]) -> Evidence {
    evidences
        .iter()
        .copied()
        .max()
        .unwrap_or(Evidence::Deterministic)
}

/// Derive effective evidence for a record given its schema and ref chain evidences.
/// SPEC.md derivation rules.
pub fn derive_evidence(schema: &Hash256, ref_evidences: &[Evidence]) -> Evidence {
    let base = base_evidence(schema);
    if ref_evidences.is_empty() {
        base
    } else {
        let mut all = vec![base];
        all.extend_from_slice(ref_evidences);
        weakest(&all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_evidence() {
        assert_eq!(
            base_evidence(&schema_id(SCHEMA_VERDICT)),
            Evidence::Deterministic
        );
        assert_eq!(
            base_evidence(&schema_id(SCHEMA_RESULT_EXTERNAL)),
            Evidence::Verified
        );
        assert_eq!(
            base_evidence(&schema_id(SCHEMA_REQUEST)),
            Evidence::Reported
        );
        assert_eq!(base_evidence(&schema_id(SCHEMA_ACTION)), Evidence::Reported);
        assert_eq!(
            base_evidence(&schema_id(SCHEMA_SUMMARY)),
            Evidence::Inferred
        );
        assert_eq!(base_evidence(&schema_id(SCHEMA_PLAN)), Evidence::Inferred);
        // Unknown schemas fall to the floor, never to a stronger class.
        assert_eq!(base_evidence(&[0xEEu8; 32]), Evidence::Assumed);
    }

    #[test]
    fn every_frozen_schema_is_classified() {
        // base_evidence classifies each frozen schema with an explicit match
        // arm. If this count changes, a schema was added or removed: update
        // the match in base_evidence (and this pin) in the same change.
        assert_eq!(ALL_SCHEMAS.len(), 17);
        for name in ALL_SCHEMAS {
            // No frozen schema may fall through to the unknown-schema floor
            // by accident; Assumed as a base class must be a deliberate
            // choice recorded in the match itself (none today).
            assert_ne!(
                base_evidence(&schema_id(name)),
                Evidence::Assumed,
                "frozen schema {name} fell through to the unknown-schema arm"
            );
        }
    }

    #[test]
    fn test_lattice_order_strongest_to_weakest() {
        assert!(Evidence::Deterministic < Evidence::Verified);
        assert!(Evidence::Verified < Evidence::Reported);
        assert!(Evidence::Reported < Evidence::Inferred);
        assert!(Evidence::Inferred < Evidence::Assumed);
    }

    #[test]
    fn test_weakest() {
        assert_eq!(
            weakest(&[Evidence::Deterministic, Evidence::Reported]),
            Evidence::Reported
        );
        assert_eq!(
            weakest(&[Evidence::Verified, Evidence::Deterministic]),
            Evidence::Verified
        );
        assert_eq!(
            weakest(&[Evidence::Reported, Evidence::Inferred, Evidence::Assumed]),
            Evidence::Assumed
        );
        assert_eq!(weakest(&[Evidence::Reported]), Evidence::Reported);
    }

    #[test]
    fn test_derive_evidence_no_refs() {
        assert_eq!(
            derive_evidence(&schema_id(SCHEMA_VERDICT), &[]),
            Evidence::Deterministic
        );
        assert_eq!(
            derive_evidence(&schema_id(SCHEMA_REQUEST), &[]),
            Evidence::Reported
        );
    }

    #[test]
    fn test_derive_evidence_with_refs() {
        // External receipt (Verified) with Cause ref to Reported action -> Reported
        assert_eq!(
            derive_evidence(&schema_id(SCHEMA_RESULT_EXTERNAL), &[Evidence::Reported]),
            Evidence::Reported
        );
        // A summary (Inferred) over an Assumed input degrades to Assumed.
        assert_eq!(
            derive_evidence(&schema_id(SCHEMA_SUMMARY), &[Evidence::Assumed]),
            Evidence::Assumed
        );
        // A summary over strong inputs is still no stronger than Inferred.
        assert_eq!(
            derive_evidence(&schema_id(SCHEMA_SUMMARY), &[Evidence::Deterministic]),
            Evidence::Inferred
        );
    }
}
