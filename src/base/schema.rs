//! Schema ID constants derived from SHA-256(utf8(schema_name)).

use crate::base::hash::{sha256_utf8, Hash256};

/// SHA-256 of a frozen UTF-8 schema name (see [`schema_id`]); stored in
/// `Record.schema` and looked up in the verifier's kind-schema map.
pub type SchemaId = Hash256;

/// Derive a SchemaId from a schema name string.
pub fn schema_id(name: &str) -> SchemaId {
    sha256_utf8(name)
}

/// The specification version this crate implements (SPEC.md §14). Carried
/// by portable artifacts - head attestations and receipts - so verifiers
/// can key their rule-sets by epoch. 0.4 is in development on this branch
/// (first released in crate 0.8.0); the previous epoch is 0.3 (crates
/// 0.3.0 through 0.7.0), whose artifacts remain valid: this validator
/// replays a 0.3 receipt under the 0.3 schema set and reaches the
/// identical decision (see [`schemas_for_epoch`]). Epoch 0.2 artifacts are
/// validated by the pinned, published 0.2.x release.
pub const SPEC_VERSION: &str = "0.4";

/// The spec versions a receipt may declare and this validator will replay,
/// oldest first. Each is replayed under its own epoch's schema set; a
/// version outside this list is a structural `Invalid` with a clear
/// unsupported-version problem, never a guess.
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["0.3", "0.4"];

/// The schema set an epoch admits. A receipt declaring `spec_version`
/// replays with exactly these schemas known: a record carrying a schema
/// introduced by a later epoch rejects as `UnknownSchema` even if the
/// embedded rules map it, so an old epoch's meaning never drifts. `None`
/// for a version this validator does not support.
pub fn schemas_for_epoch(spec_version: &str) -> Option<&'static [&'static str]> {
    match spec_version {
        "0.3" => Some(SCHEMAS_V03),
        "0.4" => Some(ALL_SCHEMAS),
        _ => None,
    }
}

/// Name whose hash is the default [`SpaceId`](crate::record::record::SpaceId):
/// a convenience for single-space deployments; hosts with their own trust
/// domains should derive space ids from their own names instead.
pub const DEFAULT_SPACE_NAME: &str = "bellbook.default_space.v1";

/// The default [`SpaceId`](crate::record::record::SpaceId): the hash of
/// [`DEFAULT_SPACE_NAME`].
#[inline]
pub fn default_space() -> Hash256 {
    sha256_utf8(DEFAULT_SPACE_NAME)
}

// Frozen schema names
/// Schema name for Request records.
pub const SCHEMA_REQUEST: &str = "bellbook.request.v1";
/// Schema name for Action records.
pub const SCHEMA_ACTION: &str = "bellbook.action.v1";
/// Schema name for Response records.
pub const SCHEMA_RESPONSE: &str = "bellbook.response.v1";
/// Schema name for internal-execution Result records.
pub const SCHEMA_RESULT: &str = "bellbook.result.v1";
/// Schema name for external-receipt Result records (base evidence `Verified`);
/// required for `ExecMode::External` actions.
pub const SCHEMA_RESULT_EXTERNAL: &str = "bellbook.result.external_receipt.v1";
/// Schema name for effect-confirmation Result records (the only valid target
/// of a `VerifiedEffect` refusal).
pub const SCHEMA_RESULT_EFFECT_CONFIRMATION: &str = "bellbook.result.effect_confirmation.v1";
/// Schema name for Capability records.
pub const SCHEMA_CAPABILITY: &str = "bellbook.capability.v1";
/// Schema name for Approval records.
pub const SCHEMA_APPROVAL: &str = "bellbook.approval.v1";
/// Schema name for Summary records.
pub const SCHEMA_SUMMARY: &str = "bellbook.summary.v1";
/// Schema name for Refusal records.
pub const SCHEMA_REFUSAL: &str = "bellbook.refusal.v1";
/// Schema name for Usage records.
pub const SCHEMA_USAGE: &str = "bellbook.usage.v1";
/// Schema name for Verdict records (base evidence `Deterministic`).
pub const SCHEMA_VERDICT: &str = "bellbook.verdict.v1";
/// Schema name for Plan records.
pub const SCHEMA_PLAN: &str = "bellbook.plan.v1";
/// Schema name for Retraction records.
pub const SCHEMA_RETRACTION: &str = "bellbook.retraction.v1";
/// Schema name for Candidate records (a source state proposed in a line of
/// development; binds a Git tree, SPEC §2).
pub const SCHEMA_CANDIDATE: &str = "bellbook.candidate.v1";
/// Schema name for Evaluation records (a judgment about one candidate under
/// one criterion).
pub const SCHEMA_EVALUATION: &str = "bellbook.evaluation.v1";
/// Schema name for Selection records (a set-valued decision over candidates
/// under an objective).
pub const SCHEMA_SELECTION: &str = "bellbook.selection.v1";
/// Schema name for Requirement records (spec 0.4: an addressable statement
/// of what a request requires, so evidence and decisions can bind to it).
pub const SCHEMA_REQUIREMENT: &str = "bellbook.requirement.v1";
/// Schema name for the extended Evaluation shape (spec 0.4): decider
/// binding, basis, evidence artifacts, bound requirements, and the
/// fail-closed outcome vocabulary. `bellbook.evaluation.v1` stays frozen.
pub const SCHEMA_EVALUATION_V2: &str = "bellbook.evaluation.v2";
/// Schema name for an attested Evaluation (spec 0.4): the extended shape
/// with base evidence `Verified`, valid only as a signed attestation from an
/// author with pinned keys, exactly like `result.external_receipt.v1`.
pub const SCHEMA_EVALUATION_ATTESTED: &str = "bellbook.evaluation.attested.v1";

/// The frozen schema set of spec epoch 0.3 (SPEC.md §14): the fifteen
/// kinds' schemas as published in crates 0.3.0 through 0.7.0. Never
/// edited; a 0.3 receipt replays with exactly these known.
pub const SCHEMAS_V03: &[&str] = &[
    SCHEMA_REQUEST,
    SCHEMA_ACTION,
    SCHEMA_RESPONSE,
    SCHEMA_RESULT,
    SCHEMA_RESULT_EXTERNAL,
    SCHEMA_RESULT_EFFECT_CONFIRMATION,
    SCHEMA_CAPABILITY,
    SCHEMA_APPROVAL,
    SCHEMA_SUMMARY,
    SCHEMA_REFUSAL,
    SCHEMA_USAGE,
    SCHEMA_VERDICT,
    SCHEMA_PLAN,
    SCHEMA_RETRACTION,
    SCHEMA_CANDIDATE,
    SCHEMA_EVALUATION,
    SCHEMA_SELECTION,
];

/// All frozen schema names of the current epoch (for reverse lookup and
/// documentation).
pub const ALL_SCHEMAS: &[&str] = &[
    SCHEMA_REQUEST,
    SCHEMA_ACTION,
    SCHEMA_RESPONSE,
    SCHEMA_RESULT,
    SCHEMA_RESULT_EXTERNAL,
    SCHEMA_RESULT_EFFECT_CONFIRMATION,
    SCHEMA_CAPABILITY,
    SCHEMA_APPROVAL,
    SCHEMA_SUMMARY,
    SCHEMA_REFUSAL,
    SCHEMA_USAGE,
    SCHEMA_VERDICT,
    SCHEMA_PLAN,
    SCHEMA_RETRACTION,
    SCHEMA_CANDIDATE,
    SCHEMA_EVALUATION,
    SCHEMA_SELECTION,
    // Spec 0.4.
    SCHEMA_REQUIREMENT,
    SCHEMA_EVALUATION_V2,
    SCHEMA_EVALUATION_ATTESTED,
];

/// Resolve a schema hash to its registered frozen name, if known.
pub fn schema_name_for_id(id: &SchemaId) -> Option<&'static str> {
    ALL_SCHEMAS.iter().copied().find(|n| schema_id(n) == *id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_id_determinism() {
        let id1 = schema_id(SCHEMA_REQUEST);
        let id2 = schema_id(SCHEMA_REQUEST);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_schemas_different_ids() {
        let id1 = schema_id(SCHEMA_REQUEST);
        let id2 = schema_id(SCHEMA_ACTION);
        assert_ne!(id1, id2);
    }

    #[test]
    fn epochs_are_nested_and_the_current_one_is_complete() {
        // Every supported epoch has a schema set, the current epoch's set is
        // the full registry, and each earlier epoch's set is a subset of the
        // next (an epoch only ever adds schemas; SPEC §14).
        assert_eq!(schemas_for_epoch(SPEC_VERSION), Some(ALL_SCHEMAS));
        assert_eq!(SUPPORTED_SPEC_VERSIONS.last(), Some(&SPEC_VERSION));
        let mut previous: Option<&[&str]> = None;
        for v in SUPPORTED_SPEC_VERSIONS {
            let set = schemas_for_epoch(v).unwrap_or_else(|| panic!("epoch {v} has no schema set"));
            if let Some(p) = previous {
                for s in p {
                    assert!(set.contains(s), "epoch {v} dropped schema {s}");
                }
            }
            previous = Some(set);
        }
        assert_eq!(SCHEMAS_V03.len(), 17);
        for s in [
            SCHEMA_REQUIREMENT,
            SCHEMA_EVALUATION_V2,
            SCHEMA_EVALUATION_ATTESTED,
        ] {
            assert!(!SCHEMAS_V03.contains(&s), "{s} is a 0.4 schema");
            assert!(ALL_SCHEMAS.contains(&s));
        }
        assert!(schemas_for_epoch("0.2").is_none());
        assert!(schemas_for_epoch("0.5").is_none());
    }
}
