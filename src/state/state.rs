//! State struct from SPEC.md.

use crate::base::canonical::map_as_pairs;
use crate::base::hash::Hash256;
use crate::base::time::Time;
use crate::record::author::ActorId;
use crate::record::evidence::Evidence;
use crate::record::kind::RefType;
use crate::record::payloads::UsageOutcomeCounts;
use crate::record::record::{Record, ScopeId};
use crate::record::refs::{RecordId, Ref};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Effective state derived from committed records and verdicts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Ids of every record whose verdict was Accept; rejected records never
    /// appear anywhere in state.
    pub accepted_records: BTreeSet<RecordId>,
    /// Requests not yet terminal: a request leaves on an explicit terminal
    /// event - a Response with `closes_request` (only valid with no open
    /// actions) or a Refusal targeting it directly. Completion is never
    /// inferred from a transient zero count of open actions.
    pub active_requests: BTreeSet<RecordId>,
    /// (actor_id, action_class, scope) → latest accepted Capability record;
    /// the lookup key Actions are checked against.
    #[serde(with = "map_as_pairs")]
    pub active_capabilities: BTreeMap<(ActorId, String, ScopeId), RecordId>,
    /// Exact approvals: SHA-256(canonical((action_author_id, ActionData)))
    /// → Approval record id; consulted first for Ask-mode actions. The
    /// hash binds the acting author together with the action content, and
    /// entries are removed when consumed (exact approvals are single-use).
    #[serde(with = "map_as_pairs")]
    pub valid_approvals: BTreeMap<Hash256, RecordId>,
    /// Class approvals: (action_class, scope, Some(actor) | None for
    /// wildcard) → Approval record id; consulted after exact matches.
    #[serde(with = "map_as_pairs")]
    pub class_approvals: BTreeMap<(String, ScopeId, Option<ActorId>), RecordId>,
    /// Accepted Actions not yet closed by a Result or an action-targeting
    /// Refusal.
    pub open_actions: BTreeSet<RecordId>,
    /// Action id → owning request id; used to decrement the request's open
    /// count when the action closes.
    #[serde(with = "map_as_pairs")]
    pub action_to_request: BTreeMap<RecordId, RecordId>,
    /// SHA-256(canonical((summary_type, subject, scope))) → latest accepted
    /// Summary record id for that identity.
    #[serde(with = "map_as_pairs")]
    pub active_summaries: BTreeMap<Hash256, RecordId>,
    /// Targets of accepted Replace refs. Superseded but never deleted;
    /// excluded from context selection.
    pub replaced_records: BTreeSet<RecordId>,
    /// Per-request count of still-open actions (the entry is removed at
    /// zero for map hygiene). Reaching zero does NOT complete the request:
    /// completion is only ever the explicit closing Response or a
    /// request-targeting Refusal. This count gates closing (a closing
    /// Response is invalid while it is non-zero).
    #[serde(with = "map_as_pairs")]
    pub request_open_action_count: BTreeMap<RecordId, u64>,
    /// (used_record, role) → tallied usage outcomes, fed back into context
    /// as usage feedback.
    #[serde(with = "map_as_pairs")]
    pub usage_counts: BTreeMap<(RecordId, String), UsageOutcomeCounts>,
    /// Maps request_id → active plan record_id.
    #[serde(with = "map_as_pairs")]
    pub active_plans: BTreeMap<RecordId, RecordId>,
    /// Request id → count of accepted Responses so far; a Response's
    /// `turn_index` must equal this count (gap-free, in order).
    #[serde(with = "map_as_pairs")]
    pub response_turns: BTreeMap<RecordId, u32>,
    /// Capability record id → its (actor, action_class, scope) key. Reverse
    /// index so a Retraction can deactivate the capability in O(log n)
    /// (linear-cost replay, SPEC §12.3).
    #[serde(with = "map_as_pairs")]
    pub capability_index: BTreeMap<RecordId, (ActorId, String, ScopeId)>,
    /// Exact-approval record id → the action hash it approves. Reverse
    /// index for retraction-time deactivation.
    #[serde(with = "map_as_pairs")]
    pub exact_approval_index: BTreeMap<RecordId, Hash256>,
    /// Class-approval record id → its (action_class, scope, actor) key.
    /// Reverse index for retraction-time deactivation.
    #[serde(with = "map_as_pairs")]
    pub class_approval_index: BTreeMap<RecordId, (String, ScopeId, Option<ActorId>)>,
    /// Targets of accepted Retractions: records whose content was asserted
    /// WRONG. They stay in the log (append-only) but are excluded from
    /// context selection, and epistemic dependence on them taints.
    pub retracted_records: BTreeSet<RecordId>,
    /// Records that epistemically depend - transitively, via `Use`/`Require`
    /// refs - on a retracted record. Tainted records replay and verify
    /// normally; taint marks their content unreliable, not the history
    /// invalid.
    pub tainted_records: BTreeSet<RecordId>,
    /// Reverse epistemic-dependence index: target → accepted records holding
    /// a `Use`/`Require` ref to it. Lets a late retraction taint dependents
    /// committed before it.
    #[serde(with = "map_as_pairs")]
    pub epistemic_dependents: BTreeMap<RecordId, BTreeSet<RecordId>>,
    /// Request id → keys of its accepted, unretracted Requirements (spec
    /// 0.4). A Requirement whose key is already here rejects with
    /// `RequirementInvalid`; retracting a Requirement releases its key so a
    /// corrected one can carry the same handle.
    #[serde(default, with = "map_as_pairs")]
    pub requirement_keys: BTreeMap<RecordId, BTreeSet<String>>,
    /// Requirement record id → (request id, key). Reverse index for
    /// retraction-time key release.
    #[serde(default, with = "map_as_pairs")]
    pub requirement_index: BTreeMap<RecordId, (RecordId, String)>,
    /// Logical time of the last record (subject or verdict) folded into this
    /// state; 0 for an empty log.
    pub applied_up_to: Time,
}

impl State {
    /// The evidence a ref contributes to weakest-link derivation, or None
    /// when the ref does not participate. Only `Use`/`Require` refs are
    /// epistemic dependence and contribute (degraded to the floor,
    /// `Assumed`, when the target is retracted or tainted).
    /// `Cause`/`Replace` refs are provenance, not epistemic dependence
    /// (SPEC §7.1): they never affect derived evidence, exactly as they
    /// never propagate taint - a Result exists because of its Action
    /// without resting on the action's claim.
    pub fn ref_evidence(&self, ref_: &Ref, target: &Record) -> Option<Evidence> {
        match ref_.type_ {
            RefType::Use | RefType::Require => {
                if !self.accepted_records.contains(&target.id)
                    || self.retracted_records.contains(&target.id)
                    || self.tainted_records.contains(&target.id)
                {
                    // Rejected, retracted, or tainted content contributes
                    // the floor: depending on it is an unverified
                    // assumption.
                    Some(Evidence::Assumed)
                } else {
                    Some(target.evidence)
                }
            }
            RefType::Cause | RefType::Replace => None,
        }
    }
}
