//! VerifierRules from SPEC.md.

use crate::base::canonical::{map_as_pairs, strict_map, strict_set};
use crate::base::hash::Hash256;
use crate::base::schema::*;
use crate::record::author::ActorId;
use crate::record::evidence::Evidence;
use crate::record::kind::{AuthorType, Kind, SummaryType};
use crate::record::payloads::BindingMode;
use crate::record::record::SpaceId;
use crate::record::sign::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Static rule configuration for the Verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRules {
    /// The single trust domain this verifier accepts; records in any other
    /// space are rejected.
    pub space: SpaceId,
    /// Frozen schema id → expected Kind. Unknown schemas reject with
    /// `UnknownSchema`, mismatched kinds with `KindSchemaMismatch`.
    #[serde(with = "map_as_pairs")]
    pub kind_schema_map: BTreeMap<Hash256, Kind>,
    /// Kinds whose author must carry a signature (`SignatureMissing`
    /// otherwise). Empty by default. Must not contain `Kind::Verdict`:
    /// verdicts are materialized unsigned by the commit protocol and take
    /// their own verification path.
    #[serde(with = "strict_set")]
    pub signature_required_kinds: BTreeSet<Kind>,
    /// Actor id → Ed25519 public keys that actor may sign with. A listed
    /// actor's records **always require a signature** (`SignatureMissing`
    /// otherwise - an actor id is just a string anyone can write, so an
    /// unsigned record claiming a pinned identity would bypass exactly
    /// the authentication pinning provides), and the signature must
    /// verify against one of the pinned keys (`SignatureInvalid`
    /// otherwise) - this is what binds a key to an identity. Unlisted
    /// actors may sign with any key; the signature still must verify.
    /// Empty by default.
    #[serde(with = "strict_author_keys")]
    pub author_keys: BTreeMap<ActorId, BTreeSet<PublicKeyBytes>>,
    /// Actor id → the single author role it holds. The envelope's declared
    /// `author.type` is adversary-controlled, so the kind-to-role table
    /// alone cannot stop a governed agent from *claiming* `User` on an
    /// Approval; this map binds identities to roles. A registered actor's
    /// records must declare exactly the registered role, and for **every
    /// kind except `Verdict`** the author MUST be registered here
    /// (unregistered authors reject with `AuthorRoleInvalid`). Note that
    /// registration binds the id to a role, not the record to a person:
    /// an actor id is only *authenticated* when the actor also has pinned
    /// keys in `author_keys`, which makes its signature mandatory.
    #[serde(with = "strict_map")]
    pub author_roles: BTreeMap<ActorId, AuthorType>,
    /// Actors allowed to retract records they did not author (an
    /// administrative override; e.g. the human principal). A Retraction is
    /// otherwise valid only when its author is the target's author -
    /// disagreement with *someone else's* record is contrary evidence or a
    /// Refusal, not a Retraction. Empty by default.
    #[serde(with = "strict_set")]
    pub admin_retraction_actors: BTreeSet<ActorId>,
    /// Summary types a Summary record may use; others reject with
    /// `InvalidPayload`.
    #[serde(with = "strict_set")]
    pub allowed_summary_types: BTreeSet<SummaryType>,
    /// Minimum evidence strength per kind: a record whose *derived*
    /// evidence is weaker than the threshold configured for its kind is
    /// rejected with `EvidenceBelowThreshold`. Empty by default (no
    /// thresholds). E.g. `{Kind::Summary: Evidence::Verified}` enforces
    /// "summaries may only rest on deterministic or verified inputs".
    #[serde(with = "strict_map")]
    pub evidence_thresholds: BTreeMap<Kind, Evidence>,
    /// Maximum number of records `build_context` selects per thread.
    pub max_context_records: u32,
    /// Minimum source binding mode a `Candidate` referenced by a Selection's
    /// winner `Require` refs must carry. `Reported` (the default) imposes no
    /// constraint; `Manifest` requires every selected candidate to bind a
    /// canonical manifest, rejecting a selection over merely reported
    /// bindings with `SelectionInvalid` (spec 0.3, delta D3).
    #[serde(default = "default_min_binding")]
    pub min_binding: BindingMode,
    /// Whether a `Selected` `Selection` must `Use` at least one `Evaluation`
    /// (default true): a decision with no evaluation evidence rejects with
    /// `SelectionInvalid`. Set false for hosts that record ungrounded
    /// selections deliberately (spec 0.3, delta D3).
    #[serde(default = "default_true")]
    pub selection_requires_evaluation: bool,
    /// Identity allowlist for reaffirming Selections (those carrying a
    /// `Replace` ref). When non-empty, a reaffirmation whose author is not
    /// listed rejects with `ReaffirmationInvalid`; empty (the default) lets
    /// the Selection author-role row alone govern (spec 0.3, delta D4).
    #[serde(default, with = "strict_set")]
    pub reaffirmation_actors: BTreeSet<ActorId>,
    /// Maximum length of a `Selection`'s `considered` list (default 4096).
    /// `considered` members are payload ids and carry no refs, so this bound
    /// is independent of `ValidationLimits::max_refs_per_record`; a
    /// comparative selection that `Use`s one evaluation per considered
    /// candidate is still bounded by the receipt ref limit (spec 0.3,
    /// delta D3).
    #[serde(default = "default_max_considered")]
    pub max_considered: u32,
    /// Whether every `Selection` must carry a valid, unconsumed `Require`d
    /// approval whose subject hash binds the selecting author, the Replace
    /// target (or null), and the `SelectionData` (SPEC §4.1, spec 0.3
    /// delta D5). Default false. When true, a Selection with no matching
    /// approval rejects with `ApprovalMissing` (or `ApprovalExpired`), and an
    /// accepted Selection consumes the approval single-use, exactly like the
    /// Action path.
    #[serde(default)]
    pub selection_requires_approval: bool,
    /// Whether a `Continuation` candidate whose anchor Selection is unsound
    /// (retracted or tainted) at its commit position is rejected with
    /// `LineageInvalid` (SPEC §7.2, spec 0.3 delta D6). Default false: by
    /// default a continuation of an unsound Selection commits and is born
    /// standing-compromised, because a ledger that cannot record ongoing
    /// work stops being a ledger. Hosts that want commit-time strictness set
    /// this.
    #[serde(default)]
    pub reject_compromised_continuation: bool,
}

/// Default `min_binding`: `Reported` imposes no minimum.
fn default_min_binding() -> BindingMode {
    BindingMode::Reported
}

/// Default `selection_requires_evaluation`: a Selected selection must rest
/// on at least one evaluation.
fn default_true() -> bool {
    true
}

/// Default `max_considered`: matches `ValidationLimits::max_refs_per_record`.
fn default_max_considered() -> u32 {
    4096
}

mod strict_author_keys {
    use super::{ActorId, BTreeMap, BTreeSet, PublicKeyBytes};
    use serde::de::{Error as _, MapAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::fmt;

    pub fn serialize<S>(
        map: &BTreeMap<ActorId, BTreeSet<PublicKeyBytes>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        map.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<ActorId, BTreeSet<PublicKeyBytes>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AuthorKeysVisitor;

        impl<'de> Visitor<'de> for AuthorKeysVisitor {
            type Value = BTreeMap<ActorId, BTreeSet<PublicKeyBytes>>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an actor-key object with unique actors and keys")
            }

            fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((actor, keys)) =
                    entries.next_entry::<ActorId, Vec<PublicKeyBytes>>()?
                {
                    let mut unique = BTreeSet::new();
                    for key in keys {
                        if !unique.insert(key) {
                            return Err(A::Error::custom("duplicate key for author"));
                        }
                    }
                    if map.insert(actor, unique).is_some() {
                        return Err(A::Error::custom("duplicate author in author_keys"));
                    }
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(AuthorKeysVisitor)
    }
}

impl VerifierRules {
    /// Build the default verifier rules: the frozen schema map, no signature
    /// requirements, all summary types allowed.
    pub fn new(space: SpaceId, max_context_records: u32) -> Self {
        Self {
            space,
            kind_schema_map: frozen_kind_schema_map(),
            signature_required_kinds: BTreeSet::new(),
            author_keys: BTreeMap::new(),
            author_roles: BTreeMap::new(),
            admin_retraction_actors: BTreeSet::new(),
            allowed_summary_types: all_summary_types(),
            evidence_thresholds: BTreeMap::new(),
            max_context_records,
            min_binding: default_min_binding(),
            selection_requires_evaluation: default_true(),
            reaffirmation_actors: BTreeSet::new(),
            max_considered: default_max_considered(),
            selection_requires_approval: false,
            reject_compromised_continuation: false,
        }
    }

    /// Register an actor's role (see `author_roles`). Returns self for
    /// chaining during rules construction.
    pub fn with_author_role(mut self, actor: impl Into<ActorId>, role: AuthorType) -> Self {
        self.author_roles.insert(actor.into(), role);
        self
    }

    /// Allow an actor to retract records it did not author (see
    /// `admin_retraction_actors`). The actor still needs an `author_roles`
    /// binding for its Retraction records to be accepted at all. Returns
    /// self for chaining during rules construction.
    pub fn with_admin_retraction_actor(mut self, actor: impl Into<ActorId>) -> Self {
        self.admin_retraction_actors.insert(actor.into());
        self
    }

    /// Set the minimum evidence strength for a kind (see
    /// `evidence_thresholds`). Returns self for chaining during rules
    /// construction.
    pub fn with_evidence_threshold(mut self, kind: Kind, threshold: Evidence) -> Self {
        self.evidence_thresholds.insert(kind, threshold);
        self
    }

    /// Apply the `bellbook-core-v1` baseline thresholds (RFC-0003 section
    /// 4.5, clause B3): Candidate and Evaluation no weaker than `Reported`,
    /// Selection no weaker than `Inferred` - each exactly the schema base
    /// class, so the rules admit nothing weaker than what the kinds already
    /// derive. `rules init` and `default_rules` apply this by default so
    /// generated rule sets are baseline-conformant.
    pub fn with_baseline_thresholds(self) -> Self {
        self.with_evidence_threshold(Kind::Candidate, Evidence::Reported)
            .with_evidence_threshold(Kind::Evaluation, Evidence::Reported)
            .with_evidence_threshold(Kind::Selection, Evidence::Inferred)
    }

    /// Restrict reaffirming Selections to an identity allowlist (see
    /// `reaffirmation_actors`); the first call switches the set from
    /// "anyone with a valid role" to "listed actors only". Returns self for
    /// chaining during rules construction.
    pub fn with_reaffirmation_actor(mut self, actor: impl Into<ActorId>) -> Self {
        self.reaffirmation_actors.insert(actor.into());
        self
    }
}

/// Build the frozen kind-schema map.
pub fn frozen_kind_schema_map() -> BTreeMap<Hash256, Kind> {
    let mut map = BTreeMap::new();
    map.insert(schema_id(SCHEMA_REQUEST), Kind::Request);
    map.insert(schema_id(SCHEMA_ACTION), Kind::Action);
    map.insert(schema_id(SCHEMA_RESPONSE), Kind::Response);
    map.insert(schema_id(SCHEMA_RESULT), Kind::Result);
    map.insert(schema_id(SCHEMA_RESULT_EXTERNAL), Kind::Result);
    map.insert(schema_id(SCHEMA_RESULT_EFFECT_CONFIRMATION), Kind::Result);
    map.insert(schema_id(SCHEMA_CAPABILITY), Kind::Capability);
    map.insert(schema_id(SCHEMA_APPROVAL), Kind::Approval);
    map.insert(schema_id(SCHEMA_SUMMARY), Kind::Summary);
    map.insert(schema_id(SCHEMA_REFUSAL), Kind::Refusal);
    map.insert(schema_id(SCHEMA_USAGE), Kind::Usage);
    map.insert(schema_id(SCHEMA_VERDICT), Kind::Verdict);
    map.insert(schema_id(SCHEMA_PLAN), Kind::Plan);
    map.insert(schema_id(SCHEMA_RETRACTION), Kind::Retraction);
    map.insert(schema_id(SCHEMA_CANDIDATE), Kind::Candidate);
    map.insert(schema_id(SCHEMA_EVALUATION), Kind::Evaluation);
    map.insert(schema_id(SCHEMA_SELECTION), Kind::Selection);
    map.insert(schema_id(SCHEMA_REQUIREMENT), Kind::Requirement);
    map
}

/// All summary types the default rules allow.
pub fn all_summary_types() -> BTreeSet<SummaryType> {
    let mut set = BTreeSet::new();
    set.insert(SummaryType::Procedure);
    set.insert(SummaryType::Pattern);
    set.insert(SummaryType::Lesson);
    set.insert(SummaryType::StateSnapshot);
    set
}
