//! Author and Signature structs.

use crate::record::kind::AuthorType;
use serde::{Deserialize, Serialize};

/// Free-form actor identifier (e.g. `"human"`, a provider name, or a tool
/// executor id); keys capability and approval lookups.
pub type ActorId = String;

/// Detached Ed25519 signature over a record's domain-separated canonical
/// signing form (SPEC §3.2). The completed signature is included in the record id. Any
/// present signature must verify or the record rejects with
/// `SignatureInvalid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// The signer's Ed25519 public key as 64 lowercase hex characters.
    pub key_id: String,
    /// The 64 raw Ed25519 signature bytes; included in the final record id.
    pub sig: Vec<u8>,
}

/// Who produced a record. The id is cryptographically bound only when the
/// record is signed and the actor's keys are pinned in
/// `VerifierRules::author_keys`; otherwise it is a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Author {
    /// Actor identifier; for Actions it must match an active capability's
    /// `actor_id`.
    pub id: ActorId,
    /// Actor category (User, Provider, System, Executor, or Verifier).
    #[serde(rename = "type")]
    pub type_: AuthorType,
    /// Optional detached signature. It is omitted from the signing form but
    /// included in the final record id. Required for kinds listed in
    /// `VerifierRules::signature_required_kinds` AND, on every kind, for
    /// any actor with pinned keys in `VerifierRules::author_keys` - a
    /// pinned identity is only ever accepted signed. Verdict records are
    /// the exception: materialized unsigned by the commit protocol, and a
    /// present signature on one rejects (unverified signature bytes would
    /// be receipt malleability).
    pub signature: Option<Signature>,
}
