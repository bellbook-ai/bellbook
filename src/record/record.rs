//! Core Record and Proposal structs from SPEC.md.

use crate::base::canonical::canonical_json;
use crate::base::hash::{sha256, Hash256};
use crate::base::time::Time;
use crate::record::author::Author;
use crate::record::evidence::Evidence;
use crate::record::kind::Kind;
use crate::record::refs::{RecordId, Ref};
use serde::{Deserialize, Serialize};

/// Trust-domain identifier; refs never cross spaces, and the verifier
/// rejects records whose space differs from `VerifierRules::space`.
pub type SpaceId = Hash256;
/// Conversation/work grouping within a space; context selection filters by
/// thread, and Actions/Results must share their request's thread.
pub type ThreadId = Hash256;
/// Scope hash carried by requests, actions, capabilities, and approvals;
/// part of the capability/approval lookup keys.
pub type ScopeId = Hash256;

/// Protocol and spec-version domain bound into every record signature.
/// Keeping this in the signed bytes prevents a valid signature from another
/// protocol or Bellbook spec epoch from being replayed as a v0.2 record.
pub const RECORD_SIGNATURE_DOMAIN: &str = "bellbook.record-signature.v0.3";

/// The one durable primitive: a typed, content-addressed entry in the
/// append-only log. Immutable once committed - the id covers everything but
/// itself. The completed detached signature is part of the id, so record
/// identity and head attestations bind the exact signed envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Content address: SHA-256 of the canonical id form (only `id`
    /// omitted; a completed signature is included), recomputed and checked
    /// by the verifier.
    pub id: RecordId,
    /// Trust domain; must equal the verifier's configured space.
    pub space: SpaceId,
    /// Conversation/work grouping this record belongs to.
    pub thread: ThreadId,
    /// Logical commit counter; strictly `prev + 1`, starting at 1.
    pub time: Time,
    /// Who produced the record; a completed signature is included in the id.
    pub author: Author,
    /// Record type; must agree with what the frozen map assigns to `schema`.
    pub kind: Kind,
    /// SHA-256 of the frozen schema name governing `data`'s payload shape.
    pub schema: Hash256,
    /// JSON payload bytes for the schema, decoded via [`decode`].
    pub data: Vec<u8>,
    /// Typed edges to prior records; sorted by (type ordinal, target bytes)
    /// and deduped before hashing.
    pub refs: Vec<Ref>,
    /// Trust class; must equal the value derived from the schema and the
    /// refs' evidence, or the verifier rejects the record.
    pub evidence: Evidence,
}

impl Record {
    /// Compute the canonical id form and derive the record id.
    ///
    /// The id form excludes only `id`; a completed detached signature is
    /// included. This makes record ids and head attestations bind the exact
    /// signed envelope.
    pub fn with_computed_id(mut self) -> Result<Self, serde_json::Error> {
        self.id = self.compute_id()?;
        Ok(self)
    }

    /// Compute the id without setting it.
    pub fn compute_id(&self) -> Result<RecordId, serde_json::Error> {
        Ok(sha256(&self.canonical_id_form()?))
    }

    /// Produce the canonical bytes used for the record id.
    /// Only `id` is excluded; `author.signature` is included.
    pub fn canonical_id_form(&self) -> Result<Vec<u8>, serde_json::Error> {
        let id_form = CanonicalIdForm {
            space: &self.space,
            thread: &self.thread,
            time: self.time,
            author: CanonicalIdAuthor {
                id: &self.author.id,
                type_: &self.author.type_,
                signature: self.author.signature.as_ref(),
            },
            kind: &self.kind,
            schema: &self.schema,
            data: &self.data,
            refs: &self.refs,
            evidence: &self.evidence,
        };
        canonical_json(&id_form)
    }

    /// Produce the canonical bytes covered by an Ed25519 signature.
    ///
    /// Both `id` and `author.signature` are excluded, avoiding a circular
    /// dependency while signing every semantic field of the record. The
    /// canonical form is wrapped with [`RECORD_SIGNATURE_DOMAIN`] so the
    /// signature cannot be replayed across protocols or spec epochs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let signing_form = DomainSeparatedSigningForm {
            domain: RECORD_SIGNATURE_DOMAIN,
            record: CanonicalSigningForm {
                space: &self.space,
                thread: &self.thread,
                time: self.time,
                author: CanonicalAuthor {
                    id: &self.author.id,
                    type_: &self.author.type_,
                },
                kind: &self.kind,
                schema: &self.schema,
                data: &self.data,
                refs: &self.refs,
                evidence: &self.evidence,
            },
        };
        canonical_json(&signing_form)
    }
}

/// Top-level signature envelope. This is deliberately part of the canonical
/// bytes rather than an implicit API parameter, so independent implementations
/// have one exact, inspectable signing input.
#[derive(Serialize)]
struct DomainSeparatedSigningForm<'a> {
    domain: &'static str,
    record: CanonicalSigningForm<'a>,
}

/// Internal struct for computing the record id. Excludes only `id`.
#[derive(Serialize)]
struct CanonicalIdForm<'a> {
    space: &'a SpaceId,
    thread: &'a ThreadId,
    time: Time,
    author: CanonicalIdAuthor<'a>,
    kind: &'a Kind,
    schema: &'a Hash256,
    data: &'a Vec<u8>,
    refs: &'a Vec<Ref>,
    evidence: &'a Evidence,
}

#[derive(Serialize)]
struct CanonicalIdAuthor<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    type_: &'a crate::record::kind::AuthorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a crate::record::author::Signature>,
}

/// Internal struct for signature input. Excludes `id` and the signature.
#[derive(Serialize)]
struct CanonicalSigningForm<'a> {
    space: &'a SpaceId,
    thread: &'a ThreadId,
    time: Time,
    author: CanonicalAuthor<'a>,
    kind: &'a Kind,
    schema: &'a Hash256,
    data: &'a Vec<u8>,
    refs: &'a Vec<Ref>,
    evidence: &'a Evidence,
}

#[derive(Serialize)]
struct CanonicalAuthor<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    type_: &'a crate::record::kind::AuthorType,
}

/// A proposal is what the Proposer emits before commit.
/// No `id`, no `time`, no `evidence` - these are assigned at commit time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// Trust domain the resulting record will live in.
    pub space: SpaceId,
    /// Thread the resulting record will belong to.
    pub thread: ThreadId,
    /// Claimed author of the proposed record.
    pub author: Author,
    /// Proposed record type; verified against `schema` at commit.
    pub kind: Kind,
    /// SHA-256 of the frozen schema name for `data`.
    pub schema: Hash256,
    /// JSON payload bytes for the schema.
    pub data: Vec<u8>,
    /// Refs as supplied by the proposer; sorted and deduped during commit,
    /// before the id is computed.
    pub refs: Vec<Ref>,
}

/// Decode payload bytes into a typed struct.
pub fn decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(data)
}

/// Encode payload struct into canonical JSON bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    canonical_json(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::kind::*;

    fn test_record() -> Record {
        Record {
            id: [0u8; 32],
            space: [1u8; 32],
            thread: [2u8; 32],
            time: 1,
            author: Author {
                id: "test".into(),
                type_: AuthorType::User,
                signature: None,
            },
            kind: Kind::Request,
            schema: [3u8; 32],
            data: b"{}".to_vec(),
            refs: vec![],
            evidence: Evidence::Reported,
        }
    }

    #[test]
    fn test_with_computed_id() {
        let record = test_record().with_computed_id().unwrap();
        // id should not be all zeros anymore
        assert_ne!(record.id, [0u8; 32]);
        // Computing again should give the same id
        let id2 = record.compute_id().unwrap();
        assert_eq!(record.id, id2);
    }

    #[test]
    fn test_id_form_excludes_id_but_binds_signature() {
        let mut r1 = test_record();
        r1.id = [99u8; 32];
        let mut r2 = r1.clone();
        r2.id = [88u8; 32];
        assert_eq!(
            r1.canonical_id_form().unwrap(),
            r2.canonical_id_form().unwrap()
        );

        r2.author.signature = Some(crate::record::author::Signature {
            key_id: "11".repeat(32),
            sig: vec![1; 64],
        });
        assert_ne!(
            r1.canonical_id_form().unwrap(),
            r2.canonical_id_form().unwrap()
        );
        assert_ne!(r1.compute_id().unwrap(), r2.compute_id().unwrap());
    }

    #[test]
    fn test_signing_bytes_exclude_id_and_signature() {
        let mut r1 = test_record();
        r1.id = [99u8; 32];
        r1.author.signature = Some(crate::record::author::Signature {
            key_id: "11".repeat(32),
            sig: vec![1; 64],
        });

        let mut r2 = test_record();
        r2.id = [88u8; 32];
        r2.author.signature = None;

        assert_eq!(r1.signing_bytes().unwrap(), r2.signing_bytes().unwrap());

        let value: serde_json::Value =
            serde_json::from_slice(&r1.signing_bytes().unwrap()).unwrap();
        assert_eq!(value["domain"], RECORD_SIGNATURE_DOMAIN);
        assert!(value.get("record").is_some());
    }

    #[test]
    fn test_id_determinism() {
        let r1 = test_record().with_computed_id().unwrap();
        let r2 = test_record().with_computed_id().unwrap();
        assert_eq!(r1.id, r2.id);
    }
}
