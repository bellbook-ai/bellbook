//! Ed25519 signing and verification over the canonical signing form.
//!
//! A signature covers the RFC 8785 (JCS) domain-separated signing form with
//! `id` and `author.signature` omitted. The final record id is then computed
//! over the completed envelope with only `id` omitted, so the id binds the
//! signature without creating a circular dependency. `Signature.key_id`
//! carries the signer's Ed25519 public key as 64 lowercase hex characters, making
//! records self-describing; binding a key to an *actor* is done through
//! `VerifierRules::author_keys`.

use crate::base::hash::{hex_decode, hex_encode};
use crate::record::author::Signature;
use crate::record::record::Record;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Raw Ed25519 public key bytes, as pinned in `VerifierRules::author_keys`.
pub type PublicKeyBytes = [u8; 32];

/// Signs records with an Ed25519 key the host supplies. Key generation and
/// storage are host concerns; the crate only consumes the 32 secret bytes.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Build a signer from 32 secret key bytes (RFC 8032 seed).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    /// The signer's public key bytes.
    pub fn public_key(&self) -> PublicKeyBytes {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The signer's public key as lowercase hex - the `Signature.key_id`
    /// this signer produces.
    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.public_key())
    }

    /// Sign a record's domain-separated canonical signing form. The record's
    /// `id` and any existing signature are excluded by construction.
    pub fn sign(&self, record: &Record) -> Result<Signature, serde_json::Error> {
        let canonical = record.signing_bytes()?;
        let sig = self.signing_key.sign(&canonical);
        Ok(Signature {
            key_id: self.public_key_hex(),
            sig: sig.to_bytes().to_vec(),
        })
    }
}

/// Verify a record's attached signature against the public key its
/// `key_id` names. Returns false on any failure: absent signature,
/// malformed key or signature bytes, or cryptographic rejection
/// (`verify_strict`, so weak-key/malleable encodings are rejected the same
/// way in every conforming implementation).
pub fn signature_verifies(record: &Record) -> bool {
    verified_key(record).is_some()
}

/// As [`signature_verifies`], but returns the public key bytes the
/// signature verified against, for binding checks against
/// `VerifierRules::author_keys`.
pub fn verified_key(record: &Record) -> Option<PublicKeyBytes> {
    let sig = record.author.signature.as_ref()?;
    let key_bytes = hex_decode(&sig.key_id)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).ok()?;
    let sig_bytes: [u8; 64] = sig.sig.as_slice().try_into().ok()?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let canonical = record.signing_bytes().ok()?;
    verifying_key
        .verify_strict(&canonical, &signature)
        .ok()
        .map(|_| key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::schema::{schema_id, SCHEMA_REQUEST};
    use crate::record::author::Author;
    use crate::record::evidence::Evidence;
    use crate::record::kind::{AuthorType, Kind};

    fn test_record() -> Record {
        Record {
            id: [0u8; 32],
            space: [1u8; 32],
            thread: [2u8; 32],
            time: 1,
            author: Author {
                id: "human".into(),
                type_: AuthorType::User,
                signature: None,
            },
            kind: Kind::Request,
            schema: schema_id(SCHEMA_REQUEST),
            data: b"{}".to_vec(),
            refs: vec![],
            evidence: Evidence::Reported,
        }
        .with_computed_id()
        .unwrap()
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let signer = Ed25519Signer::from_secret_bytes(&[7u8; 32]);
        let mut record = test_record();
        let unsigned_id = record.id;
        record.author.signature = Some(signer.sign(&record).unwrap());
        record = record.with_computed_id().unwrap();
        // The completed signature is bound into the final record id.
        assert_ne!(record.id, unsigned_id);
        assert_eq!(record.compute_id().unwrap(), record.id);
        assert!(signature_verifies(&record));
        assert_eq!(verified_key(&record), Some(signer.public_key()));
    }

    #[test]
    fn test_tampered_content_fails() {
        let signer = Ed25519Signer::from_secret_bytes(&[7u8; 32]);
        let mut record = test_record();
        record.author.signature = Some(signer.sign(&record).unwrap());
        record.data = b"{\"altered\":true}".to_vec();
        assert!(!signature_verifies(&record));
    }

    #[test]
    fn test_cross_domain_signatures_fail() {
        let signer = Ed25519Signer::from_secret_bytes(&[7u8; 32]);
        let mut record = test_record();
        let current: serde_json::Value =
            serde_json::from_slice(&record.signing_bytes().unwrap()).unwrap();

        // The pre-domain-separation form is just the nested record object.
        let legacy = crate::base::canonical::canonical_json(&current["record"]).unwrap();
        let legacy_sig = signer.signing_key.sign(&legacy);
        record.author.signature = Some(Signature {
            key_id: signer.public_key_hex(),
            sig: legacy_sig.to_bytes().to_vec(),
        });
        assert!(!signature_verifies(&record));

        // A signature carrying another Bellbook epoch's domain also fails:
        // the previous epoch (v0.2) and a hypothetical future one (v0.4).
        for other_domain in [
            "bellbook.record-signature.v0.2",
            "bellbook.record-signature.v0.4",
        ] {
            let mut other = current.clone();
            other["domain"] = serde_json::Value::String(other_domain.into());
            let other_bytes = crate::base::canonical::canonical_json(&other).unwrap();
            let other_sig = signer.signing_key.sign(&other_bytes);
            record.author.signature = Some(Signature {
                key_id: signer.public_key_hex(),
                sig: other_sig.to_bytes().to_vec(),
            });
            assert!(
                !signature_verifies(&record),
                "a {other_domain} signature must not verify as the current epoch"
            );
        }
    }

    #[test]
    fn test_malformed_signature_fails() {
        let signer = Ed25519Signer::from_secret_bytes(&[7u8; 32]);
        let mut record = test_record();
        let mut sig = signer.sign(&record).unwrap();
        sig.sig[0] ^= 0xff;
        record.author.signature = Some(sig);
        assert!(!signature_verifies(&record));

        // Garbage key_id.
        let mut sig2 = signer.sign(&record).unwrap();
        sig2.key_id = "not-hex".into();
        record.author.signature = Some(sig2);
        assert!(!signature_verifies(&record));

        // Absent signature.
        record.author.signature = None;
        assert!(!signature_verifies(&record));
    }
}
