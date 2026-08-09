//! SHA-256 hashing utilities.

use crate::base::canonical::canonical_json;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// A raw 32-byte SHA-256 digest - the universal identifier representation
/// (record ids, space/thread/scope ids, schema ids). Hex-encoded (64 chars,
/// lowercase) at wire boundaries via [`hex_encode`]/[`hex_decode`].
pub type Hash256 = [u8; 32];

/// Compute SHA-256 of raw bytes.
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 of the canonical JSON representation of a value.
pub fn sha256_canonical<T: Serialize>(value: &T) -> Result<Hash256, serde_json::Error> {
    let bytes = canonical_json(value)?;
    Ok(sha256(&bytes))
}

/// Compute SHA-256 of a UTF-8 string.
pub fn sha256_utf8(s: &str) -> Hash256 {
    sha256(s.as_bytes())
}

/// Encode a Hash256 as lowercase hex string (64 chars).
pub fn hex_encode(hash: &Hash256) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a lowercase hex string (exactly 64 chars, `0-9a-f` only) into
/// Hash256. Strict by design: uppercase or non-ASCII input returns None -
/// never panics - so hex identifiers have exactly one accepted spelling
/// and untrusted input (e.g. a signature `key_id`) cannot crash a
/// verifier.
pub fn hex_decode(s: &str) -> Option<Hash256> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
    let mut result = [0u8; 32];
    for (i, out) in result.iter_mut().enumerate() {
        *out = (nibble(bytes[i * 2])? << 4) | nibble(bytes[i * 2 + 1])?;
    }
    Some(result)
}

/// Compute SHA-256(concat(record_ids[0..n])) for checkpoint log_hash.
pub fn sha256_concat_ids(ids: &[Hash256]) -> Hash256 {
    let mut hasher = Sha256::new();
    for id in ids {
        hasher.update(id);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_determinism() {
        let h1 = sha256(b"hello");
        let h2 = sha256(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let h = sha256(b"test");
        let hex = hex_encode(&h);
        assert_eq!(hex.len(), 64);
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn test_sha256_utf8() {
        let h1 = sha256_utf8("bellbook.request.v1");
        let h2 = sha256("bellbook.request.v1".as_bytes());
        assert_eq!(h1, h2);
    }
}
