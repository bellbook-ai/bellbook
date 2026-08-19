//! Checkpoint creation and verification from SPEC.md.

use crate::base::hash::{sha256_canonical, sha256_concat_ids, Hash256};
use crate::base::time::Time;
use crate::record::record::Record;
use crate::record::refs::RecordId;
use crate::state::state::State;
use serde::{Deserialize, Serialize};

/// Trusted summary of a log prefix from which `verify_log` can resume
/// instead of replaying from genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Number of records in the covered prefix (subjects and verdicts).
    pub log_length: u64,
    /// Logical time of the prefix's final record; 0 for an empty prefix.
    pub last_time: Time,
    /// Id of the prefix's final record; all zeros for an empty prefix.
    pub last_record_id: RecordId,
    /// SHA-256(canonical(State)) after folding the prefix.
    pub state_hash: Hash256,
    /// SHA-256(concat(record ids)) over the prefix; `verify_log` recomputes
    /// this and rejects with `InvalidCheckpoint` on mismatch.
    pub log_hash: Hash256,
}

/// Create a checkpoint from the current records and state.
/// Records must be in ascending time order.
pub fn create_checkpoint(
    records: &[Record],
    state: &State,
) -> Result<Checkpoint, serde_json::Error> {
    let ids: Vec<Hash256> = records.iter().map(|r| r.id).collect();
    Ok(Checkpoint {
        log_length: records.len() as u64,
        last_time: records.last().map(|r| r.time).unwrap_or(0),
        last_record_id: records.last().map(|r| r.id).unwrap_or([0u8; 32]),
        state_hash: sha256_canonical(state)?,
        log_hash: sha256_concat_ids(&ids),
    })
}

/// A checkpoint whose covered prefix is known to have passed full replay
/// verification under a specific rule set - the **only** thing
/// `verify_log` accepts as a verification-skipping accelerator.
///
/// This type is deliberately opaque: it does not implement `Serialize`/
/// `Deserialize`, so a `TrustedCheckpoint` cannot arrive over the wire.
/// Trust is not data. It is created in exactly two ways:
///
/// - [`TrustedCheckpoint::from_verified_log`] - runs full replay
///   verification and only succeeds on Accept. This is the safe path.
/// - [`TrustedCheckpoint::assume_verified`] - the caller *asserts* the
///   checkpoint came from a prior successful verification under the same
///   rules (e.g. it was produced by `from_verified_log` in an earlier
///   process and stored where attackers cannot write). Grep for this name
///   in code review: every call site is a trust assertion.
///
/// External anchoring (§11.1) is **not** a trust path: an anchored
/// attestation proves bytes existed and were not later rewritten - it
/// says nothing about whether those bytes ever passed verification. An
/// attacker can anchor a forged history. Anchoring protects a *verified*
/// checkpoint against subsequent rewriting; it never substitutes for
/// verification.
///
/// The checkpoint is bound to the rules it was verified under; passing it
/// to `verify_log` with different rules rejects with `InvalidCheckpoint`.
pub struct TrustedCheckpoint {
    checkpoint: Checkpoint,
    rules_hash: Hash256,
}

impl TrustedCheckpoint {
    /// Run full replay verification (from genesis, no acceleration) and,
    /// on Accept, return a trusted checkpoint covering the whole log.
    /// Returns None if verification rejects.
    pub fn from_verified_log(
        records: &[Record],
        rules: &crate::verify::rules::VerifierRules,
    ) -> Option<Self> {
        let verdict = crate::verify::verifier::verify_log(records, rules, None);
        if verdict.result != crate::record::kind::VerdictResult::Accept {
            return None;
        }
        let state = crate::state::build::build_state_unchecked(records).ok()?;
        let checkpoint = create_checkpoint(records, &state).ok()?;
        Some(Self {
            checkpoint,
            rules_hash: sha256_canonical(rules).ok()?,
        })
    }

    /// Assert that `checkpoint` was produced by a prior successful
    /// Bellbook verification of its prefix under exactly these `rules`,
    /// and has been stored somewhere the ledger's writer cannot rewrite.
    ///
    /// This is an explicit trust assertion, not a check - nothing is
    /// verified here. If the assertion is wrong, `verify_log` will accept
    /// a prefix containing verdicts it would reject on full replay. When
    /// in doubt, use [`from_verified_log`](TrustedCheckpoint::from_verified_log).
    pub fn assume_verified(
        checkpoint: Checkpoint,
        rules: &crate::verify::rules::VerifierRules,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            checkpoint,
            rules_hash: sha256_canonical(rules)?,
        })
    }

    /// The underlying checkpoint data.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    pub(crate) fn rules_hash(&self) -> &Hash256 {
        &self.rules_hash
    }
}

/// The canonical head attestation (SPEC §11.1): the minimal JCS-canonical
/// structure an integrator anchors externally - in a host database, a
/// transparency log, or a timestamping service - so the ledger's writer
/// cannot silently rewrite history from genesis. This crate defines only
/// the format; witnesses and anchoring transport are host concerns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadAttestation {
    /// SHA-256 over the concatenated ids of every record in the log -
    /// the same computation as `Checkpoint::log_hash`, taken at the head.
    /// Record ids bind completed signatures, so this also binds the exact
    /// signed envelopes.
    pub head_hash: Hash256,
    /// Number of records (subjects and verdicts) the hash covers.
    pub record_count: u64,
    /// The spec version governing the attested records (e.g. `"0.3"`).
    pub spec_version: String,
    /// Host-supplied wall-clock time of attestation. The type enforces the
    /// canonical RFC 3339 UTC spelling `YYYY-MM-DDTHH:MM:SSZ`.
    pub timestamp: CanonicalUtcTimestamp,
}

/// The supplied head-attestation timestamp is not canonical RFC 3339 UTC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTimestamp;

impl std::fmt::Display for InvalidTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "head attestation timestamps must be canonical RFC 3339 UTC: YYYY-MM-DDTHH:MM:SSZ"
        )
    }
}

impl std::error::Error for InvalidTimestamp {}

/// A wall-clock timestamp with exactly one accepted wire spelling:
/// `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Construction and deserialization both validate the calendar date and
/// time, so a `HeadAttestation` cannot contain a non-canonical timestamp
/// through the public API or through Serde.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CanonicalUtcTimestamp(String);

impl CanonicalUtcTimestamp {
    /// Validate and construct a canonical UTC timestamp.
    pub fn new(value: String) -> Result<Self, InvalidTimestamp> {
        Self::try_from(value)
    }

    /// Return the canonical timestamp text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CanonicalUtcTimestamp {
    type Error = InvalidTimestamp;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_canonical_rfc3339_utc(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidTimestamp)
        }
    }
}

impl std::str::FromStr for CanonicalUtcTimestamp {
    type Err = InvalidTimestamp;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl AsRef<str> for CanonicalUtcTimestamp {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for CanonicalUtcTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CanonicalUtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// Strict check that `s` is canonical RFC 3339 UTC in exactly the form
/// `YYYY-MM-DDTHH:MM:SSZ`: fixed width, uppercase `T`/`Z`, no fractional
/// seconds, no offsets, calendar-valid date (including leap years), and
/// no leap seconds. One accepted spelling keeps attestations byte-stable
/// across producers.
fn is_canonical_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return false;
    }
    if b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return false;
    }
    let digit_at = |i: usize| b[i].is_ascii_digit();
    let num = |from: usize, to: usize| -> u32 {
        s[from..to].parse().unwrap_or(u32::MAX) // digits checked below
    };
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !digit_at(i) {
            return false;
        }
    }
    let (year, month, day) = (num(0, 4), num(5, 7), num(8, 10));
    let (hour, minute, second) = (num(11, 13), num(14, 16), num(17, 19));
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    (1..=days_in_month).contains(&day)
}

/// Build the head attestation for a full log. `timestamp` is
/// host-supplied wall-clock time and MUST be canonical RFC 3339 UTC
/// (`YYYY-MM-DDTHH:MM:SSZ`); anything else is rejected, so nonconforming
/// attestations cannot be produced through this API.
pub fn head_attestation(
    records: &[Record],
    timestamp: String,
) -> Result<HeadAttestation, InvalidTimestamp> {
    let timestamp = CanonicalUtcTimestamp::try_from(timestamp)?;
    let ids: Vec<Hash256> = records.iter().map(|r| r.id).collect();
    Ok(HeadAttestation {
        head_hash: sha256_concat_ids(&ids),
        record_count: records.len() as u64,
        spec_version: crate::base::schema::SPEC_VERSION.to_string(),
        timestamp,
    })
}

impl HeadAttestation {
    /// The exact JCS bytes a witness receives and stores.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        crate::base::canonical::canonical_json(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_checkpoint() {
        let state = State::default();
        let cp = create_checkpoint(&[], &state).unwrap();
        assert_eq!(cp.log_length, 0);
        assert_eq!(cp.last_time, 0);
        assert_eq!(cp.last_record_id, [0u8; 32]);
    }

    #[test]
    fn test_head_attestation_canonical_form() {
        let att = head_attestation(&[], "2026-08-07T12:00:00Z".into()).unwrap();
        assert_eq!(att.record_count, 0);
        let s = String::from_utf8(att.canonical_bytes().unwrap()).unwrap();
        // Keys in JCS order; head hash serialized as a byte array.
        assert!(s.starts_with("{\"head_hash\":["));
        assert!(s.contains("\"record_count\":0"));
        assert!(s.contains(&format!(
            "\"spec_version\":\"{}\"",
            crate::base::schema::SPEC_VERSION
        )));
        assert!(s.ends_with("\"timestamp\":\"2026-08-07T12:00:00Z\"}"));
        assert_eq!(att.timestamp.as_str(), "2026-08-07T12:00:00Z");
        let round_trip: HeadAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(round_trip, att);
    }

    #[test]
    fn test_head_attestation_deserialization_rejects_invalid_timestamp() {
        let att = head_attestation(&[], "2026-08-07T12:00:00Z".into()).unwrap();
        let mut value = serde_json::to_value(att).unwrap();
        value["timestamp"] = serde_json::Value::String("2026-08-07T12:00:00+00:00".into());
        assert!(serde_json::from_value::<HeadAttestation>(value).is_err());
    }

    #[test]
    fn test_checkpoint_deserialization_rejects_unknown_fields() {
        let state = State::default();
        let checkpoint = create_checkpoint(&[], &state).unwrap();
        let mut value = serde_json::to_value(checkpoint).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("trusted".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<Checkpoint>(value).is_err());
    }

    #[test]
    fn test_head_attestation_deserialization_rejects_unknown_fields() {
        let attestation = head_attestation(&[], "2026-08-07T12:00:00Z".into()).unwrap();
        let mut value = serde_json::to_value(attestation).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("witness".into(), serde_json::json!("untrusted"));
        assert!(serde_json::from_value::<HeadAttestation>(value).is_err());
    }
}
