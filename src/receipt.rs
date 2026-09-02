//! Portable receipts: export a log as a self-contained bundle and validate
//! it offline (SPEC §12).
//!
//! A [`Receipt`] carries everything a third party needs to verify without
//! trusting the producer: the spec version, the verifier rules the log was
//! committed under, and the full record sequence from genesis. [`validate`]
//! re-runs the whole verification stack from genesis - JCS id
//! recomputation, gap-free time, verdict re-derivation, signature checks,
//! evidence derivation, taint status - and returns a [`Report`].
//!
//! Receipts deliberately carry **no checkpoint**: a checkpoint attests its
//! prefix instead of re-deriving it, so its trust must come from outside
//! the artifact being validated. A checkpoint supplied inside an untrusted
//! receipt would let the producer attest their own forged prefix
//! (checkpoints remain a host-side acceleration for `verify_log` over logs
//! whose prefix the host verified itself).
//!
//! The embedded rules are part of what is being attested: a validator
//! reports `rules_hash` so an auditor can compare the rules against a value
//! agreed out of band. Acceptance is always relative to the embedded rules.

use crate::base::canonical::{canonical_json, strict_set};
use crate::base::hash::{hex_encode, sha256_canonical, sha256_concat_ids, Hash256};
use crate::base::schema::{schema_id, schemas_for_epoch, SPEC_VERSION, SUPPORTED_SPEC_VERSIONS};
use crate::base::time::Time;
use crate::record::kind::{ReasonCode, VerdictResult};
use crate::record::record::Record;
use crate::record::refs::RecordId;
use crate::verify::rules::VerifierRules;
use crate::verify::verifier::verify_log;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A portable, self-contained proof bundle: everything needed to verify a
/// log offline, without trusting the producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Spec version the records and rules conform to (e.g. `"0.3"`).
    pub spec_version: String,
    /// The verifier rules the log was committed under. Validation
    /// re-derives every verdict against these; auditors compare
    /// `Report::rules_hash` against an out-of-band value.
    pub rules: VerifierRules,
    /// The full record sequence from genesis (subjects and verdicts).
    pub records: Vec<Record>,
}

impl Receipt {
    /// Bundle a log into a receipt under the current spec version.
    pub fn new(records: &[Record], rules: &VerifierRules) -> Self {
        Self {
            spec_version: SPEC_VERSION.to_string(),
            rules: rules.clone(),
            records: records.to_vec(),
        }
    }

    /// Serialize to canonical (JCS) JSON bytes - the portable wire form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        canonical_json(self)
    }

    /// Parse a receipt from JSON bytes (canonical or not; validation
    /// re-derives everything).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Overall outcome of receipt validation: the three-way distinction a
/// consumer acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// The log replayed cleanly and contains no retracted or tainted
    /// records.
    Clean,
    /// The log replayed cleanly, but some claims were retracted or are
    /// tainted by dependence on retracted claims - valid history, listed
    /// unreliable content.
    Tainted,
    /// The receipt is not verifiable: unparseable, unsupported spec
    /// version, or the log failed replay verification.
    Invalid,
}

/// The result of validating a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Clean, Tainted, or Invalid (see [`ValidationStatus`]).
    pub status: ValidationStatus,
    /// Verifier reason for the first violation when replay failed.
    pub reason: Option<ReasonCode>,
    /// Structural problem (unparseable bytes, unsupported spec version)
    /// when validation could not even reach replay.
    pub problem: Option<String>,
    /// Spec version the receipt declared (empty if unparseable).
    pub spec_version: String,
    /// Total records in the receipt (subjects and verdicts).
    pub record_count: u64,
    /// Records that replayed cleanly before verification finished or
    /// stopped.
    pub checked_records: u64,
    /// Logical time of the final record; 0 for an empty log.
    pub last_time: Time,
    /// SHA-256 over the concatenated record ids - compare against an
    /// externally anchored head attestation (SPEC §11.1).
    pub head_hash: Hash256,
    /// SHA-256 of the canonical form of the embedded rules - compare
    /// against the rules agreed out of band.
    pub rules_hash: Hash256,
    /// Ids of retracted records (targets of accepted Retractions).
    #[serde(with = "strict_set")]
    pub retracted_records: BTreeSet<RecordId>,
    /// Ids of records tainted by epistemic dependence on retracted
    /// records.
    #[serde(with = "strict_set")]
    pub tainted_records: BTreeSet<RecordId>,
    /// The replay-derived standing section (SPEC §7.2, spec 0.3):
    /// compromised candidates, unsound Selections, and restorations.
    /// Re-derived on every validation like the taint sets; nothing standing
    /// is embedded in the receipt.
    #[serde(default)]
    pub standing: crate::verify::standing::StandingSection,
    /// Profile evaluations requested by the caller (RFC-0003, SPEC §12.2),
    /// in request order. Empty unless [`validate_with_profiles`] was used.
    /// A report alongside the verdict: never changes `status` or `reason`.
    #[serde(default)]
    pub profiles: Vec<crate::profiles::ProfileResult>,
}

impl Report {
    fn structural_failure(problem: String, spec_version: String) -> Self {
        Report {
            status: ValidationStatus::Invalid,
            reason: None,
            problem: Some(problem),
            spec_version,
            record_count: 0,
            checked_records: 0,
            last_time: 0,
            head_hash: [0u8; 32],
            rules_hash: [0u8; 32],
            retracted_records: BTreeSet::new(),
            tainted_records: BTreeSet::new(),
            standing: crate::verify::standing::StandingSection::default(),
            profiles: Vec::new(),
        }
    }
}

/// The rules as an epoch sees them: `kind_schema_map` restricted to the
/// schemas that epoch admits. Everything else in the rules is epoch-neutral.
/// A schema mapped by the embedded rules but introduced by a later epoch is
/// dropped, so a record carrying it rejects as `UnknownSchema` under the
/// older epoch, exactly as that epoch's own validator would have rejected
/// it.
fn rules_for_epoch(rules: &VerifierRules, schemas: &[&str]) -> VerifierRules {
    let known: BTreeSet<Hash256> = schemas.iter().map(|s| schema_id(s)).collect();
    let mut epoch_rules = rules.clone();
    epoch_rules
        .kind_schema_map
        .retain(|schema, _| known.contains(schema));
    epoch_rules
}

/// Resource bounds applied to untrusted receipts before verification.
/// Defaults are generous (far above any realistic honest receipt) but
/// finite, so a hostile receipt cannot demand unbounded work by
/// construction. Decoded allocation is proportional to `max_bytes`;
/// `serde_json`'s recursion limit (128) bounds nesting depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum serialized receipt size in bytes.
    pub max_bytes: usize,
    /// Maximum number of records (subjects and verdicts).
    pub max_records: usize,
    /// Maximum `data` payload size per record, in bytes.
    pub max_payload_bytes: usize,
    /// Maximum refs per record.
    pub max_refs_per_record: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            // 64 MiB: far above any realistic honest receipt, small enough
            // that parsing an adversarial one cannot demand gigabytes of
            // memory before the record/payload limits are even reached.
            // The CLI uses the same default; raise it (or use
            // `unlimited()`) only for inputs whose origin you control.
            max_bytes: 64 << 20,
            max_records: 1_000_000,
            max_payload_bytes: 16 << 20, // 16 MiB
            max_refs_per_record: 4_096,
        }
    }
}

impl ValidationLimits {
    /// No bounds at all - only for callers that fully trust the input's
    /// origin or bound it by other means.
    pub fn unlimited() -> Self {
        Self {
            max_bytes: usize::MAX,
            max_records: usize::MAX,
            max_payload_bytes: usize::MAX,
            max_refs_per_record: usize::MAX,
        }
    }
}

/// Validate a serialized [`Receipt`] offline under the default
/// [`ValidationLimits`]. Never panics and never trusts the producer: ids,
/// times, verdicts, signatures, and evidence are all re-derived from the
/// receipt's own bytes, always replaying from genesis.
pub fn validate(bytes: &[u8]) -> Report {
    validate_with_limits(bytes, &ValidationLimits::default())
}

/// As [`validate`], with caller-chosen resource bounds.
pub fn validate_with_limits(bytes: &[u8], limits: &ValidationLimits) -> Report {
    if bytes.len() > limits.max_bytes {
        return Report::structural_failure(
            format!(
                "receipt exceeds size limit ({} > {} bytes)",
                bytes.len(),
                limits.max_bytes
            ),
            String::new(),
        );
    }

    let receipt = match Receipt::from_bytes(bytes) {
        Ok(r) => r,
        Err(e) => {
            return Report::structural_failure(format!("unparseable receipt: {e}"), String::new())
        }
    };

    if receipt.records.len() > limits.max_records {
        return Report::structural_failure(
            format!(
                "receipt exceeds record limit ({} > {})",
                receipt.records.len(),
                limits.max_records
            ),
            receipt.spec_version,
        );
    }
    for (idx, record) in receipt.records.iter().enumerate() {
        if record.data.len() > limits.max_payload_bytes {
            return Report::structural_failure(
                format!("record {idx} exceeds payload size limit"),
                receipt.spec_version,
            );
        }
        if record.refs.len() > limits.max_refs_per_record {
            return Report::structural_failure(
                format!("record {idx} exceeds ref-count limit"),
                receipt.spec_version,
            );
        }
    }

    // Epoch dispatch (SPEC §14): the receipt replays under the schema set of
    // the epoch it declares, so an older receipt reaches exactly the decision
    // its own epoch's validator reached. An unsupported version never guesses.
    let Some(epoch_schemas) = schemas_for_epoch(&receipt.spec_version) else {
        return Report::structural_failure(
            format!(
                "unsupported spec version {:?} (this validator implements {:?} and validates {})",
                receipt.spec_version,
                SPEC_VERSION,
                SUPPORTED_SPEC_VERSIONS.join(", ")
            ),
            receipt.spec_version,
        );
    };
    let rules = rules_for_epoch(&receipt.rules, epoch_schemas);

    // The reported rules hash is over the rules as embedded, so auditors
    // compare what the producer committed under, not the epoch view of it.
    let rules_hash = match sha256_canonical(&receipt.rules) {
        Ok(h) => h,
        Err(e) => {
            return Report::structural_failure(
                format!("rules do not canonicalize: {e}"),
                receipt.spec_version,
            )
        }
    };

    let ids: Vec<Hash256> = receipt.records.iter().map(|r| r.id).collect();
    let head_hash = sha256_concat_ids(&ids);

    // Always replay from genesis: nothing inside an untrusted receipt may
    // establish checkpoint trust.
    let verdict = verify_log(&receipt.records, &rules, None);

    let status = match verdict.result {
        VerdictResult::Reject => ValidationStatus::Invalid,
        VerdictResult::Accept => {
            if verdict.retracted_records.is_empty() && verdict.tainted_records.is_empty() {
                ValidationStatus::Clean
            } else {
                ValidationStatus::Tainted
            }
        }
    };

    Report {
        status,
        reason: verdict.reason,
        problem: None,
        spec_version: receipt.spec_version,
        record_count: receipt.records.len() as u64,
        checked_records: verdict.checked_records,
        last_time: verdict.last_time,
        head_hash,
        rules_hash,
        retracted_records: verdict.retracted_records,
        tainted_records: verdict.tainted_records,
        standing: verdict.standing,
        profiles: Vec::new(),
    }
}

/// As [`validate_with_limits`], then evaluate each named profile over the
/// receipt and attach the results to `Report::profiles` in request order.
/// Profiles are evaluated only when the receipt parsed and reached replay
/// (`problem` is `None`): a structurally broken receipt has nothing to
/// evaluate against. An unknown profile id yields a `Unknown` result, never
/// an error. The verdict fields are exactly what `validate_with_limits`
/// returns; profile conformance is a report alongside them (SPEC §12.2).
pub fn validate_with_profiles(
    bytes: &[u8],
    limits: &ValidationLimits,
    profiles: &[&str],
) -> Report {
    let mut report = validate_with_limits(bytes, limits);
    if profiles.is_empty() || report.problem.is_some() {
        return report;
    }
    // The receipt already parsed once above; parsing again keeps the
    // verdict path untouched at the cost of one more decode, which a
    // validator invoked with profile requests can afford.
    let Ok(receipt) = Receipt::from_bytes(bytes) else {
        return report;
    };
    report.profiles = profiles
        .iter()
        .map(|id| crate::profiles::evaluate_profile(id, &receipt, &report))
        .collect();
    report
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = match self.status {
            ValidationStatus::Clean => "CLEAN",
            ValidationStatus::Tainted => "TAINTED",
            ValidationStatus::Invalid => "INVALID",
        };
        writeln!(f, "status:          {status}")?;
        if let Some(problem) = &self.problem {
            writeln!(f, "problem:         {problem}")?;
        }
        if let Some(reason) = &self.reason {
            writeln!(f, "reject reason:   {reason:?}")?;
        }
        writeln!(f, "spec version:    {}", self.spec_version)?;
        writeln!(f, "records:         {}", self.record_count)?;
        writeln!(f, "checked:         {}", self.checked_records)?;
        writeln!(f, "last time:       {}", self.last_time)?;
        writeln!(f, "head hash:       {}", hex_encode(&self.head_hash))?;
        writeln!(f, "rules hash:      {}", hex_encode(&self.rules_hash))?;
        if !self.retracted_records.is_empty() {
            writeln!(f, "retracted ({}):", self.retracted_records.len())?;
            for id in &self.retracted_records {
                writeln!(f, "  {}", hex_encode(id))?;
            }
        }
        if !self.tainted_records.is_empty() {
            writeln!(f, "tainted ({}):", self.tainted_records.len())?;
            for id in &self.tainted_records {
                writeln!(f, "  {}", hex_encode(id))?;
            }
        }
        if !self.standing.is_empty() {
            let s = &self.standing;
            if !s.compromised.is_empty() {
                writeln!(f, "standing-compromised ({}):", s.compromised.len())?;
                for id in &s.compromised {
                    writeln!(f, "  {}", hex_encode(id))?;
                }
            }
            if !s.unsound.is_empty() {
                writeln!(f, "unsound selections ({}):", s.unsound.len())?;
                for id in &s.unsound {
                    writeln!(f, "  {}", hex_encode(id))?;
                }
            }
            if !s.restorations.is_empty() {
                writeln!(f, "restorations ({}):", s.restorations.len())?;
                for (target, replacers) in &s.restorations {
                    writeln!(f, "  {} <- ", hex_encode(target))?;
                    for r in replacers {
                        writeln!(f, "    {}", hex_encode(r))?;
                    }
                }
            }
        }
        for p in &self.profiles {
            let status = match p.status {
                crate::profiles::ProfileStatus::Conformant => "CONFORMANT",
                crate::profiles::ProfileStatus::NonConformant => "NON-CONFORMANT",
                crate::profiles::ProfileStatus::Unknown => "UNKNOWN",
            };
            writeln!(f, "profile {}: {status}", p.id)?;
            if p.status != crate::profiles::ProfileStatus::Unknown {
                writeln!(f, "  hash:          {}", hex_encode(&p.hash))?;
                for c in &p.clauses {
                    let mark = if c.passed { "ok  " } else { "FAIL" };
                    writeln!(f, "  {mark} {}: {}", c.id, c.detail)?;
                }
            }
        }
        Ok(())
    }
}
