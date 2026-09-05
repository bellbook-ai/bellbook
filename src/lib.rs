//! Bellbook - a tamper-evident, replay-verifiable record of captured
//! agent activity.
//!
//! Bellbook is a small embeddable library with one durable primitive: a typed
//! [`Record`] in an append-only log. Records are content-addressed (the id is
//! the SHA-256 of the record's canonical form) and linked by typed refs, so
//! modifying hash-covered records or their committed sequence is detectable.
//! Detecting complete replacement from genesis requires external anchoring.
//! A deterministic verifier ([`verify_log`]) replays the whole log and
//! confirms it followed the rules: every record is immediately judged by a
//! [`Verdict`](Kind::Verdict), ids recompute, logical time has no gaps, and
//! every verdict itself re-derives.
//!
//! Not a logger, not a database, not a runtime - an evidence kernel a host
//! process embeds to turn "the agent says it did X" into replay-verifiable
//! evidence of the agent activity that was recorded. Bellbook proves
//! consistency of captured history, not capture completeness (see
//! SPEC.md, Known limitations).
//!
//! # Example
//!
//! ```
//! use bellbook::*;
//!
//! # #[cfg(feature = "persist")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = tempfile::tempdir()?;
//! let space = default_space();
//! // Bind actor identities to roles: the declared author type on a
//! // record is never trusted by itself.
//! let rules = VerifierRules::new(space, 200).with_author_role("human", AuthorType::User);
//!
//! let mut writer = LogWriter::open(dir.path(), &rules)?;
//! let mut state = State::default();
//!
//! let proposal = Proposal {
//!     space,
//!     thread: sha256_utf8("demo-thread"),
//!     author: Author { id: "human".into(), type_: AuthorType::User, signature: None },
//!     kind: Kind::Request,
//!     schema: schema_id(SCHEMA_REQUEST),
//!     data: encode(&RequestData {
//!         objective: "summarize the report".into(),
//!         scope: sha256_utf8("demo-scope"),
//!         attachments: vec![],
//!         parent_request_id: None,
//!     })?,
//!     refs: vec![],
//! };
//!
//! let (_id, verdict) = writer.commit(proposal, &rules, &mut state)?;
//! assert_eq!(verdict.result, VerdictResult::Accept);
//!
//! // Replay-verify the entire log: ids, times, and every verdict recompute.
//! let report = verify_log(writer.records(), &rules, None);
//! assert_eq!(report.result, VerdictResult::Accept);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "persist"))]
//! # fn main() {}
//! ```

#![warn(missing_docs)]

/// Foundations: canonical JSON, SHA-256 hashing, frozen schema ids, and the
/// logical time source.
pub mod base;
pub mod checkpoint;
/// Deterministic selection of the per-thread working set shown to an
/// untrusted proposer.
pub mod context;
#[cfg(feature = "persist")]
pub mod log;
/// Canonical manifest v1: an algorithm-independent content commitment over a
/// Git tree (SPEC §5.1).
pub mod manifest;
/// Profiles (RFC-0003): separately versioned predicates evaluated over a
/// receipt on request and reported alongside the verdict.
pub mod profiles;
/// The untrusted [`Proposer`] interface - emits proposals, holds no append
/// authority.
pub mod propose;
pub mod queries;
/// Portable receipts: export a log as a self-contained bundle and
/// validate it offline.
pub mod receipt;
/// The Record primitive: kinds, payloads, refs, authors, and evidence.
pub mod record;
/// Derived [`State`]: a pure fold over accepted (record, verdict) pairs.
pub mod state;
/// The deterministic verifier: per-record rules and full log replay.
pub mod verify;

// Re-export key types at crate root for convenience
pub use base::canonical::{canonical_json, canonical_json_string};
pub use base::hash::{
    hex_decode, hex_encode, sha256, sha256_canonical, sha256_concat_ids, sha256_utf8, Hash256,
};
pub use base::schema::{
    default_space, schema_id, schema_name_for_id, schemas_for_epoch, SchemaId, ALL_SCHEMAS,
    DEFAULT_SPACE_NAME, SCHEMAS_V03, SCHEMA_ACTION, SCHEMA_APPROVAL, SCHEMA_CANDIDATE,
    SCHEMA_CAPABILITY, SCHEMA_EVALUATION, SCHEMA_EVALUATION_ATTESTED, SCHEMA_EVALUATION_V2,
    SCHEMA_PLAN, SCHEMA_REFUSAL, SCHEMA_REQUEST, SCHEMA_REQUIREMENT, SCHEMA_RESPONSE,
    SCHEMA_RESULT, SCHEMA_RESULT_EFFECT_CONFIRMATION, SCHEMA_RESULT_EXTERNAL, SCHEMA_RETRACTION,
    SCHEMA_SELECTION, SCHEMA_SUMMARY, SCHEMA_USAGE, SCHEMA_VERDICT, SPEC_VERSION,
    SUPPORTED_SPEC_VERSIONS,
};
pub use base::time::{Time, TimeSource};

pub use record::author::{ActorId, Author, Signature};
pub use record::evidence::{base_evidence, derive_evidence, weakest, Evidence};
pub use record::kind::{
    AuthorType, CapabilityMode, ExecMode, Kind, ReasonCode, RefType, RefusalTarget, ResultStatus,
    SummaryType, UsageOutcome, VerdictResult,
};
pub use record::payloads::{
    artifact_ref_well_formed, artifact_refs_well_formed, evaluation_summary, ArtifactRef, Basis,
    DeciderBinding, EvaluationDataV2, EvaluationOutcomeV2, Provenance, RequirementData,
    ARTIFACT_DIGEST_MAX_BYTES, ARTIFACT_DIGEST_MIN_BYTES, ARTIFACT_SCHEMES,
};
pub use record::payloads::{
    selection_approval_subject_hash, ActionData, ApprovalData, Attachment, BindingMode,
    CandidateBasis, CandidateData, CapabilityData, EvaluationData, EvaluationOutcome,
    FailurePolicy, GitSource, PlanData, PlanStatus, PlanTask, PlanTaskKind, RefusalData,
    RequestData, ResponseData, ResultData, RetractionData, ScoredValue, SelectionData,
    SelectionOutcome, SourceAlgo, SourceBinding, SummaryData, TaskDoneWhen, TaskStatus, UsageData,
    UsageOutcomeCounts, VerdictData,
};
pub use record::record::{
    decode, encode, Proposal, Record, ScopeId, SpaceId, ThreadId, RECORD_SIGNATURE_DOMAIN,
};
pub use record::refs::{sort_and_dedup_refs, RecordId, Ref};
pub use record::sign::{signature_verifies, verified_key, Ed25519Signer, PublicKeyBytes};

pub use checkpoint::{
    create_checkpoint, head_attestation, CanonicalUtcTimestamp, Checkpoint, HeadAttestation,
    InvalidTimestamp, TrustedCheckpoint,
};
#[cfg(feature = "persist")]
pub use log::writer::{BatchAppend, LogWriter, DEFAULT_MAX_LOG_BYTES, EMPTY_HEAD};
pub use profiles::{
    core_v1_table, delivery_v1_table, evaluate_declared, evaluate_profile, evaluate_profiles,
    known_profiles, profile_hash, profile_ref, profile_table, Clause, ClauseResult, ProfileRef,
    ProfileResult, ProfileStatus, ProfileTable, BELLBOOK_CORE_V1, DELIVERY_RECEIPT_V1,
};
pub use receipt::{
    validate, validate_with_limits, validate_with_profiles, Receipt, Report, ValidationLimits,
    ValidationStatus, PROFILE_DECLARATIONS_SINCE,
};

pub use queries::{
    DescendantsReport, DescentReport, DescentStep, EvidenceEntry, EvidenceReport, FrontierEntry,
    FrontierReport, Node, Queries, QueryError, SelectedEntry, SelectedReport, SelectionEvidence,
    SiblingsReport, StandingReport,
};
pub use verify::rules::VerifierRules;
pub use verify::standing::{derive_standing, StandingSection};
pub use verify::verifier::{verify_log, verify_record, LogVerdict};

pub use state::build::{build_state_unchecked, verify_and_build_state};
pub use state::incremental::{apply_record, find_replace_ref};
pub use state::state::State;

pub use context::context::{build_context, build_context_with, Context, ContextPolicy};

#[cfg(feature = "persist")]
pub use manifest::manifest_from_dir;
pub use manifest::{manifest_hash, FileMode, ManifestEntry};

pub use propose::proposer::Proposer;

/// Error type for the bellbook crate.
#[derive(Debug)]
pub enum LogError {
    /// Another `LogWriter` already holds the exclusive `.lock` file for
    /// this log directory.
    AlreadyLocked,
    /// Underlying filesystem operation failed (read, append, fsync, lock).
    Io(std::io::Error),
    /// The commit protocol could not locate an expected subject or paired
    /// verdict in its own in-memory log.
    CorruptedRecovery,
    /// A prior commit attempt reached its durable phase but did not finish.
    /// Drop and reopen the writer so crash recovery can repair or confirm the
    /// tail before accepting another commit.
    RecoveryRequired,
    /// The logical time counter cannot hand out two more distinct times
    /// (subject + verdict) without overflowing; the log can accept no
    /// further commits.
    TimeExhausted,
    /// Compare-and-append found the log at a different head than the
    /// appender expected, and the batch does not correspond to what
    /// actually follows the expected head - a conflict, never a duplicate
    /// append (SPEC §5.1).
    HeadConflict {
        /// The head the appender built the batch against.
        expected: crate::record::refs::RecordId,
        /// The log's actual current head.
        actual: crate::record::refs::RecordId,
    },
    /// A record's serialized frame exceeds the storage format's u32
    /// length prefix; appending it would corrupt the log file.
    RecordTooLarge {
        /// The oversized frame's serialized length in bytes.
        bytes: usize,
    },
    /// The file-backed log exceeds the configured in-memory size bound.
    /// The file is rejected before it is read or modified.
    LogSizeLimitExceeded {
        /// Actual or projected log size in bytes.
        bytes: u64,
        /// Configured maximum size in bytes.
        max_bytes: u64,
    },
    /// Existing records failed full replay verification under the supplied
    /// rules. The writer refuses to recover or append to an invalid prefix.
    InvalidExistingLog {
        /// First verifier rejection reason, when available.
        reason: Option<crate::record::kind::ReasonCode>,
    },
    /// The caller-supplied derived state does not exactly match the current
    /// committed log. No record was appended.
    StateMismatch,
    /// Commit rules differ from the rules used to open and verify this
    /// writer. Mixing rule sets would make later replay ambiguous.
    RulesMismatch,
    /// A record, payload, or intent failed to (de)serialize as JSON.
    SerdeJson(serde_json::Error),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::AlreadyLocked => write!(f, "log is already locked by another writer"),
            LogError::Io(e) => write!(f, "I/O error: {}", e),
            LogError::CorruptedRecovery => write!(f, "corrupted commit intent during recovery"),
            LogError::RecoveryRequired => write!(
                f,
                "a commit entered its durable phase but did not finish; drop and reopen the writer"
            ),
            LogError::TimeExhausted => {
                write!(
                    f,
                    "logical time counter exhausted; log accepts no further commits"
                )
            }
            LogError::HeadConflict { expected, actual } => write!(
                f,
                "head conflict: expected {}, log is at {}",
                base::hash::hex_encode(expected),
                base::hash::hex_encode(actual)
            ),
            LogError::RecordTooLarge { bytes } => write!(
                f,
                "record frame of {} bytes exceeds the u32 length prefix; refusing to corrupt the log",
                bytes
            ),
            LogError::LogSizeLimitExceeded { bytes, max_bytes } => write!(
                f,
                "log size of {bytes} bytes exceeds configured limit of {max_bytes} bytes"
            ),
            LogError::InvalidExistingLog { reason } => {
                write!(f, "existing log failed replay verification")?;
                if let Some(reason) = reason {
                    write!(f, ": {reason:?}")?;
                }
                Ok(())
            }
            LogError::StateMismatch => write!(
                f,
                "derived state does not match the current log; rebuild it before committing"
            ),
            LogError::RulesMismatch => write!(
                f,
                "commit rules differ from the rules used to open this writer"
            ),
            LogError::SerdeJson(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LogError::Io(e) => Some(e),
            LogError::SerdeJson(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for LogError {
    fn from(e: serde_json::Error) -> Self {
        LogError::SerdeJson(e)
    }
}

impl From<std::io::Error> for LogError {
    fn from(e: std::io::Error) -> Self {
        LogError::Io(e)
    }
}
