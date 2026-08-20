//! verify_record and verify_log - the verification rule set (SPEC.md §4).

use crate::base::hash::sha256_canonical;
use crate::base::schema::*;
use crate::base::time::Time;
use crate::checkpoint::TrustedCheckpoint;
use crate::record::evidence::{derive_evidence, Evidence};
use crate::record::kind::*;
use crate::record::payloads::*;
use crate::record::record::{decode, Record};
use crate::record::refs::{RecordId, Ref};
use crate::state::build::build_state_unchecked;
use crate::state::state::State;
use crate::verify::rules::VerifierRules;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Decode payload during verification; malformed JSON becomes `InvalidPayload`.
macro_rules! dec {
    ($buf:expr, $ty:ty) => {
        match crate::record::record::decode::<$ty>($buf) {
            Ok(v) => v,
            Err(_) => return Some(ReasonCode::InvalidPayload),
        }
    };
}

/// Result of verify_log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogVerdict {
    /// Accept if the whole log replayed cleanly (ids, times, and every
    /// stored verdict re-derived); Reject on the first violation.
    pub result: VerdictResult,
    /// Reason for the first violation encountered; always None on Accept.
    pub reason: Option<ReasonCode>,
    /// Records (subjects and verdicts) that replayed cleanly - every check
    /// passed and the record was folded into state - before verification
    /// finished or stopped at a violation.
    pub checked_records: u64,
    /// Logical time of the input's final record; 0 for an empty log.
    pub last_time: Time,
    /// Ids of retracted records (targets of accepted Retractions).
    /// Populated on Accept; empty on Reject - an invalid log supersedes
    /// taint. Accept + empty sets = clean; Accept + non-empty = valid
    /// history containing retracted/tainted claims; Reject = invalid.
    pub retracted_records: BTreeSet<RecordId>,
    /// Ids of records tainted by epistemic dependence on a retracted
    /// record (see `retracted_records` for population rules).
    pub tainted_records: BTreeSet<RecordId>,
    /// The replay-derived standing section (SPEC §7.2): compromised
    /// candidates, unsound Selections, and restorations. Populated on Accept
    /// alongside the taint sets; empty on Reject.
    pub standing: crate::verify::standing::StandingSection,
}

/// Build a Reject LogVerdict; taint sets stay empty (only surfaced on Accept).
fn reject(reason: ReasonCode, checked_records: u64, records: &[Record]) -> LogVerdict {
    LogVerdict {
        result: VerdictResult::Reject,
        reason: Some(reason),
        checked_records,
        last_time: records.last().map(|r| r.time).unwrap_or(0),
        retracted_records: BTreeSet::new(),
        tainted_records: BTreeSet::new(),
        standing: crate::verify::standing::StandingSection::default(),
    }
}

mod activity;
mod evolution;
mod lifecycle;
mod plans;
mod record_checks;
mod replay;
mod verdict;

pub use record_checks::verify_record;
pub use replay::verify_log;

use activity::check_kind_specific;
use evolution::*;
use lifecycle::*;
use plans::*;
use record_checks::{check_record, decodes_canonically};
use verdict::{check_verdict_record, Prior, PriorIndex};
