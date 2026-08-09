//! LogWriter: single-writer with file lock, commit protocol, crash recovery.

use crate::base::canonical::canonical_json;
use crate::base::hash::sha256_canonical;
use crate::base::schema::{schema_id, SCHEMA_VERDICT};
use crate::base::time::TimeSource;
use crate::log::storage::FileLog;
use crate::record::author::Author;
use crate::record::evidence::Evidence;
use crate::record::kind::*;
use crate::record::payloads::VerdictData;
use crate::record::record::{encode, Proposal, Record};
use crate::record::refs::{sort_and_dedup_refs, RecordId, Ref};
use crate::record::sign::Ed25519Signer;
use crate::state::build::build_state_unchecked;
use crate::state::state::State;
use crate::verify::rules::VerifierRules;
use crate::verify::verifier::{verify_log, verify_record};
use crate::LogError;
use fs4::TryLockError;
use std::path::Path;

mod core;
mod helpers;
mod intent;

pub use core::{BatchAppend, LogWriter, DEFAULT_MAX_LOG_BYTES, EMPTY_HEAD};
pub(crate) use intent::CommitIntent;

use helpers::*;

include!("writer/tests.rs");
