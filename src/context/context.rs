//! Context struct and build_context from SPEC.md.

use crate::record::kind::Kind;
use crate::record::payloads::UsageOutcomeCounts;
use crate::record::record::{Record, ThreadId};
use crate::record::refs::RecordId;
use crate::state::state::State;
use crate::verify::rules::VerifierRules;
use std::collections::{BTreeMap, BTreeSet};

/// Whether context selection may include tainted records (records whose
/// content epistemically rests on something retracted). The safe default
/// excludes them: a proposer should not be fed content known to rest on
/// nothing without the host explicitly opting in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContextPolicy {
    /// Exclude tainted records from selection (the default).
    #[default]
    ExcludeTainted,
    /// Include tainted records; each selected tainted record's id is
    /// surfaced in [`Context::tainted_records`] so the proposer-facing
    /// host can label it.
    IncludeTainted,
}

/// Temporary working set selected for the Proposer.
#[derive(Debug, Clone)]
pub struct Context {
    /// Selected accepted, non-replaced, non-verdict records of the target
    /// thread - newest first (time desc, ties by id asc), capped at
    /// `rules.max_context_records`.
    pub records: Vec<Record>,
    /// Subset of `state.usage_counts` whose used record appears in
    /// `records`, keyed by (used_record, role).
    pub usage_feedback: BTreeMap<(RecordId, String), UsageOutcomeCounts>,
    /// Ids of records in `records` that are tainted. Always empty under
    /// [`ContextPolicy::ExcludeTainted`]; under `IncludeTainted` it
    /// identifies which selected records carry unreliable content.
    pub tainted_records: BTreeSet<RecordId>,
}

/// Build context for a specific thread with the safe default policy:
/// retracted AND tainted records are excluded. Records must be in
/// ascending time order (log order).
pub fn build_context(
    records: &[Record],
    state: &State,
    rules: &VerifierRules,
    thread: ThreadId,
) -> Context {
    build_context_with(records, state, rules, thread, ContextPolicy::default())
}

/// As [`build_context`], with an explicit tainted-record policy.
pub fn build_context_with(
    records: &[Record],
    state: &State,
    rules: &VerifierRules,
    thread: ThreadId,
    policy: ContextPolicy,
) -> Context {
    // Step 1: Select accepted records in target thread, excluding replaced,
    // retracted, and verdict records. Retracted content was asserted WRONG
    // and must never be re-fed to a proposer; tainted records (unreliable,
    // not declared wrong) are excluded by default and included only under
    // an explicit IncludeTainted policy, labeled via
    // `Context::tainted_records`.
    let include_tainted = policy == ContextPolicy::IncludeTainted;
    let mut selected: Vec<&Record> = records
        .iter()
        .filter(|r| {
            r.thread == thread
                && r.kind != Kind::Verdict
                && state.accepted_records.contains(&r.id)
                && !state.replaced_records.contains(&r.id)
                && !state.retracted_records.contains(&r.id)
                && (include_tainted || !state.tainted_records.contains(&r.id))
        })
        .collect();

    // Step 2: Sort by (time desc, id asc)
    selected.sort_by(|a, b| b.time.cmp(&a.time).then_with(|| a.id.cmp(&b.id)));

    // Step 3: Cap at max_context_records
    selected.truncate(rules.max_context_records as usize);

    let context_records: Vec<Record> = selected.into_iter().cloned().collect();

    // Step 4: Build usage_feedback - subset of state.usage_counts whose used_record is in context
    let context_ids: BTreeSet<RecordId> = context_records.iter().map(|r| r.id).collect();

    let usage_feedback: BTreeMap<(RecordId, String), UsageOutcomeCounts> = state
        .usage_counts
        .iter()
        .filter(|((used_record, _role), _counts)| context_ids.contains(used_record))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Ids of selected records that are tainted (non-empty only under
    // IncludeTainted).
    let tainted_records: BTreeSet<RecordId> = context_records
        .iter()
        .filter(|r| state.tainted_records.contains(&r.id))
        .map(|r| r.id)
        .collect();

    Context {
        records: context_records,
        usage_feedback,
        tainted_records,
    }
}
