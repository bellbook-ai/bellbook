//! Standing: the replay-derived lineage dimension (SPEC §7.2, spec 0.3
//! delta D6/D7).
//!
//! Standing answers, for each candidate: does its membership in a chosen
//! line still rest on states and decisions that stand? It is a pure function
//! of the accepted records at replay end - as deterministic and
//! forgery-resistant as the taint set, because a validator re-derives it. It
//! is not kernel taint: it does not affect evidence, does not gate commits by
//! default, and is reported alongside taint, never merged with it.
//!
//! The derivation walks three payload-id/ref edges over accepted records:
//! continuation anchors (`Cause` to a Selection) with their `parent`,
//! derivation `Cause` edges to sibling material, and Selection `Replace`
//! chains (reaffirmation). All edges point to earlier records, so the graphs
//! are acyclic; the traversal is iterative to stay panic-free on hostile
//! receipts of any depth.

use crate::base::canonical::map_as_pairs;
use crate::base::canonical::strict_set;
use crate::record::kind::{Kind, RefType};
use crate::record::payloads::{CandidateBasis, CandidateData, SelectionData, SelectionOutcome};
use crate::record::record::{decode, Record};
use crate::record::refs::RecordId;
use crate::state::state::State;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The `standing` section of the replay [`Report`](crate::receipt::Report).
/// All three fields are pure functions of the accepted records at replay
/// end. Sets are id-byte-ordered (`BTreeSet`); `restorations` encodes as
/// pairs sorted by key id with each value set id-byte-ordered, so conforming
/// implementations produce byte-identical sections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingSection {
    /// Standing-compromised `Candidate` ids.
    #[serde(with = "strict_set")]
    pub compromised: BTreeSet<RecordId>,
    /// Unsound `Selection` ids (retracted or tainted at replay end).
    #[serde(with = "strict_set")]
    pub unsound: BTreeSet<RecordId>,
    /// For each unsound Selection with at least one sound replacement chain,
    /// the set of sound replacing Selection ids.
    #[serde(with = "map_as_pairs")]
    pub restorations: BTreeMap<RecordId, BTreeSet<RecordId>>,
}

impl StandingSection {
    /// Whether the section carries any lineage compromise. When false, the
    /// whole section is empty and the line is entirely sound.
    pub fn is_empty(&self) -> bool {
        self.compromised.is_empty() && self.unsound.is_empty() && self.restorations.is_empty()
    }
}

/// Per-accepted-Candidate lineage facts.
struct CandInfo {
    basis: CandidateBasis,
    parent: Option<RecordId>,
    /// `Cause` targets (in ref order); for a continuation the first (and
    /// only) is the anchor Selection.
    causes: Vec<RecordId>,
}

/// Per-accepted-Selection lineage facts.
struct SelInfo {
    /// The selected candidate set; empty for a `none` decision.
    selected: BTreeSet<RecordId>,
    /// This Selection's `Replace` target, if it is a reaffirmation.
    replace_target: Option<RecordId>,
}

/// Derive the standing section from the accepted records at replay end.
/// `state` supplies the accepted, retracted, and tainted sets.
pub fn derive_standing(records: &[Record], state: &State) -> StandingSection {
    let mut candidates: HashMap<RecordId, CandInfo> = HashMap::new();
    let mut selections: HashMap<RecordId, SelInfo> = HashMap::new();

    for record in records {
        if !state.accepted_records.contains(&record.id) {
            continue;
        }
        match record.kind {
            Kind::Candidate => {
                let Ok(data) = decode::<CandidateData>(&record.data) else {
                    continue;
                };
                let causes: Vec<RecordId> = record
                    .refs
                    .iter()
                    .filter(|r| r.type_ == RefType::Cause)
                    .map(|r| r.target)
                    .collect();
                candidates.insert(
                    record.id,
                    CandInfo {
                        basis: data.basis,
                        parent: data.parent,
                        causes,
                    },
                );
            }
            Kind::Selection => {
                let Ok(data) = decode::<SelectionData>(&record.data) else {
                    continue;
                };
                let selected = match data.outcome {
                    SelectionOutcome::Selected { candidates } => candidates.into_iter().collect(),
                    SelectionOutcome::None => BTreeSet::new(),
                };
                let replace_target = record
                    .refs
                    .iter()
                    .find(|r| r.type_ == RefType::Replace)
                    .map(|r| r.target);
                selections.insert(
                    record.id,
                    SelInfo {
                        selected,
                        replace_target,
                    },
                );
            }
            _ => {}
        }
    }

    let is_unsound = |id: &RecordId| -> bool {
        state.retracted_records.contains(id) || state.tainted_records.contains(id)
    };

    // Unsound Selections.
    let unsound: BTreeSet<RecordId> = selections.keys().copied().filter(is_unsound).collect();

    // Replacers: for each accepted *sound* Selection S2 with a Replace chain,
    // add S2 to `replacers[A]` for every proper ancestor A on its chain
    // (intermediates need only be accepted, which every chain member is).
    let mut replacers: HashMap<RecordId, BTreeSet<RecordId>> = HashMap::new();
    for (&s2, info) in &selections {
        if is_unsound(&s2) {
            continue; // only sound Selections restore
        }
        let mut hop = info.replace_target;
        let mut guard = 0usize;
        while let Some(ancestor) = hop {
            replacers.entry(ancestor).or_default().insert(s2);
            hop = selections.get(&ancestor).and_then(|i| i.replace_target);
            // Chains point to strictly earlier records (acyclic); this guard
            // is a defensive bound, never reached on a valid log.
            guard += 1;
            if guard > selections.len() {
                break;
            }
        }
    }

    // restorations: unsound Selections that have at least one sound replacer.
    let mut restorations: BTreeMap<RecordId, BTreeSet<RecordId>> = BTreeMap::new();
    for s in &unsound {
        if let Some(set) = replacers.get(s) {
            if !set.is_empty() {
                restorations.insert(*s, set.clone());
            }
        }
    }

    // Anchor soundness for a continuation with anchor S and parent P.
    let anchor_sound = |anchor: &RecordId, parent: &RecordId| -> bool {
        if !is_unsound(anchor) {
            return true;
        }
        // Some sound Selection replacing the anchor must re-select the parent.
        replacers
            .get(anchor)
            .map(|set| {
                set.iter().any(|s2| {
                    selections
                        .get(s2)
                        .is_some_and(|i| i.selected.contains(parent))
                })
            })
            .unwrap_or(false)
    };

    // Standing per candidate, computed iteratively (post-order over the
    // candidate dependency DAG) so deep lineages cannot overflow the stack.
    let mut sound: HashMap<RecordId, bool> = HashMap::new();
    for &start in candidates.keys() {
        if sound.contains_key(&start) {
            continue;
        }
        let mut stack: Vec<(RecordId, bool)> = vec![(start, false)];
        while let Some((id, deps_done)) = stack.pop() {
            if sound.contains_key(&id) {
                continue;
            }
            let Some(info) = candidates.get(&id) else {
                // Not an accepted candidate (e.g. a derivation Evaluation
                // target); carries no standing and is skipped by callers.
                continue;
            };
            // Base case: a retracted Candidate is compromised, unconditionally
            // and unrestorably.
            if state.retracted_records.contains(&id) {
                sound.insert(id, false);
                continue;
            }
            // Candidate-standing dependencies: the parent (continuation) or
            // the candidate `Cause` targets (derivation). Evaluation targets
            // carry no standing and are not dependencies.
            let deps: Vec<RecordId> = match info.basis {
                CandidateBasis::Root => Vec::new(),
                CandidateBasis::Continuation => info.parent.into_iter().collect(),
                CandidateBasis::Derivation => info
                    .causes
                    .iter()
                    .filter(|t| candidates.contains_key(*t))
                    .copied()
                    .collect(),
            };
            if !deps_done {
                let unresolved: Vec<RecordId> = deps
                    .iter()
                    .filter(|d| !sound.contains_key(*d) && candidates.contains_key(*d))
                    .copied()
                    .collect();
                if !unresolved.is_empty() {
                    stack.push((id, true));
                    for d in unresolved {
                        stack.push((d, false));
                    }
                    continue;
                }
            }
            let dep_sound = |d: &RecordId| -> bool { *sound.get(d).unwrap_or(&false) };
            let value = match info.basis {
                CandidateBasis::Root => true,
                CandidateBasis::Continuation => match (info.causes.first(), info.parent) {
                    (Some(anchor), Some(parent)) => {
                        anchor_sound(anchor, &parent) && dep_sound(&parent)
                    }
                    // A malformed accepted continuation cannot arise (V3-C4),
                    // but treat a missing anchor or parent as compromised.
                    _ => false,
                },
                CandidateBasis::Derivation => deps.iter().all(dep_sound),
            };
            sound.insert(id, value);
        }
    }

    let compromised: BTreeSet<RecordId> = candidates
        .keys()
        .copied()
        .filter(|id| !*sound.get(id).unwrap_or(&false))
        .collect();

    StandingSection {
        compromised,
        unsound,
        restorations,
    }
}
