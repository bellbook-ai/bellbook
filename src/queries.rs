//! Read-side queries (RFC-0002): the named set q1-q7.
//!
//! Deterministic, read-only queries over canonical record relationships,
//! derived from what replay already computes - never stored, never ranked.
//! Every query is a pure function of `(records, rules)`; the CLI and the
//! Python binding are thin callers over this module, and the same JSON
//! shapes are emitted on every surface so answers are diffable.
//!
//! Queries run only on verified state: [`Queries::new`] replays the log and
//! refuses a rejecting one ([`QueryError::LogInvalid`]), so answers are
//! never derived from history that does not verify. Only accepted records
//! participate in lineage and evidence; rejected records made no claim.
//!
//! Boundaries (RFC-0002 sections 3 and 7): a closed set with fixed
//! semantics. No predicates over payload fields, no pattern matching, no
//! composition, no indexes; `selected` matches its objective exactly. The
//! general query engine remains gated on RFC-0001 section 15.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::base::hash::hex_encode;
use crate::record::kind::{Kind, ReasonCode, RefType, VerdictResult};
use crate::record::payloads::{
    evaluation_summary, ArtifactRef, CandidateBasis, CandidateData, EvaluationDataV2, ResultData,
    SelectionData, SelectionOutcome,
};
use crate::record::record::{decode, Record};
use crate::record::refs::RecordId;
use crate::state::build::build_state_unchecked;
use crate::state::state::State;
use crate::verify::rules::VerifierRules;
use crate::verify::verifier::{verify_log, LogVerdict};

/// Why a query could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// The log or receipt does not verify under the given rules; queries
    /// never run on unverified history.
    LogInvalid(Option<ReasonCode>),
    /// No record with this id exists in the verified sequence.
    NotFound(RecordId),
    /// The record exists but was rejected at commit; a rejected record made
    /// no claim, so lineage and evidence queries do not address it.
    NotAccepted(RecordId),
    /// The record is accepted but not of the kind the query addresses.
    KindMismatch {
        /// The addressed record.
        id: RecordId,
        /// What the query needed, e.g. "Candidate".
        expected: &'static str,
    },
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::LogInvalid(reason) => {
                write!(f, "log does not verify: {reason:?}")
            }
            QueryError::NotFound(id) => write!(f, "record {} not found", hex_encode(id)),
            QueryError::NotAccepted(id) => {
                write!(f, "record {} was rejected at commit", hex_encode(id))
            }
            QueryError::KindMismatch { id, expected } => {
                write!(f, "record {} is not a {expected}", hex_encode(id))
            }
        }
    }
}

impl std::error::Error for QueryError {}

/// A record reference as every query reports it: id plus the annotations a
/// reader needs to judge it without a second lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Record id, lowercase hex.
    pub id: String,
    /// Rust variant name of the kind, e.g. `"Candidate"`.
    pub kind: String,
    /// `"sound"` | `"compromised"` (candidates), `"sound"` | `"unsound"`
    /// (selections), `"n/a"` otherwise.
    pub standing: String,
    /// Kernel taint (epistemic dependence on a retracted record).
    pub tainted: bool,
    /// Target of an accepted Retraction.
    pub retracted: bool,
    /// Artifact identities the record binds (spec 0.4): a Candidate's or
    /// Result's `artifacts`, or an extended Evaluation's `evidence`. Omitted
    /// when the record binds none, so 0.3-shaped answers are unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRef>,
    /// Requirement ids (lowercase hex) an extended Evaluation speaks to,
    /// in payload order. Omitted when there are none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<String>,
}

/// One step of a line of descent: the ancestor and the edge that reached it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescentStep {
    /// The ancestor record (a Candidate, or a continuation's anchor
    /// Selection).
    pub node: Node,
    /// `"parent"` (continuation parent), `"continuation-anchor"` (the
    /// `Cause`d Selection), or `"derivation"` (a derivation `Cause` to a
    /// candidate).
    pub via: String,
}

/// q1: the line of descent from a candidate back to its roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescentReport {
    /// The queried candidate.
    pub target: Node,
    /// Ancestors in breadth-first order from the target, each edge's
    /// neighbors visited in ascending id order; every reachable ancestor
    /// appears exactly once.
    pub line: Vec<DescentStep>,
}

/// q2: the forward closure of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantsReport {
    /// The queried record.
    pub target: Node,
    /// Every candidate whose descent passes through the target, in log
    /// order.
    pub descendants: Vec<Node>,
}

/// q3: the generation of a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiblingsReport {
    /// The queried candidate.
    pub target: Node,
    /// Continuations sharing the target's anchor Selection, or derivations
    /// sharing the target's exact `Cause` target set; excludes the target;
    /// log order. Empty for a Root.
    pub siblings: Vec<Node>,
}

/// One frontier entry and why it is on the frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierEntry {
    /// The frontier candidate.
    pub node: Node,
    /// `"unconsidered"` (in no accepted Selection's `considered`) or
    /// `"selected-no-continuation"` (chosen, with no continuation yet).
    pub reason: String,
}

/// q4: the frontier of the whole log (or receipt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierReport {
    /// Frontier candidates in log order. Nothing is silently filtered:
    /// retracted or compromised candidates appear with their annotations,
    /// and the reader decides what "live" means.
    pub frontier: Vec<FrontierEntry>,
}

/// q5: the standing of one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingReport {
    /// The queried record, with its standing annotations.
    pub node: Node,
    /// For an unsound Selection with sound replacement chains: the
    /// restoring Selection ids, ascending. Empty otherwise.
    pub restorations: Vec<String>,
}

/// One piece of evaluation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEntry {
    /// The evaluation record.
    pub node: Node,
    /// The evaluation's criterion.
    pub criterion: String,
    /// `"passed"`, `"failed"`, or `"scored <value>e-<scale>"`.
    pub outcome: String,
}

/// The evidence one Selection rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionEvidence {
    /// The selection.
    pub selection: Node,
    /// The evaluations it `Use`d, in ref order.
    pub evidence: Vec<EvidenceEntry>,
}

/// q6: what a record rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReport {
    /// The queried record.
    pub target: Node,
    /// For a Selection: exactly one entry, its own evidence. For a
    /// Candidate: the evidence of every anchor Selection along its descent,
    /// in descent (breadth-first) order - the full walk, unbounded by
    /// design (RFC-0002 section 9.2).
    pub rests_on: Vec<SelectionEvidence>,
}

/// One selection under q7, with its chosen candidates and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedEntry {
    /// The selection.
    pub selection: Node,
    /// Its chosen candidates, each annotated.
    pub chosen: Vec<Node>,
    /// The evaluations the selection `Use`d.
    pub evidence: Vec<EvidenceEntry>,
}

/// q7: the accepted `Selected` selections under an exact objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedReport {
    /// The exact objective string queried.
    pub objective: String,
    /// Matching selections in log order. Bellbook does not rank: the reader
    /// sees the sound and unsound alike, annotated, and decides.
    pub selections: Vec<SelectedEntry>,
}

/// The verified context every query runs against.
pub struct Queries<'a> {
    records: &'a [Record],
    verdict: LogVerdict,
    state: State,
    by_id: BTreeMap<RecordId, usize>,
}

impl<'a> Queries<'a> {
    /// Verify the records under `rules` and build the query context.
    /// Returns [`QueryError::LogInvalid`] if replay rejects: queries never
    /// answer over unverified history.
    pub fn new(records: &'a [Record], rules: &VerifierRules) -> Result<Self, QueryError> {
        let verdict = verify_log(records, rules, None);
        if verdict.result != VerdictResult::Accept {
            return Err(QueryError::LogInvalid(verdict.reason));
        }
        // An accepting log has canonical payloads, so the unchecked build
        // cannot fail; surface the impossible case as invalid, never panic.
        let state = build_state_unchecked(records).map_err(|_| QueryError::LogInvalid(None))?;
        let by_id = records.iter().enumerate().map(|(i, r)| (r.id, i)).collect();
        Ok(Queries {
            records,
            verdict,
            state,
            by_id,
        })
    }

    // --- shared helpers ----------------------------------------------------

    fn get(&self, id: RecordId) -> Result<&'a Record, QueryError> {
        let idx = *self.by_id.get(&id).ok_or(QueryError::NotFound(id))?;
        Ok(&self.records[idx])
    }

    fn get_accepted(&self, id: RecordId) -> Result<&'a Record, QueryError> {
        let rec = self.get(id)?;
        if !self.state.accepted_records.contains(&id) {
            return Err(QueryError::NotAccepted(id));
        }
        Ok(rec)
    }

    fn node(&self, rec: &Record) -> Node {
        let standing = match rec.kind {
            Kind::Candidate => {
                if self.verdict.standing.compromised.contains(&rec.id) {
                    "compromised"
                } else {
                    "sound"
                }
            }
            Kind::Selection => {
                if self.verdict.standing.unsound.contains(&rec.id) {
                    "unsound"
                } else {
                    "sound"
                }
            }
            _ => "n/a",
        };
        // Bindings the record carries (spec 0.4), reported as recorded so a
        // reader sees what a candidate or a judgment was bound to without a
        // second lookup. A 0.3 payload has none and the fields stay absent.
        let (artifacts, requirements) = match rec.kind {
            Kind::Candidate => (
                decode::<CandidateData>(&rec.data)
                    .ok()
                    .and_then(|c| c.artifacts)
                    .unwrap_or_default(),
                Vec::new(),
            ),
            Kind::Result => (
                decode::<ResultData>(&rec.data)
                    .ok()
                    .and_then(|r| r.artifacts)
                    .unwrap_or_default(),
                Vec::new(),
            ),
            Kind::Evaluation => decode::<EvaluationDataV2>(&rec.data)
                .ok()
                .map(|e| {
                    (
                        e.evidence,
                        e.requirements.iter().map(hex_encode).collect::<Vec<_>>(),
                    )
                })
                .unwrap_or_default(),
            _ => (Vec::new(), Vec::new()),
        };
        Node {
            id: hex_encode(&rec.id),
            kind: format!("{:?}", rec.kind),
            standing: standing.to_string(),
            tainted: self.verdict.tainted_records.contains(&rec.id),
            retracted: self.verdict.retracted_records.contains(&rec.id),
            artifacts,
            requirements,
        }
    }

    fn candidate_data(&self, rec: &Record) -> Result<CandidateData, QueryError> {
        if rec.kind != Kind::Candidate {
            return Err(QueryError::KindMismatch {
                id: rec.id,
                expected: "Candidate",
            });
        }
        decode::<CandidateData>(&rec.data).map_err(|_| QueryError::NotFound(rec.id))
    }

    /// The backward edges of one accepted candidate:
    /// `(ancestor id, via)` pairs in ascending id order per edge class.
    /// Continuations contribute the anchor Selection and the `parent`
    /// candidate; derivations contribute their candidate-kind `Cause`
    /// targets (evaluation-kind causes are motivation, surfaced by q6, not
    /// structure). Roots contribute nothing.
    fn back_edges(&self, rec: &Record, data: &CandidateData) -> Vec<(RecordId, &'static str)> {
        let mut edges = Vec::new();
        match data.basis {
            CandidateBasis::Root => {}
            CandidateBasis::Continuation => {
                let mut anchors: Vec<RecordId> = rec
                    .refs
                    .iter()
                    .filter(|r| r.type_ == RefType::Cause)
                    .map(|r| r.target)
                    .collect();
                anchors.sort();
                for a in anchors {
                    edges.push((a, "continuation-anchor"));
                }
                if let Some(p) = data.parent {
                    edges.push((p, "parent"));
                }
            }
            CandidateBasis::Derivation => {
                let mut causes: Vec<RecordId> = rec
                    .refs
                    .iter()
                    .filter(|r| r.type_ == RefType::Cause)
                    .map(|r| r.target)
                    .collect();
                causes.sort();
                for c in causes {
                    if self.get(c).map(|t| t.kind) == Ok(Kind::Candidate) {
                        edges.push((c, "derivation"));
                    }
                }
            }
        }
        edges
    }

    /// The evidence one accepted Selection `Use`d, in ref order.
    fn selection_evidence(&self, rec: &Record) -> Vec<EvidenceEntry> {
        let mut out = Vec::new();
        for rf in rec.refs.iter().filter(|r| r.type_ == RefType::Use) {
            let Ok(target) = self.get(rf.target) else {
                continue;
            };
            if target.kind != Kind::Evaluation {
                continue;
            }
            // Either evaluation shape (v1, or the spec 0.4 v2/attested).
            let Some((_, criterion, outcome)) = evaluation_summary(&target.schema, &target.data)
            else {
                continue;
            };
            out.push(EvidenceEntry {
                node: self.node(target),
                criterion,
                outcome,
            });
        }
        out
    }

    // --- the named set -----------------------------------------------------

    /// q1: the line of descent from `candidate` back to its roots.
    pub fn descent(&self, candidate: RecordId) -> Result<DescentReport, QueryError> {
        let rec = self.get_accepted(candidate)?;
        let data = self.candidate_data(rec)?;

        let mut line = Vec::new();
        let mut seen: BTreeSet<RecordId> = BTreeSet::new();
        seen.insert(candidate);
        let mut queue: VecDeque<(RecordId, &'static str)> =
            self.back_edges(rec, &data).into_iter().collect();
        while let Some((id, via)) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            let anc = self.get(id)?;
            line.push(DescentStep {
                node: self.node(anc),
                via: via.to_string(),
            });
            if anc.kind == Kind::Candidate {
                let ad = self.candidate_data(anc)?;
                queue.extend(self.back_edges(anc, &ad));
            }
        }
        Ok(DescentReport {
            target: self.node(rec),
            line,
        })
    }

    /// q2: every candidate whose descent passes through `id`, in log order.
    pub fn descendants(&self, id: RecordId) -> Result<DescendantsReport, QueryError> {
        let target_rec = self.get_accepted(id)?;
        let mut descendants = Vec::new();
        for rec in self.records {
            if rec.kind != Kind::Candidate
                || rec.id == id
                || !self.state.accepted_records.contains(&rec.id)
            {
                continue;
            }
            let descent = self.descent(rec.id)?;
            let target_hex = hex_encode(&id);
            if descent.line.iter().any(|s| s.node.id == target_hex) {
                descendants.push(self.node(rec));
            }
        }
        Ok(DescendantsReport {
            target: self.node(target_rec),
            descendants,
        })
    }

    /// q3: the generation of `candidate` (excluding itself), in log order.
    pub fn siblings(&self, candidate: RecordId) -> Result<SiblingsReport, QueryError> {
        let rec = self.get_accepted(candidate)?;
        let data = self.candidate_data(rec)?;
        let cause_set = |r: &Record| -> BTreeSet<RecordId> {
            r.refs
                .iter()
                .filter(|rf| rf.type_ == RefType::Cause)
                .map(|rf| rf.target)
                .collect()
        };
        let own_causes = cause_set(rec);

        let mut siblings = Vec::new();
        for other in self.records {
            if other.kind != Kind::Candidate
                || other.id == candidate
                || !self.state.accepted_records.contains(&other.id)
            {
                continue;
            }
            let Ok(od) = self.candidate_data(other) else {
                continue;
            };
            let same_generation = match (&data.basis, &od.basis) {
                (CandidateBasis::Continuation, CandidateBasis::Continuation) => {
                    cause_set(other) == own_causes
                }
                (CandidateBasis::Derivation, CandidateBasis::Derivation) => {
                    cause_set(other) == own_causes
                }
                _ => false,
            };
            if same_generation {
                siblings.push(self.node(other));
            }
        }
        Ok(SiblingsReport {
            target: self.node(rec),
            siblings,
        })
    }

    /// q4: the frontier of the whole log, in log order.
    pub fn frontier(&self) -> FrontierReport {
        // Every candidate id any accepted Selection considered, and every
        // id it chose.
        let mut considered: BTreeSet<RecordId> = BTreeSet::new();
        let mut chosen: BTreeSet<RecordId> = BTreeSet::new();
        for rec in self.records {
            if rec.kind != Kind::Selection || !self.state.accepted_records.contains(&rec.id) {
                continue;
            }
            let Ok(sd) = decode::<SelectionData>(&rec.data) else {
                continue;
            };
            considered.extend(sd.considered.iter().copied());
            if let SelectionOutcome::Selected { candidates } = &sd.outcome {
                chosen.extend(candidates.iter().copied());
            }
        }
        // Chosen candidates that some accepted continuation already extends.
        let mut continued: BTreeSet<RecordId> = BTreeSet::new();
        for rec in self.records {
            if rec.kind != Kind::Candidate || !self.state.accepted_records.contains(&rec.id) {
                continue;
            }
            if let Ok(cd) = decode::<CandidateData>(&rec.data) {
                if cd.basis == CandidateBasis::Continuation {
                    if let Some(p) = cd.parent {
                        continued.insert(p);
                    }
                }
            }
        }

        let mut frontier = Vec::new();
        for rec in self.records {
            if rec.kind != Kind::Candidate || !self.state.accepted_records.contains(&rec.id) {
                continue;
            }
            let reason = if !considered.contains(&rec.id) {
                Some("unconsidered")
            } else if chosen.contains(&rec.id) && !continued.contains(&rec.id) {
                Some("selected-no-continuation")
            } else {
                None
            };
            if let Some(reason) = reason {
                frontier.push(FrontierEntry {
                    node: self.node(rec),
                    reason: reason.to_string(),
                });
            }
        }
        FrontierReport { frontier }
    }

    /// q5: the standing of one accepted record.
    pub fn standing(&self, id: RecordId) -> Result<StandingReport, QueryError> {
        let rec = self.get_accepted(id)?;
        let restorations = self
            .verdict
            .standing
            .restorations
            .get(&id)
            .map(|set| set.iter().map(hex_encode).collect())
            .unwrap_or_default();
        Ok(StandingReport {
            node: self.node(rec),
            restorations,
        })
    }

    /// q6: what `id` rests on. For a Selection, its own evidence; for a
    /// Candidate, the evidence of every anchor Selection along its descent.
    pub fn evidence(&self, id: RecordId) -> Result<EvidenceReport, QueryError> {
        let rec = self.get_accepted(id)?;
        let rests_on = match rec.kind {
            Kind::Selection => vec![SelectionEvidence {
                selection: self.node(rec),
                evidence: self.selection_evidence(rec),
            }],
            Kind::Candidate => {
                let descent = self.descent(id)?;
                let mut out = Vec::new();
                for step in &descent.line {
                    if step.node.kind == "Selection" {
                        let sel = self.get(parse_hex(&step.node.id))?;
                        out.push(SelectionEvidence {
                            selection: step.node.clone(),
                            evidence: self.selection_evidence(sel),
                        });
                    }
                }
                out
            }
            _ => {
                return Err(QueryError::KindMismatch {
                    id,
                    expected: "Candidate or Selection",
                })
            }
        };
        Ok(EvidenceReport {
            target: self.node(rec),
            rests_on,
        })
    }

    /// q7: the accepted `Selected` selections whose objective equals
    /// `objective` exactly, in log order.
    pub fn selected(&self, objective: &str) -> SelectedReport {
        let mut selections = Vec::new();
        for rec in self.records {
            if rec.kind != Kind::Selection || !self.state.accepted_records.contains(&rec.id) {
                continue;
            }
            let Ok(sd) = decode::<SelectionData>(&rec.data) else {
                continue;
            };
            if sd.objective != objective {
                continue;
            }
            let SelectionOutcome::Selected { candidates } = &sd.outcome else {
                continue;
            };
            let chosen = candidates
                .iter()
                .filter_map(|c| self.get(*c).ok())
                .map(|c| self.node(c))
                .collect();
            selections.push(SelectedEntry {
                selection: self.node(rec),
                chosen,
                evidence: self.selection_evidence(rec),
            });
        }
        SelectedReport {
            objective: objective.to_string(),
            selections,
        }
    }
}

/// Decode a lowercase-hex id this module itself produced; ids in reports
/// round-trip by construction, so a failure is a bug, not bad input.
fn parse_hex(hex: &str) -> RecordId {
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0);
    }
    id
}
