use super::*;

pub(super) fn check_verdict_record(
    record: &Record,
    prior: &Prior<'_>,
    rules: &VerifierRules,
) -> Option<ReasonCode> {
    // Id must match the canonical id form.
    match record.compute_id() {
        Ok(id) if id == record.id => {}
        _ => return Some(ReasonCode::InvalidPayload),
    }

    // Must be Verdict kind with verdict schema
    if record.schema != schema_id(SCHEMA_VERDICT) {
        return Some(ReasonCode::KindSchemaMismatch);
    }
    if record.author.type_ != AuthorType::Verifier {
        return Some(ReasonCode::InvalidPayload);
    }

    // Verdicts are materialized unsigned by the commit protocol. Reject a
    // present signature because verifier output has no external signer and
    // conforming implementations must produce one deterministic envelope.
    // (For all records, including verdicts, a completed signature would be
    // included in the id.)
    if record.author.signature.is_some() {
        return Some(ReasonCode::InvalidPayload);
    }

    // Space must match the verifier's space, and evidence is always
    // Deterministic - the verifier derived it itself.
    if record.space != rules.space {
        return Some(ReasonCode::InvalidPayload);
    }
    if record.evidence != Evidence::Deterministic {
        return Some(ReasonCode::InvalidPayload);
    }

    // Payload must be the canonical serialization of VerdictData.
    if !decodes_canonically::<VerdictData>(&record.data) {
        return Some(ReasonCode::InvalidPayload);
    }

    // Exactly one ref: the Cause edge to the subject.
    let [subject_ref] = record.refs.as_slice() else {
        return Some(ReasonCode::InvalidPayload);
    };
    if subject_ref.type_ != RefType::Cause {
        return Some(ReasonCode::InvalidPayload);
    }
    let subject_id = subject_ref.target;

    // Subject must resolve to a prior non-verdict record in the same
    // space and thread. An unresolved subject is a rejection, never a
    // pass.
    let Some(subject) = prior.find(subject_id) else {
        return Some(ReasonCode::RefUnresolved);
    };
    if subject.kind == Kind::Verdict {
        return Some(ReasonCode::InvalidPayload);
    }
    if subject.space != record.space || subject.thread != record.thread {
        return Some(ReasonCode::InvalidPayload);
    }

    // At most one verdict per subject
    if prior.has_verdict_for(subject_id) {
        return Some(ReasonCode::InvalidPayload);
    }

    None
}

/// Id-indexed view of the records preceding the one under verification.
///
/// Ref resolution, subject lookup, and duplicate-verdict detection all go
/// through this index, so verification cost stays proportional to log
/// size. A linear scan per lookup would make replay quadratic, letting a
/// receipt packed with many small records demand enormous CPU from a
/// validator (SPEC §12.3).
pub(super) struct Prior<'a> {
    /// The record sequence the index positions point into.
    records: &'a [Record],
    /// Id to position for every record in the prior set. First occurrence
    /// wins, matching a front-to-back scan.
    by_id: &'a HashMap<RecordId, usize>,
    /// Subjects already carrying a verdict: the Cause targets of every
    /// verdict record in the prior set.
    verdicted_subjects: &'a HashSet<RecordId>,
}

impl<'a> Prior<'a> {
    /// Find a prior record by id.
    pub(super) fn find(&self, id: RecordId) -> Option<&'a Record> {
        self.by_id.get(&id).map(|&pos| &self.records[pos])
    }

    /// Whether some prior verdict already judges this subject.
    pub(super) fn has_verdict_for(&self, subject: RecordId) -> bool {
        self.verdicted_subjects.contains(&subject)
    }
}

/// The owned backing for [`Prior`] views. `verify_log` grows one
/// incrementally as replay advances; the public [`verify_record`] builds
/// a one-off index over its prior slice.
#[derive(Default)]
pub(super) struct PriorIndex {
    by_id: HashMap<RecordId, usize>,
    verdicted_subjects: HashSet<RecordId>,
}

impl PriorIndex {
    /// Index every record of `records` (positions are slice positions).
    pub(super) fn of(records: &[Record]) -> Self {
        let mut index = Self::default();
        for (pos, record) in records.iter().enumerate() {
            index.insert(pos, record);
        }
        index
    }

    /// Register `record`, sitting at `pos` of the record sequence, as
    /// part of the prior set.
    pub(super) fn insert(&mut self, pos: usize, record: &Record) {
        self.by_id.entry(record.id).or_insert(pos);
        if record.kind == Kind::Verdict {
            for r in &record.refs {
                if r.type_ == RefType::Cause {
                    self.verdicted_subjects.insert(r.target);
                }
            }
        }
    }

    /// Borrow a lookup view. `records` must be the sequence the inserted
    /// positions point into.
    pub(super) fn view<'a>(&'a self, records: &'a [Record]) -> Prior<'a> {
        Prior {
            records,
            by_id: &self.by_id,
            verdicted_subjects: &self.verdicted_subjects,
        }
    }
}
