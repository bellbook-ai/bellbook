use super::*;

/// Deterministic batch order: sort by SHA-256(canonical(proposal))
/// ascending, so commit order is independent of caller order.
pub(super) fn sort_batch(proposals: &mut [Proposal]) {
    proposals.sort_unstable_by(|a, b| {
        let ka = sha256_canonical(a).unwrap_or([0xff; 32]);
        let kb = sha256_canonical(b).unwrap_or([0xff; 32]);
        ka.cmp(&kb)
    });
}

/// Content equality between a proposal and a committed subject record,
/// ignoring only writer-assigned fields (id, time, evidence). A proposal's
/// signature is part of its identity and must match exactly.
pub(super) fn proposal_matches_record(proposal: &Proposal, record: &Record) -> bool {
    let mut refs = proposal.refs.clone();
    sort_and_dedup_refs(&mut refs);
    record.space == proposal.space
        && record.thread == proposal.thread
        && record.author == proposal.author
        && record.kind == proposal.kind
        && record.schema == proposal.schema
        && record.data == proposal.data
        && record.refs == refs
}

/// Materialize a verdict record for a subject.
pub(super) fn materialize_verdict(
    subject: &Record,
    verdict_time: u64,
    verdict_data: &VerdictData,
) -> Result<Record, LogError> {
    let verdict_schema = schema_id(SCHEMA_VERDICT);
    let data = encode(verdict_data)?;

    Ok(Record {
        id: [0u8; 32],
        space: subject.space,
        thread: subject.thread,
        time: verdict_time,
        author: Author {
            id: "verifier".into(),
            type_: AuthorType::Verifier,
            signature: None,
        },
        kind: Kind::Verdict,
        schema: verdict_schema,
        data,
        refs: vec![Ref {
            type_: RefType::Cause,
            target: subject.id,
        }],
        evidence: Evidence::Deterministic,
    }
    .with_computed_id()?)
}
