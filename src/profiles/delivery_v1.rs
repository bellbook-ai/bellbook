//! `delivery-receipt-v1` (RFC-0003 section 4.6, SPEC section 12.2): the
//! profile that makes a receipt a delivery receipt.
//!
//! A delivery claim is an accepted `Selection` with outcome `Selected`
//! whose `Use`d evaluations bind to requirements of exactly one `Request`
//! (RFC-0003 section 4.4): the claim's request is determined from the
//! record, never declared. Over that claim the profile checks the grammar
//! of "requirement R was met by evidence E, judged by evaluator V, over
//! artifact A, under capability profile L": coverage, truthful completion,
//! binding equality, producer/evaluator separation, the decider binding,
//! the named capability profile, and standing. It carries no domain
//! scoring or thresholds, and every clause is fail-closed: a claim that
//! cannot be checked does not conform.
//!
//! Like every profile, this is a report alongside the verdict. It never
//! changes `status` or `reason`.

use std::collections::{BTreeMap, BTreeSet};

use crate::base::hash::hex_encode;
use crate::receipt::{Receipt, Report, ValidationStatus};
use crate::record::kind::{Kind, RefType};
use crate::record::payloads::{
    Basis, CandidateData, EvaluationDataV2, EvaluationOutcomeV2, RequirementData, ResultData,
    SelectionData, SelectionOutcome,
};
use crate::record::record::{decode, Record};
use crate::record::refs::RecordId;

use super::{
    evaluate_declared, evaluate_profile, profile_hash, Clause, ClauseResult, ProfileResult,
    ProfileStatus, ProfileTable, BELLBOOK_CORE_V1, DELIVERY_RECEIPT_V1,
};

/// The clause table of `delivery-receipt-v1`. The statements are the
/// normative text; `docs/profiles/delivery-receipt-v1.md` quotes them.
pub fn table() -> ProfileTable {
    ProfileTable {
        id: DELIVERY_RECEIPT_V1.to_string(),
        version: 1,
        clauses: vec![
            Clause {
                id: "D0".into(),
                statement: "At least one delivery claim exists: an accepted Selection with outcome Selected whose Used evaluations bind to requirements of exactly one Request. For each request the latest sound claim is evaluated; earlier ones are reported superseded.".into(),
            },
            Clause {
                id: "D1".into(),
                statement: "Every accepted, unretracted Requirement with required true under the claim's request, as of the receipt head, has at least one evaluation among the claim's Used evaluations that references it with outcome passed.".into(),
            },
            Clause {
                id: "D2".into(),
                statement: "No evaluation among the claim's Used evaluations that references a required requirement has an outcome other than passed.".into(),
            },
            Clause {
                id: "D3".into(),
                statement: "The claim chooses exactly one candidate; every evaluation it uses judges that candidate, carries a non-empty evidence set, and every evidence reference appears in the candidate's artifacts or in the artifacts of an accepted Result in the same thread.".into(),
            },
            Clause {
                id: "D4".into(),
                statement: "The author of every evaluation the claim uses is a different actor from the author of the claimed candidate.".into(),
            },
            Clause {
                id: "D5".into(),
                statement: "Every evaluation the claim uses carries evaluator.id, evaluator.procedure_hash, evaluator.input_hash, and a declared basis; the weakest basis in the claim is reported.".into(),
            },
            Clause {
                id: "D6".into(),
                statement: "The receipt conforms to bellbook-core-v1 (or a stronger tier), and if it declares that profile the declaration names the evaluated table.".into(),
            },
            Clause {
                id: "D7".into(),
                statement: "The claim's Selection is sound, untainted, and unretracted at the receipt head.".into(),
            },
        ],
    }
}

const CLAUSE_IDS: [&str; 8] = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"];

/// One delivery claim as the profile sees it.
struct Claim<'a> {
    selection: &'a Record,
    request: RecordId,
    chosen: Vec<RecordId>,
    /// The accepted Evaluation records the Selection `Use`s, in ref order.
    used: Vec<&'a Record>,
}

fn short(id: &RecordId) -> String {
    hex_encode(id)[..12].to_string()
}

fn finish(clauses: Vec<ClauseResult>) -> ProfileResult {
    let status = if clauses.iter().all(|c| c.passed) {
        ProfileStatus::Conformant
    } else {
        ProfileStatus::NonConformant
    };
    ProfileResult {
        id: DELIVERY_RECEIPT_V1.to_string(),
        hash: profile_hash(&table()),
        status,
        clauses,
        declared: false,
        declaration_matches: None,
    }
}

/// Every clause failed for one reason that precedes the claim itself.
fn all_failed(reason: &str) -> ProfileResult {
    finish(
        CLAUSE_IDS
            .iter()
            .map(|id| ClauseResult {
                id: (*id).into(),
                passed: false,
                detail: reason.into(),
            })
            .collect(),
    )
}

/// Evaluate the profile over a validated receipt. `report` must be the
/// result of validating `receipt`.
pub fn evaluate(receipt: &Receipt, report: &Report) -> ProfileResult {
    if report.status == ValidationStatus::Invalid {
        return all_failed("receipt is Invalid");
    }
    // An accepting log has canonical payloads; the unchecked build cannot
    // fail. Surface the impossible case as a non-conformance, never a panic.
    let Ok(state) = crate::state::build::build_state_unchecked(&receipt.records) else {
        return all_failed("state could not be rebuilt");
    };
    let accepted = &state.accepted_records;
    let retracted = &report.retracted_records;
    let by_id: BTreeMap<RecordId, &Record> = receipt.records.iter().map(|r| (r.id, r)).collect();
    let is_accepted = |id: &RecordId| accepted.contains(id) && by_id.contains_key(id);

    // The request a Requirement belongs to: the target of its single Cause.
    let requirement_request = |rid: &RecordId| -> Option<RecordId> {
        let r = by_id.get(rid)?;
        if r.kind != Kind::Requirement || !is_accepted(rid) {
            return None;
        }
        r.refs
            .iter()
            .find(|f| f.type_ == RefType::Cause)
            .map(|f| f.target)
    };

    // --- D0: find the claims and pick the latest sound one per request ----
    let mut candidates: Vec<Claim<'_>> = Vec::new();
    for rec in &receipt.records {
        if rec.kind != Kind::Selection || !is_accepted(&rec.id) {
            continue;
        }
        let Ok(sd) = decode::<SelectionData>(&rec.data) else {
            continue;
        };
        let SelectionOutcome::Selected { candidates: chosen } = sd.outcome else {
            continue;
        };
        let used: Vec<&Record> = rec
            .refs
            .iter()
            .filter(|f| f.type_ == RefType::Use)
            .filter_map(|f| by_id.get(&f.target).copied())
            .filter(|t| t.kind == Kind::Evaluation && is_accepted(&t.id))
            .collect();
        let mut requests: BTreeSet<RecordId> = BTreeSet::new();
        for e in &used {
            if let Ok(ev) = decode::<EvaluationDataV2>(&e.data) {
                for rid in &ev.requirements {
                    if let Some(req) = requirement_request(rid) {
                        requests.insert(req);
                    }
                }
            }
        }
        if requests.len() != 1 {
            // Spans two requests, or binds to none: not a delivery claim.
            continue;
        }
        candidates.push(Claim {
            selection: rec,
            request: requests.into_iter().next().unwrap_or([0u8; 32]),
            chosen,
            used,
        });
    }

    let sound = |sel: &Record| {
        !report.standing.unsound.contains(&sel.id)
            && !retracted.contains(&sel.id)
            && !report.tainted_records.contains(&sel.id)
    };
    // Group by request in log order; the latest sound claim is evaluated,
    // or the latest one when none is sound (it then fails D7).
    let mut by_request: BTreeMap<RecordId, Vec<Claim<'_>>> = BTreeMap::new();
    for c in candidates {
        by_request.entry(c.request).or_default().push(c);
    }
    let mut claims: Vec<Claim<'_>> = Vec::new();
    let mut superseded: Vec<RecordId> = Vec::new();
    for (_, mut group) in by_request {
        group.sort_by_key(|c| c.selection.time);
        let pick = group
            .iter()
            .rposition(|c| sound(c.selection))
            .unwrap_or(group.len() - 1);
        for (i, c) in group.into_iter().enumerate() {
            if i == pick {
                claims.push(c);
            } else {
                superseded.push(c.selection.id);
            }
        }
    }
    claims.sort_by_key(|c| c.selection.time);

    let mut clauses = Vec::with_capacity(8);
    if claims.is_empty() {
        clauses.push(ClauseResult {
            id: "D0".into(),
            passed: false,
            detail: "no delivery claim: no accepted Selected selection whose used evaluations bind to requirements of exactly one request".into(),
        });
        for id in &CLAUSE_IDS[1..] {
            clauses.push(ClauseResult {
                id: (*id).into(),
                passed: false,
                detail: "no claim to evaluate".into(),
            });
        }
        return finish(clauses);
    }
    let mut d0 = claims
        .iter()
        .map(|c| {
            format!(
                "claim {} for request {}",
                short(&c.selection.id),
                short(&c.request)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if !superseded.is_empty() {
        d0.push_str(&format!(
            "; superseded: {}",
            superseded.iter().map(short).collect::<Vec<_>>().join(", ")
        ));
    }
    clauses.push(ClauseResult {
        id: "D0".into(),
        passed: true,
        detail: d0,
    });

    // Per-claim facts, aggregated: a clause passes when it holds for every
    // evaluated claim.
    let mut d1 = (true, Vec::new());
    let mut d2 = (true, Vec::new());
    let mut d3 = (true, Vec::new());
    let mut d4 = (true, Vec::new());
    let mut d5 = (true, Vec::new());
    let mut d7 = (true, Vec::new());

    for claim in &claims {
        let tag = short(&claim.selection.id);
        let used_v2: Vec<(&Record, EvaluationDataV2)> = claim
            .used
            .iter()
            .filter_map(|e| decode::<EvaluationDataV2>(&e.data).ok().map(|d| (*e, d)))
            .collect();

        // Required requirements under the request, at the head.
        let mut required: Vec<(RecordId, String)> = Vec::new();
        let mut required_ids: BTreeSet<RecordId> = BTreeSet::new();
        for rec in &receipt.records {
            if rec.kind != Kind::Requirement
                || !is_accepted(&rec.id)
                || retracted.contains(&rec.id)
                || requirement_request(&rec.id) != Some(claim.request)
            {
                continue;
            }
            if let Ok(rd) = decode::<RequirementData>(&rec.data) {
                if rd.required {
                    required.push((rec.id, rd.key));
                    required_ids.insert(rec.id);
                }
            }
        }

        // D1: coverage by a passed, unretracted evaluation.
        let mut uncovered = Vec::new();
        for (rid, key) in &required {
            let covered = used_v2.iter().any(|(e, d)| {
                !retracted.contains(&e.id)
                    && d.outcome == EvaluationOutcomeV2::Passed
                    && d.requirements.contains(rid)
            });
            if !covered {
                uncovered.push(key.clone());
            }
        }
        if uncovered.is_empty() {
            d1.1.push(format!(
                "{tag}: {} required requirement(s) covered",
                required.len()
            ));
        } else {
            d1.0 = false;
            d1.1.push(format!("{tag}: uncovered {}", uncovered.join(", ")));
        }

        // D2: no non-passing evaluation over a required requirement.
        let mut non_passing = Vec::new();
        for (e, d) in &used_v2 {
            if d.requirements.iter().any(|r| required_ids.contains(r))
                && d.outcome != EvaluationOutcomeV2::Passed
            {
                non_passing.push(format!("{} {}", short(&e.id), d.outcome.label()));
            }
        }
        if non_passing.is_empty() {
            d2.1.push(format!(
                "{tag}: every used evaluation of a required requirement passed"
            ));
        } else {
            d2.0 = false;
            d2.1.push(format!("{tag}: non-passing {}", non_passing.join(", ")));
        }

        // D3: one candidate, every evaluation judges it, evidence non-empty
        // and on the record.
        let mut d3_notes = Vec::new();
        let chosen = if claim.chosen.len() == 1 {
            Some(claim.chosen[0])
        } else {
            d3_notes.push(format!("chooses {} candidates", claim.chosen.len()));
            None
        };
        let candidate_rec = chosen.and_then(|c| by_id.get(&c).copied());
        let mut on_record: BTreeSet<(String, String)> = BTreeSet::new();
        if let Some(c) = candidate_rec {
            if let Ok(cd) = decode::<CandidateData>(&c.data) {
                for a in cd.artifacts.unwrap_or_default() {
                    on_record.insert((a.scheme, a.digest));
                }
            }
            for rec in &receipt.records {
                if rec.kind == Kind::Result
                    && is_accepted(&rec.id)
                    && rec.thread == claim.selection.thread
                {
                    if let Ok(rd) = decode::<ResultData>(&rec.data) {
                        for a in rd.artifacts.unwrap_or_default() {
                            on_record.insert((a.scheme, a.digest));
                        }
                    }
                }
            }
        }
        if used_v2.len() != claim.used.len() {
            d3_notes.push(format!(
                "{} evaluation(s) without an evidence set (v1 shape)",
                claim.used.len() - used_v2.len()
            ));
        }
        for (e, d) in &used_v2 {
            if Some(d.candidate) != chosen {
                d3_notes.push(format!("{} judges another candidate", short(&e.id)));
            }
            if d.evidence.is_empty() {
                d3_notes.push(format!("{} has no evidence", short(&e.id)));
            }
            for a in &d.evidence {
                if !on_record.contains(&(a.scheme.clone(), a.digest.clone())) {
                    d3_notes.push(format!(
                        "{} cites {}:{} which is not on the record",
                        short(&e.id),
                        a.scheme,
                        a.digest
                    ));
                }
            }
        }
        if d3_notes.is_empty() {
            d3.1.push(format!(
                "{tag}: {} evaluation(s) bound to the chosen candidate, evidence on the record",
                used_v2.len()
            ));
        } else {
            d3.0 = false;
            d3.1.push(format!("{tag}: {}", d3_notes.join("; ")));
        }

        // D4: producer and evaluator are distinct actors.
        let producer = candidate_rec.map(|c| c.author.id.as_str());
        let self_judged: Vec<String> = claim
            .used
            .iter()
            .filter(|e| Some(e.author.id.as_str()) == producer)
            .map(|e| short(&e.id))
            .collect();
        match (producer, self_judged.is_empty()) {
            (Some(p), true) => {
                d4.1.push(format!("{tag}: producer {p:?}, every evaluator distinct"))
            }
            (Some(p), false) => {
                d4.0 = false;
                d4.1.push(format!(
                    "{tag}: producer {p:?} authored evaluation(s) {}",
                    self_judged.join(", ")
                ));
            }
            (None, _) => {
                d4.0 = false;
                d4.1.push(format!("{tag}: no single claimed candidate"));
            }
        }

        // D5: decider binding present; weakest basis reported.
        let mut unbound = Vec::new();
        if used_v2.len() != claim.used.len() {
            unbound.push(format!(
                "{} evaluation(s) carry no decider binding (v1 shape)",
                claim.used.len() - used_v2.len()
            ));
        }
        // Recomputed is the stronger basis; one Declared makes the claim's
        // weakest basis Declared.
        let mut any_declared = false;
        for (e, d) in &used_v2 {
            if d.evaluator.procedure_hash.is_none() || d.evaluator.input_hash.is_none() {
                unbound.push(format!(
                    "{} lacks procedure_hash or input_hash",
                    short(&e.id)
                ));
            }
            any_declared |= matches!(d.basis, Basis::Declared);
        }
        let basis_label = if used_v2.is_empty() {
            "none"
        } else if any_declared {
            "declared"
        } else {
            "recomputed"
        };
        if unbound.is_empty() && !used_v2.is_empty() {
            d5.1.push(format!("{tag}: weakest basis {basis_label}"));
        } else {
            d5.0 = false;
            if unbound.is_empty() {
                unbound.push("no evaluation used".into());
            }
            d5.1.push(format!(
                "{tag}: {}; weakest basis {basis_label}",
                unbound.join("; ")
            ));
        }

        // D7: the claim's standing at the head.
        let unsound = report.standing.unsound.contains(&claim.selection.id);
        let tainted = report.tainted_records.contains(&claim.selection.id);
        let was_retracted = retracted.contains(&claim.selection.id);
        if !unsound && !tainted && !was_retracted {
            d7.1.push(format!("{tag}: sound, untainted"));
        } else {
            d7.0 = false;
            let mut why = Vec::new();
            if unsound {
                why.push("unsound");
            }
            if tainted {
                why.push("tainted");
            }
            if was_retracted {
                why.push("retracted");
            }
            d7.1.push(format!("{tag}: {}", why.join(", ")));
        }
    }

    // D6: the capability profile, declared or evaluated as a fallback.
    let core = match receipt.profiles.iter().find(|p| p.id == BELLBOOK_CORE_V1) {
        Some(decl) => evaluate_declared(decl, receipt, report),
        None => evaluate_profile(BELLBOOK_CORE_V1, receipt, report),
    };
    let d6_pass = core.met();
    let d6_detail = format!(
        "{}: {:?}{}",
        BELLBOOK_CORE_V1,
        core.status,
        match (core.declared, core.declaration_matches) {
            (true, Some(true)) => " (declared, declaration matches)",
            (true, Some(false)) => " (declared, DECLARATION MISMATCH)",
            (true, None) => " (declared)",
            (false, _) => " (not declared; evaluated as the fallback)",
        }
    );

    for (id, (passed, notes)) in [("D1", d1), ("D2", d2), ("D3", d3), ("D4", d4), ("D5", d5)] {
        clauses.push(ClauseResult {
            id: id.into(),
            passed,
            detail: notes.join("; "),
        });
    }
    clauses.push(ClauseResult {
        id: "D6".into(),
        passed: d6_pass,
        detail: d6_detail,
    });
    clauses.push(ClauseResult {
        id: "D7".into(),
        passed: d7.0,
        detail: d7.1.join("; "),
    });
    finish(clauses)
}
