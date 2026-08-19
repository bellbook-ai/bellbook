//! Payload structs from SPEC.md.

use crate::base::hash::Hash256;
use crate::base::time::Time;
use crate::record::author::ActorId;
use crate::record::kind::*;
use crate::record::refs::RecordId;
use serde::{Deserialize, Serialize};

/// Inline file content attached to a Request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    /// Path label identifying the attachment (as supplied by the user).
    pub path: String,
    /// Full attachment content, stored inline in the record payload.
    pub content: String,
}

/// Payload for `Kind::Request` (`bellbook.request.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestData {
    /// Human-stated goal the agent should accomplish.
    pub objective: String,
    /// Scope hash this request operates in; actions inherit scoping from it.
    pub scope: Hash256,
    /// Inline files supplied with the request; empty when none.
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// When set, this request is a delegated child of the given parent
    /// request (same thread), and the record must carry exactly one
    /// `Cause` ref naming exactly that parent. When None, the record must
    /// carry no Request `Cause` refs at all - the declared parent and the
    /// Cause edges always state the same delegation graph.
    #[serde(default)]
    pub parent_request_id: Option<RecordId>,
}

/// Payload for `Kind::Action` (`bellbook.action.v1`) - one tool invocation
/// attempt. The verifier requires an active request and an effective
/// capability for (author, `action_class`, `scope`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionData {
    /// Id of the accepted, still-active Request this action serves; must be
    /// in the same thread and space.
    pub request_id: RecordId,
    /// Capability class name (e.g. tool name) matched against
    /// `state.active_capabilities` and class approvals.
    pub action_class: String,
    /// Scope hash; part of the capability/approval lookup key.
    pub scope: Hash256,
    /// Internal or External; determines which schema the closing Result
    /// must use.
    pub exec_mode: ExecMode,
    /// Free-form tool arguments; included in the SHA-256 hash that exact
    /// approvals target.
    pub params: serde_json::Value,
}

/// Payload for `Kind::Response` (`bellbook.response.v1`) - provider text
/// output for a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseData {
    /// Serialized as a JSON array of 32 bytes (or hex at the wire boundary).
    pub request_id: RecordId,
    /// Provider-generated text of this turn.
    pub content: String,
    /// 0-based position of this response within the request's conversation;
    /// must equal the count of previously accepted responses for the
    /// request (gap-free, in order).
    pub turn_index: u32,
    /// True marks this as the request's final response: the request leaves
    /// `active_requests`. Only valid when the request has no open actions.
    /// Request completion is always this explicit event (or a
    /// request-targeting Refusal) - never inferred from action counts.
    pub closes_request: bool,
}

/// Payload for `Kind::Result` (`bellbook.result.v1` and its external/effect
/// variants) - closes an open Action. The executor's identity is the
/// record's envelope `author.id` (role-checked and, for external results,
/// key-pinned) - there is deliberately no separate executor field to
/// drift from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultData {
    /// Id of the open Action this result closes; must also be the target of
    /// the record's single `Cause` ref.
    pub action_id: RecordId,
    /// Executor-reported Success or Failure; either way the action closes.
    pub status: ResultStatus,
    /// Raw tool output (or error text) as produced by the executor.
    pub output: String,
}

/// Payload for `Kind::Capability` (`bellbook.capability.v1`) - a permission
/// grant keyed by (actor, action_class, scope). Replacements must keep that
/// key identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityData {
    /// Actor this capability applies to (matched against the Action's
    /// author id).
    pub actor_id: ActorId,
    /// Action class the grant covers (e.g. a tool name).
    pub action_class: String,
    /// Scope hash the grant is limited to.
    pub scope: Hash256,
    /// Auto (no approval needed), Ask (approval required), or Deny (always
    /// rejected).
    pub mode: CapabilityMode,
    /// Logical time at which the grant lapses; None = never. Actions with
    /// `time >= expiry` fail with `CapabilityMissing`.
    pub expiry: Option<Time>,
}

/// Payload for `Kind::Approval` (`bellbook.approval.v1`) - human
/// authorization for Ask-mode actions. Exactly one of `target_action` or
/// `action_class` must be set: an approval authorizes one thing, never
/// silently two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalData {
    /// Exact-match form: `SHA-256(canonical((action_author_id,
    /// ActionData)))` - the hash binds the acting author together with the
    /// action content, so one actor's approval never authorizes another
    /// actor's byte-identical action. None for class-wide approvals.
    /// Exact approvals are single-use: an accepted action consumes them.
    pub target_action: Option<Hash256>,
    /// Class-wide form: approves every action of this class (in `scope`);
    /// None for exact-only approvals.
    pub action_class: Option<String>,
    /// Scope hash the approval applies to; part of the class-approval key.
    pub scope: Hash256,
    /// Restricts a class approval to one actor; None = wildcard (any actor).
    pub actor_id: Option<ActorId>,
    /// Logical time at which the approval lapses; None = never. Matched but
    /// expired class approvals yield `ApprovalExpired`.
    pub expiry: Option<Time>,
}

/// Payload for `Kind::Summary` (`bellbook.summary.v1` family) - a durable
/// knowledge claim. Replacements must keep (summary_type, subject, scope)
/// identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryData {
    /// Category of claim; must be in `VerifierRules::allowed_summary_types`.
    pub summary_type: SummaryType,
    /// Hash naming what the summary is about; part of the active-summary key.
    pub subject: Hash256,
    /// Scope hash; part of the active-summary key.
    pub scope: Hash256,
    /// Opaque claim content (Inferred evidence - derived, not independently verified).
    pub claim_payload: Vec<u8>,
}

/// Payload for `Kind::Refusal` (`bellbook.refusal.v1`) - cancels or
/// disputes a target record. Requires exactly one `Cause` ref to `target_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalData {
    /// Record being refused; its actual kind must match `target_kind`.
    pub target_id: RecordId,
    /// Whether an open Action, an active Request, or a verified effect is
    /// being refused.
    pub target_kind: RefusalTarget,
    /// Optional machine-readable justification (e.g. `Refused`); not
    /// interpreted by the verifier.
    pub reason_code: Option<ReasonCode>,
}

/// Payload for `Kind::Retraction` (`bellbook.retraction.v1`) - asserts an
/// accepted record's content was wrong, with nothing replacing it. Requires
/// exactly one `Cause` ref to `target_id`; the target may be any accepted
/// record except a Verdict or another Retraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetractionData {
    /// The record whose content is being retracted. It stays in the log;
    /// its id enters `state.retracted_records` and its epistemic dependents
    /// become tainted.
    pub target_id: RecordId,
    /// Free-form statement of why the content is wrong; not interpreted by
    /// the verifier.
    pub reason: String,
}

/// Payload for `Kind::Usage` (`bellbook.usage.v1`) - records that one
/// record's content fed another, with outcome feedback. Requires exactly
/// one `Use` ref to `used_record`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageData {
    /// Actor reporting the usage.
    pub actor: ActorId,
    /// Record whose content was consumed; tally key together with `role`.
    pub used_record: RecordId,
    /// Accepted Result or Refusal that consumed the input.
    pub consuming_record: RecordId,
    /// Free-form label for how the record was used (part of the
    /// `usage_counts` key).
    pub role: String,
    /// Whether the consumption helped; incremented into
    /// `state.usage_counts`.
    pub outcome: UsageOutcome,
}

/// Payload for `Kind::Verdict` (`bellbook.verdict.v1`) - the deterministic
/// judgment of the immediately preceding record. Stored verdicts are
/// re-derived and compared during `verify_log`, never trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictData {
    /// Accept (record folds into state) or Reject (no state effect).
    pub result: VerdictResult,
    /// Rejection rule that fired; always None on Accept.
    pub reason: Option<ReasonCode>,
}

/// Per-(record, role) tally of usage outcomes, kept in
/// `state.usage_counts` and surfaced as context usage feedback.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageOutcomeCounts {
    /// Number of `UsageOutcome::Done` reports.
    pub done: u64,
    /// Number of `UsageOutcome::NotDone` reports.
    pub not_done: u64,
    /// Number of `UsageOutcome::NoChange` reports.
    pub no_change: u64,
}

// ──────────────────────────── Plan payloads ────────────────────────────

/// Overall plan status; must be consistent with the task statuses
/// (the status-consistency verifier rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    /// At least one task is still Pending or Running.
    Running,
    /// Every task is Done.
    Completed,
    /// All tasks are terminal and at least one is Failed or Skipped;
    /// removes the plan from `state.active_plans`.
    Abandoned,
}

/// Per-task execution status within a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Not started yet.
    Pending,
    /// Currently executing.
    Running,
    /// Finished successfully (terminal).
    Done,
    /// Finished unsuccessfully (terminal).
    Failed,
    /// Deliberately not executed (terminal).
    Skipped,
}

/// What the host does when a task fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    /// Proceed with the remaining tasks.
    Continue,
    /// Pause and surface the failure to the user for a decision.
    AskUser,
    /// Stop the whole plan.
    Abort,
}

/// Coarse category of work a plan task performs; a hint for the host,
/// not enforced by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PlanTaskKind {
    /// Uncategorized work (the default).
    #[default]
    Generic,
    /// Examine existing data or state.
    Inspect,
    /// Locate information.
    Search,
    /// Pull structured content out of a source.
    Extract,
    /// Confirm a prior result or claim.
    Verify,
    /// Produce or modify an artifact.
    Write,
    /// Condense findings.
    Summarize,
}

/// Criterion for considering a task done, evaluated by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskDoneWhen {
    /// The tool call reported success (the default).
    #[default]
    ToolSuccess,
    /// The tool call returned non-empty output.
    NonEmptyResult,
    /// The targeted content was actually retrieved.
    ContentRetrieved,
    /// A final response for the request was produced.
    FinalResponse,
}

/// One node in a plan's task DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanTask {
    /// Task identifier, unique within the plan; referenced by other tasks'
    /// `depends_on` and `inputs_from`.
    pub id: String,
    /// Human-readable statement of what the task does.
    pub description: String,
    /// Work category hint; defaults to `Generic`.
    #[serde(default)]
    pub kind: PlanTaskKind,
    /// Suggested tool to use; None leaves the choice to the host.
    pub tool_hint: Option<String>,
    /// Ids of tasks whose outputs feed this one; empty when self-contained.
    #[serde(default)]
    pub inputs_from: Vec<String>,
    /// Label of the artifact this task yields, for downstream tasks; None
    /// when it produces nothing named.
    #[serde(default)]
    pub produces: Option<String>,
    /// Completion criterion; defaults to `ToolSuccess`.
    #[serde(default)]
    pub done_when: TaskDoneWhen,
    /// Current execution status; constrains the plan's overall status.
    pub status: TaskStatus,
    /// Related result: an accepted Result of this plan's request offered
    /// as supporting evidence for the task's outcome (allowed only on
    /// Done/Failed tasks). This is NOT task-to-proof binding - actions
    /// carry no task id, so the verifier cannot bind a specific task to a
    /// specific action; plans are advisory orchestration metadata.
    pub result_record_id: Option<RecordId>,
    /// Ids of tasks that must finish first; must exist in the plan and form
    /// no cycle (the dependency verifier rules).
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// What the host does if this task fails.
    pub on_failure: FailurePolicy,
}

// ─────────────────────── Evolution payloads (spec 0.3) ───────────────────────

/// The I-JSON safe-integer magnitude bound (SPEC §3); JCS refuses to
/// serialize integers beyond it, so typed decode refuses them symmetrically
/// and both implementations reject at the same boundary.
const MAX_SAFE_INTEGER_I64: i64 = 9_007_199_254_740_991;

/// Largest allowed `Scored.scale` (SPEC §2, `bellbook.evaluation.v1`):
/// value/10^scale with scale beyond 12 pushes unbounded fixed-point
/// arithmetic onto consumers.
const MAX_SCORE_SCALE: u8 = 12;

/// Git object format of a candidate's source pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAlgo {
    /// Classic Git object format; `tree`/`commit` are 40 hex characters.
    Sha1,
    /// SHA-256 object-format repositories; 64 hex characters.
    Sha256,
}

/// How a candidate's source identity is bound (SPEC §2, Source bindings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingMode {
    /// The host asserts the Git OIDs; the record proves the claim was
    /// recorded, not that the OIDs match any contents.
    Reported,
    /// `manifest_hash` additionally commits to the canonical manifest of the
    /// tree; a party holding the tree can recompute and compare. When both
    /// are present the manifest is the authoritative identity commitment.
    Manifest,
}

/// Git pointer inside a [`SourceBinding`]. Hex validity and length against
/// `algo` are verifier rules (`SourceBindingInvalid`), not decode rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSource {
    /// Object format the OIDs below are expressed in.
    pub algo: SourceAlgo,
    /// Tree OID: the content identity (two commits with the same tree are
    /// the same software state).
    pub tree: String,
    /// Commit OID: provenance only, never identity.
    #[serde(default)]
    pub commit: Option<String>,
}

/// A candidate's source identity (SPEC §2, Source bindings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    /// The Git pointer.
    pub git: GitSource,
    /// SHA-256 over the canonical manifest of the tree; present iff
    /// `binding == Manifest` (`SourceBindingInvalid` otherwise).
    #[serde(default)]
    pub manifest_hash: Option<Hash256>,
    /// Which binding mode this candidate carries.
    pub binding: BindingMode,
}

/// How a candidate entered its line of development; fixes its ref
/// obligations (`LineageInvalid` when violated) and how standing reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateBasis {
    /// Starts a line (imported or initial state); at most one `Cause`,
    /// targeting an accepted Request; no `parent`.
    Root,
    /// Continues from a selected state: exactly one `Cause` to an accepted
    /// Selection whose outcome is `Selected`, with `parent` naming a member
    /// of its selected set. Deliberately `Cause`, not `Require`: a
    /// candidate's evidence reflects its own content and a tainted history
    /// never blocks recording ongoing work; the anchor's health is carried
    /// by standing.
    Continuation,
    /// Derived from sibling material (repair, mutation, binding upgrade):
    /// one or more `Cause` refs, each an accepted Candidate or Evaluation;
    /// no `parent`.
    Derivation,
}

/// Payload for `Kind::Candidate` (`bellbook.candidate.v1`) - a source state
/// proposed in a line of development.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateData {
    /// The source identity this candidate binds.
    pub source: SourceBinding,
    /// How the candidate entered the line.
    pub basis: CandidateBasis,
    /// The selected candidate this one continues from; present iff
    /// `basis == Continuation` and resolving per the payload-id rules.
    #[serde(default)]
    pub parent: Option<RecordId>,
    /// Free-form label; not interpreted by the verifier.
    #[serde(default)]
    pub note: Option<String>,
}

/// A bounded fixed-point score: `value / 10^scale`. Bounds are enforced at
/// decode so both implementations reject at the same boundary
/// (`InvalidPayload`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ScoredValueRaw")]
pub struct ScoredValue {
    /// Signed integer within the I-JSON safe range.
    pub value: i64,
    /// Decimal scale, 0 through 12.
    pub scale: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScoredValueRaw {
    value: i64,
    scale: u8,
}

impl TryFrom<ScoredValueRaw> for ScoredValue {
    type Error = String;
    fn try_from(raw: ScoredValueRaw) -> Result<Self, Self::Error> {
        if raw.value.abs() > MAX_SAFE_INTEGER_I64 {
            return Err("score value outside the I-JSON safe range".into());
        }
        if raw.scale > MAX_SCORE_SCALE {
            return Err("score scale above 12".into());
        }
        Ok(Self {
            value: raw.value,
            scale: raw.scale,
        })
    }
}

/// Outcome of an evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOutcome {
    /// The criterion held.
    Passed,
    /// The criterion did not hold.
    Failed,
    /// A fixed-point measurement against the criterion.
    Scored(ScoredValue),
}

/// Payload for `Kind::Evaluation` (`bellbook.evaluation.v1`) - a judgment
/// about exactly one candidate under exactly one criterion. One criterion
/// per record is deliberate: retraction is record-granular, so per-metric
/// evaluations let one broken metric be retracted without erasing the
/// others.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "EvaluationDataRaw")]
pub struct EvaluationData {
    /// The candidate judged; must resolve to an accepted Candidate and be
    /// matched by a `Use` ref (`EvaluationInvalid` otherwise).
    pub candidate: RecordId,
    /// Non-empty criterion name (e.g. "unit-tests").
    pub criterion: String,
    /// How it was run (command, harness, version); not interpreted.
    #[serde(default)]
    pub procedure: Option<String>,
    /// Passed, Failed, or a bounded fixed-point score.
    pub outcome: EvaluationOutcome,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationDataRaw {
    candidate: RecordId,
    criterion: String,
    #[serde(default)]
    procedure: Option<String>,
    outcome: EvaluationOutcome,
}

impl TryFrom<EvaluationDataRaw> for EvaluationData {
    type Error = String;
    fn try_from(raw: EvaluationDataRaw) -> Result<Self, Self::Error> {
        if raw.criterion.is_empty() {
            return Err("evaluation criterion must be non-empty".into());
        }
        Ok(Self {
            candidate: raw.candidate,
            criterion: raw.criterion,
            procedure: raw.procedure,
            outcome: raw.outcome,
        })
    }
}

/// A selection's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionOutcome {
    /// The named candidates survive; each must appear in `considered` and be
    /// referenced by a `Require` ref (`SelectionInvalid` otherwise).
    Selected {
        /// The surviving candidates (one or more, unique).
        candidates: Vec<RecordId>,
    },
    /// No candidate was acceptable under the objective (pruning,
    /// backtracking); carries no candidate `Require`s.
    None,
}

/// Payload for `Kind::Selection` (`bellbook.selection.v1`) - a set-valued
/// decision over candidates under an objective. A `Replace` ref to a prior
/// Selection makes this a reaffirmation (SPEC §7.1); the objective string is
/// its compatibility key, so hosts treat objectives as identifiers, not
/// prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "SelectionDataRaw")]
pub struct SelectionData {
    /// Non-empty objective this decision was made under.
    pub objective: String,
    /// Candidates the decision was made over (one or more; uniqueness,
    /// resolution, and the `max_considered` bound are verifier rules).
    pub considered: Vec<RecordId>,
    /// The decision.
    pub outcome: SelectionOutcome,
    /// Free-form justification; not interpreted by the verifier.
    #[serde(default)]
    pub rationale: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionDataRaw {
    objective: String,
    considered: Vec<RecordId>,
    outcome: SelectionOutcome,
    #[serde(default)]
    rationale: Option<String>,
}

impl TryFrom<SelectionDataRaw> for SelectionData {
    type Error = String;
    fn try_from(raw: SelectionDataRaw) -> Result<Self, Self::Error> {
        if raw.objective.is_empty() {
            return Err("selection objective must be non-empty".into());
        }
        Ok(Self {
            objective: raw.objective,
            considered: raw.considered,
            outcome: raw.outcome,
            rationale: raw.rationale,
        })
    }
}

#[cfg(test)]
mod evolution_payload_tests {
    use super::*;

    fn scored(value: i64, scale: u8) -> String {
        format!(
            r#"{{"candidate":{:?},"criterion":"bench","outcome":{{"scored":{{"scale":{scale},"value":{value}}}}},"procedure":null}}"#,
            vec![0u8; 32]
        )
    }

    #[test]
    fn evaluation_decode_bounds() {
        // In-range scored outcome decodes.
        let ok: Result<EvaluationData, _> = serde_json::from_str(&scored(930, 3));
        assert!(ok.is_ok());
        // Scale above 12 rejects at decode.
        let bad_scale: Result<EvaluationData, _> = serde_json::from_str(&scored(930, 13));
        assert!(bad_scale.is_err());
        // Value beyond the I-JSON safe range rejects at decode.
        let bad_value: Result<EvaluationData, _> =
            serde_json::from_str(&scored(9_007_199_254_740_992, 0));
        assert!(bad_value.is_err());
        // The negative bound is symmetric.
        let ok_neg: Result<EvaluationData, _> =
            serde_json::from_str(&scored(-9_007_199_254_740_991, 0));
        assert!(ok_neg.is_ok());
        let bad_neg: Result<EvaluationData, _> =
            serde_json::from_str(&scored(-9_007_199_254_740_992, 0));
        assert!(bad_neg.is_err());
    }

    #[test]
    fn evaluation_criterion_must_be_non_empty() {
        let empty = format!(
            r#"{{"candidate":{:?},"criterion":"","outcome":"passed","procedure":null}}"#,
            vec![0u8; 32]
        );
        let r: Result<EvaluationData, _> = serde_json::from_str(&empty);
        assert!(r.is_err());
    }

    #[test]
    fn selection_objective_must_be_non_empty() {
        let empty = format!(
            r#"{{"considered":[{:?}],"objective":"","outcome":"none","rationale":null}}"#,
            vec![1u8; 32]
        );
        let r: Result<SelectionData, _> = serde_json::from_str(&empty);
        assert!(r.is_err());
        let ok = format!(
            r#"{{"considered":[{:?}],"objective":"latency","outcome":"none","rationale":null}}"#,
            vec![1u8; 32]
        );
        let r: Result<SelectionData, _> = serde_json::from_str(&ok);
        assert!(r.is_ok());
    }

    #[test]
    fn unknown_fields_reject_across_evolution_payloads() {
        let cand = r#"{"basis":"root","extra":1,"note":null,"parent":null,"source":{"binding":"reported","git":{"algo":"sha1","commit":null,"tree":"aa"},"manifest_hash":null}}"#.to_string();
        let r: Result<CandidateData, _> = serde_json::from_str(&cand);
        assert!(r.is_err(), "unknown field must reject");
        let nested = r#"{"basis":"root","note":null,"parent":null,"source":{"binding":"reported","extra":true,"git":{"algo":"sha1","commit":null,"tree":"aa"},"manifest_hash":null}}"#;
        let r: Result<CandidateData, _> = serde_json::from_str(nested);
        assert!(r.is_err(), "unknown nested field must reject");
    }

    #[test]
    fn selection_outcome_shapes() {
        let sel = format!(
            r#"{{"considered":[{:?}],"objective":"latency","outcome":{{"selected":{{"candidates":[{:?}]}}}},"rationale":"fastest"}}"#,
            vec![1u8; 32],
            vec![1u8; 32]
        );
        let r: Result<SelectionData, _> = serde_json::from_str(&sel);
        assert!(r.is_ok());
        // An unknown outcome variant rejects.
        let bad = format!(
            r#"{{"considered":[{:?}],"objective":"latency","outcome":"maybe","rationale":null}}"#,
            vec![1u8; 32]
        );
        let r: Result<SelectionData, _> = serde_json::from_str(&bad);
        assert!(r.is_err());
    }

    #[test]
    fn candidate_basis_and_binding_variants() {
        for (basis, binding, manifest) in [
            ("root", "reported", "null"),
            ("continuation", "reported", "null"),
            (
                "derivation",
                "manifest",
                &format!("{:?}", vec![2u8; 32])[..],
            ),
        ] {
            let cand = format!(
                r#"{{"basis":{basis:?},"note":null,"parent":null,"source":{{"binding":{binding:?},"git":{{"algo":"sha256","commit":null,"tree":"bb"}},"manifest_hash":{manifest}}}}}"#,
            );
            let r: Result<CandidateData, _> = serde_json::from_str(&cand);
            assert!(r.is_ok(), "case {basis}/{binding} should decode: {r:?}");
        }
        let bad = r#"{"basis":"fork","note":null,"parent":null,"source":{"binding":"reported","git":{"algo":"sha1","commit":null,"tree":"aa"},"manifest_hash":null}}"#;
        let r: Result<CandidateData, _> = serde_json::from_str(bad);
        assert!(r.is_err(), "unknown basis variant must reject");
    }

    #[test]
    fn evolution_payloads_round_trip_canonically() {
        // Encode -> decode -> encode is byte-stable (the canonical-payload
        // rule depends on it).
        let data = SelectionData {
            objective: "latency".into(),
            considered: vec![[1u8; 32]],
            outcome: SelectionOutcome::Selected {
                candidates: vec![[1u8; 32]],
            },
            rationale: None,
        };
        let bytes = crate::record::record::encode(&data).unwrap();
        let back: SelectionData = crate::record::record::decode(&bytes).unwrap();
        assert_eq!(back, data);
        assert_eq!(crate::record::record::encode(&back).unwrap(), bytes);
    }
}

/// Payload for `Kind::Plan` (`bellbook.plan.v1`) - a task graph for a
/// request: **advisory orchestration metadata, not compliance proof**.
/// The verifier keeps plans internally consistent (acyclic, real task
/// ids, real same-request result citations, coherent statuses) but does
/// not - and cannot - bind tasks to the actions that executed them.
/// Requires exactly one `Cause` ref to `request_id`; replacements
/// must keep the same `request_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanData {
    /// Accepted, active Request this plan serves (same thread/space).
    pub request_id: RecordId,
    /// Non-empty task list; ids unique, `depends_on` edges acyclic.
    pub tasks: Vec<PlanTask>,
    /// Overall status; must agree with the task statuses.
    pub status: PlanStatus,
}
