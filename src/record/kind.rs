//! Kind enum and all supporting enums from SPEC.md.

use serde::{Deserialize, Serialize};

/// The record type; determines which payload struct `data` decodes to and
/// which kind-specific verifier rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Kind {
    /// A user objective; stays in `state.active_requests` until a Response
    /// with `closes_request` (with no actions still open) or a Refusal
    /// targets it - completion is always an explicit event, never inferred
    /// from action counts.
    Request,
    /// A tool invocation attempt; must name an active Request and resolve a
    /// Capability (`Auto`, or `Ask` plus an unexpired Approval).
    Action,
    /// Provider (LLM) text output for a request; no state effect beyond
    /// acceptance.
    Response,
    /// Closes an open Action with executor output; schema must match the
    /// action's exec mode.
    Result,
    /// Durable knowledge claim (procedure/pattern/lesson/snapshot);
    /// replaceable, keyed by (summary_type, subject, scope).
    Summary,
    /// Human authorization for Ask-mode actions - exact (by action hash),
    /// class-wide, or class wildcard.
    Approval,
    /// Grants or denies an (actor, action_class, scope) permission with a
    /// mode of Auto, Ask, or Deny.
    Capability,
    /// Feedback that a record was used, tallied per (used_record, role) in
    /// `state.usage_counts`.
    Usage,
    /// Cancels an open Action, an active Request, or disputes a verified
    /// effect.
    Refusal,
    /// The deterministic verifier's judgment of the immediately preceding
    /// record; verifier-authored, `Deterministic` evidence.
    Verdict,
    /// A task graph for a Request; tasks form a DAG via `depends_on`,
    /// replaceable as the plan evolves.
    Plan,
    /// Asserts that an accepted record's content was WRONG and nothing
    /// replaces it. Append-only: the target stays in the log; records that
    /// epistemically depend on it (via `Use`/`Require` refs) become tainted.
    Retraction,
    /// A source state proposed in a line of development; binds a Git tree
    /// (identity) and optionally a commit (provenance). Its `basis` says how
    /// it entered the line: `Root`, `Continuation` of a Selection, or
    /// `Derivation` from sibling material.
    Candidate,
    /// A judgment about exactly one candidate under exactly one criterion;
    /// `Use`s its candidate, so a retracted candidate taints its
    /// evaluations.
    Evaluation,
    /// A set-valued decision over candidates under an objective: the
    /// survivors of best-of-N, a population generation, or a
    /// single-candidate accept.
    Selection,
}

/// Typed edge from a record to a prior record in the same space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RefType {
    /// This record exists because of the target (Result → Action,
    /// Verdict → subject, delegated Request → parent).
    Cause,
    /// The target's content was used as input (e.g. Usage → used record).
    Use,
    /// The target must be accepted state for this record to be valid
    /// (Action → Capability/Approval).
    Require,
    /// This record supersedes the target; the target enters
    /// `state.replaced_records` (never deleted). Only Summary, Capability,
    /// Approval, and Plan may be replaced, by a same-kind compatible record.
    Replace,
}

/// Who authored a record; constrains which kinds an author may produce.
/// The kind-to-author-type mapping is normative and enforced by the
/// verifier ([`allowed_author_types`]); a record whose author type is not
/// allowed for its kind rejects with [`ReasonCode::AuthorRoleInvalid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AuthorType {
    /// The human principal: Request, Approval, Refusal, Capability,
    /// Retraction.
    User,
    /// AI provider (LLM), the governed party: Response, Action, Summary,
    /// Plan, Usage, Retraction.
    Provider,
    /// Host/system actor (deployment configuration, watchdogs): Capability,
    /// Refusal, Usage, Retraction.
    System,
    /// Tool executor: Result records only.
    Executor,
    /// The deterministic verifier: Verdict records only.
    Verifier,
}

/// The normative kind-to-author-type table (SPEC §2): which author types
/// may produce records of each kind. Enforced in `verify_record`;
/// violations reject with [`ReasonCode::AuthorRoleInvalid`].
///
/// Rationale: authority-granting and authority-exercising roles must not
/// coincide. Capabilities and Approvals come from the human principal (or,
/// for capabilities, deployment configuration) - never from the governed
/// agent or its executor. Actions, Responses, Plans, and Summaries come
/// from the governed agent. Results come only from the executor that ran
/// the tool. Retraction is open to every accountable party (an agent
/// retracting its own wrong claim is behavior the model rewards), but
/// never to the Executor or Verifier, whose records are attestations
/// others retract.
pub fn allowed_author_types(kind: Kind) -> &'static [AuthorType] {
    match kind {
        Kind::Request => &[AuthorType::User],
        Kind::Action => &[AuthorType::Provider],
        Kind::Response => &[AuthorType::Provider],
        Kind::Result => &[AuthorType::Executor],
        Kind::Summary => &[AuthorType::Provider],
        Kind::Approval => &[AuthorType::User],
        Kind::Capability => &[AuthorType::User, AuthorType::System],
        Kind::Usage => &[AuthorType::Provider, AuthorType::System],
        Kind::Refusal => &[AuthorType::User, AuthorType::System],
        Kind::Verdict => &[AuthorType::Verifier],
        Kind::Plan => &[AuthorType::Provider],
        Kind::Retraction => &[AuthorType::User, AuthorType::Provider, AuthorType::System],
        // Candidates and evaluations are things any accountable actor may
        // honestly report producing or observing; rules narrow per
        // deployment. Selections are decisions, so Executor - the role that
        // performs work - may not author them. Note the retraction
        // consequence: Executor may never author a Retraction, so
        // Executor-authored evaluations are retractable only through
        // admin_retraction_actors (SPEC §2).
        Kind::Candidate => &[
            AuthorType::User,
            AuthorType::Provider,
            AuthorType::Executor,
            AuthorType::System,
        ],
        Kind::Evaluation => &[
            AuthorType::User,
            AuthorType::Provider,
            AuthorType::Executor,
            AuthorType::System,
        ],
        Kind::Selection => &[AuthorType::User, AuthorType::Provider, AuthorType::System],
    }
}

/// Whether records of this kind require their author to be registered in
/// `VerifierRules::author_roles` (SPEC §2): every kind except `Verdict`,
/// which is materialized by the deterministic commit protocol and takes
/// its own verification path. The declared `author.type` is
/// adversary-controlled, so the identity-to-role binding must come from
/// configuration for control records of all kinds - an unregistered
/// actor claiming `User` could otherwise close requests with Refusals,
/// inject Summaries into context, skew Usage feedback, or retract its
/// own accepted records.
pub fn requires_registered_author(kind: Kind) -> bool {
    match kind {
        Kind::Request
        | Kind::Action
        | Kind::Approval
        | Kind::Capability
        | Kind::Response
        | Kind::Result
        | Kind::Plan
        | Kind::Summary
        | Kind::Usage
        | Kind::Refusal
        | Kind::Retraction
        | Kind::Candidate
        | Kind::Evaluation
        | Kind::Selection => true,
        Kind::Verdict => false,
    }
}

/// Outcome of deterministic verification of a record (or a whole log).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VerdictResult {
    /// The record passed all verifier rules; it is folded into `State`.
    Accept,
    /// The record violated a rule (see [`ReasonCode`]); it has no state effect.
    Reject,
}

/// Why the verifier rejected a record; each variant maps to specific rules
/// in `verify_record`/`verify_log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReasonCode {
    /// The record's schema hash is not in `VerifierRules::kind_schema_map`
    /// (no frozen name registered).
    UnknownSchema,
    /// The record's `kind` differs from the kind the frozen map assigns to
    /// its schema.
    KindSchemaMismatch,
    /// The kind is in `signature_required_kinds` but `author.signature` is
    /// absent.
    SignatureMissing,
    /// A present signature failed strict Ed25519 verification over the
    /// domain-separated canonical signing form, or was made with a key not
    /// pinned for its actor in `author_keys`.
    SignatureInvalid,
    /// A ref target does not exist in the committed prefix.
    RefUnresolved,
    /// A ref target exists but belongs to a different space; refs never
    /// cross spaces.
    RefCrossSpace,
    /// The named request is not an accepted, active request in the same
    /// thread/space (Action, Response, Plan, or Refusal-of-request).
    RequestMissing,
    /// No active capability for the action's (author, action_class, scope),
    /// or the capability expired at `record.time`.
    CapabilityMissing,
    /// The resolved capability has mode `Deny`.
    CapabilityDenied,
    /// Ask-mode capability with no matching exact, class, or wildcard
    /// approval.
    ApprovalMissing,
    /// A matching class/wildcard approval exists but expired
    /// (`record.time >= expiry`).
    ApprovalExpired,
    /// A Result or Refusal targets an action that is not open (already
    /// closed, or wrong thread/space).
    ActionClosed,
    /// A Replace ref on a non-replaceable kind, an unresolved/unaccepted or
    /// kind-mismatched target, or an incompatible payload identity.
    ReplacementInvalid,
    /// A Result for an `External` exec-mode action does not carry the
    /// external-receipt schema.
    ExternalReceiptRequired,
    /// The record's derived (effective) evidence is weaker than the
    /// threshold `VerifierRules::evidence_thresholds` configures for its
    /// kind.
    EvidenceBelowThreshold,
    /// The target was refused; carried in `RefusalData::reason_code` rather
    /// than emitted by `verify_record`.
    Refused,
    /// Catch-all structural rejection: payload fails to decode, id or
    /// evidence mismatch, malformed refs, or a per-kind rule violation.
    InvalidPayload,
    /// A checkpoint failed validation in `verify_log`: `log_length` exceeds
    /// the log, `log_hash`/`state_hash`/`last_time`/`last_record_id` do not
    /// match the verified prefix, or the boundary splits a subject/verdict
    /// pair.
    InvalidCheckpoint,
    /// The record's `author.type` is not allowed for its kind (the
    /// normative table in [`allowed_author_types`]) - e.g. a
    /// Provider-authored Approval or an Executor-authored Capability.
    AuthorRoleInvalid,
    /// An Action does not carry the `Require` ref naming the exact
    /// Capability (and, for Ask mode, the exact Approval) that authorizes
    /// it, so the audit graph would not show which authority was used.
    AuthorityRefMissing,
    /// A `Candidate`'s `SourceBinding` is malformed: a `tree`/`commit` OID
    /// whose hex length does not match its `algo`, or a `manifest_hash`
    /// present without `binding == Manifest` (or absent with it).
    SourceBindingInvalid,
    /// A `Candidate`'s basis obligations do not hold: the wrong number or
    /// kind of `Cause` targets for its `basis`, a `parent` present where the
    /// basis forbids it (or absent where it requires one), a `Continuation`
    /// whose `parent` is not in its anchor Selection's selected set, or a
    /// `Cause` target that is not accepted at commit position.
    LineageInvalid,
    /// A payload id (`CandidateData.parent`, a `SelectionData.considered`
    /// member, or `EvaluationData.candidate`) does not resolve, in the same
    /// space, to a previously accepted `Candidate` record.
    PayloadRefUnresolved,
    /// An `Evaluation` does not carry the `Use` ref naming the candidate its
    /// payload judges, so its epistemic dependence on that candidate is not
    /// recorded.
    EvaluationInvalid,
    /// A `Selection` violates its structural rules: empty or non-unique
    /// `considered`, `considered` beyond `max_considered`, a selected set
    /// that is empty, non-unique, not a subset of `considered`, or not
    /// exactly matched by the winner `Require` refs, a `Used` Evaluation
    /// whose candidate is not in `considered`, a `None` decision carrying
    /// candidate `Require` refs, a winner below `min_binding`, or a missing
    /// required Evaluation.
    SelectionInvalid,
    /// A reaffirming `Selection` (one carrying a `Replace` ref) targets a
    /// Selection with a different `objective`, or its author is not in the
    /// configured `reaffirmation_actors` allowlist.
    ReaffirmationInvalid,
    /// An `artifacts` list (spec 0.4) is malformed: a scheme that is not a
    /// valid token, a digest that is not lowercase hex of the length its
    /// scheme dictates (registered length, or an even 20..=64 bytes for an
    /// unregistered scheme), or a list that is not strictly sorted and
    /// deduplicated by `(scheme, digest, name)`.
    ArtifactRefInvalid,
}

/// How a capability gates actions of its (actor, action_class, scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CapabilityMode {
    /// Actions proceed without any approval.
    Auto,
    /// Each action needs an unexpired Approval - exact, class, or wildcard,
    /// checked in that priority order.
    Ask,
    /// All actions are rejected with `CapabilityDenied`.
    Deny,
}

/// Where an action executes; dictates the schema its Result must use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExecMode {
    /// In-process execution; the Result must not use the external-receipt
    /// schema.
    Internal,
    /// External execution; the Result must carry
    /// `bellbook.result.external_receipt.v1` (base evidence `Verified`),
    /// else `ExternalReceiptRequired`.
    External,
}

/// Executor-reported outcome of an action, recorded in `ResultData`.
/// This is the executor's report, not verified effect: whether the
/// intended real-world effect actually held is a separate
/// effect-confirmation Result or a host concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResultStatus {
    /// The executor reports the tool ran and returned success.
    Success,
    /// The tool ran but failed; the action still closes.
    Failure,
}

/// Category of knowledge a Summary claims; must be in
/// `VerifierRules::allowed_summary_types` and is part of the summary's
/// replacement identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SummaryType {
    /// A reusable how-to sequence.
    Procedure,
    /// A recurring observation across records.
    Pattern,
    /// A conclusion drawn from an outcome (often a failure).
    Lesson,
    /// A point-in-time snapshot of derived state.
    StateSnapshot,
}

/// Whether using a record helped; tallied into
/// `state.usage_counts` per (used_record, role).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum UsageOutcome {
    /// The consuming record succeeded with this input.
    Done,
    /// The consuming record failed despite this input.
    NotDone,
    /// The input made no observable difference.
    NoChange,
}

/// What a Refusal targets; must match the target record's actual kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RefusalTarget {
    /// Closes an open Action without a Result.
    Action,
    /// Cancels an active Request (and drops its active plan).
    Request,
    /// Disputes an accepted effect-confirmation Result; no automatic state
    /// change - outer policy decides retry/skip/stop.
    VerifiedEffect,
}
