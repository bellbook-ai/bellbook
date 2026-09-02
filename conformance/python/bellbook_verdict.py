"""Independent Python reimplementation of Bellbook's verdict rule battery.

This is the second increment of issue #5. The first increment
(`bellbook_conformance.py`) reproduced canonicalization, record ids, hashes,
strict decoding, and structural log integrity. This module reproduces the
*semantic* layer the first one deliberately deferred: the full per-record rule
battery (`verify_record`), the retraction + transitive-taint state machine, and
whole-log replay (`verify_log`) with its Clean / Tainted / Invalid status.

Like its sibling it is a *from-scratch* implementation - it shares no code path
with the Rust crate, only the published data files. It ports, in Python, the
normative rules in `src/verify/verifier/*`, `src/state/*`, and
`src/record/evidence.rs`, so an independent party can confirm that Bellbook's
verification *policy* - not just its hashing - is reproducible.

Signature verification of a *present* signature needs the `cryptography`
package (as in the sibling module); a record that carries a signature cannot be
judged without it, so those cases raise `SignatureUnavailable` and the runner
skips or fails them per `BELLBOOK_REQUIRE_SIGNATURE`. Everything with no present
signature - which is every receipt case and most record cases - is pure
standard library.

Scope note: the canonical-payload rule is reproduced as a typed decode (every
payload field, including nested plan tasks and attachments, is checked for its
serde type and enum-variant membership, and the exact field set is enforced)
*plus* a JCS round-trip that confirms the bytes are the canonical serialization.
Together these reject the same payloads the reference's typed `serde` decode
does. Envelope enums (kind, author type, evidence, ref types) are validated
structurally before any rule runs, so an unknown variant is a clean rejection
rather than a lookup crash.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import bellbook_conformance as bb

# ---------------------------------------------------------------------------
# Frozen schema names and ids (SHA-256 of the UTF-8 name; src/base/schema.rs).
# ---------------------------------------------------------------------------

SCHEMA_REQUEST = "bellbook.request.v1"
SCHEMA_ACTION = "bellbook.action.v1"
SCHEMA_RESPONSE = "bellbook.response.v1"
SCHEMA_RESULT = "bellbook.result.v1"
SCHEMA_RESULT_EXTERNAL = "bellbook.result.external_receipt.v1"
SCHEMA_RESULT_EFFECT_CONFIRMATION = "bellbook.result.effect_confirmation.v1"
SCHEMA_CAPABILITY = "bellbook.capability.v1"
SCHEMA_APPROVAL = "bellbook.approval.v1"
SCHEMA_SUMMARY = "bellbook.summary.v1"
SCHEMA_REFUSAL = "bellbook.refusal.v1"
SCHEMA_USAGE = "bellbook.usage.v1"
SCHEMA_VERDICT = "bellbook.verdict.v1"
SCHEMA_PLAN = "bellbook.plan.v1"
SCHEMA_RETRACTION = "bellbook.retraction.v1"
SCHEMA_CANDIDATE = "bellbook.candidate.v1"
SCHEMA_EVALUATION = "bellbook.evaluation.v1"
SCHEMA_SELECTION = "bellbook.selection.v1"

ALL_SCHEMAS = [
    SCHEMA_REQUEST,
    SCHEMA_ACTION,
    SCHEMA_RESPONSE,
    SCHEMA_RESULT,
    SCHEMA_RESULT_EXTERNAL,
    SCHEMA_RESULT_EFFECT_CONFIRMATION,
    SCHEMA_CAPABILITY,
    SCHEMA_APPROVAL,
    SCHEMA_SUMMARY,
    SCHEMA_REFUSAL,
    SCHEMA_USAGE,
    SCHEMA_VERDICT,
    SCHEMA_PLAN,
    SCHEMA_RETRACTION,
    SCHEMA_CANDIDATE,
    SCHEMA_EVALUATION,
    SCHEMA_SELECTION,
]


# The frozen schema set of epoch 0.3 (SPEC 14): a 0.3 receipt replays with
# exactly these known, so a schema a later epoch introduces rejects as
# UnknownSchema under 0.3 even if the embedded rules map it. Mirrors the
# reference's `SCHEMAS_V03` / `schemas_for_epoch`.
SCHEMAS_V03 = list(ALL_SCHEMAS)
EPOCH_SCHEMAS = {"0.3": SCHEMAS_V03, "0.4": ALL_SCHEMAS}


def schema_id_hex(name: str) -> str:
    return bb.sha256(name.encode("utf-8")).hex()


SCHEMA_ID_TO_NAME = {schema_id_hex(n): n for n in ALL_SCHEMAS}

# Enum variant sets (serde rejects any other string at decode). Most enums use
# the PascalCase variant name; the plan enums are `#[serde(rename_all =
# "snake_case")]` (src/record/payloads.rs, src/record/kind.rs).
EXEC_MODE = frozenset({"Internal", "External"})
CAP_MODE = frozenset({"Auto", "Ask", "Deny"})
RESULT_STATUS = frozenset({"Success", "Failure"})
SUMMARY_TYPE = frozenset({"Procedure", "Pattern", "Lesson", "StateSnapshot"})
USAGE_OUTCOME = frozenset({"Done", "NotDone", "NoChange"})
REFUSAL_TARGET = frozenset({"Action", "Request", "VerifiedEffect"})
VERDICT_RESULT = frozenset({"Accept", "Reject"})
REASON_CODE = frozenset({
    "UnknownSchema", "KindSchemaMismatch", "SignatureMissing", "SignatureInvalid",
    "RefUnresolved", "RefCrossSpace", "RequestMissing", "CapabilityMissing",
    "CapabilityDenied", "ApprovalMissing", "ApprovalExpired", "ActionClosed",
    "ReplacementInvalid", "ExternalReceiptRequired", "EvidenceBelowThreshold",
    "Refused", "InvalidPayload", "InvalidCheckpoint", "AuthorRoleInvalid",
    "AuthorityRefMissing", "SourceBindingInvalid", "LineageInvalid",
    "PayloadRefUnresolved", "EvaluationInvalid", "SelectionInvalid",
    "ReaffirmationInvalid", "ArtifactRefInvalid",
})
PLAN_STATUS = frozenset({"running", "completed", "abandoned"})
TASK_STATUS = frozenset({"pending", "running", "done", "failed", "skipped"})
PLAN_TASK_KIND = frozenset(
    {"generic", "inspect", "search", "extract", "verify", "write", "summarize"}
)
TASK_DONE_WHEN = frozenset(
    {"tool_success", "non_empty_result", "content_retrieved", "final_response"}
)
FAILURE_POLICY = frozenset({"continue", "ask_user", "abort"})
SOURCE_ALGO = frozenset({"sha1", "sha256"})
BINDING_MODE = frozenset({"reported", "manifest"})
CANDIDATE_BASIS = frozenset({"root", "continuation", "derivation"})

# Envelope enums (validated structurally, as serde does when it decodes a
# Record; an unknown value here is a decode rejection, not a rule violation).
KINDS = frozenset(
    {
        "Request", "Action", "Response", "Result", "Summary", "Approval",
        "Capability", "Usage", "Refusal", "Verdict", "Plan", "Retraction",
        "Candidate", "Evaluation", "Selection",
    }
)
AUTHOR_TYPES = frozenset({"User", "Provider", "System", "Executor", "Verifier"})
EVIDENCES = frozenset({"Deterministic", "Verified", "Reported", "Inferred", "Assumed"})
REF_TYPES = frozenset({"Cause", "Use", "Require", "Replace"})

# Typed field descriptors for each payload struct, mirroring the serde types so
# an unknown enum variant or a mistyped field rejects exactly as the reference's
# typed decode does. A stored payload also serializes its complete field set, so
# an exact-key-set check reproduces `deny_unknown_fields` and missing fields.
_STRUCT_SPECS = {
    "Attachment": {"path": "str", "content": "str"},
    "GitSource": {
        "algo": ("enum", SOURCE_ALGO),
        "tree": "str",
        "commit": ("opt", "str"),
    },
    "SourceBinding": {
        "git": ("struct", "GitSource"),
        "manifest_hash": ("opt", "hash"),
        "binding": ("enum", BINDING_MODE),
    },
    # Bounded fixed-point score: value within the I-JSON safe range, scale
    # 0..=12 (src/record/payloads.rs ScoredValue try_from bounds).
    "ScoredValue": {
        "value": ("int_range", -9007199254740991, 9007199254740991),
        "scale": ("int_range", 0, 12),
    },
    "SelectedCandidates": {"candidates": ("vec", "hash")},
    # Artifact identity (spec 0.4): scheme token, hex digest, optional label.
    "ArtifactRef": {"scheme": "str", "digest": "str", "name": ("opt", "str")},
    "PlanTask": {
        "id": "str",
        "description": "str",
        "kind": ("enum", PLAN_TASK_KIND),
        "tool_hint": ("opt", "str"),
        "inputs_from": ("vec", "str"),
        "produces": ("opt", "str"),
        "done_when": ("enum", TASK_DONE_WHEN),
        "status": ("enum", TASK_STATUS),
        "result_record_id": ("opt", "hash"),
        "depends_on": ("vec", "str"),
        "on_failure": ("enum", FAILURE_POLICY),
    },
}

_PAYLOAD_SPECS = {
    SCHEMA_REQUEST: {
        "objective": "str",
        "scope": "hash",
        "attachments": ("vec", ("struct", "Attachment")),
        "parent_request_id": ("opt", "hash"),
    },
    SCHEMA_ACTION: {
        "request_id": "hash",
        "action_class": "str",
        "scope": "hash",
        "exec_mode": ("enum", EXEC_MODE),
        "params": "value",
    },
    SCHEMA_RESPONSE: {
        "request_id": "hash",
        "content": "str",
        "turn_index": "u32",
        "closes_request": "bool",
    },
    SCHEMA_RESULT: {
        "action_id": "hash",
        "status": ("enum", RESULT_STATUS),
        "output": "str",
        # Additive (spec 0.4): the key may be absent; when present it must
        # be a list (a present `null` is not canonical and rejects, as the
        # reference's `skip_serializing_if = Option::is_none` re-encode does).
        "artifacts": ("optkey", ("vec", ("struct", "ArtifactRef"))),
    },
    SCHEMA_CAPABILITY: {
        "actor_id": "str",
        "action_class": "str",
        "scope": "hash",
        "mode": ("enum", CAP_MODE),
        "expiry": ("opt", "u64"),
    },
    SCHEMA_APPROVAL: {
        "target_action": ("opt", "hash"),
        "action_class": ("opt", "str"),
        "scope": "hash",
        "actor_id": ("opt", "str"),
        "expiry": ("opt", "u64"),
    },
    SCHEMA_SUMMARY: {
        "summary_type": ("enum", SUMMARY_TYPE),
        "subject": "hash",
        "scope": "hash",
        "claim_payload": "bytes",
    },
    SCHEMA_REFUSAL: {
        "target_id": "hash",
        "target_kind": ("enum", REFUSAL_TARGET),
        "reason_code": ("opt", ("enum", REASON_CODE)),
    },
    SCHEMA_USAGE: {
        "actor": "str",
        "used_record": "hash",
        "consuming_record": "hash",
        "role": "str",
        "outcome": ("enum", USAGE_OUTCOME),
    },
    SCHEMA_VERDICT: {"result": ("enum", VERDICT_RESULT), "reason": ("opt", ("enum", REASON_CODE))},
    SCHEMA_PLAN: {
        "request_id": "hash",
        "tasks": ("vec", ("struct", "PlanTask")),
        "status": ("enum", PLAN_STATUS),
    },
    SCHEMA_RETRACTION: {"target_id": "hash", "reason": "str"},
    SCHEMA_CANDIDATE: {
        "source": ("struct", "SourceBinding"),
        "basis": ("enum", CANDIDATE_BASIS),
        "parent": ("opt", "hash"),
        "note": ("opt", "str"),
        "artifacts": ("optkey", ("vec", ("struct", "ArtifactRef"))),
    },
    SCHEMA_EVALUATION: {
        "candidate": "hash",
        "criterion": "nonempty_str",
        "procedure": ("opt", "str"),
        # Externally tagged: "passed" | "failed" | {"scored": ScoredValue}.
        "outcome": ("tagged", frozenset({"passed", "failed"}), {"scored": "ScoredValue"}),
    },
    SCHEMA_SELECTION: {
        "objective": "nonempty_str",
        "considered": ("vec", "hash"),
        # Externally tagged: "none" | {"selected": {"candidates": [...]}}.
        "outcome": ("tagged", frozenset({"none"}), {"selected": "SelectedCandidates"}),
        "rationale": ("opt", "str"),
    },
}
# The three Result schemas share the ResultData shape.
_PAYLOAD_SPECS[SCHEMA_RESULT_EXTERNAL] = _PAYLOAD_SPECS[SCHEMA_RESULT]
_PAYLOAD_SPECS[SCHEMA_RESULT_EFFECT_CONFIRMATION] = _PAYLOAD_SPECS[SCHEMA_RESULT]

# ---------------------------------------------------------------------------
# Ordinals and normative tables (src/record/kind.rs, evidence.rs).
# ---------------------------------------------------------------------------

# Evidence order, strongest -> weakest; "weaker" is a larger ordinal.
EVIDENCE_ORDER = {
    "Deterministic": 0,
    "Verified": 1,
    "Reported": 2,
    "Inferred": 3,
    "Assumed": 4,
}

# RefType declaration order (used for the strict refs ordering rule).
REFTYPE_ORD = {"Cause": 0, "Use": 1, "Require": 2, "Replace": 3}

BASE_EVIDENCE = {
    SCHEMA_VERDICT: "Deterministic",
    SCHEMA_RESULT_EXTERNAL: "Verified",
    SCHEMA_REQUEST: "Reported",
    SCHEMA_ACTION: "Reported",
    SCHEMA_RESPONSE: "Reported",
    SCHEMA_RESULT: "Reported",
    SCHEMA_RESULT_EFFECT_CONFIRMATION: "Reported",
    SCHEMA_CAPABILITY: "Reported",
    SCHEMA_APPROVAL: "Reported",
    SCHEMA_REFUSAL: "Reported",
    SCHEMA_USAGE: "Reported",
    SCHEMA_RETRACTION: "Reported",
    SCHEMA_CANDIDATE: "Reported",
    SCHEMA_EVALUATION: "Reported",
    SCHEMA_SUMMARY: "Inferred",
    SCHEMA_PLAN: "Inferred",
    SCHEMA_SELECTION: "Inferred",
}

ALLOWED_AUTHOR_TYPES = {
    "Request": frozenset({"User"}),
    "Action": frozenset({"Provider"}),
    "Response": frozenset({"Provider"}),
    "Result": frozenset({"Executor"}),
    "Summary": frozenset({"Provider"}),
    "Approval": frozenset({"User"}),
    "Capability": frozenset({"User", "System"}),
    "Usage": frozenset({"Provider", "System"}),
    "Refusal": frozenset({"User", "System"}),
    "Verdict": frozenset({"Verifier"}),
    "Plan": frozenset({"Provider"}),
    "Retraction": frozenset({"User", "Provider", "System"}),
    "Candidate": frozenset({"User", "Provider", "Executor", "System"}),
    "Evaluation": frozenset({"User", "Provider", "Executor", "System"}),
    "Selection": frozenset({"User", "Provider", "System"}),
}

# Every kind except Verdict must have its author registered in author_roles.
REQUIRES_REGISTERED = frozenset(ALLOWED_AUTHOR_TYPES.keys()) - {"Verdict"}

# The u32 ceiling the Response turn counter must not pass.
U32_MAX = 0xFFFF_FFFF


def base_evidence(schema_hex: str) -> str:
    name = SCHEMA_ID_TO_NAME.get(schema_hex)
    return BASE_EVIDENCE.get(name, "Assumed")


def weakest(evidences: list[str]) -> str:
    if not evidences:
        return "Deterministic"
    return max(evidences, key=lambda e: EVIDENCE_ORDER[e])


def derive_evidence(schema_hex: str, ref_evidences: list[str]) -> str:
    base = base_evidence(schema_hex)
    if not ref_evidences:
        return base
    return weakest([base] + ref_evidences)


# ---------------------------------------------------------------------------
# Wire helpers.
# ---------------------------------------------------------------------------


def h(arr: Any) -> str:
    """Hex of a 32-byte wire value (a JSON array of 32 ints)."""
    return bytes(arr).hex()


def payload(record: dict) -> Any:
    """The record's decoded payload: `data` is a byte array whose bytes are the
    canonical JSON of the schema's payload type."""
    return json.loads(bytes(record["data"]).decode("utf-8"))


def schema_hex(record: dict) -> str:
    return h(record["schema"])


def refs_of(record: dict, ref_type: str) -> list[dict]:
    return [r for r in record["refs"] if r["type"] == ref_type]


class SignatureUnavailable(Exception):
    """A present signature could not be verified because `cryptography` is not
    installed. The caller decides whether that is a skip or a hard failure."""


def verified_key(record: dict) -> Optional[bytes]:
    """Return the signing public key if the record's present signature verifies
    strictly over the domain-separated signing form, else None. Mirrors
    `src/record/sign.rs::verified_key`. Raises SignatureUnavailable if the
    signature is present but `cryptography` cannot be loaded."""
    sig = record["author"].get("signature")
    if sig is None:
        return None
    key_id = sig["key_id"]
    # `key_id` is the signer's Ed25519 public key as 64 lowercase hex chars;
    # any other spelling is unresolvable (hex_decode is strict).
    if len(key_id) != 64 or any(c not in "0123456789abcdef" for c in key_id):
        return None
    sig_bytes = bytes(sig["sig"])
    if len(sig_bytes) != 64:
        return None
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except BaseException as e:  # noqa: BLE001 - broken native bindings surface oddly
        raise SignatureUnavailable(str(e))
    key_bytes = bytes.fromhex(key_id)
    try:
        pk = Ed25519PublicKey.from_public_bytes(key_bytes)
        pk.verify(sig_bytes, bb.signing_bytes(record))
    except InvalidSignature:
        return None
    except ValueError:
        return None
    return key_bytes


# ---------------------------------------------------------------------------
# Rules access (wire form of VerifierRules; src/verify/rules.rs).
# ---------------------------------------------------------------------------


class Rules:
    """Read-only view over a receipt/record-case `rules` wire object, as the
    declared epoch sees it: `kind_schema_map` keeps only the schemas that
    epoch admits (src/receipt.rs `rules_for_epoch`). Everything else in the
    rules is epoch-neutral."""

    def __init__(self, wire: dict, spec_version: str = bb.SPEC_VERSION):
        self.space = h(wire["space"])
        known = {schema_id_hex(n) for n in EPOCH_SCHEMAS[spec_version]}
        # kind_schema_map: array of [schema_bytes, kind_name] pairs.
        self.kind_schema_map = {h(s): k for s, k in wire["kind_schema_map"] if h(s) in known}
        self.signature_required_kinds = set(wire["signature_required_kinds"])
        # author_keys: actor -> [pubkey_bytes, ...]; compare by raw bytes (hex).
        self.author_keys = {
            actor: {bytes(k).hex() for k in keys}
            for actor, keys in wire["author_keys"].items()
        }
        self.author_roles = dict(wire["author_roles"])
        self.admin_retraction_actors = set(wire["admin_retraction_actors"])
        self.allowed_summary_types = set(wire["allowed_summary_types"])
        self.evidence_thresholds = dict(wire["evidence_thresholds"])
        # Evolution knobs (spec 0.3). Absent keys take the reference defaults
        # so a rules object serialized before these fields existed still
        # parses; a serialized v0.3 rules object always carries them.
        self.min_binding = wire.get("min_binding", "reported")
        self.selection_requires_evaluation = wire.get("selection_requires_evaluation", True)
        self.reaffirmation_actors = set(wire.get("reaffirmation_actors", []))
        self.max_considered = wire.get("max_considered", 4096)
        self.selection_requires_approval = wire.get("selection_requires_approval", False)
        self.reject_compromised_continuation = wire.get("reject_compromised_continuation", False)


# ---------------------------------------------------------------------------
# Prior index (src/verify/verifier/verdict.rs).
# ---------------------------------------------------------------------------


class Prior:
    """Id-indexed view over the records preceding the one under verification."""

    def __init__(self):
        self._by_id: dict[str, dict] = {}
        self._verdicted: set[str] = set()

    def insert(self, record: dict) -> None:
        rid = h(record["id"])
        if rid not in self._by_id:  # first occurrence wins
            self._by_id[rid] = record
        if record["kind"] == "Verdict":
            for r in record["refs"]:
                if r["type"] == "Cause":
                    self._verdicted.add(h(r["target"]))

    def find(self, target_hex: str) -> Optional[dict]:
        return self._by_id.get(target_hex)

    def has_verdict_for(self, subject_hex: str) -> bool:
        return subject_hex in self._verdicted


def prior_index(records: list[dict]) -> Prior:
    idx = Prior()
    for r in records:
        idx.insert(r)
    return idx


# ---------------------------------------------------------------------------
# State (src/state/state.rs) + incremental application (src/state/incremental.rs).
# ---------------------------------------------------------------------------


class State:
    def __init__(self):
        self.accepted: set[str] = set()
        self.active_requests: set[str] = set()
        self.active_capabilities: dict[tuple, str] = {}
        self.valid_approvals: dict[str, str] = {}
        self.class_approvals: dict[tuple, str] = {}
        self.open_actions: set[str] = set()
        self.action_to_request: dict[str, str] = {}
        self.request_open_action_count: dict[str, int] = {}
        self.active_plans: dict[str, str] = {}
        self.response_turns: dict[str, int] = {}
        self.capability_index: dict[str, tuple] = {}
        self.exact_approval_index: dict[str, str] = {}
        self.class_approval_index: dict[str, tuple] = {}
        self.retracted: set[str] = set()
        self.tainted: set[str] = set()
        self.epistemic_dependents: dict[str, set[str]] = {}

    def ref_evidence(self, ref: dict, target: dict) -> Optional[str]:
        """Evidence a ref contributes to weakest-link derivation, or None if it
        does not participate (Cause/Replace are provenance)."""
        if ref["type"] in ("Use", "Require"):
            tid = h(target["id"])
            if tid not in self.accepted or tid in self.retracted or tid in self.tainted:
                return "Assumed"
            return target["evidence"]
        return None


def exact_action_hash(record: dict, action_data: dict) -> str:
    """SHA-256(canonical((action_author_id, ActionData))): binds the acting
    author to the action content (src/verify/verifier/activity.rs)."""
    return bb.sha256(bb.jcs([record["author"]["id"], action_data]).encode("utf-8")).hex()


SELECTION_APPROVAL_DOMAIN = "bellbook.selection-approval.v0.3"


def selection_approval_subject_hash(record: dict, replace_target, data: dict) -> str:
    """SHA-256(canonical((domain, selection_author_id, replace_target_or_null,
    SelectionData))) (src/record/payloads.rs). `replace_target` is the wire
    ref target (a byte array) or None, matching the Rust `Option<RecordId>`."""
    return bb.sha256(
        bb.jcs(
            [SELECTION_APPROVAL_DOMAIN, record["author"]["id"], replace_target, data]
        ).encode("utf-8")
    ).hex()


def _mark_tainted(state: State, rid: str) -> None:
    stack = [rid]
    while stack:
        current = stack.pop()
        if current in state.tainted:
            continue
        state.tainted.add(current)
        deps = state.epistemic_dependents.get(current)
        if deps:
            stack.extend(deps)


def apply_accepted(state: State, record: dict) -> None:
    """Fold an accepted record into state (src/state/incremental.rs)."""
    rid = h(record["id"])
    state.accepted.add(rid)

    inherits_taint = False
    for r in record["refs"]:
        if r["type"] in ("Use", "Require"):
            tgt = h(r["target"])
            state.epistemic_dependents.setdefault(tgt, set()).add(rid)
            if tgt in state.retracted or tgt in state.tainted:
                inherits_taint = True
    if inherits_taint:
        _mark_tainted(state, rid)

    k = record["kind"]
    if k == "Request":
        state.active_requests.add(rid)
    elif k == "Action":
        data = payload(record)
        exact_hash = exact_action_hash(record, data)
        approval_id = state.valid_approvals.get(exact_hash)
        if approval_id is not None and any(
            r["type"] == "Require" and h(r["target"]) == approval_id for r in record["refs"]
        ):
            state.valid_approvals.pop(exact_hash, None)
            state.exact_approval_index.pop(approval_id, None)
        state.open_actions.add(rid)
        req = h(data["request_id"])
        state.action_to_request[rid] = req
        state.request_open_action_count[req] = state.request_open_action_count.get(req, 0) + 1
    elif k == "Result":
        data = payload(record)
        aid = h(data["action_id"])
        state.open_actions.discard(aid)
        _close_action_for_request(state, aid)
    elif k == "Refusal":
        data = payload(record)
        tgt = h(data["target_id"])
        tk = data["target_kind"]
        if tk == "Action":
            state.open_actions.discard(tgt)
            _close_action_for_request(state, tgt)
        elif tk == "Request":
            state.active_requests.discard(tgt)
            state.active_plans.pop(tgt, None)
        # VerifiedEffect: no automatic state change.
    elif k == "Capability":
        data = payload(record)
        key = (data["actor_id"], data["action_class"], h(data["scope"]))
        state.capability_index[rid] = key
        state.active_capabilities[key] = rid
    elif k == "Approval":
        data = payload(record)
        if data.get("target_action") is not None:
            target = h(data["target_action"])
            state.exact_approval_index[rid] = target
            state.valid_approvals[target] = rid
        if data.get("action_class") is not None:
            key = (data["action_class"], h(data["scope"]), data.get("actor_id"))
            state.class_approval_index[rid] = key
            state.class_approvals[key] = rid
    elif k == "Summary":
        pass  # active_summaries is not consulted by any verdict rule.
    elif k == "Usage":
        pass  # usage_counts is not consulted by any verdict rule.
    elif k == "Plan":
        data = payload(record)
        req = h(data["request_id"])
        state.active_plans[req] = rid
        if data["status"] in ("completed", "abandoned"):
            state.active_plans.pop(req, None)
    elif k == "Retraction":
        data = payload(record)
        target = h(data["target_id"])
        state.retracted.add(target)
        for dep in list(state.epistemic_dependents.get(target, set())):
            _mark_tainted(state, dep)
        # Deactivate retracted authority, only if the active slot still points
        # at the retracted record.
        cap_key = state.capability_index.get(target)
        if cap_key is not None and state.active_capabilities.get(cap_key) == target:
            state.active_capabilities.pop(cap_key, None)
        ex_hash = state.exact_approval_index.get(target)
        if ex_hash is not None and state.valid_approvals.get(ex_hash) == target:
            state.valid_approvals.pop(ex_hash, None)
        cl_key = state.class_approval_index.get(target)
        if cl_key is not None and state.class_approvals.get(cl_key) == target:
            state.class_approvals.pop(cl_key, None)
    elif k == "Response":
        data = payload(record)
        req = h(data["request_id"])
        state.response_turns[req] = min(state.response_turns.get(req, 0) + 1, U32_MAX)
        if data["closes_request"]:
            state.active_requests.discard(req)
            state.active_plans.pop(req, None)
    elif k == "Selection":
        # Single-use consumption of a Selection approval (delta D5), parallel
        # to the Action exact-approval path. replaced_records is not tracked
        # here (no verdict rule consults it).
        data = payload(record)
        replace_refs = refs_of(record, "Replace")
        replace_target = replace_refs[0]["target"] if replace_refs else None
        subject_hash = selection_approval_subject_hash(record, replace_target, data)
        approval_id = state.valid_approvals.get(subject_hash)
        if approval_id is not None and any(
            r["type"] == "Require" and h(r["target"]) == approval_id for r in record["refs"]
        ):
            state.valid_approvals.pop(subject_hash, None)
            state.exact_approval_index.pop(approval_id, None)
    # Verdict, Candidate, Evaluation: no operational state.


def _close_action_for_request(state: State, action_id: str) -> None:
    req = state.action_to_request.get(action_id)
    if req is None:
        return
    if req in state.request_open_action_count:
        state.request_open_action_count[req] -= 1
        if state.request_open_action_count[req] == 0:
            del state.request_open_action_count[req]


def build_state_unchecked(records: list[dict]) -> State:
    """Trusting build over an already-verified prefix (src/state/build.rs)."""
    state = State()
    if not records:
        return state
    verdict_map: dict[str, dict] = {}
    for record in records:
        if record["kind"] == "Verdict":
            cause = refs_of(record, "Cause")
            if cause:
                verdict_map[h(cause[0]["target"])] = payload(record)
    for record in records:
        if record["kind"] == "Verdict":
            continue
        v = verdict_map.get(h(record["id"]))
        if v is not None and v["result"] == "Accept":
            apply_accepted(state, record)
    return state


# ---------------------------------------------------------------------------
# Typed payload decode + canonical-payload rule (record_checks.rs).
# ---------------------------------------------------------------------------


def _is_uint(v: Any, bits: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= (1 << bits) - 1


def _conforms(value: Any, desc: Any) -> bool:
    """Whether `value` decodes to the serde type described by `desc` - the check
    the reference's typed `serde` decode performs (unknown enum variants and
    mistyped fields reject)."""
    if desc == "str":
        return isinstance(value, str)
    if desc == "bool":
        return isinstance(value, bool)
    if desc == "u32":
        return _is_uint(value, 32)
    if desc == "u64":
        # u64 on the wire, but JCS caps integers at the I-JSON safe bound and
        # rejects negatives, so that is the effective accepted range.
        return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= bb.MAX_SAFE_INTEGER
    if desc == "hash":
        return isinstance(value, list) and len(value) == 32 and all(_is_uint(b, 8) for b in value)
    if desc == "bytes":
        return isinstance(value, list) and all(_is_uint(b, 8) for b in value)
    if desc == "value":  # serde_json::Value - any JSON is accepted.
        return True
    if desc == "nonempty_str":
        return isinstance(value, str) and len(value) > 0
    tag = desc[0]
    if tag == "enum":
        return isinstance(value, str) and value in desc[1]
    if tag == "opt":
        return value is None or _conforms(value, desc[1])
    if tag == "vec":
        return isinstance(value, list) and all(_conforms(x, desc[1]) for x in value)
    if tag == "struct":
        return _struct_conforms(value, _STRUCT_SPECS[desc[1]])
    if tag == "int_range":
        lo, hi = desc[1], desc[2]
        return isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi
    if tag == "tagged":
        # serde externally tagged enum: a unit variant is its snake_case
        # name; a struct variant is a one-key object whose value conforms
        # to the named struct spec.
        units, structs = desc[1], desc[2]
        if isinstance(value, str):
            return value in units
        if isinstance(value, dict) and len(value) == 1:
            (variant, inner), = value.items()
            spec_name = structs.get(variant)
            return spec_name is not None and _struct_conforms(inner, _STRUCT_SPECS[spec_name])
        return False
    raise AssertionError(f"unknown descriptor {desc!r}")


def _is_optkey(desc: Any) -> bool:
    return isinstance(desc, tuple) and desc[0] == "optkey"


def _struct_conforms(value: Any, spec: dict) -> bool:
    """Exact key set, except that an `optkey` field may be absent (an
    additive spec-0.4 field the reference declares with `serde(default,
    skip_serializing_if)`); when present it must conform to its inner
    descriptor - a present `null` is a non-canonical spelling of "absent"
    and rejects."""
    if not isinstance(value, dict):
        return False
    required = {f for f, d in spec.items() if not _is_optkey(d)}
    if not required <= set(value.keys()) <= set(spec.keys()):
        return False
    for field, d in spec.items():
        if field not in value:
            continue
        inner = d[1] if _is_optkey(d) else d
        if not _conforms(value[field], inner):
            return False
    return True


def _decodes_canonically(record: dict) -> bool:
    """Payload must be the exact JCS canonical serialization of its schema's
    type: it must decode to that type (typed field/enum check) AND re-serialize
    byte-for-byte to the stored bytes (canonical form)."""
    name = SCHEMA_ID_TO_NAME.get(schema_hex(record))
    if name is None:
        return False
    try:
        raw = bytes(record["data"]).decode("utf-8")
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not _struct_conforms(value, _PAYLOAD_SPECS[name]):
        return False
    try:
        return bb.jcs(value) == raw
    except bb.DecodeError:
        return False


def envelope_ok(record: dict) -> bool:
    """Structural validity of a record's envelope enums (kind, author type,
    evidence, ref types). serde rejects an unknown variant when it decodes the
    Record, before any rule runs; reproducing that here keeps hostile input a
    clean rejection instead of a KeyError on an enum-ordinal lookup."""
    if record.get("kind") not in KINDS:
        return False
    author = record.get("author")
    if not isinstance(author, dict) or author.get("type") not in AUTHOR_TYPES:
        return False
    if record.get("evidence") not in EVIDENCES:
        return False
    refs = record.get("refs")
    if not isinstance(refs, list) or any(r.get("type") not in REF_TYPES for r in refs):
        return False
    return True


def _structurally_decodes(record: dict) -> bool:
    """A record is structurally decodable (the reference deserializes the whole
    receipt with serde before replay): full wire-shape decode plus valid
    envelope enums. Hostile shapes become a clean rejection, never a crash."""
    try:
        bb.decode_record(record)
    except bb.DecodeError:
        return False
    return envelope_ok(record)


# ---------------------------------------------------------------------------
# Per-record rule battery (src/verify/verifier/record_checks.rs + activity.rs +
# lifecycle.rs + plans.rs). Returns a ReasonCode string to reject, or None to
# accept.
# ---------------------------------------------------------------------------


def check_record(record: dict, prior: Prior, rules: Rules, state: State) -> Optional[str]:
    if record["kind"] == "Verdict":
        return check_verdict_record(record, prior, rules)

    # Structural: id matches its canonical recomputation.
    if bb.record_id(record) != bytes(record["id"]):
        return "InvalidPayload"

    # Refs strictly sorted by (type ordinal, target) and deduplicated.
    keys = [(REFTYPE_ORD[r["type"]], bytes(r["target"])) for r in record["refs"]]
    if any(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)):
        return "InvalidPayload"

    # Space.
    if h(record["space"]) != rules.space:
        return "InvalidPayload"

    # Schema -> expected kind.
    expected_kind = rules.kind_schema_map.get(schema_hex(record))
    if expected_kind is None:
        return "UnknownSchema"
    if record["kind"] != expected_kind:
        return "KindSchemaMismatch"

    # Author type allowed for the kind (normative table).
    if record["author"]["type"] not in ALLOWED_AUTHOR_TYPES[record["kind"]]:
        return "AuthorRoleInvalid"

    # Identity-to-role binding.
    role = rules.author_roles.get(record["author"]["id"])
    if role is not None:
        if record["author"]["type"] != role:
            return "AuthorRoleInvalid"
    else:
        if record["kind"] in REQUIRES_REGISTERED:
            return "AuthorRoleInvalid"

    # Signatures.
    sig_required = (
        record["kind"] in rules.signature_required_kinds
        or record["author"]["id"] in rules.author_keys
    )
    if sig_required and record["author"].get("signature") is None:
        return "SignatureMissing"
    if record["author"].get("signature") is not None:
        key = verified_key(record)
        if key is None:
            return "SignatureInvalid"
        allowed = rules.author_keys.get(record["author"]["id"])
        if allowed is not None and key.hex() not in allowed:
            return "SignatureInvalid"

    # Refs resolve to prior committed records in the same space; a Require ref
    # needs its target to be accepted, non-retracted, non-tainted.
    for r in record["refs"]:
        target = prior.find(h(r["target"]))
        if target is None:
            return "RefUnresolved"
        if h(target["space"]) != h(record["space"]):
            return "RefCrossSpace"
        if r["type"] == "Require":
            tid = h(target["id"])
            if tid not in state.accepted or tid in state.retracted or tid in state.tainted:
                return "RefUnresolved"

    # Replacement.
    replace_refs = refs_of(record, "Replace")
    if len(replace_refs) > 1:
        return "InvalidPayload"
    if replace_refs:
        if record["kind"] not in ("Summary", "Capability", "Approval", "Plan", "Selection"):
            return "ReplacementInvalid"
        target = prior.find(h(replace_refs[0]["target"]))
        if target is None:
            return "ReplacementInvalid"
        if h(target["id"]) not in state.accepted:
            return "ReplacementInvalid"
        if target["kind"] != record["kind"]:
            return "ReplacementInvalid"
        reason = _check_replacement_compatibility(record, target)
        if reason is not None:
            return reason

    # Evidence must equal derived (only Use/Require refs contribute).
    ref_evidences: list[str] = []
    for r in record["refs"]:
        target = prior.find(h(r["target"]))
        if target is not None:
            ev = state.ref_evidence(r, target)
            if ev is not None:
                ref_evidences.append(ev)
    expected_evidence = derive_evidence(schema_hex(record), ref_evidences)
    if record["evidence"] != expected_evidence:
        return "InvalidPayload"

    # Evidence threshold (weaker == larger ordinal).
    threshold = rules.evidence_thresholds.get(record["kind"])
    if threshold is not None and EVIDENCE_ORDER[expected_evidence] > EVIDENCE_ORDER[threshold]:
        return "EvidenceBelowThreshold"

    # Canonical payload.
    if not _decodes_canonically(record):
        return "InvalidPayload"

    return _check_kind_specific(record, prior, rules, state)


def _check_replacement_compatibility(record: dict, target: dict) -> Optional[str]:
    k = record["kind"]
    new, old = payload(record), payload(target)
    if k == "Capability":
        if (
            new["actor_id"] != old["actor_id"]
            or new["action_class"] != old["action_class"]
            or new["scope"] != old["scope"]
        ):
            return "ReplacementInvalid"
    elif k == "Approval":
        if new.get("target_action") is not None and old.get("target_action") is not None:
            if new["scope"] != old["scope"] or new["target_action"] != old["target_action"]:
                return "ReplacementInvalid"
        elif new.get("action_class") is not None and old.get("action_class") is not None:
            if (
                new["action_class"] != old["action_class"]
                or new["scope"] != old["scope"]
                or new.get("actor_id") != old.get("actor_id")
            ):
                return "ReplacementInvalid"
        else:
            return "ReplacementInvalid"
    elif k == "Summary":
        if (
            new["summary_type"] != old["summary_type"]
            or new["subject"] != old["subject"]
            or new["scope"] != old["scope"]
        ):
            return "ReplacementInvalid"
    elif k == "Plan":
        if new["request_id"] != old["request_id"]:
            return "ReplacementInvalid"
    return None


# --- Kind-specific checks. ---------------------------------------------------


def _check_kind_specific(record: dict, prior: Prior, rules: Rules, state: State) -> Optional[str]:
    dispatch = {
        "Request": _check_request,
        "Action": _check_action,
        "Result": _check_result,
        "Refusal": _check_refusal,
        "Usage": _check_usage,
        "Summary": _check_summary,
        "Response": _check_response,
        "Approval": _check_approval,
        "Plan": _check_plan,
        "Retraction": _check_retraction,
        "Candidate": _check_candidate,
        "Evaluation": _check_evaluation,
        "Selection": _check_selection,
    }
    fn = dispatch.get(record["kind"])
    return fn(record, prior, rules, state) if fn else None


def _check_request(record, prior, rules, state):
    data = payload(record)
    cause_targets = [h(r["target"]) for r in record["refs"] if r["type"] == "Cause"]
    for tid in cause_targets:
        parent = prior.find(tid)
        if parent is None:
            return "RefUnresolved"
        if parent["kind"] != "Request":
            return "InvalidPayload"
        if h(parent["thread"]) != h(record["thread"]):
            return "InvalidPayload"
        if tid not in state.accepted:
            return "RequestMissing"
    pid = data.get("parent_request_id")
    if pid is None:
        if cause_targets:
            return "InvalidPayload"
    else:
        if len(cause_targets) != 1 or cause_targets[0] != h(pid):
            return "InvalidPayload"
    return None


def _check_action(record, prior, rules, state):
    data = payload(record)
    req = h(data["request_id"])
    if req not in state.active_requests:
        return "RequestMissing"
    request = prior.find(req)
    if request is None:
        return "RequestMissing"
    if h(request["thread"]) != h(record["thread"]) or h(request["space"]) != h(record["space"]):
        return "RequestMissing"
    request_data = payload(request)
    if data["scope"] != request_data["scope"]:
        return "InvalidPayload"

    cap_key = (record["author"]["id"], data["action_class"], h(data["scope"]))
    cap_id = state.active_capabilities.get(cap_key)
    if cap_id is None:
        return "CapabilityMissing"
    cap_record = prior.find(cap_id)
    if cap_record is None:
        return "CapabilityMissing"
    if cap_id in state.retracted or cap_id in state.tainted:
        return "CapabilityMissing"
    cap_data = payload(cap_record)
    if cap_data.get("expiry") is not None and record["time"] >= cap_data["expiry"]:
        return "CapabilityMissing"

    mode = cap_data["mode"]
    approval_id = None
    if mode == "Deny":
        return "CapabilityDenied"
    elif mode == "Auto":
        approval_id = None
    elif mode == "Ask":
        ok, val = _check_approval_for_action(record, data, prior, state)
        if not ok:
            return val
        approval_id = val

    if not _has_require_ref(record, cap_id):
        return "AuthorityRefMissing"
    if approval_id is not None and not _has_require_ref(record, approval_id):
        return "AuthorityRefMissing"
    return None


def _has_require_ref(record, target_hex):
    return any(r["type"] == "Require" and h(r["target"]) == target_hex for r in record["refs"])


def _check_approval_for_action(record, data, prior, state):
    """Returns (True, approval_id) or (False, reason)."""
    action_hash = exact_action_hash(record, data)

    def usable(aid):
        return aid in state.accepted and aid not in state.retracted and aid not in state.tainted

    # Priority 1: exact match (single-use).
    approval_id = state.valid_approvals.get(action_hash)
    if approval_id is not None:
        ar = prior.find(approval_id)
        if ar is not None and usable(approval_id):
            ad = payload(ar)
            if ad.get("actor_id") == record["author"]["id"] and ad["scope"] == data["scope"]:
                expiry = ad.get("expiry")
                if not (expiry is not None and record["time"] >= expiry):
                    return True, approval_id

    # Priority 2: class match with specific actor.
    class_key = (data["action_class"], h(data["scope"]), record["author"]["id"])
    approval_id = state.class_approvals.get(class_key)
    if approval_id is not None:
        ar = prior.find(approval_id)
        if ar is not None and usable(approval_id):
            ad = payload(ar)
            if ad.get("expiry") is not None and record["time"] >= ad["expiry"]:
                return False, "ApprovalExpired"
            return True, approval_id

    # Priority 3: class wildcard.
    wildcard_key = (data["action_class"], h(data["scope"]), None)
    approval_id = state.class_approvals.get(wildcard_key)
    if approval_id is not None:
        ar = prior.find(approval_id)
        if ar is not None and usable(approval_id):
            ad = payload(ar)
            if ad.get("expiry") is not None and record["time"] >= ad["expiry"]:
                return False, "ApprovalExpired"
            return True, approval_id

    return False, "ApprovalMissing"


def _check_result(record, prior, rules, state):
    data = payload(record)
    if not _artifacts_well_formed(data.get("artifacts")):
        return "ArtifactRefInvalid"
    aid = h(data["action_id"])
    if aid not in state.open_actions:
        return "ActionClosed"
    action = prior.find(aid)
    if action is None:
        return "ActionClosed"
    if h(action["thread"]) != h(record["thread"]) or h(action["space"]) != h(record["space"]):
        return "ActionClosed"
    action_data = payload(action)
    external_schema = schema_id_hex(SCHEMA_RESULT_EXTERNAL)
    if action_data["exec_mode"] == "External":
        if schema_hex(record) != external_schema:
            return "ExternalReceiptRequired"
        if record["author"].get("signature") is None:
            return "SignatureMissing"
        if record["author"]["id"] not in rules.author_keys:
            return "SignatureInvalid"
    else:  # Internal
        if schema_hex(record) == external_schema:
            return "InvalidPayload"
    cause_refs = refs_of(record, "Cause")
    if len(cause_refs) != 1 or h(cause_refs[0]["target"]) != aid:
        return "InvalidPayload"
    return None


def _check_refusal(record, prior, rules, state):
    data = payload(record)
    tid = h(data["target_id"])
    target = prior.find(tid)
    if target is None:
        return "RequestMissing"
    tk = data["target_kind"]
    if tk == "Action":
        if target["kind"] != "Action":
            return "InvalidPayload"
        if tid not in state.open_actions:
            return "ActionClosed"
        if h(target["thread"]) != h(record["thread"]) or h(target["space"]) != h(record["space"]):
            return "ActionClosed"
    elif tk == "Request":
        if target["kind"] != "Request":
            return "InvalidPayload"
        if tid not in state.active_requests:
            return "RequestMissing"
        if h(target["thread"]) != h(record["thread"]) or h(target["space"]) != h(record["space"]):
            return "RequestMissing"
    elif tk == "VerifiedEffect":
        if target["kind"] != "Result" or schema_hex(target) != schema_id_hex(
            SCHEMA_RESULT_EFFECT_CONFIRMATION
        ):
            return "InvalidPayload"
        if tid not in state.accepted:
            return "InvalidPayload"
        if h(target["thread"]) != h(record["thread"]) or h(target["space"]) != h(record["space"]):
            return "InvalidPayload"
    cause_refs = refs_of(record, "Cause")
    if len(cause_refs) != 1 or h(cause_refs[0]["target"]) != tid:
        return "InvalidPayload"
    return None


def _check_usage(record, prior, rules, state):
    data = payload(record)
    if data["actor"] != record["author"]["id"]:
        return "InvalidPayload"
    if prior.find(h(data["used_record"])) is None:
        return "InvalidPayload"
    consuming = prior.find(h(data["consuming_record"]))
    if consuming is None:
        return "InvalidPayload"
    if h(data["consuming_record"]) not in state.accepted:
        return "InvalidPayload"
    if consuming["kind"] not in ("Result", "Refusal"):
        return "InvalidPayload"
    if h(consuming["thread"]) != h(record["thread"]):
        return "InvalidPayload"
    use_refs = refs_of(record, "Use")
    if len(use_refs) != 1 or h(use_refs[0]["target"]) != h(data["used_record"]):
        return "InvalidPayload"
    return None


def _check_summary(record, prior, rules, state):
    data = payload(record)
    if data["summary_type"] not in rules.allowed_summary_types:
        return "InvalidPayload"
    if len(refs_of(record, "Use")) == 0:
        return "InvalidPayload"
    return None


def _check_response(record, prior, rules, state):
    data = payload(record)
    req = h(data["request_id"])
    if req not in state.active_requests:
        return "RequestMissing"
    request = prior.find(req)
    if request is None:
        return "RequestMissing"
    if h(request["thread"]) != h(record["thread"]) or h(request["space"]) != h(record["space"]):
        return "RequestMissing"
    expected_turn = state.response_turns.get(req, 0)
    if expected_turn == U32_MAX or data["turn_index"] != expected_turn:
        return "InvalidPayload"
    if data["closes_request"]:
        if state.request_open_action_count.get(req, 0) > 0:
            return "InvalidPayload"
        if req in state.active_plans:
            return "InvalidPayload"
    return None


def _check_approval(record, prior, rules, state):
    data = payload(record)
    if (data.get("target_action") is not None) == (data.get("action_class") is not None):
        return "InvalidPayload"
    if data.get("target_action") is not None and data.get("actor_id") is None:
        return "InvalidPayload"
    return None


def _check_plan(record, prior, rules, state):
    data = payload(record)
    cause_refs = refs_of(record, "Cause")
    if len(cause_refs) != 1:
        return "RequestMissing"
    if h(cause_refs[0]["target"]) != h(data["request_id"]):
        return "RequestMissing"
    req = h(data["request_id"])
    if req not in state.active_requests:
        return "RequestMissing"
    request = prior.find(req)
    if request is None:
        return "RequestMissing"
    if h(request["thread"]) != h(record["thread"]) or h(request["space"]) != h(record["space"]):
        return "RequestMissing"

    tasks = data["tasks"]
    if not tasks:
        return "InvalidPayload"
    seen = set()
    for t in tasks:
        if t["id"] in seen:
            return "InvalidPayload"
        seen.add(t["id"])
    for t in tasks:
        for dep in t["depends_on"]:
            if dep not in seen:
                return "InvalidPayload"
        for inp in t["inputs_from"]:
            if inp not in seen:
                return "InvalidPayload"
    for t in tasks:
        result_id = t.get("result_record_id")
        if result_id is None:
            continue
        if t["status"] not in ("done", "failed"):
            return "InvalidPayload"
        result_record = prior.find(h(result_id))
        if result_record is None:
            return "InvalidPayload"
        if (
            result_record["kind"] != "Result"
            or h(result_id) not in state.accepted
            or h(result_record["thread"]) != h(record["thread"])
            or h(result_record["space"]) != h(record["space"])
        ):
            return "InvalidPayload"
        result_data = payload(result_record)
        action_record = prior.find(h(result_data["action_id"]))
        if action_record is None:
            return "InvalidPayload"
        action_data = payload(action_record)
        if h(action_data["request_id"]) != req:
            return "InvalidPayload"
    if _has_cycle(tasks):
        return "InvalidPayload"

    any_pending_running = any(t["status"] in ("pending", "running") for t in tasks)
    all_done = all(t["status"] == "done" for t in tasks)
    all_terminal = all(t["status"] in ("done", "failed", "skipped") for t in tasks)
    any_failed_skipped = any(t["status"] in ("failed", "skipped") for t in tasks)
    status = data["status"]
    if status == "running":
        if not any_pending_running:
            return "InvalidPayload"
    elif status == "completed":
        if not all_done:
            return "InvalidPayload"
    elif status == "abandoned":
        if not all_terminal or not any_failed_skipped:
            return "InvalidPayload"
    return None


def _has_cycle(tasks) -> bool:
    in_degree = {t["id"]: 0 for t in tasks}
    adj: dict[str, list[str]] = {t["id"]: [] for t in tasks}
    for t in tasks:
        for dep in t["depends_on"]:
            in_degree[t["id"]] += 1
            adj.setdefault(dep, []).append(t["id"])
    queue = [tid for tid, d in in_degree.items() if d == 0]
    visited = 0
    while queue:
        cur = queue.pop(0)
        visited += 1
        for nb in adj.get(cur, []):
            if nb in in_degree:
                in_degree[nb] -= 1
                if in_degree[nb] == 0:
                    queue.append(nb)
    return visited != len(tasks)


def _check_retraction(record, prior, rules, state):
    data = payload(record)
    cause_refs = refs_of(record, "Cause")
    tid = h(data["target_id"])
    if len(cause_refs) != 1 or h(cause_refs[0]["target"]) != tid:
        return "InvalidPayload"
    target = prior.find(tid)
    if target is None:
        return "RefUnresolved"
    if tid not in state.accepted:
        return "InvalidPayload"
    if target["kind"] in ("Verdict", "Retraction"):
        return "InvalidPayload"
    if (
        record["author"]["id"] != target["author"]["id"]
        and record["author"]["id"] not in rules.admin_retraction_actors
    ):
        return "AuthorRoleInvalid"
    return None


# --- Evolution-kind checks (src/verify/verifier/evolution.rs, spec 0.3). ------

_OID_HEX_LEN = {"sha1": 40, "sha256": 64}


def _is_lower_hex(s: Any, length: int) -> bool:
    return isinstance(s, str) and len(s) == length and all(c in "0123456789abcdef" for c in s)


# Registered artifact schemes and digest lengths in bytes (SPEC 2, spec 0.4);
# an unregistered scheme takes the generic even 20..=64-byte rule.
_ARTIFACT_SCHEMES = {
    "git-tree-sha1": 20,
    "git-tree-sha256": 32,
    "manifest-v1": 32,
    "git-archive-tar-v1": 32,
    "oci-image-manifest": 32,
    "sha256-bytes": 32,
}


def _artifact_ref_well_formed(a: dict) -> bool:
    scheme, digest = a["scheme"], a["digest"]
    if not scheme or scheme[0] not in "abcdefghijklmnopqrstuvwxyz0123456789":
        return False
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in scheme):
        return False
    if len(digest) % 2 != 0 or not all(c in "0123456789abcdef" for c in digest):
        return False
    n = len(digest) // 2
    want = _ARTIFACT_SCHEMES.get(scheme)
    return n == want if want is not None else 20 <= n <= 64


def _artifacts_well_formed(artifacts) -> bool:
    """Absent is fine; a present list must be well-formed entry by entry and
    strictly increasing by (scheme, digest, name), with an absent name
    ordering before any present one (Rust `Option` ordering)."""
    if artifacts is None:
        return True
    keys = []
    for a in artifacts:
        if not _artifact_ref_well_formed(a):
            return False
        name = a.get("name")
        keys.append((a["scheme"], a["digest"], (0, "") if name is None else (1, name)))
    return all(x < y for x, y in zip(keys, keys[1:]))


def _source_binding_well_formed(sb: dict) -> bool:
    length = _OID_HEX_LEN[sb["git"]["algo"]]
    if not _is_lower_hex(sb["git"]["tree"], length):
        return False
    commit = sb["git"].get("commit")
    if commit is not None and not _is_lower_hex(commit, length):
        return False
    return (sb.get("manifest_hash") is not None) == (sb["binding"] == "manifest")


def _resolve_candidate(target_id, record, prior, state) -> Optional[dict]:
    """A lineage payload id must resolve, in the same space, to a prior
    accepted Candidate. Returns the record or None (PayloadRefUnresolved)."""
    t = prior.find(h(target_id))
    if t is None:
        return None
    if h(t["space"]) != h(record["space"]) or t["kind"] != "Candidate":
        return None
    if h(t["id"]) not in state.accepted:
        return None
    return t


def _check_candidate(record, prior, rules, state):
    data = payload(record)
    if not _source_binding_well_formed(data["source"]):
        return "SourceBindingInvalid"
    if not _artifacts_well_formed(data.get("artifacts")):
        return "ArtifactRefInvalid"

    parent = data.get("parent")
    if parent is not None and _resolve_candidate(parent, record, prior, state) is None:
        return "PayloadRefUnresolved"

    causes = []
    for r in refs_of(record, "Cause"):
        t = prior.find(h(r["target"]))
        if t is None:
            return "RefUnresolved"
        causes.append(t)

    basis = data["basis"]
    if basis == "root":
        if parent is not None or len(causes) > 1:
            return "LineageInvalid"
        if causes:
            c = causes[0]
            if c["kind"] != "Request" or h(c["id"]) not in state.accepted:
                return "LineageInvalid"
    elif basis == "continuation":
        if len(causes) != 1:
            return "LineageInvalid"
        anchor = causes[0]
        if anchor["kind"] != "Selection" or h(anchor["id"]) not in state.accepted:
            return "LineageInvalid"
        # Optional commit-time strictness (delta D6): reject a continuation
        # whose anchor is already unsound (retracted or tainted).
        if rules.reject_compromised_continuation and (
            h(anchor["id"]) in state.retracted or h(anchor["id"]) in state.tainted
        ):
            return "LineageInvalid"
        if parent is None:
            return "LineageInvalid"
        anchor_data = payload(anchor)
        outcome = anchor_data["outcome"]
        if not isinstance(outcome, dict) or "selected" not in outcome:
            return "LineageInvalid"
        selected = [h(c) for c in outcome["selected"]["candidates"]]
        if h(parent) not in selected:
            return "LineageInvalid"
    elif basis == "derivation":
        if parent is not None or not causes:
            return "LineageInvalid"
        for c in causes:
            if h(c["id"]) not in state.accepted:
                return "LineageInvalid"
            if c["kind"] not in ("Candidate", "Evaluation"):
                return "LineageInvalid"
    return None


def _check_evaluation(record, prior, rules, state):
    data = payload(record)
    if _resolve_candidate(data["candidate"], record, prior, state) is None:
        return "PayloadRefUnresolved"
    cand_hex = h(data["candidate"])
    if not any(r["type"] == "Use" and h(r["target"]) == cand_hex for r in record["refs"]):
        return "EvaluationInvalid"
    return None


def _resolve_selection_approval(record, data, prior, rules, state):
    """Resolve the approval a Selection must carry (delta D5). Returns
    (approval_id_or_None, reason_or_None); reason is set only on rejection
    (ApprovalMissing / ApprovalExpired). Mirrors evolution.rs."""
    if not rules.selection_requires_approval:
        return None, None
    replace_refs = refs_of(record, "Replace")
    replace_target = replace_refs[0]["target"] if replace_refs else None
    subject_hash = selection_approval_subject_hash(record, replace_target, data)
    approval_id = state.valid_approvals.get(subject_hash)
    if approval_id is None:
        return None, "ApprovalMissing"
    if not any(r["type"] == "Require" and h(r["target"]) == approval_id for r in record["refs"]):
        return None, "ApprovalMissing"
    if approval_id not in state.accepted or approval_id in state.retracted or approval_id in state.tainted:
        return None, "ApprovalMissing"
    approval_record = prior.find(approval_id)
    if approval_record is None:
        return None, "ApprovalMissing"
    approval_data = payload(approval_record)
    if approval_data.get("actor_id") != record["author"]["id"]:
        return None, "ApprovalMissing"
    if approval_data.get("expiry") is not None and record["time"] >= approval_data["expiry"]:
        return None, "ApprovalExpired"
    return approval_id, None


def _check_selection(record, prior, rules, state):
    data = payload(record)
    considered = [h(c) for c in data["considered"]]
    if not considered or len(considered) > rules.max_considered:
        return "SelectionInvalid"
    considered_set = set(considered)
    if len(considered_set) != len(considered):
        return "SelectionInvalid"
    for cid in data["considered"]:
        if _resolve_candidate(cid, record, prior, state) is None:
            return "PayloadRefUnresolved"

    # Only accepted Evaluations count and are constraint-checked. A Use of a
    # rejected Evaluation-kind record is legal (it degrades the Selection's
    # evidence, like any Use of bad content) but is not evidence and its
    # bytes need not decode as EvaluationData; gating on acceptance keeps this
    # loop total and byte-for-decision identical to the Rust reference.
    used_evaluations = 0
    for r in refs_of(record, "Use"):
        t = prior.find(h(r["target"]))
        if t is not None and t["kind"] == "Evaluation" and h(t["id"]) in state.accepted:
            used_evaluations += 1
            if h(payload(t)["candidate"]) not in considered_set:
                return "SelectionInvalid"

    require_targets = {h(r["target"]) for r in refs_of(record, "Require")}

    outcome = data["outcome"]
    if isinstance(outcome, dict) and "selected" in outcome:
        winners = [h(c) for c in outcome["selected"]["candidates"]]
        winner_set = set(winners)
        if not winner_set or len(winner_set) != len(winners) or not winner_set <= considered_set:
            return "SelectionInvalid"
        if rules.min_binding == "manifest":
            for c in winner_set:
                t = prior.find(c)
                if t is None or payload(t)["source"]["binding"] != "manifest":
                    return "SelectionInvalid"
        if rules.selection_requires_evaluation and used_evaluations == 0:
            return "SelectionInvalid"
    else:
        winner_set = set()

    # Selection approval binding (delta D5): the only authority Require a
    # Selection may carry.
    approval_require, reason = _resolve_selection_approval(record, data, prior, rules, state)
    if reason is not None:
        return reason

    # Require-target exactness: exactly the winners plus the required approval.
    allowed = set(winner_set)
    if approval_require is not None:
        allowed.add(approval_require)
    if require_targets != allowed:
        return "SelectionInvalid"

    replace_refs = refs_of(record, "Replace")
    if replace_refs:
        target = prior.find(h(replace_refs[0]["target"]))
        if target is not None and payload(target)["objective"] != data["objective"]:
            return "ReaffirmationInvalid"
        if rules.reaffirmation_actors and record["author"]["id"] not in rules.reaffirmation_actors:
            return "ReaffirmationInvalid"
    return None


# --- Verdict record checks (src/verify/verifier/verdict.rs). ------------------


def check_verdict_record(record: dict, prior: Prior, rules: Rules) -> Optional[str]:
    if bb.record_id(record) != bytes(record["id"]):
        return "InvalidPayload"
    if schema_hex(record) != schema_id_hex(SCHEMA_VERDICT):
        return "KindSchemaMismatch"
    if record["author"]["type"] != "Verifier":
        return "InvalidPayload"
    if record["author"].get("signature") is not None:
        return "InvalidPayload"
    if h(record["space"]) != rules.space:
        return "InvalidPayload"
    if record["evidence"] != "Deterministic":
        return "InvalidPayload"
    if not _decodes_canonically(record):
        return "InvalidPayload"
    if len(record["refs"]) != 1:
        return "InvalidPayload"
    subject_ref = record["refs"][0]
    if subject_ref["type"] != "Cause":
        return "InvalidPayload"
    subject_id = h(subject_ref["target"])
    subject = prior.find(subject_id)
    if subject is None:
        return "RefUnresolved"
    if subject["kind"] == "Verdict":
        return "InvalidPayload"
    if h(subject["space"]) != h(record["space"]) or h(subject["thread"]) != h(record["thread"]):
        return "InvalidPayload"
    if prior.has_verdict_for(subject_id):
        return "InvalidPayload"
    return None


# ---------------------------------------------------------------------------
# Public verdict entry points.
# ---------------------------------------------------------------------------


def verify_record(record: dict, prior_records: list[dict], rules: Rules, state: State) -> dict:
    """Reproduce verify_record: the VerdictData that should be committed.

    The reference's `verify_record` takes an already-decoded `Record`, so an
    envelope that would not survive serde decode cannot reach it. Reproducing
    that here (a structurally undecodable candidate or prior rejects, never
    crashes) keeps hostile input from tracebacking on an enum-ordinal lookup."""
    if not _structurally_decodes(record) or not all(
        _structurally_decodes(p) for p in prior_records
    ):
        return {"result": "Reject", "reason": "InvalidPayload"}
    prior = prior_index(prior_records)
    reason = check_record(record, prior, rules, state)
    if reason is None:
        return {"result": "Accept", "reason": None}
    return {"result": "Reject", "reason": reason}


_EMPTY_STANDING = {"compromised": [], "unsound": [], "restorations": []}


def derive_standing(records: list[dict], state: State) -> dict:
    """Replay-derived standing section (src/verify/standing.rs, SPEC §7.2).
    Pure function of the accepted records at replay end. Sets are returned as
    sorted hex-id lists (lowercase-hex sort equals the reference's id-byte
    order); restorations as pairs sorted by key with sorted value lists."""
    candidates: dict[str, dict] = {}
    selections: dict[str, dict] = {}
    for record in records:
        rid = h(record["id"])
        if rid not in state.accepted:
            continue
        k = record["kind"]
        if k == "Candidate":
            data = payload(record)
            causes = [h(r["target"]) for r in record["refs"] if r["type"] == "Cause"]
            parent = h(data["parent"]) if data.get("parent") is not None else None
            candidates[rid] = {"basis": data["basis"], "parent": parent, "causes": causes}
        elif k == "Selection":
            data = payload(record)
            outcome = data["outcome"]
            if isinstance(outcome, dict) and "selected" in outcome:
                selected = set(h(c) for c in outcome["selected"]["candidates"])
            else:
                selected = set()
            replace_refs = [r for r in record["refs"] if r["type"] == "Replace"]
            replace_target = h(replace_refs[0]["target"]) if replace_refs else None
            selections[rid] = {"selected": selected, "replace_target": replace_target}

    def is_unsound(sid: str) -> bool:
        return sid in state.retracted or sid in state.tainted

    unsound = set(s for s in selections if is_unsound(s))

    # replacers[A] = sound Selections with a Replace chain reaching A (proper
    # ancestor); intermediates need only be accepted, which every chain member
    # is.
    replacers: dict[str, set] = {}
    for s2, info in selections.items():
        if is_unsound(s2):
            continue
        hop = info["replace_target"]
        guard = 0
        while hop is not None:
            replacers.setdefault(hop, set()).add(s2)
            nxt = selections.get(hop)
            hop = nxt["replace_target"] if nxt else None
            guard += 1
            if guard > len(selections):
                break

    restorations = {s: set(replacers[s]) for s in unsound if replacers.get(s)}

    def anchor_sound(anchor: str, parent: str) -> bool:
        if not is_unsound(anchor):
            return True
        return any(
            parent in selections.get(s2, {}).get("selected", set())
            for s2 in replacers.get(anchor, ())
        )

    sound: dict[str, bool] = {}

    def standing_sound(cid: str) -> bool:
        if cid in sound:
            return sound[cid]
        info = candidates.get(cid)
        if info is None:
            return False
        if cid in state.retracted:
            sound[cid] = False
            return False
        basis = info["basis"]
        if basis == "root":
            val = True
        elif basis == "continuation":
            anchor = info["causes"][0] if info["causes"] else None
            parent = info["parent"]
            val = (
                anchor is not None
                and parent is not None
                and anchor_sound(anchor, parent)
                and standing_sound(parent)
            )
        else:  # derivation
            val = all(standing_sound(t) for t in info["causes"] if t in candidates)
        sound[cid] = val
        return val

    compromised = set(cid for cid in candidates if not standing_sound(cid))
    return {
        "compromised": sorted(compromised),
        "unsound": sorted(unsound),
        "restorations": sorted((k, sorted(v)) for k, v in restorations.items()),
    }


class LogVerdict:
    def __init__(self, result, reason, checked, last_time, retracted, tainted, standing=None):
        self.result = result
        self.reason = reason
        self.checked = checked
        self.last_time = last_time
        self.retracted = retracted
        self.tainted = tainted
        self.standing = standing if standing is not None else dict(_EMPTY_STANDING)


def _reject(reason, checked, records):
    last_time = records[-1]["time"] if records else 0
    return LogVerdict("Reject", reason, checked, last_time, set(), set())


def verify_log(records: list[dict], rules: Rules) -> LogVerdict:
    """Whole-log replay from genesis (no checkpoint; receipts always do this).
    Mirrors src/verify/verifier/replay.rs."""
    state = State()
    index = Prior()
    checked = 0

    # Gap-free time.
    for i in range(1, len(records)):
        if records[i]["time"] != records[i - 1]["time"] + 1:
            return _reject("InvalidPayload", checked, records)
    # Genesis time is 1.
    if records and records[0]["time"] != 1:
        return _reject("InvalidPayload", 0, records)
    # Every id recomputes.
    for record in records:
        if bb.record_id(record) != bytes(record["id"]):
            return _reject("InvalidPayload", checked, records)

    i = 0
    n = len(records)
    while i < n:
        record = records[i]
        if record["kind"] == "Verdict":
            reason = check_verdict_record(record, index, rules)
            if reason is not None:
                return _reject(reason, checked, records)
            stored = payload(record)
            cause = refs_of(record, "Cause")
            if not cause:
                return _reject("InvalidPayload", checked, records)
            subject = index.find(h(cause[0]["target"]))
            if subject is not None and stored["result"] == "Accept":
                apply_accepted(state, subject)
            index.insert(record)
            checked += 1
            i += 1
            continue

        # Non-verdict record: the next record must be its verdict.
        if i + 1 >= n:
            return _reject("InvalidPayload", checked, records)
        nxt = records[i + 1]
        if nxt["kind"] != "Verdict":
            return _reject("InvalidPayload", checked, records)

        index.insert(record)
        # The paired verdict's own envelope is verified in full.
        reason = check_verdict_record(nxt, index, rules)
        if reason is not None:
            return _reject(reason, checked, records)
        if h(nxt["refs"][0]["target"]) != h(record["id"]):
            return _reject("InvalidPayload", checked, records)

        recomputed_reason = check_record(record, index, rules, state)
        recomputed = (
            {"result": "Accept", "reason": None}
            if recomputed_reason is None
            else {"result": "Reject", "reason": recomputed_reason}
        )
        stored = payload(nxt)
        if recomputed["result"] != stored["result"] or recomputed["reason"] != stored["reason"]:
            return _reject(recomputed["reason"] or "InvalidPayload", checked, records)

        if stored["result"] == "Accept":
            apply_accepted(state, record)
        index.insert(nxt)
        checked += 2
        i += 2

    last_time = records[-1]["time"] if records else 0
    standing = derive_standing(records, state)
    return LogVerdict(
        "Accept", None, checked, last_time, state.retracted, state.tainted, standing
    )


def validate_receipt(
    records: list[dict], rules_wire: dict, spec_version: str = bb.SPEC_VERSION
) -> dict:
    """Reproduce receipt validate()'s status/reason/taint (src/receipt.rs).

    The reference deserializes the whole receipt (validating every record's wire
    shape and enums) before replay; a record that fails that is a structural
    `Invalid` with no reason code, exactly like an unparseable receipt. The
    replay runs under the schema set of the receipt's declared epoch."""
    for r in records:
        if not _structurally_decodes(r):
            return {
                "status": "Invalid",
                "reason": None,
                "retracted": [],
                "tainted": [],
                "standing": dict(_EMPTY_STANDING),
            }
    rules = Rules(rules_wire, spec_version)
    v = verify_log(records, rules)
    if v.result == "Reject":
        status = "Invalid"
    elif not v.retracted and not v.tainted:
        status = "Clean"
    else:
        status = "Tainted"
    return {
        "status": status,
        "reason": v.reason,
        "retracted": sorted(v.retracted),
        "tainted": sorted(v.tainted),
        "standing": v.standing,
    }
