//! Python bindings for Bellbook (issue #13): offline receipt validation and
//! reading from Python.
//!
//! - `bellbook.validate(data: bytes, require_profile=None) -> Report` wraps
//!   the crate's `validate`, so Python reaches the exact same Clean / Tainted
//!   / Invalid decision the Rust CLI does, over the same core. Naming a
//!   profile (`"bellbook-core-v1"`, or a list of ids) adds the profile
//!   results to the report without changing the verdict.
//! - `bellbook.read(data: bytes) -> Receipt` parses a receipt for inspection
//!   (records, kinds, authors, evidence, refs, payloads). Reading does not
//!   verify; call `validate` for the decision.
//! - `bellbook.Writer(log_dir, rules)` records evolution to a persistent,
//!   single-writer log: `request`, `requirement`, `candidate`, `evaluate`,
//!   `select`, and `retract` each commit one record and return a
//!   [`Commit`]. The writer holds the same exclusive lock and runs the same
//!   replay-on-commit the Rust `LogWriter` does. Export the log with
//!   `writer.receipt()` (optionally declaring profiles) and feed it straight
//!   back to `validate`.
//! - The RFC-0002 named query set - `descent`, `descendants`, `siblings`,
//!   `frontier`, `standing`, `evidence`, `selected` - is available as
//!   methods on both `Receipt` and `Writer`, returning the shared surface
//!   JSON shapes as plain dicts/lists. Queries run only over verified
//!   state: an input that does not verify raises `ValueError`, not answers.

// `#[pyfunction]` generates a result conversion that clippy reads as a
// useless `PyErr -> PyErr` conversion for any `PyResult`-returning function.
// It is a macro artifact, not our code, so allow it crate-wide.
#![allow(clippy::useless_conversion)]

use bellbook_core::{
    artifact_ref_well_formed, decode, default_space, encode, hex_decode, hex_encode,
    manifest_from_dir, manifest_hash, schema_id, validate_with_profiles, verify_and_build_state,
    ArtifactRef, Author, AuthorType, Basis, BindingMode, CandidateBasis, CandidateData,
    DeciderBinding, EvaluationData, EvaluationDataV2, EvaluationOutcome, EvaluationOutcomeV2,
    GitSource, Kind, LogWriter, Proposal, Provenance, Queries, Receipt as CoreReceipt,
    Record as CoreRecord, RecordId, Ref, RefType, Report as CoreReport, RequestData,
    RequirementData, RetractionData, ScoredValue, SelectionData, SelectionOutcome, SourceAlgo,
    SourceBinding, State, ValidationLimits, ValidationStatus, VerdictResult, VerifierRules,
    SCHEMA_CANDIDATE, SCHEMA_EVALUATION, SCHEMA_EVALUATION_V2, SCHEMA_REQUEST, SCHEMA_REQUIREMENT,
    SCHEMA_RETRACTION, SCHEMA_SELECTION,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::BTreeMap;
use std::path::Path;

/// The result of validating a receipt. A read-only view over the crate's
/// `Report`; every field is re-derived by validation, never trusted from the
/// receipt.
#[pyclass(frozen, name = "Report", module = "bellbook")]
struct Report {
    inner: CoreReport,
}

fn ids(set: &std::collections::BTreeSet<[u8; 32]>) -> Vec<String> {
    set.iter().map(hex_encode).collect()
}

#[pymethods]
impl Report {
    /// `"clean"`, `"tainted"`, or `"invalid"`.
    #[getter]
    fn status(&self) -> &'static str {
        match self.inner.status {
            ValidationStatus::Clean => "clean",
            ValidationStatus::Tainted => "tainted",
            ValidationStatus::Invalid => "invalid",
        }
    }

    /// True only for a `"clean"` receipt.
    #[getter]
    fn is_clean(&self) -> bool {
        matches!(self.inner.status, ValidationStatus::Clean)
    }

    /// Verifier reason code for the first violation when replay failed.
    #[getter]
    fn reason(&self) -> Option<String> {
        self.inner.reason.map(|r| format!("{r:?}"))
    }

    /// Structural problem (unparseable bytes, unsupported spec version) when
    /// validation could not even reach replay.
    #[getter]
    fn problem(&self) -> Option<String> {
        self.inner.problem.clone()
    }

    /// Spec version the receipt declared (empty string if unparseable).
    #[getter]
    fn spec_version(&self) -> String {
        self.inner.spec_version.clone()
    }

    #[getter]
    fn record_count(&self) -> u64 {
        self.inner.record_count
    }

    #[getter]
    fn checked_records(&self) -> u64 {
        self.inner.checked_records
    }

    #[getter]
    fn last_time(&self) -> u64 {
        self.inner.last_time
    }

    /// Lowercase hex of the SHA-256 head hash (compare against an anchored
    /// head attestation).
    #[getter]
    fn head_hash(&self) -> String {
        hex_encode(&self.inner.head_hash)
    }

    /// Lowercase hex of the SHA-256 rules hash (compare against rules agreed
    /// out of band).
    #[getter]
    fn rules_hash(&self) -> String {
        hex_encode(&self.inner.rules_hash)
    }

    /// Hex ids of retracted records.
    #[getter]
    fn retracted(&self) -> Vec<String> {
        ids(&self.inner.retracted_records)
    }

    /// Hex ids of tainted records.
    #[getter]
    fn tainted(&self) -> Vec<String> {
        ids(&self.inner.tainted_records)
    }

    /// The replay-derived standing section (spec 0.3) as a dict:
    /// `{"compromised": [id...], "unsound": [id...], "restorations": {id: [id...]}}`.
    #[getter]
    fn standing<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = &self.inner.standing;
        let out = PyDict::new(py);
        out.set_item("compromised", ids(&s.compromised))?;
        out.set_item("unsound", ids(&s.unsound))?;
        let restorations = PyDict::new(py);
        for (target, replacers) in &s.restorations {
            restorations.set_item(hex_encode(target), ids(replacers))?;
        }
        out.set_item("restorations", restorations)?;
        Ok(out)
    }

    /// Profile results: every profile the receipt declares (spec 0.4), in
    /// declaration order, then the ids requested via
    /// `validate(..., require_profile=...)` that the receipt did not declare.
    /// Empty when the receipt declares nothing and nothing was requested.
    /// Each is a dict `{"id", "hash" (lowercase hex of the profile's
    /// clause-table hash the validator evaluated), "status" ("Conformant" |
    /// "NonConformant" | "Unknown"), "declared" (bool),
    /// "declaration_matches" (True/False for a declared, known profile:
    /// whether the declared version and hash name the evaluated table; None
    /// otherwise), "met" (Conformant and, if declared, matching),
    /// "clauses": [{"id", "passed", "detail"}, ...]}`. A declaration is
    /// never trusted, and a profile result is a report alongside the
    /// verdict: it never changes `status` or `reason`.
    #[getter]
    fn profiles<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.inner
            .profiles
            .iter()
            .map(|p| {
                let out = PyDict::new(py);
                out.set_item("id", &p.id)?;
                out.set_item("hash", hex_encode(&p.hash))?;
                out.set_item("status", format!("{:?}", p.status))?;
                out.set_item("declared", p.declared)?;
                out.set_item("declaration_matches", p.declaration_matches)?;
                out.set_item("met", p.met())?;
                let clauses = p
                    .clauses
                    .iter()
                    .map(|c| {
                        let d = PyDict::new(py);
                        d.set_item("id", &c.id)?;
                        d.set_item("passed", c.passed)?;
                        d.set_item("detail", &c.detail)?;
                        Ok(d)
                    })
                    .collect::<PyResult<Vec<_>>>()?;
                out.set_item("clauses", clauses)?;
                Ok(out)
            })
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "Report(status={:?}, records={}, spec_version={:?})",
            self.status(),
            self.inner.record_count,
            self.inner.spec_version
        )
    }

    /// The full human-readable report, identical to the CLI's text output.
    fn __str__(&self) -> String {
        format!("{}", self.inner)
    }
}

/// Validate a receipt offline and return a [`Report`]. This performs the same
/// replay the `bellbook validate` CLI does: ids, chain, every verdict
/// re-derived, evidence, taint, and the standing section. It never raises for
/// an invalid receipt - an unparseable or failing receipt returns a `Report`
/// with `status == "invalid"` and a `problem` or `reason` set.
///
/// `require_profile` names a profile id (or a list of ids) to evaluate on
/// top of the verdict, e.g. `"bellbook-core-v1"`; the results land in
/// `Report.profiles` in request order. An id the validator does not know is
/// reported as `"Unknown"`, never raised. Profiles never change the verdict.
#[pyfunction]
#[pyo3(signature = (data, require_profile=None))]
fn validate(data: &[u8], require_profile: Option<Bound<'_, PyAny>>) -> PyResult<Report> {
    let profiles = match require_profile {
        None => Vec::new(),
        Some(v) => profile_ids(&v)?,
    };
    let ids: Vec<&str> = profiles.iter().map(String::as_str).collect();
    Ok(Report {
        inner: validate_with_profiles(data, &ValidationLimits::default(), &ids),
    })
}

/// `require_profile` accepts one id or a list of ids; anything else is a
/// `ValueError` rather than a silently ignored argument.
fn profile_ids(v: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    if let Ok(one) = v.extract::<String>() {
        return Ok(vec![one]);
    }
    v.extract::<Vec<String>>().map_err(|_| {
        PyValueError::new_err("require_profile must be a profile id (str) or a list of ids")
    })
}

// --- read-side queries (RFC-0002, the named set) ---------------------------

/// Convert a query report (surface JSON) into Python dicts/lists via the
/// stdlib `json` module, so every surface hands out the identical shape.
fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let s = serde_json::to_string(value).map_err(|e| PyRuntimeError::new_err(format!("{e}")))?;
    Ok(py.import("json")?.call_method1("loads", (s,))?.unbind())
}

/// Flatten a query result into the surface JSON value, mapping both a query
/// error and the (unreachable in practice) serialization error to a message.
fn to_value<T: serde::Serialize>(
    result: Result<T, bellbook_core::QueryError>,
) -> Result<serde_json::Value, String> {
    let report = result.map_err(|e| e.to_string())?;
    serde_json::to_value(report).map_err(|e| e.to_string())
}

/// Build the verified query context and run one named query. Queries never
/// answer over unverified history: a log or receipt that does not verify
/// raises `ValueError`, as do a missing or rejected id and a kind mismatch.
fn run_query<F>(
    py: Python<'_>,
    records: &[CoreRecord],
    rules: &VerifierRules,
    f: F,
) -> PyResult<Py<PyAny>>
where
    F: FnOnce(&Queries<'_>) -> Result<serde_json::Value, String>,
{
    let q = Queries::new(records, rules).map_err(|e| PyValueError::new_err(format!("{e}")))?;
    let value = f(&q).map_err(PyValueError::new_err)?;
    json_to_py(py, &value)
}

/// A parsed receipt, for inspection. Reading does not verify: call
/// [`validate`] for the Clean / Tainted / Invalid decision. A record's fields
/// are as recorded; only replay confirms they are consistent.
///
/// The receipt also answers the RFC-0002 named query set (`descent`,
/// `descendants`, `siblings`, `frontier`, `standing`, `evidence`,
/// `selected`); those methods replay the receipt first and raise
/// `ValueError` if it does not verify.
#[pyclass(frozen, name = "Receipt", module = "bellbook")]
struct Receipt {
    inner: CoreReceipt,
}

#[pymethods]
impl Receipt {
    /// Spec version the receipt declares (e.g. `"0.3"`).
    #[getter]
    fn spec_version(&self) -> String {
        self.inner.spec_version.clone()
    }

    /// The records in order, from genesis (subjects and verdicts).
    #[getter]
    fn records(&self) -> Vec<Record> {
        self.inner
            .records
            .iter()
            .cloned()
            .map(|inner| Record { inner })
            .collect()
    }

    /// Number of records (subjects and verdicts).
    fn __len__(&self) -> usize {
        self.inner.records.len()
    }

    /// q1 `descent(id)`: the line of descent from a candidate back to its
    /// roots (RFC-0002). Returns the shared surface JSON as dicts/lists.
    fn descent(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, &self.inner.records, &self.inner.rules, |q| {
            to_value(q.descent(id))
        })
    }

    /// q2 `descendants(id)`: every candidate whose descent passes through
    /// the record, in log order.
    fn descendants(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, &self.inner.records, &self.inner.rules, |q| {
            to_value(q.descendants(id))
        })
    }

    /// q3 `siblings(id)`: the candidate's generation (same anchor Selection,
    /// or same exact derivation cause set), excluding itself.
    fn siblings(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, &self.inner.records, &self.inner.rules, |q| {
            to_value(q.siblings(id))
        })
    }

    /// q4 `frontier()`: candidates no accepted Selection considered, and
    /// chosen candidates with no continuation yet. Nothing is silently
    /// filtered; every node carries its annotations.
    fn frontier(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        run_query(py, &self.inner.records, &self.inner.rules, |q| {
            to_value(Ok(q.frontier()))
        })
    }

    /// q5 `standing(id)`: the record's standing, taint, and retraction
    /// status, plus any restoring Selection ids.
    fn standing(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, &self.inner.records, &self.inner.rules, |q| {
            to_value(q.standing(id))
        })
    }

    /// q6 `evidence(id)`: what the record rests on. For a Selection, its own
    /// evidence; for a Candidate, the evidence of every anchor Selection
    /// along its full descent (unbounded by design).
    fn evidence(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, &self.inner.records, &self.inner.rules, |q| {
            to_value(q.evidence(id))
        })
    }

    /// q7 `selected(objective)`: the accepted Selected selections whose
    /// objective equals the string exactly (no patterns), with chosen
    /// candidates and evidence.
    fn selected(&self, py: Python<'_>, objective: &str) -> PyResult<Py<PyAny>> {
        run_query(py, &self.inner.records, &self.inner.rules, |q| {
            to_value(Ok(q.selected(objective)))
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Receipt(spec_version={:?}, records={})",
            self.inner.spec_version,
            self.inner.records.len()
        )
    }
}

/// One record in a receipt. A read-only view; strings for the enum-valued
/// fields are the record's Rust variant names (`kind`, `author_type`,
/// `evidence`, and each ref's `type`).
#[pyclass(frozen, name = "Record", module = "bellbook")]
struct Record {
    inner: CoreRecord,
}

#[pymethods]
impl Record {
    /// Content-address id, lowercase hex.
    #[getter]
    fn id(&self) -> String {
        hex_encode(&self.inner.id)
    }

    /// Record kind (e.g. `"Candidate"`, `"Selection"`, `"Verdict"`).
    #[getter]
    fn kind(&self) -> String {
        format!("{:?}", self.inner.kind)
    }

    /// Logical time (1-based commit counter).
    #[getter]
    fn time(&self) -> u64 {
        self.inner.time
    }

    /// Author actor id.
    #[getter]
    fn author_id(&self) -> String {
        self.inner.author.id.clone()
    }

    /// Author role (`"User"`, `"Provider"`, `"System"`, `"Executor"`,
    /// `"Verifier"`).
    #[getter]
    fn author_type(&self) -> String {
        format!("{:?}", self.inner.author.type_)
    }

    /// Whether the author carries a signature.
    #[getter]
    fn signed(&self) -> bool {
        self.inner.author.signature.is_some()
    }

    /// Evidence class (`"Deterministic"`, `"Verified"`, `"Reported"`,
    /// `"Inferred"`, `"Assumed"`).
    #[getter]
    fn evidence(&self) -> String {
        format!("{:?}", self.inner.evidence)
    }

    /// Schema id, lowercase hex.
    #[getter]
    fn schema(&self) -> String {
        hex_encode(&self.inner.schema)
    }

    /// Typed edges to prior records, as `{"type": str, "target": hex}` dicts.
    #[getter]
    fn refs<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.inner
            .refs
            .iter()
            .map(|r| {
                let d = PyDict::new(py);
                d.set_item("type", format!("{:?}", r.type_))?;
                d.set_item("target", hex_encode(&r.target))?;
                Ok(d)
            })
            .collect()
    }

    /// The raw payload as a JSON string (parse with `json.loads`). This is the
    /// record's canonical `data` bytes, decoded as UTF-8.
    #[getter]
    fn payload_json(&self) -> String {
        String::from_utf8_lossy(&self.inner.data).into_owned()
    }

    fn __repr__(&self) -> String {
        format!(
            "Record(kind={:?}, time={}, id={}...)",
            format!("{:?}", self.inner.kind),
            self.inner.time,
            &hex_encode(&self.inner.id)[..12]
        )
    }
}

/// Parse a receipt for inspection. Raises `ValueError` if the bytes are not a
/// parseable receipt. Reading does not verify - use [`validate`] for the
/// decision.
#[pyfunction]
fn read(data: &[u8]) -> PyResult<Receipt> {
    CoreReceipt::from_bytes(data)
        .map(|inner| Receipt { inner })
        .map_err(|e| PyValueError::new_err(format!("not a parseable receipt: {e}")))
}

fn parse_role(s: &str) -> PyResult<AuthorType> {
    match s.to_ascii_lowercase().as_str() {
        "user" => Ok(AuthorType::User),
        "provider" => Ok(AuthorType::Provider),
        "system" => Ok(AuthorType::System),
        "executor" => Ok(AuthorType::Executor),
        "verifier" => Ok(AuthorType::Verifier),
        other => Err(PyValueError::new_err(format!(
            "invalid role {other:?} (user|provider|system|executor|verifier)"
        ))),
    }
}

/// Build a starter verifier-rules JSON string, binding each actor id to a role.
/// This is the Python counterpart to `bellbook rules init`: it removes the need
/// to hand-author a rules object before opening a [`Writer`]. `authors` maps an
/// actor id to one of `user`, `provider`, `system`, `executor`, or `verifier`
/// (case-insensitive). The result is a JSON string ready to pass to `Writer`.
///
/// `admins` lists actors allowed to retract records they did not author (a
/// Retraction is otherwise valid only from the target's own author, and an
/// Executor may never author one). `reaffirmers`, when non-empty, restricts
/// reaffirming selections to the listed actors. Both must also appear in
/// `authors`: an actor with no role binding could never author an accepted
/// record, so listing it here would be a silent no-op.
///
/// Like `bellbook rules init`, the result carries the `bellbook-core-v1`
/// baseline evidence thresholds (Candidate `Reported`, Evaluation
/// `Reported`, Selection `Inferred` - the schema base classes), so a log
/// committed under it conforms to the baseline profile out of the box.
///
/// ```python
/// rules = bellbook.default_rules({"agent": "provider", "evaluator": "provider"},
///                                admins=["agent"])
/// w = bellbook.Writer("./log", rules)
/// ```
#[pyfunction]
#[pyo3(signature = (authors, max_context=200, admins=None, reaffirmers=None))]
fn default_rules(
    authors: BTreeMap<String, String>,
    max_context: u32,
    admins: Option<Vec<String>>,
    reaffirmers: Option<Vec<String>>,
) -> PyResult<String> {
    if authors.is_empty() {
        return Err(PyValueError::new_err(
            "default_rules needs at least one author binding",
        ));
    }
    let mut rules = VerifierRules::new(default_space(), max_context).with_baseline_thresholds();
    for (id, role) in &authors {
        if id.is_empty() {
            return Err(PyValueError::new_err("author id must be non-empty"));
        }
        rules = rules.with_author_role(id.clone(), parse_role(role)?);
    }
    for (name, ids) in [("admins", &admins), ("reaffirmers", &reaffirmers)] {
        for id in ids.iter().flatten() {
            if !authors.contains_key(id) {
                return Err(PyValueError::new_err(format!(
                    "{name} entry {id:?} has no author binding; add it to authors"
                )));
            }
        }
    }
    // Direct inserts into the public sets; equivalent to the core's
    // `with_admin_retraction_actor` / `with_reaffirmation_actor` builders.
    for id in admins.iter().flatten() {
        rules.admin_retraction_actors.insert(id.clone().into());
    }
    for id in reaffirmers.iter().flatten() {
        rules.reaffirmation_actors.insert(id.clone().into());
    }
    serde_json::to_string(&rules)
        .map_err(|e| PyRuntimeError::new_err(format!("cannot serialize rules: {e}")))
}

// ---------------------------------------------------------------------------
// Writer (persistent, single-writer log)
// ---------------------------------------------------------------------------

/// The outcome of committing one record. The record is durably appended and
/// immediately judged by replay. A *rejected* record is still committed - it
/// is durable evidence that a proposal was refused - so `accepted` is `False`
/// and `reason` carries the verifier's reason code; the writer does not raise.
#[pyclass(frozen, name = "Commit", module = "bellbook")]
struct Commit {
    /// Content-address id of the committed record, lowercase hex.
    #[pyo3(get)]
    id: String,
    /// `True` if the record was accepted by replay, `False` if rejected.
    #[pyo3(get)]
    accepted: bool,
    /// `"accept"` or `"reject"`.
    #[pyo3(get)]
    result: String,
    /// Verifier reason code when the record was rejected.
    #[pyo3(get)]
    reason: Option<String>,
}

#[pymethods]
impl Commit {
    fn __repr__(&self) -> String {
        format!(
            "Commit(id={}..., accepted={}, reason={:?})",
            &self.id[..12.min(self.id.len())],
            if self.accepted { "True" } else { "False" },
            self.reason
        )
    }
}

fn parse_id(hex: &str) -> PyResult<RecordId> {
    hex_decode(hex).ok_or_else(|| PyValueError::new_err(format!("invalid record id {hex:?}")))
}

fn parse_hash(name: &str, hex: &str) -> PyResult<[u8; 32]> {
    hex_decode(hex).ok_or_else(|| {
        PyValueError::new_err(format!("invalid {name} {hex:?} (expected 64 hex chars)"))
    })
}

/// `artifacts=[...]` (spec 0.4): each entry is `"scheme:digest[:name]"` (the
/// CLI form) or a dict `{"scheme", "digest", "name"?}`. Every reference is
/// checked against the artifact rule before anything is written, and the
/// list is sorted and deduplicated into the canonical order the verifier
/// requires, so a well-formed call never mints an `ArtifactRefInvalid`
/// record. `None` when the argument was omitted.
fn parse_artifacts(items: Option<Vec<Bound<'_, PyAny>>>) -> PyResult<Option<Vec<ArtifactRef>>> {
    let Some(items) = items else {
        return Ok(None);
    };
    let mut refs = Vec::with_capacity(items.len());
    for item in items {
        let a = if let Ok(s) = item.extract::<String>() {
            let mut parts = s.splitn(3, ':');
            let scheme = parts.next().unwrap_or_default().to_string();
            let digest = parts
                .next()
                .ok_or_else(|| {
                    PyValueError::new_err(format!(
                        "invalid artifact {s:?} (expected scheme:digest[:name])"
                    ))
                })?
                .to_string();
            ArtifactRef {
                scheme,
                digest,
                name: parts.next().map(str::to_string),
            }
        } else if let Ok(d) = item.cast::<PyDict>() {
            let field = |k: &str| -> PyResult<Option<String>> {
                match d.get_item(k)? {
                    Some(v) if !v.is_none() => Ok(Some(v.extract::<String>()?)),
                    _ => Ok(None),
                }
            };
            ArtifactRef {
                scheme: field("scheme")?
                    .ok_or_else(|| PyValueError::new_err("artifact dict requires scheme"))?,
                digest: field("digest")?
                    .ok_or_else(|| PyValueError::new_err("artifact dict requires digest"))?,
                name: field("name")?,
            }
        } else {
            return Err(PyValueError::new_err(
                "artifacts entries must be 'scheme:digest[:name]' strings or dicts",
            ));
        };
        if !artifact_ref_well_formed(&a) {
            return Err(PyValueError::new_err(format!(
                "invalid artifact {}:{}: scheme must match [a-z0-9][a-z0-9.-]* and the digest must be lowercase hex of the scheme's length",
                a.scheme, a.digest
            )));
        }
        refs.push(a);
    }
    refs.sort();
    refs.dedup();
    Ok(Some(refs))
}

/// Encode a payload, then decode it back so the payload's `TryFrom` invariants
/// (score bounds, non-empty criterion/objective) are checked before the write,
/// exactly as the CLI does. Without this a statically-knowable violation would
/// serialize, commit, and only then reject as a durable record with an opaque
/// reason; here it is a clean `ValueError` and nothing is written.
fn checked_encode<T>(value: &T) -> PyResult<Vec<u8>>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let bytes = encode(value).map_err(|e| PyValueError::new_err(format!("{e}")))?;
    decode::<T>(&bytes).map_err(|e| PyValueError::new_err(format!("invalid payload: {e}")))?;
    Ok(bytes)
}

/// Records evolution to a persistent, single-writer log. A thin wrapper over
/// the crate's `LogWriter`: it holds the same exclusive `.lock`, re-verifies
/// the existing log on open, and replays every commit. Rules are the verifier
/// rules the log is committed under, given as a JSON string (the same object a
/// receipt embeds under `rules`).
///
/// Concurrency (SPEC 5.1): the log is deliberately single-writer. Generate
/// candidates concurrently, then record them serially through one `Writer`.
#[pyclass(unsendable, name = "Writer", module = "bellbook")]
struct Writer {
    inner: LogWriter,
    rules: VerifierRules,
    state: State,
}

impl Writer {
    /// Resolve an actor id to an `Author` via the rules' `author_roles`. The
    /// declared role on a record is never trusted; the writer binds the role
    /// from the rules, so an unregistered author is refused before any write.
    fn resolve_author(&self, id: &str) -> PyResult<Author> {
        let type_ = self.rules.author_roles.get(id).copied().ok_or_else(|| {
            PyValueError::new_err(format!(
                "author {id:?} is not registered in the rules' author_roles"
            ))
        })?;
        Ok(Author {
            id: id.to_string(),
            type_,
            signature: None,
        })
    }

    fn do_commit(
        &mut self,
        author: Author,
        kind: Kind,
        schema: bellbook_core::SchemaId,
        data: Vec<u8>,
        refs: Vec<Ref>,
    ) -> PyResult<Commit> {
        let proposal = Proposal {
            space: self.rules.space,
            // Single-thread writer: thread == space id, as the CLI does.
            thread: self.rules.space,
            author,
            kind,
            schema,
            data,
            refs,
        };
        let (id, verdict) = self
            .inner
            .commit(proposal, &self.rules, &mut self.state)
            .map_err(|e| PyRuntimeError::new_err(format!("commit failed: {e}")))?;
        let accepted = verdict.result == VerdictResult::Accept;
        Ok(Commit {
            id: hex_encode(&id),
            accepted,
            result: if accepted { "accept" } else { "reject" }.to_string(),
            reason: verdict.reason.map(|r| format!("{r:?}")),
        })
    }
}

#[pymethods]
impl Writer {
    /// Open (or create) the log at `log_dir` under `rules` (a JSON string).
    /// Rebuilds and re-verifies state from the committed records; raises if the
    /// existing log does not verify, or if another writer holds the lock.
    #[new]
    #[pyo3(signature = (log_dir, rules))]
    fn new(log_dir: &str, rules: &str) -> PyResult<Self> {
        let rules: VerifierRules = serde_json::from_str(rules)
            .map_err(|e| PyValueError::new_err(format!("invalid rules JSON: {e}")))?;
        let inner = LogWriter::open(Path::new(log_dir), &rules)
            .map_err(|e| PyRuntimeError::new_err(format!("cannot open log: {e}")))?;
        let state = verify_and_build_state(inner.records(), &rules).map_err(|_| {
            PyValueError::new_err("the existing log does not verify under these rules")
        })?;
        Ok(Writer {
            inner,
            rules,
            state,
        })
    }

    /// Record a Request: what a person asked for (spec 0.4 surfaces bind
    /// requirements to it). Single-thread writer, so the request's scope is
    /// the space and it has no parent request. The verifier admits only a
    /// user-role author.
    #[pyo3(signature = (author, objective))]
    fn request(&mut self, author: &str, objective: &str) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
        let data = checked_encode(&RequestData {
            objective: objective.to_string(),
            scope: self.rules.space,
            attachments: Vec::new(),
            parent_request_id: None,
        })?;
        self.do_commit(
            author,
            Kind::Request,
            schema_id(SCHEMA_REQUEST),
            data,
            Vec::new(),
        )
    }

    /// Record a Requirement under a request (spec 0.4): an addressable
    /// statement of what it requires. Exactly one `Cause` to the request; the
    /// key must be unique among the request's accepted, unretracted
    /// requirements (a duplicate commits as a durable rejected record with
    /// `RequirementInvalid`; retract-and-record releases the key).
    /// `provenance` is `"user_authored"` or `"derived"` and is bound to the
    /// author's role by the verifier; it defaults from the role (user ->
    /// user_authored, provider or system -> derived) and a stated value the
    /// role cannot carry raises `ValueError` before anything is written.
    /// `required=False` records an informational requirement a profile never
    /// counts; `expected_evidence` is recorded, not interpreted.
    #[pyo3(signature = (author, request, key, description, *, required=true,
        expected_evidence=None, provenance=None))]
    #[allow(clippy::too_many_arguments)]
    fn requirement(
        &mut self,
        author: &str,
        request: &str,
        key: &str,
        description: &str,
        required: bool,
        expected_evidence: Option<String>,
        provenance: Option<&str>,
    ) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
        let request_id = parse_id(request)?;
        if !self.state.accepted_records.contains(&request_id)
            || !self
                .inner
                .records()
                .iter()
                .any(|r| r.id == request_id && r.kind == Kind::Request)
        {
            return Err(PyValueError::new_err(format!(
                "request {request:?} is not an accepted Request in this log"
            )));
        }
        if key.is_empty() || description.is_empty() {
            return Err(PyValueError::new_err(
                "key and description must be non-empty",
            ));
        }
        let role_default = match author.type_ {
            AuthorType::User => Provenance::UserAuthored,
            AuthorType::Provider | AuthorType::System => Provenance::Derived,
            other => {
                return Err(PyValueError::new_err(format!(
                    "author {:?} has role {other:?}, which cannot author a Requirement",
                    author.id
                )))
            }
        };
        let provenance = match provenance {
            None => role_default,
            Some("user_authored") | Some("user-authored") => Provenance::UserAuthored,
            Some("derived") => Provenance::Derived,
            Some(other) => {
                return Err(PyValueError::new_err(format!(
                    "invalid provenance {other:?} (expected user_authored or derived)"
                )))
            }
        };
        if provenance != role_default {
            return Err(PyValueError::new_err(format!(
                "provenance {:?} cannot be authored by {:?} (role {:?}): provenance is bound to the author's role",
                match provenance {
                    Provenance::UserAuthored => "user_authored",
                    Provenance::Derived => "derived",
                },
                author.id,
                author.type_
            )));
        }
        let data = checked_encode(&RequirementData {
            key: key.to_string(),
            description: description.to_string(),
            required,
            expected_evidence,
            provenance,
        })?;
        self.do_commit(
            author,
            Kind::Requirement,
            schema_id(SCHEMA_REQUIREMENT),
            data,
            vec![Ref {
                type_: RefType::Cause,
                target: request_id,
            }],
        )
    }

    /// Record a Candidate (a proposed source state). Basis is chosen by exactly
    /// one of `continues` (with `parent`), `derives_from`, or `upgrades`;
    /// omitting all three records a Root. `algo` is `"sha1"` (default) or
    /// `"sha256"`. Passing `manifest` (a directory path) binds the source by a
    /// canonical manifest hash; otherwise the git tree is reported.
    /// `artifacts` (spec 0.4) binds artifact identities: a list of
    /// `"scheme:digest[:name]"` strings or `{"scheme", "digest", "name"?}`
    /// dicts, checked and canonically ordered before the write.
    #[pyo3(signature = (author, git_tree, *, git_commit=None, algo="sha1", note=None,
        continues=None, parent=None, derives_from=None, upgrades=None, manifest=None,
        artifacts=None))]
    #[allow(clippy::too_many_arguments)]
    fn candidate(
        &mut self,
        author: &str,
        git_tree: &str,
        git_commit: Option<String>,
        algo: &str,
        note: Option<String>,
        continues: Option<&str>,
        parent: Option<&str>,
        derives_from: Option<Vec<String>>,
        upgrades: Option<&str>,
        manifest: Option<&str>,
        artifacts: Option<Vec<Bound<'_, PyAny>>>,
    ) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
        let artifacts = parse_artifacts(artifacts)?;
        let algo = match algo {
            "sha1" => SourceAlgo::Sha1,
            "sha256" => SourceAlgo::Sha256,
            other => return Err(PyValueError::new_err(format!("invalid algo {other:?}"))),
        };

        // Basis selection is mutually exclusive.
        let n_basis = [
            continues.is_some(),
            derives_from.is_some(),
            upgrades.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if n_basis > 1 {
            return Err(PyValueError::new_err(
                "continues, derives_from, and upgrades are mutually exclusive",
            ));
        }
        // `parent` names the continued-from candidate and is meaningful only
        // for a continuation; refuse it elsewhere rather than drop stated intent.
        if continues.is_none() && parent.is_some() {
            return Err(PyValueError::new_err("parent is only valid with continues"));
        }

        let (basis, parent_id, refs) = if let Some(sel) = continues {
            let parent = parent.ok_or_else(|| {
                PyValueError::new_err("continues requires parent (the continued candidate id)")
            })?;
            (
                CandidateBasis::Continuation,
                Some(parse_id(parent)?),
                vec![Ref {
                    type_: RefType::Cause,
                    target: parse_id(sel)?,
                }],
            )
        } else if let Some(ids) = &derives_from {
            if ids.is_empty() {
                return Err(PyValueError::new_err(
                    "derives_from requires at least one id",
                ));
            }
            let refs = ids
                .iter()
                .map(|s| {
                    parse_id(s).map(|t| Ref {
                        type_: RefType::Cause,
                        target: t,
                    })
                })
                .collect::<PyResult<Vec<_>>>()?;
            (CandidateBasis::Derivation, None, refs)
        } else if let Some(target_hex) = upgrades {
            // Binding upgrade: a Derivation over the target with the SAME tree.
            let target = parse_id(target_hex)?;
            let target_data = self
                .inner
                .records()
                .iter()
                .find(|r| r.id == target && r.kind == Kind::Candidate)
                .and_then(|r| decode::<CandidateData>(&r.data).ok())
                .ok_or_else(|| {
                    PyValueError::new_err(format!(
                        "upgrades target {target_hex:?} is not a Candidate in this log"
                    ))
                })?;
            if !self.state.accepted_records.contains(&target) {
                return Err(PyValueError::new_err(format!(
                    "upgrades target {target_hex:?} is not an accepted Candidate"
                )));
            }
            if self.state.retracted_records.contains(&target) {
                return Err(PyValueError::new_err(format!(
                    "upgrades target {target_hex:?} is retracted; upgrade a live candidate"
                )));
            }
            if target_data.source.git.tree != git_tree {
                return Err(PyValueError::new_err(format!(
                    "refusing upgrade: git_tree {git_tree:?} differs from the target's tree {:?}",
                    target_data.source.git.tree
                )));
            }
            (
                CandidateBasis::Derivation,
                None,
                vec![Ref {
                    type_: RefType::Cause,
                    target,
                }],
            )
        } else {
            (CandidateBasis::Root, None, Vec::new())
        };

        // A manifest binding when `manifest` is given; reported otherwise.
        let (manifest_hash_val, binding) = match manifest {
            Some(path) => {
                let entries = manifest_from_dir(Path::new(path), &BTreeMap::new())
                    .map_err(|e| PyValueError::new_err(format!("cannot walk tree {path}: {e}")))?;
                let h = manifest_hash(&entries).ok_or_else(|| {
                    PyValueError::new_err("manifest has duplicate paths".to_string())
                })?;
                (Some(h), BindingMode::Manifest)
            }
            None => (None, BindingMode::Reported),
        };

        let data = checked_encode(&CandidateData {
            artifacts,
            source: SourceBinding {
                git: GitSource {
                    algo,
                    tree: git_tree.to_string(),
                    commit: git_commit,
                },
                manifest_hash: manifest_hash_val,
                binding,
            },
            basis,
            parent: parent_id,
            note,
        })?;
        self.do_commit(
            author,
            Kind::Candidate,
            schema_id(SCHEMA_CANDIDATE),
            data,
            refs,
        )
    }

    /// Record an Evaluation of a candidate. Exactly one outcome: `passed`,
    /// `failed`, a `score` (with `scale`), or one of the spec 0.4 fail-closed
    /// outcomes `blocked`, `insufficient`, `stale`, `not_run` (only `passed`
    /// passes; a decision that could not run to a pass is recorded as exactly
    /// what it is). The evaluation Uses its candidate, each requirement it
    /// speaks to, plus any extra `uses` ids.
    ///
    /// With `evaluator` and `basis` (`"recomputed"` or `"declared"`; basis is
    /// declared, never inferred) the extended shape is written
    /// (`bellbook.evaluation.v2`): who decided (`evaluator`,
    /// `evaluator_version`, `procedure_hash`, `input_hash`), the artifacts
    /// judged (`artifacts`, as on `candidate`), and the accepted Requirement
    /// ids it speaks to (`requirements`). Any of those, or a fail-closed
    /// outcome, without both `evaluator` and `basis` raises `ValueError`.
    /// Without them the v1 shape is written as before.
    #[pyo3(signature = (author, candidate, criterion, *, passed=false, failed=false,
        score=None, scale=None, procedure=None, uses=None, blocked=false,
        insufficient=false, stale=false, not_run=false, evaluator=None,
        evaluator_version=None, procedure_hash=None, input_hash=None, basis=None,
        requirements=None, artifacts=None))]
    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &mut self,
        author: &str,
        candidate: &str,
        criterion: &str,
        passed: bool,
        failed: bool,
        score: Option<i64>,
        scale: Option<u8>,
        procedure: Option<String>,
        uses: Option<Vec<String>>,
        blocked: bool,
        insufficient: bool,
        stale: bool,
        not_run: bool,
        evaluator: Option<String>,
        evaluator_version: Option<String>,
        procedure_hash: Option<&str>,
        input_hash: Option<&str>,
        basis: Option<&str>,
        requirements: Option<Vec<String>>,
        artifacts: Option<Vec<Bound<'_, PyAny>>>,
    ) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
        let candidate = parse_id(candidate)?;

        // Exactly one outcome.
        let unit: Vec<&str> = [
            ("passed", passed),
            ("failed", failed),
            ("blocked", blocked),
            ("insufficient", insufficient),
            ("stale", stale),
            ("not_run", not_run),
        ]
        .into_iter()
        .filter(|(_, on)| *on)
        .map(|(name, _)| name)
        .collect();
        let scored = match score {
            Some(value) => {
                let scale = scale.ok_or_else(|| {
                    PyValueError::new_err("score requires scale (the denominator)")
                })?;
                Some(ScoredValue { value, scale })
            }
            None => None,
        };
        if unit.len() + usize::from(scored.is_some()) != 1 {
            return Err(PyValueError::new_err(
                "exactly one of passed, failed, score, blocked, insufficient, stale, or not_run is required",
            ));
        }
        let outcome_v2 = match (unit.first().copied(), scored) {
            (_, Some(s)) => EvaluationOutcomeV2::Scored(s),
            (Some("passed"), None) => EvaluationOutcomeV2::Passed,
            (Some("failed"), None) => EvaluationOutcomeV2::Failed,
            (Some("blocked"), None) => EvaluationOutcomeV2::Blocked,
            (Some("insufficient"), None) => EvaluationOutcomeV2::Insufficient,
            (Some("stale"), None) => EvaluationOutcomeV2::Stale,
            (Some("not_run"), None) => EvaluationOutcomeV2::NotRun,
            _ => unreachable!("one outcome was checked above"),
        };

        // The extended shape is chosen by its binding: evaluator and basis
        // together. Any other 0.4-only argument or outcome needs them.
        let extended_args: Vec<&str> = [
            ("evaluator", evaluator.is_some()),
            ("evaluator_version", evaluator_version.is_some()),
            ("procedure_hash", procedure_hash.is_some()),
            ("input_hash", input_hash.is_some()),
            ("basis", basis.is_some()),
            ("requirements", requirements.is_some()),
            ("artifacts", artifacts.is_some()),
            ("blocked", blocked),
            ("insufficient", insufficient),
            ("stale", stale),
            ("not_run", not_run),
        ]
        .into_iter()
        .filter(|(_, on)| *on)
        .map(|(name, _)| name)
        .collect();
        let extended = !extended_args.is_empty();
        if extended && !(evaluator.is_some() && basis.is_some()) {
            return Err(PyValueError::new_err(format!(
                "the extended evaluation ({}) requires both evaluator and basis ('recomputed' or 'declared')",
                extended_args.join(", ")
            )));
        }

        // The evaluation must Use its candidate, then each requirement it
        // speaks to (mirrored in the payload), then any extra uses refs.
        let mut refs = vec![Ref {
            type_: RefType::Use,
            target: candidate,
        }];
        let mut requirement_ids: Vec<RecordId> = requirements
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|s| parse_id(s))
            .collect::<PyResult<_>>()?;
        requirement_ids.sort();
        requirement_ids.dedup();
        for rid in &requirement_ids {
            if !self
                .inner
                .records()
                .iter()
                .any(|r| r.id == *rid && r.kind == Kind::Requirement)
                || !self.state.accepted_records.contains(rid)
            {
                return Err(PyValueError::new_err(format!(
                    "requirement {} is not an accepted Requirement in this log",
                    hex_encode(rid)
                )));
            }
            refs.push(Ref {
                type_: RefType::Use,
                target: *rid,
            });
        }
        if let Some(extra) = &uses {
            for s in extra {
                refs.push(Ref {
                    type_: RefType::Use,
                    target: parse_id(s)?,
                });
            }
        }

        let (schema, data) = if extended {
            let evaluator_id = evaluator.unwrap_or_default();
            if evaluator_id.is_empty() {
                return Err(PyValueError::new_err("evaluator must be non-empty"));
            }
            let basis = match basis.unwrap_or_default() {
                "recomputed" => Basis::Recomputed,
                "declared" => Basis::Declared,
                other => {
                    return Err(PyValueError::new_err(format!(
                        "invalid basis {other:?} (expected 'recomputed' or 'declared')"
                    )))
                }
            };
            let data = checked_encode(&EvaluationDataV2 {
                candidate,
                criterion: criterion.to_string(),
                procedure,
                outcome: outcome_v2,
                evaluator: DeciderBinding {
                    id: evaluator_id,
                    version: evaluator_version,
                    procedure_hash: procedure_hash
                        .map(|h| parse_hash("procedure_hash", h))
                        .transpose()?,
                    input_hash: input_hash
                        .map(|h| parse_hash("input_hash", h))
                        .transpose()?,
                },
                basis,
                evidence: parse_artifacts(artifacts)?.unwrap_or_default(),
                requirements: requirement_ids,
            })?;
            (SCHEMA_EVALUATION_V2, data)
        } else {
            let outcome = match outcome_v2 {
                EvaluationOutcomeV2::Passed => EvaluationOutcome::Passed,
                EvaluationOutcomeV2::Failed => EvaluationOutcome::Failed,
                EvaluationOutcomeV2::Scored(s) => EvaluationOutcome::Scored(s),
                _ => unreachable!("fail-closed outcomes select the extended shape"),
            };
            let data = checked_encode(&EvaluationData {
                candidate,
                criterion: criterion.to_string(),
                procedure,
                outcome,
            })?;
            (SCHEMA_EVALUATION, data)
        };
        self.do_commit(author, Kind::Evaluation, schema_id(schema), data, refs)
    }

    /// Record a Selection over candidates, or a reaffirmation. Exactly one of
    /// `choose` (with `uses_eval`) or `none=True` states the outcome. `replaces`
    /// adds a Replace ref to a prior Selection (a reaffirmation).
    #[pyo3(signature = (author, objective, consider, *, choose=None, uses_eval=None,
        none=false, replaces=None, rationale=None))]
    #[allow(clippy::too_many_arguments)]
    fn select(
        &mut self,
        author: &str,
        objective: &str,
        consider: Vec<String>,
        choose: Option<Vec<String>>,
        uses_eval: Option<Vec<String>>,
        none: bool,
        replaces: Option<&str>,
        rationale: Option<String>,
    ) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
        if consider.is_empty() {
            return Err(PyValueError::new_err(
                "consider requires at least one candidate id",
            ));
        }
        let considered = consider
            .iter()
            .map(|s| parse_id(s))
            .collect::<PyResult<Vec<_>>>()?;

        if none == choose.is_some() {
            return Err(PyValueError::new_err(
                "exactly one of choose or none=True is required",
            ));
        }

        let mut refs = Vec::new();
        let outcome = if none {
            SelectionOutcome::None
        } else {
            let winners = choose
                .unwrap()
                .iter()
                .map(|s| parse_id(s))
                .collect::<PyResult<Vec<_>>>()?;
            for w in &winners {
                refs.push(Ref {
                    type_: RefType::Require,
                    target: *w,
                });
            }
            let evals = uses_eval.ok_or_else(|| {
                PyValueError::new_err("choose requires uses_eval with at least one evaluation")
            })?;
            if evals.is_empty() {
                return Err(PyValueError::new_err(
                    "uses_eval requires at least one evaluation",
                ));
            }
            for s in &evals {
                refs.push(Ref {
                    type_: RefType::Use,
                    target: parse_id(s)?,
                });
            }
            SelectionOutcome::Selected {
                candidates: winners,
            }
        };

        if let Some(sel) = replaces {
            refs.push(Ref {
                type_: RefType::Replace,
                target: parse_id(sel)?,
            });
        }

        let data = checked_encode(&SelectionData {
            objective: objective.to_string(),
            considered,
            outcome,
            rationale,
        })?;
        self.do_commit(
            author,
            Kind::Selection,
            schema_id(SCHEMA_SELECTION),
            data,
            refs,
        )
    }

    /// Retract a committed record: assert its content is wrong. The target
    /// stays in the log; on acceptance its id enters the retracted set and
    /// its epistemic dependents become tainted, so the receipt reports
    /// Tainted from then on - permanently. `reason` is a free-form statement
    /// of why the content is wrong; it is recorded, not interpreted.
    ///
    /// Ownership is enforced by replay (SPEC section 2): the retraction is
    /// accepted only when `author` is the target's author or is listed in the
    /// rules' `admin_retraction_actors` (see `default_rules(admins=...)`).
    /// An Executor may never author a Retraction. A Verdict or a Retraction
    /// cannot be retracted. As with the other verbs, a rejected retraction
    /// is still durably committed, with `accepted=False` and the reason.
    #[pyo3(signature = (author, target, reason))]
    fn retract(&mut self, author: &str, target: &str, reason: &str) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
        let target = parse_id(target)?;

        // The verifier requires exactly one Cause ref naming the target.
        let refs = vec![Ref {
            type_: RefType::Cause,
            target,
        }];
        let data = checked_encode(&RetractionData {
            target_id: target,
            reason: reason.to_string(),
        })?;
        self.do_commit(
            author,
            Kind::Retraction,
            schema_id(SCHEMA_RETRACTION),
            data,
            refs,
        )
    }

    /// The current head id, lowercase hex (all-zero for an empty log).
    #[getter]
    fn head(&self) -> String {
        hex_encode(&self.inner.head())
    }

    /// The committed records in order (subjects and verdicts).
    #[getter]
    fn records(&self) -> Vec<Record> {
        self.inner
            .records()
            .iter()
            .cloned()
            .map(|inner| Record { inner })
            .collect()
    }

    /// Number of committed records (subjects and verdicts).
    fn __len__(&self) -> usize {
        self.inner.records().len()
    }

    /// Export the log as a portable receipt (canonical JSON bytes). Feed it to
    /// `validate` or `read`, or hand it to any independent verifier.
    /// `profiles` (spec 0.4) declares the named profiles the receipt claims
    /// (e.g. `["bellbook-core-v1"]`), with the version and hash this
    /// package knows; the declaration is not evaluated here - every validator
    /// re-checks it - so a false claim exports and then reports
    /// `NonConformant`. An unknown or repeated id raises `ValueError`.
    #[pyo3(signature = (profiles=None))]
    fn receipt<'py>(
        &self,
        py: Python<'py>,
        profiles: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let declared: Vec<&str> = profiles
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect();
        let bytes = CoreReceipt::new(self.inner.records(), &self.rules)
            .with_declared_profiles(&declared)
            .map_err(PyValueError::new_err)?
            .to_bytes()
            .map_err(|e| PyRuntimeError::new_err(format!("cannot serialize receipt: {e}")))?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// q1 `descent(id)`: the line of descent from a candidate back to its
    /// roots (RFC-0002). Returns the shared surface JSON as dicts/lists -
    /// byte-for-byte the shapes `Receipt` and the CLI emit.
    fn descent(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, self.inner.records(), &self.rules, |q| {
            to_value(q.descent(id))
        })
    }

    /// q2 `descendants(id)`: every candidate whose descent passes through
    /// the record, in log order.
    fn descendants(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, self.inner.records(), &self.rules, |q| {
            to_value(q.descendants(id))
        })
    }

    /// q3 `siblings(id)`: the candidate's generation (same anchor Selection,
    /// or same exact derivation cause set), excluding itself.
    fn siblings(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, self.inner.records(), &self.rules, |q| {
            to_value(q.siblings(id))
        })
    }

    /// q4 `frontier()`: candidates no accepted Selection considered, and
    /// chosen candidates with no continuation yet. Nothing is silently
    /// filtered; every node carries its annotations.
    fn frontier(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        run_query(py, self.inner.records(), &self.rules, |q| {
            to_value(Ok(q.frontier()))
        })
    }

    /// q5 `standing(id)`: the record's standing, taint, and retraction
    /// status, plus any restoring Selection ids.
    fn standing(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, self.inner.records(), &self.rules, |q| {
            to_value(q.standing(id))
        })
    }

    /// q6 `evidence(id)`: what the record rests on. For a Selection, its own
    /// evidence; for a Candidate, the evidence of every anchor Selection
    /// along its full descent (unbounded by design).
    fn evidence(&self, py: Python<'_>, id: &str) -> PyResult<Py<PyAny>> {
        let id = parse_id(id)?;
        run_query(py, self.inner.records(), &self.rules, |q| {
            to_value(q.evidence(id))
        })
    }

    /// q7 `selected(objective)`: the accepted Selected selections whose
    /// objective equals the string exactly (no patterns), with chosen
    /// candidates and evidence.
    fn selected(&self, py: Python<'_>, objective: &str) -> PyResult<Py<PyAny>> {
        run_query(py, self.inner.records(), &self.rules, |q| {
            to_value(Ok(q.selected(objective)))
        })
    }

    fn __repr__(&self) -> String {
        format!("Writer(records={})", self.inner.records().len())
    }
}

#[pymodule]
fn bellbook(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    m.add_function(wrap_pyfunction!(read, m)?)?;
    m.add_function(wrap_pyfunction!(default_rules, m)?)?;
    m.add_class::<Report>()?;
    m.add_class::<Receipt>()?;
    m.add_class::<Record>()?;
    m.add_class::<Writer>()?;
    m.add_class::<Commit>()?;
    Ok(())
}
