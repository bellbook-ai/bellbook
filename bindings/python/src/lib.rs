//! Python bindings for Bellbook (issue #13): offline receipt validation and
//! reading from Python.
//!
//! - `bellbook.validate(data: bytes) -> Report` wraps the crate's `validate`,
//!   so Python reaches the exact same Clean / Tainted / Invalid decision the
//!   Rust CLI does, over the same core.
//! - `bellbook.read(data: bytes) -> Receipt` parses a receipt for inspection
//!   (records, kinds, authors, evidence, refs, payloads). Reading does not
//!   verify; call `validate` for the decision.
//! - `bellbook.Writer(log_dir, rules)` records evolution to a persistent,
//!   single-writer log: `candidate`, `evaluate`, and `select` each commit one
//!   record and return a [`Commit`]. The writer holds the same exclusive lock
//!   and runs the same replay-on-commit the Rust `LogWriter` does. Export the
//!   log with `writer.receipt()` and feed it straight back to `validate`.

// `#[pyfunction]` generates a result conversion that clippy reads as a
// useless `PyErr -> PyErr` conversion for any `PyResult`-returning function.
// It is a macro artifact, not our code, so allow it crate-wide.
#![allow(clippy::useless_conversion)]

use bellbook_core::{
    decode, default_space, encode, hex_decode, hex_encode, manifest_from_dir, manifest_hash,
    schema_id, validate as core_validate, verify_and_build_state, Author, AuthorType, BindingMode,
    CandidateBasis, CandidateData, EvaluationData, EvaluationOutcome, GitSource, Kind, LogWriter,
    Proposal, Receipt as CoreReceipt, Record as CoreRecord, RecordId, Ref, RefType,
    Report as CoreReport, ScoredValue, SelectionData, SelectionOutcome, SourceAlgo, SourceBinding,
    State, ValidationStatus, VerdictResult, VerifierRules, SCHEMA_CANDIDATE, SCHEMA_EVALUATION,
    SCHEMA_SELECTION,
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
#[pyfunction]
fn validate(data: &[u8]) -> Report {
    Report {
        inner: core_validate(data),
    }
}

/// A parsed receipt, for inspection. Reading does not verify: call
/// [`validate`] for the Clean / Tainted / Invalid decision. A record's fields
/// are as recorded; only replay confirms they are consistent.
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
    let mut rules = VerifierRules::new(default_space(), max_context);
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
    // Insert into the public sets directly rather than through the core's
    // builder methods, so the binding keeps building against the published
    // core crate (the builders arrive with the next core release).
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

    /// Record a Candidate (a proposed source state). Basis is chosen by exactly
    /// one of `continues` (with `parent`), `derives_from`, or `upgrades`;
    /// omitting all three records a Root. `algo` is `"sha1"` (default) or
    /// `"sha256"`. Passing `manifest` (a directory path) binds the source by a
    /// canonical manifest hash; otherwise the git tree is reported.
    #[pyo3(signature = (author, git_tree, *, git_commit=None, algo="sha1", note=None,
        continues=None, parent=None, derives_from=None, upgrades=None, manifest=None))]
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
    ) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
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

    /// Record an Evaluation of a candidate. Exactly one of `passed`, `failed`,
    /// or a `score` (with `scale`) states the outcome. The evaluation Uses its
    /// candidate, plus any extra `uses` ids.
    #[pyo3(signature = (author, candidate, criterion, *, passed=false, failed=false,
        score=None, scale=None, procedure=None, uses=None))]
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
    ) -> PyResult<Commit> {
        let author = self.resolve_author(author)?;
        let candidate = parse_id(candidate)?;

        let outcome = match (passed, failed, score) {
            (true, false, None) => EvaluationOutcome::Passed,
            (false, true, None) => EvaluationOutcome::Failed,
            (false, false, Some(value)) => {
                let scale = scale.ok_or_else(|| {
                    PyValueError::new_err("score requires scale (the denominator)")
                })?;
                EvaluationOutcome::Scored(ScoredValue { value, scale })
            }
            _ => {
                return Err(PyValueError::new_err(
                    "exactly one of passed, failed, or score is required",
                ))
            }
        };

        // The evaluation must Use its candidate, plus any extra uses refs.
        let mut refs = vec![Ref {
            type_: RefType::Use,
            target: candidate,
        }];
        if let Some(extra) = &uses {
            for s in extra {
                refs.push(Ref {
                    type_: RefType::Use,
                    target: parse_id(s)?,
                });
            }
        }

        let data = checked_encode(&EvaluationData {
            candidate,
            criterion: criterion.to_string(),
            procedure,
            outcome,
        })?;
        self.do_commit(
            author,
            Kind::Evaluation,
            schema_id(SCHEMA_EVALUATION),
            data,
            refs,
        )
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
    fn receipt<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = CoreReceipt::new(self.inner.records(), &self.rules)
            .to_bytes()
            .map_err(|e| PyRuntimeError::new_err(format!("cannot serialize receipt: {e}")))?;
        Ok(PyBytes::new(py, &bytes))
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
