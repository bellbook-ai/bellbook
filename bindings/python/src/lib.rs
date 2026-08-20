//! Python bindings for Bellbook (issue #13): offline receipt validation and
//! reading from Python.
//!
//! - `bellbook.validate(data: bytes) -> Report` wraps the crate's `validate`,
//!   so Python reaches the exact same Clean / Tainted / Invalid decision the
//!   Rust CLI does, over the same core.
//! - `bellbook.read(data: bytes) -> Receipt` parses a receipt for inspection
//!   (records, kinds, authors, evidence, refs, payloads). Reading does not
//!   verify; call `validate` for the decision.
//!
//! The writer API lands in a later stage.

// `#[pyfunction]` generates a result conversion that clippy reads as a
// useless `PyErr -> PyErr` conversion for any `PyResult`-returning function.
// It is a macro artifact, not our code, so allow it crate-wide.
#![allow(clippy::useless_conversion)]

use bellbook_core::{
    hex_encode, validate as core_validate, Receipt as CoreReceipt, Record as CoreRecord,
    Report as CoreReport, ValidationStatus,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

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
        let out = PyDict::new_bound(py);
        out.set_item("compromised", ids(&s.compromised))?;
        out.set_item("unsound", ids(&s.unsound))?;
        let restorations = PyDict::new_bound(py);
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
                let d = PyDict::new_bound(py);
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

#[pymodule]
fn bellbook(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    m.add_function(wrap_pyfunction!(read, m)?)?;
    m.add_class::<Report>()?;
    m.add_class::<Receipt>()?;
    m.add_class::<Record>()?;
    Ok(())
}
