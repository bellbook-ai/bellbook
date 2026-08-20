//! Python bindings for Bellbook, Stage 1 (issue #13): offline receipt
//! validation from Python.
//!
//! `bellbook.validate(data: bytes) -> Report` wraps the crate's `validate`,
//! so Python reaches the exact same Clean / Tainted / Invalid decision the
//! Rust CLI does, over the same core. The writer API and receipt reading land
//! in later stages; this stage is validation only.

use bellbook_core::{
    hex_encode, validate as core_validate, Report as CoreReport, ValidationStatus,
};
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

#[pymodule]
fn bellbook(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    m.add_class::<Report>()?;
    Ok(())
}
