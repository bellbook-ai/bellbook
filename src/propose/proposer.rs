//! Proposer trait from SPEC.md.
//!
//! The Proposer is **untrusted** logic that emits [`Proposal`] values. Nothing is durable until
//! `LogWriter::commit` (behind the `persist` feature) runs under [`crate::VerifierRules`].
//!
//! Host runtimes implement this trait when generating proposals from a [`Context`] - e.g. an
//! orchestrator that builds provider [`Proposal`]s after an LLM step.

use crate::context::context::Context;
use crate::record::record::Proposal;

/// Untrusted proposer interface. Implementations emit proposals from a [`Context`]; they have **no**
/// append authority - every proposal is verified and committed through the log pipeline.
pub trait Proposer {
    /// Produce zero or more proposals from the given working set. Output is
    /// untrusted - each proposal is independently verified at commit and may
    /// be rejected.
    fn propose(&self, context: &Context) -> Vec<Proposal>;
}
