//! Persistent log implementation (append-only file + writer). Requires feature `persist`.

#[cfg(feature = "persist")]
pub(crate) mod storage;
#[cfg(feature = "persist")]
pub mod writer;
