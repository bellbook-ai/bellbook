//! Ref struct and utilities.

use crate::base::hash::Hash256;
use crate::record::kind::RefType;
use serde::{Deserialize, Serialize};

/// Content address of a record: SHA-256 of its canonical id form (only `id`
/// omitted; a completed signature is included). Any mutation of a record
/// changes its id and breaks every dependent ref.
pub type RecordId = Hash256;

/// A typed edge to a prior record. Targets must already exist in the log
/// and share the record's space; the ref list is sorted and deduped before
/// hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ref {
    /// Edge semantics: Cause, Use, Require, or Replace (see [`RefType`]).
    #[serde(rename = "type")]
    pub type_: RefType,
    /// Id of the referenced prior record; unresolved targets reject the
    /// record with `RefUnresolved`.
    pub target: RecordId,
}

/// Sort refs by (type_ ordinal, target bytes) and deduplicate.
/// Required before hashing (SPEC.md §3); the verifier rejects records whose
/// refs are not sorted and deduplicated.
pub fn sort_and_dedup_refs(refs: &mut Vec<Ref>) {
    refs.sort_by(|a, b| {
        let ord_a = a.type_ as u8;
        let ord_b = b.type_ as u8;
        ord_a.cmp(&ord_b).then_with(|| a.target.cmp(&b.target))
    });
    refs.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_and_dedup() {
        let target_a = [0u8; 32];
        let target_b = [1u8; 32];
        let mut refs = vec![
            Ref {
                type_: RefType::Replace,
                target: target_a,
            },
            Ref {
                type_: RefType::Cause,
                target: target_b,
            },
            Ref {
                type_: RefType::Cause,
                target: target_a,
            },
            Ref {
                type_: RefType::Cause,
                target: target_a,
            }, // duplicate
        ];
        sort_and_dedup_refs(&mut refs);
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].type_, RefType::Cause);
        assert_eq!(refs[0].target, target_a);
        assert_eq!(refs[1].type_, RefType::Cause);
        assert_eq!(refs[1].target, target_b);
        assert_eq!(refs[2].type_, RefType::Replace);
    }
}
