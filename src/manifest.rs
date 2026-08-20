//! Canonical manifest v1 (SPEC §5.1, spec 0.3): an algorithm-independent
//! content commitment over a Git tree.
//!
//! A `manifest` source binding carries `manifest_hash = SHA-256(JCS bytes of
//! the canonical manifest)`. The manifest maps each repo-relative POSIX path
//! to `{ mode, sha256 }`, where `sha256` is over the file bytes (regular and
//! executable), the symlink target string, or - for a submodule gitlink - the
//! submodule commit OID as a lowercase-hex ASCII string.
//!
//! This is a recording/interoperability utility, not part of the verifier's
//! verdict: the verifier checks a binding is well-formed (V3-C1/V3-C2) but
//! never recomputes a manifest (SPEC §13). A party holding the tree uses this
//! to recompute `manifest_hash` and confirm a `manifest` binding commits to
//! the contents it claims. The manifest object itself is never stored or
//! embedded; only the hash rides in the payload.
//!
//! Gitlink entries commit to the submodule *pointer* only, and their OID is
//! sourced from the Git tree object, never worktree state, so an initialized
//! and an uninitialized checkout of the same tree yield the same manifest.

use crate::base::hash::{hex_encode, sha256, sha256_canonical, Hash256};
use serde::Serialize;
use std::collections::BTreeMap;

/// The Git file mode of a manifest entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    /// `100644`: a regular file.
    Regular,
    /// `100755`: an executable file.
    Executable,
    /// `120000`: a symlink; the content hash is over the target string.
    Symlink,
    /// `160000`: a submodule gitlink; the content hash is over the commit OID
    /// string.
    Gitlink,
}

impl FileMode {
    /// The Git mode string stored in the manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            FileMode::Regular => "100644",
            FileMode::Executable => "100755",
            FileMode::Symlink => "120000",
            FileMode::Gitlink => "160000",
        }
    }
}

/// One entry: a repo-relative POSIX path, its Git mode, and the SHA-256 of
/// its content per the mode rules. Build entries with the constructors so the
/// per-mode hashing rule is applied consistently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Repo-relative POSIX path (forward slashes), never containing `.git`.
    pub path: String,
    /// The Git file mode.
    pub mode: FileMode,
    /// The content SHA-256 per the mode rule.
    pub sha256: Hash256,
}

impl ManifestEntry {
    /// A regular or executable file: `sha256` is over the file bytes exactly
    /// as materialized, with no EOL or attribute normalization.
    pub fn file(path: impl Into<String>, executable: bool, bytes: &[u8]) -> Self {
        Self {
            path: path.into(),
            mode: if executable {
                FileMode::Executable
            } else {
                FileMode::Regular
            },
            sha256: sha256(bytes),
        }
    }

    /// A symlink: `sha256` is over the target string bytes.
    pub fn symlink(path: impl Into<String>, target: &str) -> Self {
        Self {
            path: path.into(),
            mode: FileMode::Symlink,
            sha256: sha256(target.as_bytes()),
        }
    }

    /// A submodule gitlink: `sha256` is over the submodule commit OID as a
    /// lowercase-hex ASCII string with **no trailing newline**, sourced from
    /// the Git tree object and never worktree state. Returns `None` unless the
    /// OID is exactly 40 (SHA-1) or 64 (SHA-256) lowercase-hex characters (a
    /// submodule may use a different object format than its parent).
    pub fn gitlink(path: impl Into<String>, commit_oid_hex: &str) -> Option<Self> {
        let len_ok = commit_oid_hex.len() == 40 || commit_oid_hex.len() == 64;
        let hex_ok = commit_oid_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !len_ok || !hex_ok {
            return None;
        }
        Some(Self {
            path: path.into(),
            mode: FileMode::Gitlink,
            sha256: sha256(commit_oid_hex.as_bytes()),
        })
    }
}

/// The per-path manifest value: `{ mode, sha256 }`. Serialized as an object;
/// JCS sorts its two members and the outer path keys by UTF-16 code unit.
#[derive(Serialize)]
struct ManifestValue {
    mode: &'static str,
    sha256: String,
}

/// Compute `manifest_hash` over a set of entries: `SHA-256` of the JCS bytes
/// of the object mapping each path to `{ mode, sha256 }`. Paths must be
/// unique; a duplicate path yields `None` (an ambiguous manifest). An empty
/// set hashes the empty object `{}` (an empty tree is a valid state).
pub fn manifest_hash(entries: &[ManifestEntry]) -> Option<Hash256> {
    let mut object: BTreeMap<String, ManifestValue> = BTreeMap::new();
    for e in entries {
        let value = ManifestValue {
            mode: e.mode.as_str(),
            sha256: hex_encode(&e.sha256),
        };
        if object.insert(e.path.clone(), value).is_some() {
            return None;
        }
    }
    // canonical_json (JCS) re-sorts every object member by UTF-16 code unit,
    // so BTreeMap insertion order does not affect the bytes.
    sha256_canonical(&object).ok()
}

/// Walk a worktree directory into manifest entries (SPEC §5.1). Regular and
/// executable files contribute their bytes; symlinks contribute their target
/// string; `.git` at any level is excluded. Submodule gitlinks cannot be
/// derived from worktree state, so their paths and tree-object commit OIDs are
/// supplied in `gitlinks` (repo-relative POSIX path -> lowercase-hex OID); a
/// directory whose path is a gitlink key is not descended into, and every
/// gitlink in the map is emitted regardless of whether its directory exists on
/// disk. This keeps the manifest identical across initialized and
/// uninitialized submodule checkouts of the same tree.
///
/// The walk is iterative, so arbitrarily deep trees cannot overflow the stack.
/// A manifest object is JSON, so paths and symlink targets must be UTF-8; a
/// non-UTF-8 name or target is a hard error (`InvalidData`) rather than a
/// silent lossy substitution that would commit to a hash no tree-object
/// recompute could match. A path that appears both as a walked entry and as a
/// gitlink key is also `InvalidData`. The executable bit is read on Unix
/// (owner-execute, matching Git's tree mode); on other platforms every file is
/// treated as regular and symlinks are followed as their targets, a documented
/// platform limitation of worktree materialization, not of the manifest format.
#[cfg(feature = "persist")]
pub fn manifest_from_dir(
    root: &std::path::Path,
    gitlinks: &BTreeMap<String, String>,
) -> std::io::Result<Vec<ManifestEntry>> {
    use std::io::{Error, ErrorKind};

    fn utf8_name(os: &std::ffi::OsStr) -> std::io::Result<String> {
        os.to_str().map(str::to_owned).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "non-UTF-8 path is not representable in a manifest",
            )
        })
    }

    let mut out = Vec::new();
    let mut walked_paths = std::collections::BTreeSet::new();
    // Explicit work-stack of (directory, repo-relative prefix).
    let mut stack: Vec<(std::path::PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut children: Vec<_> = std::fs::read_dir(&dir)?.collect::<Result<_, _>>()?;
        children.sort_by_key(|e| e.file_name());
        for entry in children {
            let name = utf8_name(&entry.file_name())?;
            if name == ".git" {
                continue;
            }
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            // A submodule root: skip it (the gitlink comes from the map below),
            // never descend into whatever the worktree holds there.
            if gitlinks.contains_key(&rel) {
                continue;
            }
            let meta = std::fs::symlink_metadata(entry.path())?;
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                let target = std::fs::read_link(entry.path())?;
                let target = utf8_name(target.as_os_str())?;
                out.push(ManifestEntry::symlink(rel.clone(), &target));
                walked_paths.insert(rel);
            } else if file_type.is_dir() {
                stack.push((entry.path(), rel));
            } else if file_type.is_file() {
                let bytes = std::fs::read(entry.path())?;
                out.push(ManifestEntry::file(
                    rel.clone(),
                    is_executable(&meta),
                    &bytes,
                ));
                walked_paths.insert(rel);
            }
            // Other node types (fifos, sockets, devices) are not tree contents.
        }
    }

    // Gitlinks are driven by the map (the tree object), not the worktree, so
    // the manifest is identical whether or not each submodule is checked out.
    for (path, oid) in gitlinks {
        if walked_paths.contains(path) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "a gitlink path collides with a walked file or symlink",
            ));
        }
        let entry = ManifestEntry::gitlink(path.clone(), oid).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "gitlink OID is not a 40- or 64-hex string",
            )
        })?;
        out.push(entry);
    }
    Ok(out)
}

#[cfg(all(feature = "persist", unix))]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // Git records mode 100755 only when the owner-execute bit is set.
    meta.permissions().mode() & 0o100 != 0
}

#[cfg(all(feature = "persist", not(unix)))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // The empty-tree SHA-1 OID, used as a stable gitlink OID in tests.
    const OID: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

    #[test]
    fn hash_is_order_independent_and_deterministic() {
        let a = ManifestEntry::file("src/a.rs", false, b"alpha");
        let b = ManifestEntry::file("src/b.rs", true, b"beta");
        let c = ManifestEntry::symlink("link", "src/a.rs");
        let h1 = manifest_hash(&[a.clone(), b.clone(), c.clone()]).unwrap();
        // Same entries in a different order hash identically.
        let h2 = manifest_hash(&[c, a, b]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn mode_and_content_change_the_hash() {
        let base = manifest_hash(&[ManifestEntry::file("f", false, b"x")]).unwrap();
        // Executable bit changes the mode, hence the manifest.
        let exec = manifest_hash(&[ManifestEntry::file("f", true, b"x")]).unwrap();
        // Different bytes change the content hash.
        let other = manifest_hash(&[ManifestEntry::file("f", false, b"y")]).unwrap();
        assert_ne!(base, exec);
        assert_ne!(base, other);
    }

    #[test]
    fn symlink_hashes_the_target_string() {
        let link = ManifestEntry::symlink("l", "target/path");
        assert_eq!(link.sha256, sha256(b"target/path"));
        assert_eq!(link.mode, FileMode::Symlink);
    }

    #[test]
    fn gitlink_hashes_the_oid_string_and_validates_hex() {
        let g = ManifestEntry::gitlink("sub", OID).unwrap();
        assert_eq!(g.sha256, sha256(OID.as_bytes()));
        assert_eq!(g.mode, FileMode::Gitlink);
        // Uppercase, non-hex, empty, or wrong-length OIDs are rejected.
        assert!(ManifestEntry::gitlink("sub", "4B825D").is_none());
        assert!(ManifestEntry::gitlink("sub", "nothex").is_none());
        assert!(ManifestEntry::gitlink("sub", "").is_none());
        assert!(ManifestEntry::gitlink("sub", "abc").is_none()); // valid hex, wrong length
        assert!(ManifestEntry::gitlink("sub", &"a".repeat(64)).is_some()); // sha256 length
    }

    #[test]
    fn gitlink_manifest_is_checkout_state_independent() {
        // A gitlink entry depends only on the tree-object OID, never on any
        // worktree contents under the submodule path, so an initialized and an
        // uninitialized checkout of the same tree yield the same manifest.
        let with_sub = manifest_hash(&[
            ManifestEntry::file("a", false, b"root"),
            ManifestEntry::gitlink("vendor/lib", OID).unwrap(),
        ])
        .unwrap();
        let with_sub_again = manifest_hash(&[
            ManifestEntry::gitlink("vendor/lib", OID).unwrap(),
            ManifestEntry::file("a", false, b"root"),
        ])
        .unwrap();
        assert_eq!(with_sub, with_sub_again);
        // A submodule-free tree (same root file) differs from the
        // submodule-bearing one.
        let no_sub = manifest_hash(&[ManifestEntry::file("a", false, b"root")]).unwrap();
        assert_ne!(with_sub, no_sub);
    }

    #[test]
    fn duplicate_path_is_ambiguous() {
        let dup = manifest_hash(&[
            ManifestEntry::file("f", false, b"x"),
            ManifestEntry::file("f", false, b"y"),
        ]);
        assert!(dup.is_none());
    }

    #[test]
    fn empty_tree_hashes_the_empty_object() {
        let empty = manifest_hash(&[]).unwrap();
        assert_eq!(empty, sha256(b"{}"));
    }

    #[cfg(feature = "persist")]
    #[test]
    fn dir_walk_matches_hand_built_entries_and_excludes_git() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), b"alpha").unwrap();
        std::fs::write(root.join("readme"), b"hello").unwrap();
        // A .git directory that must be excluded.
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), b"secret").unwrap();

        let gitlinks = BTreeMap::new();
        let walked = manifest_from_dir(root, &gitlinks).unwrap();
        let walked_hash = manifest_hash(&walked).unwrap();

        let expected = manifest_hash(&[
            ManifestEntry::file("readme", false, b"hello"),
            ManifestEntry::file("src/a.rs", false, b"alpha"),
        ])
        .unwrap();
        assert_eq!(walked_hash, expected);
    }

    #[cfg(feature = "persist")]
    #[test]
    fn dir_walk_treats_submodule_dir_as_gitlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a"), b"root").unwrap();
        // A submodule worktree with arbitrary (checkout-dependent) contents.
        std::fs::create_dir(root.join("vendor")).unwrap();
        std::fs::create_dir(root.join("vendor/lib")).unwrap();
        std::fs::write(root.join("vendor/lib/whatever"), b"checkout-specific").unwrap();

        let mut gitlinks = BTreeMap::new();
        gitlinks.insert("vendor/lib".to_string(), OID.to_string());
        let walked = manifest_hash(&manifest_from_dir(root, &gitlinks).unwrap()).unwrap();

        // The submodule's worktree contents do not enter the manifest.
        let expected = manifest_hash(&[
            ManifestEntry::file("a", false, b"root"),
            ManifestEntry::gitlink("vendor/lib", OID).unwrap(),
        ])
        .unwrap();
        assert_eq!(walked, expected);
    }

    #[cfg(feature = "persist")]
    #[test]
    fn dir_walk_gitlink_is_emitted_when_submodule_dir_is_absent() {
        // Checkout-state independence: a gitlink in the map is emitted even
        // when its directory was never checked out on disk, so a sparse or
        // uninitialized checkout yields the same manifest as a populated one.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a"), b"root").unwrap();
        // No vendor/lib directory exists on disk at all.
        let mut gitlinks = BTreeMap::new();
        gitlinks.insert("vendor/lib".to_string(), OID.to_string());
        let walked = manifest_hash(&manifest_from_dir(root, &gitlinks).unwrap()).unwrap();
        let expected = manifest_hash(&[
            ManifestEntry::file("a", false, b"root"),
            ManifestEntry::gitlink("vendor/lib", OID).unwrap(),
        ])
        .unwrap();
        assert_eq!(walked, expected);
    }

    #[cfg(all(feature = "persist", unix))]
    #[test]
    fn dir_walk_uses_owner_execute_bit_like_git() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("f"), b"x").unwrap();
        // Group-execute only (0o654): Git records this as a regular file.
        std::fs::set_permissions(root.join("f"), std::fs::Permissions::from_mode(0o654)).unwrap();
        let walked = manifest_from_dir(root, &BTreeMap::new()).unwrap();
        assert_eq!(walked.len(), 1);
        assert_eq!(walked[0].mode, FileMode::Regular);
        // Owner-execute (0o744): executable.
        std::fs::set_permissions(root.join("f"), std::fs::Permissions::from_mode(0o744)).unwrap();
        let walked = manifest_from_dir(root, &BTreeMap::new()).unwrap();
        assert_eq!(walked[0].mode, FileMode::Executable);
    }

    // Linux-only: macOS and Windows reject non-UTF-8 filenames at the
    // filesystem layer, so the fixture cannot even be created there. The code
    // under test (fail-closed on non-UTF-8) is platform-independent; only this
    // fixture is Linux-specific.
    #[cfg(all(feature = "persist", target_os = "linux"))]
    #[test]
    fn dir_walk_rejects_non_utf8_name() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let bad = std::ffi::OsStr::from_bytes(b"bad\xffname");
        std::fs::write(root.join(bad), b"x").unwrap();
        // A non-UTF-8 name is a hard error, never a silent lossy hash.
        let err = manifest_from_dir(root, &BTreeMap::new()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
