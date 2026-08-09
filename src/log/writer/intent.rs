use super::*;

/// Commit intent for crash recovery.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommitIntent {
    /// Id of the subject record the interrupted commit was appending.
    pub subject_id: RecordId,
    /// False before the subject is appended to the log, flipped to true
    /// right after; tells recovery whether a verdict may still be owed.
    pub written: bool,
}

impl CommitIntent {
    /// Persist the intent to `path` durably and atomically: write a
    /// temporary file, fsync it, rename it over `path`, and fsync the
    /// containing directory (where the platform supports it). A crash at
    /// any point leaves either the old intent or the new one - never a
    /// truncated or empty file where one existed.
    pub(crate) fn write_to_file(&self, path: &Path) -> Result<(), LogError> {
        use std::io::Write;
        let bytes =
            canonical_json(self).map_err(|e| LogError::Io(std::io::Error::other(e.to_string())))?;
        let tmp_path = path.with_extension("intent.tmp");
        {
            // Write and fsync through the same writable handle. Reopening
            // the file read-only just to sync it fails on Windows, where
            // FlushFileBuffers needs write access.
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        sync_parent_dir(path)?;
        Ok(())
    }

    /// Remove the intent file (final commit step); a no-op when it does not
    /// exist, making recovery idempotent.
    pub(crate) fn clear_file(path: &Path) -> Result<(), LogError> {
        if path.exists() {
            std::fs::remove_file(path)?;
            sync_parent_dir(path)?;
        }
        Ok(())
    }
}

/// Fsync the directory containing `path`, so a rename or unlink is
/// durable across power loss. Directory handles cannot be fsynced on
/// Windows; there the rename itself is the best available guarantee.
fn sync_parent_dir(path: &Path) -> Result<(), LogError> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
