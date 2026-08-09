//! FileLog: append-only record storage from SPEC.md.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::base::canonical::canonical_json;
use crate::base::time::Time;
use crate::record::record::Record;
use crate::record::refs::RecordId;
use crate::LogError;

/// The append-only file-backed log (feature `persist`).
/// Stores records as a flat append-only file and keeps all records in memory.
pub(crate) struct FileLog {
    pub(crate) dir: PathBuf,
    pub(crate) file: std::fs::File,
    pub(crate) records: Vec<Record>,
    pub(crate) index: HashMap<RecordId, usize>,
    pub(crate) max_file_bytes: u64,
}

impl FileLog {
    /// Open or create a log at the given directory.
    ///
    /// A torn trailing frame (crash mid-append) is truncated away before the
    /// handle is positioned for append, so later writes continue from the last
    /// complete record instead of burying garbage inside the file.
    pub(crate) fn open(dir: &Path, max_file_bytes: u64) -> Result<Self, LogError> {
        std::fs::create_dir_all(dir)?;
        let file_path = dir.join("records.log");
        // Resolve the path once. Every size check, read, recovery truncation,
        // and later append operates on this exact file handle, so another
        // process cannot swap the path between validation and use.
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&file_path)?;

        let metadata_len = file.metadata()?.len();
        if metadata_len > max_file_bytes {
            return Err(LogError::LogSizeLimitExceeded {
                bytes: metadata_len,
                max_bytes: max_file_bytes,
            });
        }

        // The metadata check gives an exact diagnostic for an already-large
        // file. The bounded read closes the grow-after-metadata race: at most
        // max + 1 bytes are allocated, and that extra byte proves overflow.
        let (records, valid_len, bytes_read) = Self::read_all_records(&mut file, max_file_bytes)?;

        if valid_len < bytes_read {
            file.set_len(valid_len)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;

        let mut index = HashMap::new();
        for (pos, record) in records.iter().enumerate() {
            index.insert(record.id, pos);
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            file,
            records,
            index,
            max_file_bytes,
        })
    }

    /// Check that every supplied record frame fits in the remaining file
    /// capacity as one operation. The writer uses this before starting a
    /// subject/verdict commit, so the subject is never made durable without
    /// space reserved for its deterministic verdict.
    pub(crate) fn ensure_capacity_for(&self, records: &[&Record]) -> Result<(), LogError> {
        let mut projected_bytes = self.file.metadata()?.len();
        for record in records {
            let (_, len) = encode_record(record)?;
            projected_bytes = projected_bytes.checked_add(4u64 + u64::from(len)).ok_or(
                LogError::LogSizeLimitExceeded {
                    bytes: u64::MAX,
                    max_bytes: self.max_file_bytes,
                },
            )?;
        }
        if projected_bytes > self.max_file_bytes {
            return Err(LogError::LogSizeLimitExceeded {
                bytes: projected_bytes,
                max_bytes: self.max_file_bytes,
            });
        }
        Ok(())
    }

    /// Append a record to the log file and in-memory store. Records whose
    /// serialized frame exceeds `u32::MAX` bytes are refused with
    /// [`LogError::RecordTooLarge`] - a silent `as u32` truncation would
    /// write a corrupt frame length and destroy the log.
    pub(crate) fn append(&mut self, record: Record) -> Result<(), LogError> {
        let (bytes, len) = encode_record(&record)?;
        self.ensure_capacity_for(&[&record])?;

        // The process-wide writer lock makes this the only cooperative
        // appender. Re-seek on every append so reads or recovery never leave
        // the shared handle at an interior offset.
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&len.to_be_bytes())?;
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;

        let pos = self.records.len();
        self.index.insert(record.id, pos);
        self.records.push(record);
        Ok(())
    }

    /// Get a record by its id.
    pub fn get(&self, id: RecordId) -> Option<&Record> {
        self.index.get(&id).map(|&pos| &self.records[pos])
    }

    /// Scan records in range [from, to] (inclusive) by logical time.
    /// Returns a contiguous subslice in ascending time order.
    pub fn scan(&self, from: Time, to: Time) -> &[Record] {
        let start = self.records.partition_point(|r| r.time < from);
        let end = self.records.partition_point(|r| r.time <= to);
        &self.records[start..end]
    }

    /// Get a reference to all records in the log.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Get the time of the last record, if any.
    pub fn last_time(&self) -> Option<Time> {
        self.records.last().map(|r| r.time)
    }

    /// Read all records from the log file.
    ///
    /// Returns the records plus the byte length of the valid prefix (the end
    /// of the last complete frame); trailing bytes past that point belong to
    /// a torn write and are ignored.
    fn read_all_records(
        file: &mut std::fs::File,
        max_file_bytes: u64,
    ) -> Result<(Vec<Record>, u64, u64), LogError> {
        let read_limit = max_file_bytes.saturating_add(1);
        let mut data = Vec::new();
        file.take(read_limit).read_to_end(&mut data)?;
        let bytes_read = data.len() as u64;
        if bytes_read > max_file_bytes {
            return Err(LogError::LogSizeLimitExceeded {
                bytes: bytes_read,
                max_bytes: max_file_bytes,
            });
        }
        let mut records = Vec::new();
        let mut cursor = 0;

        while data.len().saturating_sub(cursor) >= 4 {
            let body_start = cursor + 4;
            let len = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;

            let Some(frame_end) = complete_frame_end(body_start, len, data.len()) else {
                // Torn or arithmetically impossible frame at end of file -
                // stop at the last complete record without overflowing.
                break;
            };

            let record: Record =
                serde_json::from_slice(&data[body_start..frame_end]).map_err(|e| {
                    LogError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to deserialize record: {}", e),
                    ))
                })?;
            records.push(record);
            cursor = frame_end;
        }

        Ok((records, cursor as u64, bytes_read))
    }
}

fn encode_record(record: &Record) -> Result<(Vec<u8>, u32), LogError> {
    let bytes = canonical_json(record).map_err(|e| {
        LogError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })?;
    let len =
        u32::try_from(bytes.len()).map_err(|_| LogError::RecordTooLarge { bytes: bytes.len() })?;
    Ok((bytes, len))
}

fn complete_frame_end(body_start: usize, body_len: usize, total_len: usize) -> Option<usize> {
    body_start
        .checked_add(body_len)
        .filter(|&frame_end| frame_end <= total_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::author::Author;
    use crate::record::evidence::Evidence;
    use crate::record::kind::*;

    fn test_record(time: Time) -> Record {
        Record {
            id: [time as u8; 32],
            space: [1u8; 32],
            thread: [2u8; 32],
            time,
            author: Author {
                id: "test".into(),
                type_: AuthorType::User,
                signature: None,
            },
            kind: Kind::Request,
            schema: [3u8; 32],
            data: b"{}".to_vec(),
            refs: vec![],
            evidence: Evidence::Reported,
        }
    }

    #[test]
    fn test_frame_length_overflow_is_incomplete_not_a_panic() {
        assert_eq!(complete_frame_end(8, usize::MAX, usize::MAX), None);
        assert_eq!(complete_frame_end(4, 3, 7), Some(7));
        assert_eq!(complete_frame_end(4, 4, 7), None);
    }

    #[test]
    fn test_open_rejects_oversized_file_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.log");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(9).unwrap();

        assert!(matches!(
            FileLog::open(dir.path(), 8),
            Err(LogError::LogSizeLimitExceeded {
                bytes: 9,
                max_bytes: 8
            })
        ));
    }

    #[test]
    fn test_bounded_handle_read_detects_growth_after_metadata_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.log");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Model a file that passed an 8-byte metadata check and then grew
        // before parsing. The reader allocates at most max + 1 and rejects.
        file.set_len(9).unwrap();
        assert!(matches!(
            FileLog::read_all_records(&mut file, 8),
            Err(LogError::LogSizeLimitExceeded {
                bytes: 9,
                max_bytes: 8
            })
        ));
    }

    #[test]
    fn test_append_respects_log_size_limit_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = FileLog::open(dir.path(), 1).unwrap();
        let result = log.append(test_record(1));
        assert!(matches!(
            result,
            Err(LogError::LogSizeLimitExceeded { max_bytes: 1, .. })
        ));
        assert_eq!(
            std::fs::metadata(dir.path().join("records.log"))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_open_creates_dir_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join("test_log");
        let log = FileLog::open(&log_dir, u64::MAX).unwrap();
        assert!(log_dir.join("records.log").exists());
        assert_eq!(log.records.len(), 0);
    }

    #[test]
    fn test_append_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = FileLog::open(dir.path(), u64::MAX).unwrap();

        let r = test_record(1);
        let id = r.id;
        log.append(r).unwrap();

        let retrieved = log.get(id).unwrap();
        assert_eq!(retrieved.time, 1);
    }

    #[test]
    fn test_scan() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = FileLog::open(dir.path(), u64::MAX).unwrap();

        for t in 1..=5 {
            log.append(test_record(t)).unwrap();
        }

        let slice = log.scan(2, 4);
        assert_eq!(slice.len(), 3);
        assert_eq!(slice[0].time, 2);
        assert_eq!(slice[2].time, 4);
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        // Write
        {
            let mut log = FileLog::open(dir.path(), u64::MAX).unwrap();
            log.append(test_record(1)).unwrap();
            log.append(test_record(2)).unwrap();
        }

        // Read back
        let log = FileLog::open(dir.path(), u64::MAX).unwrap();
        assert_eq!(log.records.len(), 2);
        assert_eq!(log.records[0].time, 1);
        assert_eq!(log.records[1].time, 2);
    }

    #[test]
    fn test_last_time() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = FileLog::open(dir.path(), u64::MAX).unwrap();
        assert_eq!(log.last_time(), None);

        log.append(test_record(5)).unwrap();
        assert_eq!(log.last_time(), Some(5));
    }
}
