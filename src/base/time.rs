//! Logical time source.

/// Logical commit counter, not wall-clock time; strictly `prev + 1` per
/// committed record, starting at 1 for the first record of a log.
pub type Time = u64;

/// Deterministic logical counter for record time assignment.
pub struct TimeSource {
    next: u64,
}

impl TimeSource {
    /// Restore from the last committed record's time.
    /// For an empty log, last_time is None, so first record gets time = 1.
    /// Saturates instead of overflowing on hostile input; a saturated
    /// counter is caught by [`exhausted`](TimeSource::exhausted) before any
    /// commit rather than wrapping.
    pub fn from_last_time(last_time: Option<Time>) -> Self {
        let last = last_time.unwrap_or(0);
        Self {
            next: last.saturating_add(1),
        }
    }

    /// Get the next logical time and advance the counter. Saturates at
    /// `u64::MAX` instead of wrapping; callers must check
    /// [`exhausted`](TimeSource::exhausted) first (the commit protocol
    /// does).
    pub fn next_time(&mut self) -> Time {
        let t = self.next;
        self.next = self.next.saturating_add(1);
        t
    }

    /// True when the counter can no longer hand out two distinct times (a
    /// commit needs one for the subject and one for the verdict).
    pub fn exhausted(&self) -> bool {
        self.next >= Time::MAX - 1
    }

    /// Peek at the next time without advancing.
    pub fn peek(&self) -> Time {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_log_starts_at_1() {
        let mut ts = TimeSource::from_last_time(None);
        assert_eq!(ts.next_time(), 1);
        assert_eq!(ts.next_time(), 2);
    }

    #[test]
    fn test_restore_from_last_time() {
        let mut ts = TimeSource::from_last_time(Some(10));
        assert_eq!(ts.next_time(), 11);
        assert_eq!(ts.next_time(), 12);
    }

    #[test]
    fn test_increments_by_one() {
        let mut ts = TimeSource::from_last_time(Some(5));
        let t1 = ts.next_time();
        let t2 = ts.next_time();
        assert_eq!(t2 - t1, 1);
    }
}
