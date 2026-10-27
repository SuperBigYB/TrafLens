// SPDX-License-Identifier: Apache-2.0
//! Bounded joins for process termination. A timeout is a failed shutdown.
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JoinError {
    TimedOut,
    Panicked,
}

pub(crate) fn join_with_timeout<T>(
    handle: JoinHandle<T>,
    timeout: Duration,
) -> Result<T, JoinError> {
    let deadline = Instant::now() + timeout;
    loop {
        if handle.is_finished() {
            return handle.join().map_err(|_| JoinError::Panicked);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // Dropping the handle detaches it. The caller exits with failure;
            // it must not report a completed drain or retry uncertain writes.
            return Err(JoinError::TimedOut);
        }
        thread::park_timeout(remaining.min(Duration::from_millis(10)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn completed_and_panicking_workers_have_distinct_results() {
        assert_eq!(
            join_with_timeout(thread::spawn(|| 42), Duration::from_secs(2)),
            Ok(42)
        );
        assert_eq!(
            join_with_timeout(
                thread::spawn(|| panic!("synthetic")),
                Duration::from_secs(2)
            ),
            Err(JoinError::Panicked)
        );
    }

    #[test]
    fn blocked_worker_cannot_turn_deadline_into_success() {
        let (release, wait) = mpsc::channel::<()>();
        let (done, finished) = mpsc::channel();
        let handle = thread::spawn(move || {
            wait.recv().unwrap();
            done.send(()).unwrap();
        });
        assert_eq!(
            join_with_timeout(handle, Duration::from_millis(20)),
            Err(JoinError::TimedOut)
        );
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(2)).unwrap();
    }
}
