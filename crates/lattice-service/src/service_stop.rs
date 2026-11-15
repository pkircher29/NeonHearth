//! Platform-neutral pieces of the Windows service stop sequence.
//!
//! `win_service` (Windows only) reports `StopPending` to the SCM and bounds the runtime
//! drain; the decisions live here so every platform's CI runs their tests. The Windows glue
//! only supplies the real sleep, the real status call and the real runtime.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Wait hint reported while stopping; the checkpoint is advanced every half hint.
pub const STOP_WAIT_HINT: Duration = Duration::from_secs(10);
/// Longest the runtime may take to drop outstanding blocking work after `serve` returns.
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);
/// Checkpoint reported together with the first `StopPending` (sent when the stop is requested).
pub const FIRST_STOP_CHECKPOINT: u32 = 1;

/// The `StopPending` heartbeat that follows the first report: until `stopped` is set it waits
/// half a wait hint via `sleep`, then (unless the stop completed meanwhile) calls `report`
/// with the next checkpoint, which starts at `FIRST_STOP_CHECKPOINT + 1` and rises by one.
pub fn stop_pending_heartbeat(
    stopped: &AtomicBool,
    wait_hint: Duration,
    mut sleep: impl FnMut(Duration),
    mut report: impl FnMut(u32),
) {
    let mut checkpoint = FIRST_STOP_CHECKPOINT + 1;
    while !stopped.load(Ordering::Acquire) {
        sleep(wait_hint / 2);
        if stopped.load(Ordering::Acquire) {
            break;
        }
        report(checkpoint);
        checkpoint += 1;
    }
}

/// Drops the runtime, waiting at most `drain` for outstanding blocking work. Dropping a
/// runtime normally waits for every `spawn_blocking` task (ICMP echoes, neighbor and socket
/// table reads) with no limit; this gives up on them so `Stopped` is always reported.
pub fn shutdown_runtime(runtime: tokio::runtime::Runtime, drain: Duration) {
    runtime.shutdown_timeout(drain);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::{Arc, mpsc};

    #[test]
    fn heartbeat_reports_rising_checkpoints_each_half_hint_until_stopped() {
        let stopped = AtomicBool::new(false);
        let sleeps = RefCell::new(Vec::new());
        let reports = RefCell::new(Vec::new());
        let calls = Cell::new(0u32);
        stop_pending_heartbeat(
            &stopped,
            STOP_WAIT_HINT,
            |d| {
                sleeps.borrow_mut().push(d);
                calls.set(calls.get() + 1);
                // The runtime finishes during the fourth wait: no report after it.
                if calls.get() == 4 {
                    stopped.store(true, Ordering::Release);
                }
            },
            |checkpoint| reports.borrow_mut().push(checkpoint),
        );
        assert_eq!(*reports.borrow(), [2, 3, 4]);
        assert_eq!(*sleeps.borrow(), [STOP_WAIT_HINT / 2; 4]);
    }

    #[test]
    fn heartbeat_does_nothing_when_the_stop_already_completed() {
        let stopped = AtomicBool::new(true);
        stop_pending_heartbeat(
            &stopped,
            STOP_WAIT_HINT,
            |_| panic!("must not wait after the stop completed"),
            |_| panic!("must not report after the stop completed"),
        );
    }

    #[test]
    fn heartbeat_keeps_checkpoints_strictly_increasing_while_the_runtime_never_stops() {
        let stopped = AtomicBool::new(false);
        let calls = Cell::new(0u32);
        let reports = RefCell::new(Vec::new());
        stop_pending_heartbeat(
            &stopped,
            STOP_WAIT_HINT,
            |_| {
                calls.set(calls.get() + 1);
                // Only the bounded drain (below) ends a stuck stop; the heartbeat has no
                // deadline of its own, so the fake gives up after many wait hints.
                if calls.get() == 1000 {
                    stopped.store(true, Ordering::Release);
                }
            },
            |checkpoint| reports.borrow_mut().push(checkpoint),
        );
        let reports = reports.borrow();
        assert_eq!(reports.len(), 999);
        assert_eq!(reports[0], FIRST_STOP_CHECKPOINT + 1);
        assert!(reports.windows(2).all(|pair| pair[1] == pair[0] + 1));
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn runtime_with_finished_work_shuts_down_within_the_drain() {
        let runtime = runtime();
        let value = runtime.block_on(async { tokio::task::spawn_blocking(|| 7).await.unwrap() });
        assert_eq!(value, 7);
        shutdown_runtime(runtime, SHUTDOWN_DRAIN);
    }

    #[test]
    fn runtime_with_stuck_blocking_work_is_abandoned_at_the_drain_bound() {
        let runtime = runtime();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let finished = Arc::new(AtomicBool::new(false));
        let task_finished = Arc::clone(&finished);
        let _task = runtime.spawn_blocking(move || {
            started_tx.send(()).unwrap();
            // Parked like an ICMP echo or table read that never returns.
            let _ = release_rx.recv();
            task_finished.store(true, Ordering::Release);
        });
        started_rx.recv().unwrap();
        // Returns although the blocking task is still running; unbounded, this would hang.
        shutdown_runtime(runtime, Duration::from_millis(20));
        assert!(!finished.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
    }
}
