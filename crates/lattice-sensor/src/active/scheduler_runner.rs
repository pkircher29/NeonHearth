use super::{
    ActiveEngine, ActiveError, AdmissionDecision, AttemptTransport, Clock, ProbeCatalog,
    ProbeCredential, ProbeOutcome, ProbeRequest, Scheduler, SchedulerConfig, WorkKey,
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify, mpsc, watch},
    task::JoinHandle,
};

#[async_trait]
pub trait ExecutionCredentialSource: Send + Sync {
    /// Implementations that call blocking OS/keyring APIs must offload them with
    /// `spawn_blocking`; this future must remain cancellation-safe.
    async fn credential_for(
        &self,
        request: &ProbeRequest,
    ) -> Result<Option<ProbeCredential>, ActiveError>;
}
struct NoCredentials;
#[async_trait]
impl ExecutionCredentialSource for NoCredentials {
    async fn credential_for(
        &self,
        _: &ProbeRequest,
    ) -> Result<Option<ProbeCredential>, ActiveError> {
        Ok(None)
    }
}
#[derive(Debug)]
pub struct RunnerEvent {
    pub request: ProbeRequest,
    pub attempt: u8,
    pub result: Result<ProbeOutcome, ActiveError>,
    pub will_retry: bool,
}
struct RetryItem {
    due: Duration,
    request: ProbeRequest,
    attempt: u8,
}
struct Reservation<C: Clock> {
    scheduler: Arc<Mutex<Scheduler<C>>>,
    request: ProbeRequest,
}
impl<C: Clock> Drop for Reservation<C> {
    fn drop(&mut self) {
        self.scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finish(&self.request);
    }
}
enum Lifecycle {
    Running(Vec<JoinHandle<()>>),
    Draining,
    Drained,
}

async fn wait_for_deadline(delay: Option<Duration>) {
    match delay {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending().await,
    }
}

async fn wait_for_result_capacity(sender: &mpsc::Sender<RunnerEvent>, blocked: bool) {
    if blocked {
        let _ = sender.reserve().await;
    } else {
        std::future::pending().await
    }
}

pub struct SchedulerRunner<C: Clock, T: AttemptTransport> {
    scheduler: Arc<Mutex<Scheduler<C>>>,
    engine: Arc<ActiveEngine<T>>,
    credentials: Arc<dyn ExecutionCredentialSource>,
    catalog: ProbeCatalog,
    clock: Arc<C>,
    retries: Mutex<VecDeque<RetryItem>>,
    attempts: Mutex<HashMap<WorkKey, u8>>,
    pending: Mutex<HashSet<WorkKey>>,
    lifecycle: AsyncMutex<Lifecycle>,
    drain_complete: watch::Sender<bool>,
    stop_signal: watch::Sender<bool>,
    results: mpsc::Sender<RunnerEvent>,
    notify: Notify,
    stopped: AtomicBool,
    queue_capacity: usize,
    max_retry_attempts: u8,
    credential_timeout: Duration,
    next_eligibility: Mutex<Option<Duration>>,
    scan_count: AtomicUsize,
    result_blocked: AtomicBool,
}
impl<C: Clock + 'static, T: AttemptTransport + 'static> SchedulerRunner<C, T> {
    pub fn new(
        config: SchedulerConfig,
        clock: Arc<C>,
        engine: Arc<ActiveEngine<T>>,
        catalog: ProbeCatalog,
        result_capacity: usize,
    ) -> Result<(Arc<Self>, mpsc::Receiver<RunnerEvent>), ActiveError> {
        Self::new_with_credentials(
            config,
            clock,
            engine,
            catalog,
            result_capacity,
            Arc::new(NoCredentials),
        )
    }
    pub fn new_with_credentials(
        config: SchedulerConfig,
        clock: Arc<C>,
        engine: Arc<ActiveEngine<T>>,
        catalog: ProbeCatalog,
        result_capacity: usize,
        credentials: Arc<dyn ExecutionCredentialSource>,
    ) -> Result<(Arc<Self>, mpsc::Receiver<RunnerEvent>), ActiveError> {
        if result_capacity == 0 || result_capacity > super::MAX_QUEUE {
            return Err(ActiveError::InvalidConfig);
        }
        let queue_capacity = config.queue_capacity;
        let max_retry_attempts = config.max_retry_attempts;
        let credential_timeout = config.credential_timeout;
        let scheduler = Scheduler::new(config, clock.clone())?;
        let (results, receiver) = mpsc::channel(result_capacity);
        let (drain_complete, _) = watch::channel(false);
        let (stop_signal, _) = watch::channel(false);
        Ok((
            Arc::new(Self {
                scheduler: Arc::new(Mutex::new(scheduler)),
                engine,
                credentials,
                catalog,
                clock,
                retries: Mutex::new(VecDeque::new()),
                attempts: Mutex::new(HashMap::new()),
                pending: Mutex::new(HashSet::new()),
                lifecycle: AsyncMutex::new(Lifecycle::Running(Vec::new())),
                drain_complete,
                stop_signal,
                results,
                notify: Notify::new(),
                stopped: AtomicBool::new(false),
                queue_capacity,
                max_retry_attempts,
                credential_timeout,
                next_eligibility: Mutex::new(None),
                scan_count: AtomicUsize::new(0),
                result_blocked: AtomicBool::new(false),
            }),
            receiver,
        ))
    }
    pub fn enqueue(&self, request: ProbeRequest) -> Result<bool, ActiveError> {
        if self.catalog.resolve(&request.probe_id).is_none() {
            return Err(ActiveError::UnknownProbe);
        }
        let key = WorkKey::from(&request);
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.contains(&key) {
            return Ok(false);
        }
        if pending.len() >= self.queue_capacity {
            return Err(ActiveError::QueueFull);
        }
        pending.insert(key.clone());
        drop(pending);
        match self
            .scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enqueue(request)
        {
            Ok(inserted) => {
                if inserted {
                    self.notify.notify_one()
                }
                Ok(inserted)
            }
            Err(error) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
                Err(error)
            }
        }
    }
    fn promote_due_retries(&self) {
        let now = self.clock.monotonic();
        let mut retries = self.retries.lock().unwrap_or_else(|e| e.into_inner());
        let mut scheduler = self.scheduler.lock().unwrap_or_else(|e| e.into_inner());
        let mut remaining = VecDeque::new();
        while let Some(item) = retries.pop_front() {
            if item.due <= now && scheduler.enqueue(item.request.clone()).is_ok() {
                self.attempts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(WorkKey::from(&item.request), item.attempt);
            } else {
                remaining.push_back(item)
            }
        }
        *retries = remaining;
    }
    pub async fn dispatch_ready(self: &Arc<Self>) -> usize {
        if self.stopped.load(Ordering::Acquire) {
            return 0;
        }
        self.promote_due_retries();
        self.result_blocked.store(false, Ordering::Release);
        *self
            .next_eligibility
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        let mut dispatched = 0;
        let mut remaining = self
            .scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue_len();
        while remaining > 0 {
            remaining -= 1;
            self.scan_count.fetch_add(1, Ordering::Relaxed);
            let permit = match self.results.clone().try_reserve_owned() {
                Ok(p) => p,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.result_blocked.store(true, Ordering::Release);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.stop_and_drain().await;
                    break;
                }
            };
            let mut lifecycle = self.lifecycle.lock().await;
            let Lifecycle::Running(tasks) = &mut *lifecycle else {
                break;
            };
            tasks.retain(|task| !task.is_finished());
            let Some(request) = self
                .scheduler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .next_request()
            else {
                break;
            };
            let Some(descriptor) = self.catalog.resolve(&request.probe_id) else {
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&WorkKey::from(&request));
                continue;
            };
            let attempt = self
                .attempts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&WorkKey::from(&request))
                .unwrap_or(0);
            let admission = self
                .scheduler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .admission_decision(&request, descriptor.rate_cost);
            if admission != AdmissionDecision::Admitted {
                if let AdmissionDecision::EligibleAt(deadline) = admission {
                    let mut next = self
                        .next_eligibility
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    *next = Some(next.map_or(deadline, |current| current.min(deadline)));
                }
                if attempt > 0 {
                    self.attempts
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(WorkKey::from(&request), attempt);
                }
                let _ = self
                    .scheduler
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .enqueue(request);
                continue;
            }
            dispatched += 1;
            let runner = self.clone();
            let task = tokio::spawn(async move {
                runner.execute_admitted(request, attempt, permit).await;
            });
            tasks.push(task);
            drop(lifecycle);
        }
        dispatched
    }

    async fn execute_admitted(
        self: Arc<Self>,
        request: ProbeRequest,
        attempt: u8,
        permit: mpsc::OwnedPermit<RunnerEvent>,
    ) {
        let reservation = Reservation {
            scheduler: self.scheduler.clone(),
            request: request.clone(),
        };
        let mut stop = self.stop_signal.subscribe();
        let execution = AssertUnwindSafe(async {
            let credential = if self
                .catalog
                .resolve(&request.probe_id)
                .is_some_and(|descriptor| descriptor.credential_required)
            {
                tokio::select! {
                    biased;
                    _ = stop.wait_for(|stopped| *stopped) => return Err(ActiveError::Cancelled),
                    result = tokio::time::timeout(
                        self.credential_timeout,
                        self.credentials.credential_for(&request),
                    ) => result.map_err(|_| ActiveError::CredentialTimeout)??,
                }
            } else {
                None
            };
            self.engine
                .execute(request.clone(), credential.as_ref())
                .await
        })
        .catch_unwind()
        .await;
        drop(reservation);

        let result = execution.unwrap_or(Err(ActiveError::Internal));
        let will_retry = self
            .schedule_retry_if_transient(&request, attempt, &result)
            .await;
        if !will_retry && !matches!(result, Err(ActiveError::Cancelled)) {
            self.scheduler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_success(&request);
        }
        if !will_retry {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&WorkKey::from(&request));
        }
        permit.send(RunnerEvent {
            request,
            attempt,
            result,
            will_retry,
        });
        self.notify.notify_one();
    }

    async fn schedule_retry_if_transient(
        &self,
        request: &ProbeRequest,
        attempt: u8,
        result: &Result<ProbeOutcome, ActiveError>,
    ) -> bool {
        let transient = matches!(
            result,
            Ok(ProbeOutcome::Timeout { .. }) | Err(ActiveError::Network)
        );
        if !transient || attempt >= self.max_retry_attempts {
            return false;
        }
        // Serialize retry admission with stop so no retry can appear after stop clears state.
        let lifecycle = self.lifecycle.lock().await;
        if !matches!(*lifecycle, Lifecycle::Running(_)) || self.stopped.load(Ordering::Acquire) {
            return false;
        }
        let mut scheduler = self.scheduler.lock().unwrap_or_else(|e| e.into_inner());
        let delay = scheduler.retry_delay(request, attempt);
        let due = self
            .clock
            .monotonic()
            .saturating_add(delay)
            .saturating_add(scheduler.jitter(delay));
        drop(scheduler);
        let mut retries = self.retries.lock().unwrap_or_else(|e| e.into_inner());
        if retries.len() >= self.queue_capacity {
            return false;
        }
        retries.push_back(RetryItem {
            due,
            request: request.clone(),
            attempt: attempt.saturating_add(1),
        });
        drop(lifecycle);
        true
    }
    pub async fn run(self: Arc<Self>) {
        while !self.stopped.load(Ordering::Acquire) {
            // This dispatch consumes the wake that made work visible. Clear its retained
            // permit so a full denied queue cannot immediately rescan without a new event.
            while self.notify.notified().now_or_never().is_some() {}
            self.dispatch_ready().await;
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let deadline = self.next_deadline();
            let delay = deadline.map(|deadline| deadline.saturating_sub(self.clock.monotonic()));
            tokio::select! {
                biased;
                _ = self.results.closed() => {
                    self.stop_and_drain().await;
                    return;
                }
                _ = self.notify.notified() => {}
                _ = wait_for_result_capacity(
                    &self.results,
                    self.result_blocked.load(Ordering::Acquire),
                ) => {}
                _ = wait_for_deadline(delay) => {}
            }
        }
    }
    pub fn start(self: &Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(self.clone().run())
    }

    fn next_deadline(&self) -> Option<Duration> {
        let eligibility = *self
            .next_eligibility
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let retry = self
            .retries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|item| item.due)
            .min();
        match (eligibility, retry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    pub fn scan_count(&self) -> usize {
        self.scan_count.load(Ordering::Relaxed)
    }

    /// Wakes a runner after an injected monotonic clock is advanced externally.
    pub fn notify_clock_advanced(&self) {
        self.notify.notify_one();
    }
    pub async fn stop_and_drain(self: &Arc<Self>) {
        let mut completion = self.drain_complete.subscribe();
        let tasks = {
            let mut lifecycle = self.lifecycle.lock().await;
            match &mut *lifecycle {
                Lifecycle::Running(tasks) => {
                    let tasks = std::mem::take(tasks);
                    *lifecycle = Lifecycle::Draining;
                    self.begin_stop();
                    Some(tasks)
                }
                Lifecycle::Draining => None,
                Lifecycle::Drained => return,
            }
        };

        if let Some(tasks) = tasks {
            let runner = self.clone();
            tokio::spawn(async move {
                for task in tasks {
                    let _ = task.await;
                }
                let mut lifecycle = runner.lifecycle.lock().await;
                *lifecycle = Lifecycle::Drained;
                runner.drain_complete.send_replace(true);
            });
        }

        let _ = completion.wait_for(|drained| *drained).await;
    }

    fn begin_stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stop_signal.send_replace(true);
        self.scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop();
        self.retries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.engine.stop();
        self.notify.notify_waiters();
    }
    pub fn state_sizes(&self) -> (usize, usize, usize) {
        self.scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state_sizes()
    }
}
