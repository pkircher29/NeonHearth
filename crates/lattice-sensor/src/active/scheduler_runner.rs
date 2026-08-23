use std::{
    collections::{HashMap, HashSet, VecDeque},
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures_util::FutureExt;
use tokio::{
    sync::{Notify, mpsc},
    task::JoinHandle,
};

use super::{
    ActiveEngine, ActiveError, AttemptTransport, Clock, ProbeCatalog, ProbeCredential,
    ProbeOutcome, ProbeRequest, Scheduler, SchedulerConfig, WorkKey,
};

pub trait ExecutionCredentialSource: Send + Sync {
    fn credential_for(&self, request: &ProbeRequest) -> Option<ProbeCredential>;
}
struct NoCredentials;
impl ExecutionCredentialSource for NoCredentials {
    fn credential_for(&self, _: &ProbeRequest) -> Option<ProbeCredential> {
        None
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

pub struct SchedulerRunner<C: Clock, T: AttemptTransport> {
    scheduler: Arc<Mutex<Scheduler<C>>>,
    engine: Arc<ActiveEngine<T>>,
    credentials: Arc<dyn ExecutionCredentialSource>,
    catalog: ProbeCatalog,
    clock: Arc<C>,
    retries: Mutex<VecDeque<RetryItem>>,
    attempts: Mutex<HashMap<WorkKey, u8>>,
    pending: Mutex<HashSet<WorkKey>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    results: mpsc::Sender<RunnerEvent>,
    notify: Notify,
    stopped: AtomicBool,
    queue_capacity: usize,
    max_retry_attempts: u8,
}

impl<C, T> SchedulerRunner<C, T>
where
    C: Clock + 'static,
    T: AttemptTransport + 'static,
{
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
        let scheduler = Scheduler::new(config, clock.clone())?;
        let (results, receiver) = mpsc::channel(result_capacity);
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
                tasks: Mutex::new(Vec::new()),
                results,
                notify: Notify::new(),
                stopped: AtomicBool::new(false),
                queue_capacity,
                max_retry_attempts,
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
        let inserted = self
            .scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enqueue(request);
        let inserted = match inserted {
            Ok(inserted) => inserted,
            Err(error) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
                return Err(error);
            }
        };
        if inserted {
            self.notify.notify_one();
        }
        Ok(inserted)
    }

    fn promote_due_retries(&self) {
        let now = self.clock.monotonic();
        let mut retries = self.retries.lock().unwrap_or_else(|e| e.into_inner());
        let mut scheduler = self.scheduler.lock().unwrap_or_else(|e| e.into_inner());
        let mut remaining = VecDeque::new();
        while let Some(item) = retries.pop_front() {
            if item.due <= now {
                if scheduler.enqueue(item.request.clone()).is_ok() {
                    self.attempts
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(WorkKey::from(&item.request), item.attempt);
                } else {
                    remaining.push_back(item);
                }
            } else {
                remaining.push_back(item);
            }
        }
        *retries = remaining;
    }

    pub async fn dispatch_ready(self: &Arc<Self>) -> usize {
        if self.stopped.load(Ordering::Acquire) {
            return 0;
        }
        self.promote_due_retries();
        self.tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|task| !task.is_finished());
        let mut dispatched = 0;
        let mut remaining = self
            .scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue_len();
        while remaining > 0 {
            remaining -= 1;
            let Some(request) = self
                .scheduler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .next_request()
            else {
                break;
            };
            let Some(descriptor) = self.catalog.resolve(&request.probe_id) else {
                continue;
            };
            let attempt = self
                .attempts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&WorkKey::from(&request))
                .unwrap_or(0);
            let started = self
                .scheduler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .try_start_cost(&request, descriptor.rate_cost);
            if !started {
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
                break;
            }
            dispatched += 1;
            let runner = self.clone();
            let task_request = request.clone();
            let task = tokio::spawn(async move {
                let reservation = Reservation {
                    scheduler: runner.scheduler.clone(),
                    request: task_request.clone(),
                };
                let credential = runner.credentials.credential_for(&task_request);
                let execution = AssertUnwindSafe(
                    runner
                        .engine
                        .execute(task_request.clone(), credential.as_ref()),
                )
                .catch_unwind()
                .await;
                drop(reservation);
                let result = match execution {
                    Ok(result) => result,
                    Err(_) => Err(ActiveError::Internal),
                };
                let transient = matches!(
                    result,
                    Ok(ProbeOutcome::Timeout { .. }) | Err(ActiveError::Network)
                );
                let mut will_retry = false;
                if transient
                    && attempt < runner.max_retry_attempts
                    && !runner.stopped.load(Ordering::Acquire)
                {
                    let mut scheduler = runner.scheduler.lock().unwrap_or_else(|e| e.into_inner());
                    let delay = scheduler.retry_delay(&task_request, attempt);
                    let due = runner
                        .clock
                        .monotonic()
                        .saturating_add(delay)
                        .saturating_add(scheduler.jitter(delay));
                    drop(scheduler);
                    let mut retries = runner.retries.lock().unwrap_or_else(|e| e.into_inner());
                    if retries.len() < runner.queue_capacity {
                        retries.push_back(RetryItem {
                            due,
                            request: task_request.clone(),
                            attempt: attempt.saturating_add(1),
                        });
                        will_retry = true;
                    }
                }
                if !will_retry && !matches!(result, Err(ActiveError::Cancelled)) {
                    runner
                        .scheduler
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_success(&task_request);
                }
                if !will_retry {
                    runner
                        .pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&WorkKey::from(&task_request));
                }
                let _ = runner
                    .results
                    .send(RunnerEvent {
                        request: task_request,
                        attempt,
                        result,
                        will_retry,
                    })
                    .await;
                runner.notify.notify_one();
            });
            self.tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(task);
        }
        dispatched
    }

    pub async fn run(self: Arc<Self>) {
        while !self.stopped.load(Ordering::Acquire) {
            self.dispatch_ready().await;
            tokio::select! {
                () = self.notify.notified() => {},
                () = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }

    pub async fn stop_and_drain(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
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
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|e| e.into_inner()));
        for task in tasks {
            let _ = task.await;
        }
    }

    pub fn state_sizes(&self) -> (usize, usize, usize) {
        self.scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state_sizes()
    }
}
