//! Event bus abstractions for NeonHearth.

use std::{collections::VecDeque, sync::Arc};

use chrono::{DateTime, Utc};
use lattice_domain::{EventEnvelope, EventPayload};
use tokio::sync::{Mutex, broadcast};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resume {
    Events(Vec<EventEnvelope>),
    SnapshotRequired,
}

/// Identifies one run of the bus. Sequence numbers restart at 1 in every run,
/// so a resume position is only meaningful together with its epoch.
fn new_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    // Never 0 so "0" can mean "unknown/legacy" to clients.
    nanos.max(1)
}

struct State {
    next_sequence: u64,
    replay: VecDeque<EventEnvelope>,
}

#[derive(Clone)]
pub struct EventBus {
    epoch: u64,
    replay_capacity: usize,
    state: Arc<Mutex<State>>,
    sender: broadcast::Sender<EventEnvelope>,
}

impl EventBus {
    pub fn new(replay_capacity: usize, subscriber_capacity: usize) -> Self {
        assert!(
            replay_capacity > 0,
            "replay capacity must be greater than zero"
        );
        assert!(
            subscriber_capacity > 0,
            "subscriber capacity must be greater than zero"
        );
        let (sender, _) = broadcast::channel(subscriber_capacity);
        Self {
            epoch: new_epoch(),
            replay_capacity,
            state: Arc::new(Mutex::new(State {
                next_sequence: 1,
                replay: VecDeque::new(),
            })),
            sender,
        }
    }

    pub async fn publish(
        &self,
        occurred_at: DateTime<Utc>,
        payload: EventPayload,
    ) -> EventEnvelope {
        {
            let mut state = self.state.lock().await;
            let following_sequence = state
                .next_sequence
                .checked_add(1)
                .expect("event sequence space exhausted");
            let envelope = EventEnvelope {
                sequence: state.next_sequence,
                occurred_at,
                payload,
            };
            state.next_sequence = following_sequence;
            state.replay.push_back(envelope.clone());
            while state.replay.len() > self.replay_capacity {
                state.replay.pop_front();
            }
            let _ = self.sender.send(envelope.clone());
            envelope
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope> {
        self.sender.subscribe()
    }

    /// The identifier of this bus run. Clients should store it next to the last
    /// sequence they saw and present both to [`Self::resume_after_epoch`].
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Like [`Self::resume_after`] but a position from a different run of the
    /// bus (`epoch` is `Some` and differs) can never resume: sequence numbers
    /// restart at 1 after a restart, so the same number names another event.
    /// `None` keeps the legacy, epoch-less behaviour.
    pub async fn resume_after_epoch(&self, epoch: Option<u64>, sequence: u64) -> Resume {
        if epoch.is_some_and(|epoch| epoch != self.epoch) {
            return Resume::SnapshotRequired;
        }
        self.resume_after(sequence).await
    }

    /// Subscribes and computes the replay in one step: `publish` holds the same
    /// lock while it stores and broadcasts an event, so no event can fall
    /// between the replay and the live receiver (duplicates are still possible
    /// only if the caller reads the receiver before draining the replay; filter
    /// by sequence).
    pub async fn subscribe_and_resume(
        &self,
        epoch: Option<u64>,
        sequence: u64,
    ) -> (broadcast::Receiver<EventEnvelope>, Resume) {
        let state = self.state.lock().await;
        let receiver = self.sender.subscribe();
        let resume = if epoch.is_some_and(|epoch| epoch != self.epoch) {
            Resume::SnapshotRequired
        } else {
            Self::resume_locked(&state, sequence)
        };
        (receiver, resume)
    }
    pub async fn current_sequence(&self) -> u64 {
        self.state.lock().await.next_sequence.saturating_sub(1)
    }

    pub async fn resume_after(&self, sequence: u64) -> Resume {
        let state = self.state.lock().await;
        Self::resume_locked(&state, sequence)
    }

    fn resume_locked(state: &State, sequence: u64) -> Resume {
        let last_sequence = state.next_sequence.saturating_sub(1);
        if sequence == last_sequence {
            return Resume::Events(Vec::new());
        }
        if sequence > last_sequence || state.replay.is_empty() {
            return Resume::SnapshotRequired;
        }
        let oldest = state
            .replay
            .front()
            .expect("replay checked non-empty")
            .sequence;
        if sequence.saturating_add(1) < oldest {
            return Resume::SnapshotRequired;
        }
        Resume::Events(
            state
                .replay
                .iter()
                .filter(|event| event.sequence > sequence)
                .cloned()
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_domain::{EventPayload, ServiceStatus};

    #[tokio::test]
    #[should_panic(expected = "event sequence space exhausted")]
    async fn publish_rejects_sequence_exhaustion() {
        let bus = EventBus::new(1, 1);
        bus.state.lock().await.next_sequence = u64::MAX;
        bus.publish(
            Utc::now(),
            EventPayload::ServiceStatus(ServiceStatus {
                state: "ready".to_owned(),
                detail: "test".to_owned(),
            }),
        )
        .await;
    }
}
