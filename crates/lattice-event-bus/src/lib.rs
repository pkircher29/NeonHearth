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

struct State {
    next_sequence: u64,
    replay: VecDeque<EventEnvelope>,
}

#[derive(Clone)]
pub struct EventBus {
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

    pub async fn resume_after(&self, sequence: u64) -> Resume {
        let state = self.state.lock().await;
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
