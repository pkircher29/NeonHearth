use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use lattice_domain::EventEnvelope;
use lattice_event_bus::{EventBus, Resume};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ServerMessage {
    Event(EventEnvelope),
    ResyncRequired,
}

pub async fn resume_messages(bus: &EventBus, sequence: u64) -> Vec<ServerMessage> {
    match bus.resume_after(sequence).await {
        Resume::Events(events) => events.into_iter().map(ServerMessage::Event).collect(),
        Resume::SnapshotRequired => vec![ServerMessage::ResyncRequired],
    }
}

async fn send_message(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    message: ServerMessage,
) -> Result<(), axum::Error> {
    let encoded = serde_json::to_string(&message).expect("server messages serialize");
    sink.send(Message::Text(encoded.into())).await
}

pub(crate) async fn serve_socket(socket: WebSocket, bus: EventBus, after_sequence: u64) {
    // Subscribe before reading replay so publish cannot be lost between the two operations.
    let mut receiver = bus.subscribe();
    let messages = resume_messages(&bus, after_sequence).await;
    let (mut sink, mut stream) = socket.split();
    let mut last_sent_sequence = after_sequence;

    for message in messages {
        match message {
            ServerMessage::ResyncRequired => {
                let _ = send_message(&mut sink, ServerMessage::ResyncRequired).await;
                return;
            }
            ServerMessage::Event(event) => {
                last_sent_sequence = event.sequence;
                if send_message(&mut sink, ServerMessage::Event(event))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }

    loop {
        tokio::select! {
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => return,
            },
            event = receiver.recv() => match event {
                Ok(event) if event.sequence <= last_sent_sequence => {},
                Ok(event) if event.sequence != last_sent_sequence.saturating_add(1) => {
                    let _ = send_message(&mut sink, ServerMessage::ResyncRequired).await;
                    return;
                }
                Ok(event) => {
                    last_sent_sequence = event.sequence;
                    if send_message(&mut sink, ServerMessage::Event(event)).await.is_err() {
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let _ = send_message(&mut sink, ServerMessage::ResyncRequired).await;
                    return;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lattice_domain::{EventPayload, ServiceStatus};
    use lattice_event_bus::EventBus;

    fn payload() -> EventPayload {
        EventPayload::ServiceStatus(ServiceStatus {
            state: "ready".to_owned(),
            detail: "test".to_owned(),
        })
    }

    #[tokio::test]
    async fn resume_requires_resync_when_replay_has_a_gap() {
        let bus = EventBus::new(1, 8);
        bus.publish(Utc::now(), payload()).await;
        bus.publish(Utc::now(), payload()).await;

        assert_eq!(
            resume_messages(&bus, 0).await,
            vec![ServerMessage::ResyncRequired]
        );
    }

    #[tokio::test]
    async fn resume_returns_events_in_sequence_order() {
        let bus = EventBus::new(8, 8);
        bus.publish(Utc::now(), payload()).await;
        bus.publish(Utc::now(), payload()).await;
        bus.publish(Utc::now(), payload()).await;

        let messages = resume_messages(&bus, 1).await;
        assert!(
            matches!(messages.as_slice(), [ServerMessage::Event(first), ServerMessage::Event(second)] if first.sequence == 2 && second.sequence == 3)
        );
        assert!(resume_messages(&bus, 3).await.is_empty());
    }

    #[test]
    fn resync_message_has_a_stable_wire_format() {
        assert_eq!(
            serde_json::to_value(ServerMessage::ResyncRequired).unwrap(),
            serde_json::json!({"type": "resync_required"})
        );
    }
}
