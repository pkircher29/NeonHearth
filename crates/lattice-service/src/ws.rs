use crate::{auth::Principal, state::SocketLimits};
use axum::extract::ws::{CloseFrame, Message, WebSocket, close_code};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use lattice_domain::EventEnvelope;
use lattice_event_bus::{EventBus, Resume};
use lattice_store::RemoteAccessRepository;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::{
    sync::{OwnedSemaphorePermit, broadcast},
    time::{Instant, MissedTickBehavior, interval, sleep_until, timeout},
};
use uuid::Uuid;

/// Largest frame or message a client may send. Clients never legitimately
/// send data (anything but control frames is refused), so this is tiny; it
/// stops a peer buffering megabytes before the first frame is even seen.
pub(crate) const MAX_CLIENT_MESSAGE_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ServerMessage {
    Event(EventEnvelope),
    ResyncRequired,
}

pub async fn resume_messages(bus: &EventBus, sequence: u64) -> Vec<ServerMessage> {
    resume_to_messages(bus.resume_after(sequence).await)
}

/// Like [`resume_messages`] for a client that remembers which bus run its
/// sequence belongs to: a position from another run (the service restarted)
/// answers with a resync instead of replaying unrelated events.
pub async fn resume_messages_with_epoch(
    bus: &EventBus,
    epoch: Option<u64>,
    sequence: u64,
) -> Vec<ServerMessage> {
    resume_to_messages(bus.resume_after_epoch(epoch, sequence).await)
}

fn resume_to_messages(resume: Resume) -> Vec<ServerMessage> {
    match resume {
        Resume::Events(events) => events.into_iter().map(ServerMessage::Event).collect(),
        Resume::SnapshotRequired => vec![ServerMessage::ResyncRequired],
    }
}

/// Everything an event socket needs to stay bound to the principal that
/// redeemed its ticket.
pub(crate) struct SocketGuard {
    pub principal: Principal,
    pub pool: SqlitePool,
    pub revocations: broadcast::Receiver<Uuid>,
    pub limits: SocketLimits,
    /// Held for the socket's lifetime; releases the connection cap on drop.
    pub permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
enum SendMessageError {
    Serialization(serde_json::Error),
    Transport(axum::Error),
    TimedOut,
}

impl std::fmt::Display for SendMessageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(error) => {
                write!(formatter, "message serialization failed: {error}")
            }
            Self::Transport(error) => write!(formatter, "message transport failed: {error}"),
            Self::TimedOut => formatter.write_str("message send timed out"),
        }
    }
}

impl std::error::Error for SendMessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::TimedOut => None,
        }
    }
}

type Sink = futures_util::stream::SplitSink<WebSocket, Message>;

/// Writes one frame, giving up when the peer stops reading: a stalled client
/// must not pin a task (and its subscription) forever.
async fn send_frame(
    sink: &mut Sink,
    message: Message,
    limit: std::time::Duration,
) -> Result<(), SendMessageError> {
    match timeout(limit, sink.send(message)).await {
        Ok(result) => result.map_err(SendMessageError::Transport),
        Err(_) => Err(SendMessageError::TimedOut),
    }
}

async fn send_message(
    sink: &mut Sink,
    message: ServerMessage,
    limit: std::time::Duration,
) -> Result<(), SendMessageError> {
    let encoded = serde_json::to_string(&message).map_err(SendMessageError::Serialization)?;
    send_frame(sink, Message::Text(encoded.into()), limit).await
}

async fn send_close(sink: &mut Sink, code: u16, reason: &'static str, limit: std::time::Duration) {
    let _ = send_frame(
        sink,
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
        limit,
    )
    .await;
}

async fn handle_send_error(sink: &mut Sink, error: SendMessageError, limit: std::time::Duration) {
    if matches!(error, SendMessageError::Serialization(_)) {
        send_close(sink, close_code::ERROR, "internal server error", limit).await;
    }
}

async fn send_resync_and_close(sink: &mut Sink, limit: std::time::Duration) {
    match send_message(sink, ServerMessage::ResyncRequired, limit).await {
        Ok(()) => {
            let _ = send_frame(sink, Message::Close(None), limit).await;
        }
        Err(error) => handle_send_error(sink, error, limit).await,
    }
}

/// Whether a phone session may still stream. Storage trouble keeps the socket
/// (fail open for availability is wrong for revocation, but a transient read
/// error must not drop every phone; the next recheck retries, and the
/// broadcast path closes immediately on an explicit revoke).
async fn session_still_valid(pool: &SqlitePool, session: Uuid) -> bool {
    match RemoteAccessRepository::new(pool.clone())
        .load_phone_session(session)
        .await
    {
        Ok(Some(row)) => !row.revoked && Utc::now() < row.expires_at,
        Ok(None) => false,
        Err(error) => {
            tracing::warn!(%error, "phone session recheck failed; keeping socket until next check");
            true
        }
    }
}

pub(crate) async fn serve_socket(
    socket: WebSocket,
    bus: EventBus,
    after_sequence: u64,
    epoch: Option<u64>,
    guard: SocketGuard,
) {
    let SocketGuard {
        principal,
        pool,
        mut revocations,
        limits,
        permit: _permit,
    } = guard;
    let send_limit = limits.send_timeout;
    // Subscribing and computing the replay under the bus lock means no publish can fall
    // between the two; a position from an earlier run of the bus gets a resync.
    let (mut receiver, resume) = bus.subscribe_and_resume(epoch, after_sequence).await;
    let messages = resume_to_messages(resume);
    let (mut sink, mut stream) = socket.split();
    let mut last_sent_sequence = after_sequence;

    for message in messages {
        match message {
            ServerMessage::ResyncRequired => {
                send_resync_and_close(&mut sink, send_limit).await;
                return;
            }
            ServerMessage::Event(event) => {
                last_sent_sequence = event.sequence;
                if let Err(error) =
                    send_message(&mut sink, ServerMessage::Event(event), send_limit).await
                {
                    handle_send_error(&mut sink, error, send_limit).await;
                    return;
                }
            }
        }
    }

    let phone = principal.session_id();
    let mut last_seen = Instant::now();
    let mut ping = interval(limits.ping_interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ping.tick().await;
    let mut recheck = interval(limits.session_recheck);
    recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
    recheck.tick().await;
    let lifetime = sleep_until(Instant::now() + limits.max_lifetime);
    tokio::pin!(lifetime);

    loop {
        tokio::select! {
            incoming = stream.next() => {
                last_seen = Instant::now();
                match incoming {
                    Some(Ok(Message::Ping(payload))) => {
                        if send_frame(&mut sink, Message::Pong(payload), send_limit).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {},
                    Some(Ok(Message::Close(_))) => {
                        let _ = send_frame(&mut sink, Message::Close(None), send_limit).await;
                        return;
                    }
                    Some(Ok(Message::Text(_))) | Some(Ok(Message::Binary(_))) => {
                        send_close(&mut sink, close_code::UNSUPPORTED, "unsolicited client data", send_limit).await;
                        return;
                    }
                    None | Some(Err(_)) => return,
                }
            },
            event = receiver.recv() => match event {
                Ok(event) if event.sequence <= last_sent_sequence => {},
                Ok(event) if event.sequence != last_sent_sequence.saturating_add(1) => {
                    send_resync_and_close(&mut sink, send_limit).await;
                    return;
                }
                Ok(event) => {
                    last_sent_sequence = event.sequence;
                    if let Err(error) = send_message(&mut sink, ServerMessage::Event(event), send_limit).await {
                        handle_send_error(&mut sink, error, send_limit).await;
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    send_resync_and_close(&mut sink, send_limit).await;
                    return;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },
            _ = ping.tick() => {
                if last_seen.elapsed() >= limits.idle_timeout {
                    send_close(&mut sink, close_code::AWAY, "idle timeout", send_limit).await;
                    return;
                }
                if send_frame(&mut sink, Message::Ping(Vec::<u8>::new().into()), send_limit).await.is_err() {
                    return;
                }
            },
            () = &mut lifetime => {
                // Clients reconnect and resume by sequence.
                send_close(&mut sink, close_code::AWAY, "lifetime reached; reconnect", send_limit).await;
                return;
            },
            _ = recheck.tick(), if phone.is_some() => {
                if let Some(session) = phone
                    && !session_still_valid(&pool, session).await
                {
                    send_close(&mut sink, close_code::POLICY, "session no longer valid", send_limit).await;
                    return;
                }
            },
            revoked = revocations.recv(), if phone.is_some() => match revoked {
                Ok(id) if Some(id) == phone => {
                    send_close(&mut sink, close_code::POLICY, "session revoked", send_limit).await;
                    return;
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Missed announcements: validate against storage now.
                    if let Some(session) = phone
                        && !session_still_valid(&pool, session).await
                    {
                        send_close(&mut sink, close_code::POLICY, "session no longer valid", send_limit).await;
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
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

    #[tokio::test]
    async fn a_position_from_an_earlier_bus_run_requires_resync() {
        let restarted = EventBus::new(8, 8);
        // Any value other than the running bus's epoch stands for an earlier run.
        let stale = Some(restarted.epoch().wrapping_add(1));
        restarted.publish(Utc::now(), payload()).await;
        restarted.publish(Utc::now(), payload()).await;

        assert_eq!(
            resume_messages_with_epoch(&restarted, stale, 1).await,
            vec![ServerMessage::ResyncRequired]
        );
        let same_run = resume_messages_with_epoch(&restarted, Some(restarted.epoch()), 1).await;
        assert!(matches!(same_run.as_slice(), [ServerMessage::Event(e)] if e.sequence == 2));
        // Clients that do not send an epoch keep the legacy behaviour.
        assert_eq!(
            resume_messages_with_epoch(&restarted, None, 2).await.len(),
            0
        );
    }

    #[test]
    fn resync_message_has_a_stable_wire_format() {
        assert_eq!(
            serde_json::to_value(ServerMessage::ResyncRequired).unwrap(),
            serde_json::json!({"type": "resync_required"})
        );
    }
}
