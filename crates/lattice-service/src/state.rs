use lattice_event_bus::EventBus;
use secrecy::{ExposeSecret, SecretString};
use std::{collections::HashMap, fmt, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) const EVENT_TICKET_TTL: Duration = Duration::from_secs(30);
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InvalidServiceToken;
impl fmt::Display for InvalidServiceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid service token configuration")
    }
}
impl std::error::Error for InvalidServiceToken {}
#[derive(Clone)]
pub struct AppState {
    token: SecretString,
    events: EventBus,
    event_tickets: Arc<Mutex<HashMap<String, Instant>>>,
}
impl AppState {
    pub fn new(token: impl Into<String>) -> Result<Self, InvalidServiceToken> {
        let token = token.into();
        if token.len() < 32
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(InvalidServiceToken);
        }
        Ok(Self {
            token: SecretString::from(token),
            events: EventBus::new(4096, 1024),
            event_tickets: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub fn events(&self) -> &EventBus {
        &self.events
    }
    pub(crate) fn token_matches(&self, supplied: &str) -> bool {
        supplied
            .as_bytes()
            .ct_eq(self.token.expose_secret().as_bytes())
            .into()
    }

    pub(crate) async fn issue_event_ticket(&self, now: Instant) -> String {
        let mut tickets = self.event_tickets.lock().await;
        tickets.retain(|_, expires_at| *expires_at >= now);
        let ticket = Uuid::new_v4().to_string();
        tickets.insert(ticket.clone(), now + EVENT_TICKET_TTL);
        ticket
    }

    pub(crate) async fn consume_event_ticket(&self, ticket: &str, now: Instant) -> bool {
        self.event_tickets
            .lock()
            .await
            .remove(ticket)
            .is_some_and(|expires_at| expires_at >= now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, Instant};

    const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

    #[tokio::test]
    async fn event_ticket_is_one_time_and_expires() {
        let state = AppState::new(TOKEN).expect("valid token");
        let now = Instant::now();
        let ticket = state.issue_event_ticket(now).await;

        assert!(!ticket.contains(TOKEN));
        assert!(state.consume_event_ticket(&ticket, now).await);
        assert!(!state.consume_event_ticket(&ticket, now).await);

        let expired = state.issue_event_ticket(now).await;
        assert!(
            !state
                .consume_event_ticket(&expired, now + Duration::from_secs(31))
                .await
        );
        assert!(!state.consume_event_ticket("unknown", now).await);
    }
}
