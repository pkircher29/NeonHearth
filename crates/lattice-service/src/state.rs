use lattice_event_bus::EventBus;
use lattice_store::M2StateRepository;
use secrecy::{ExposeSecret, SecretString};
use std::{collections::HashMap, fmt, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::{
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) const EVENT_TICKET_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_OUTSTANDING_EVENT_TICKETS: usize = 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TicketLimitReached;
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
    state_repository: M2StateRepository,
    event_tickets: Arc<Mutex<HashMap<String, Instant>>>,
}
impl AppState {
    pub fn new(
        token: impl Into<String>,
        state_repository: M2StateRepository,
    ) -> Result<Self, InvalidServiceToken> {
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
            state_repository,
            event_tickets: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub fn events(&self) -> &EventBus {
        &self.events
    }
    pub(crate) fn state_repository(&self) -> &M2StateRepository {
        &self.state_repository
    }
    pub(crate) fn token_matches(&self, supplied: &str) -> bool {
        supplied
            .as_bytes()
            .ct_eq(self.token.expose_secret().as_bytes())
            .into()
    }

    pub(crate) async fn issue_event_ticket(
        &self,
        now: Instant,
    ) -> Result<String, TicketLimitReached> {
        let mut tickets = self.event_tickets.lock().await;
        tickets.retain(|_, expires_at| *expires_at >= now);
        if tickets.len() >= MAX_OUTSTANDING_EVENT_TICKETS {
            return Err(TicketLimitReached);
        }
        let ticket = Uuid::new_v4().to_string();
        tickets.insert(ticket.clone(), now + EVENT_TICKET_TTL);
        Ok(ticket)
    }

    pub(crate) async fn consume_event_ticket(&self, ticket: &str, now: Instant) -> bool {
        let mut tickets = self.event_tickets.lock().await;
        tickets.retain(|_, expires_at| *expires_at >= now);
        tickets.remove(ticket).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_store::{M2StateRepository, connect_memory};
    use tokio::time::{Duration, Instant};

    const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

    #[tokio::test]
    async fn event_ticket_is_bounded_one_time_and_expires() {
        let state = AppState::new(
            TOKEN,
            M2StateRepository::new(connect_memory().await.unwrap()),
        )
        .expect("valid token");
        let now = Instant::now();
        let tickets: Vec<_> = (0..MAX_OUTSTANDING_EVENT_TICKETS)
            .map(|_| state.issue_event_ticket(now))
            .collect::<Vec<_>>();
        let tickets = futures_util::future::join_all(tickets).await;
        assert!(tickets.iter().all(Result::is_ok));
        let ticket = tickets[0].as_ref().unwrap().clone();
        assert_eq!(
            tickets
                .iter()
                .map(|ticket| ticket.as_ref().unwrap())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            MAX_OUTSTANDING_EVENT_TICKETS
        );
        assert!(state.issue_event_ticket(now).await.is_err());

        assert!(!ticket.contains(TOKEN));
        assert!(state.consume_event_ticket(&ticket, now).await);
        assert!(!state.consume_event_ticket(&ticket, now).await);

        let expired = state
            .issue_event_ticket(now + Duration::from_secs(31))
            .await
            .unwrap();
        assert_eq!(state.event_tickets.lock().await.len(), 1);
        assert!(
            !state
                .consume_event_ticket(&expired, now + Duration::from_secs(62))
                .await
        );
        assert!(!state.consume_event_ticket("unknown", now).await);
    }
}
