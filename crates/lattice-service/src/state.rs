use lattice_event_bus::EventBus;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
#[derive(Clone)]
pub struct AppState {
    token: SecretString,
    events: EventBus,
}
impl AppState {
    pub fn new(token: impl Into<SecretString>) -> Self {
        Self {
            token: token.into(),
            events: EventBus::new(4096, 1024),
        }
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
}
