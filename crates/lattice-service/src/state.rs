use lattice_event_bus::EventBus;
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use subtle::ConstantTimeEq;
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
}
