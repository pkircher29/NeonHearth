//! Fixture-driven connector boundary for W6 network quarantine appliances.
//! This crate intentionally contains no production HTTP endpoint mapping.

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Capability {
    DisconnectNow,
    DenyWifiAssociation,
    DenyInternet,
    DenyLan,
    PersistentFilter,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub fingerprint: String,
    pub capabilities: Vec<Capability>,
    pub filter_capacity: Option<u32>,
}

impl Profile {
    pub fn advertises(&self, c: Capability) -> bool {
        self.capabilities.contains(&c)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedQuarantine {
    DisconnectNow,
    DenyWifiAssociation,
    DenyInternet,
    DenyLan,
    PersistentFilter,
}

impl RequestedQuarantine {
    fn capability(self) -> Capability {
        match self {
            Self::DisconnectNow => Capability::DisconnectNow,
            Self::DenyWifiAssociation => Capability::DenyWifiAssociation,
            Self::DenyInternet => Capability::DenyInternet,
            Self::DenyLan => Capability::DenyLan,
            Self::PersistentFilter => Capability::PersistentFilter,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceState {
    pub quarantined: bool,
    pub filter_entries: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    Verified,
    Unverified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationReport {
    pub verification: Verification,
    pub capability: Capability,
    pub previous: Option<DeviceState>,
    pub used: u32,
    pub remaining: Option<u32>,
}

#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("transport unavailable")]
    Transport,
    #[error("authentication failed")]
    Authentication,
    #[error("session expired")]
    SessionExpired,
    #[error("unknown device profile")]
    UnknownProfile,
    #[error("capability unavailable")]
    CapabilityUnavailable,
    #[error("persistent filter capacity exhausted")]
    CapacityExhausted,
    #[error("verification failed")]
    VerificationFailed,
}

#[async_trait]
pub trait Transport: Send {
    async fn login(&mut self, username: &str, password: &SecretString) -> Result<(), Error>;
    async fn renew(&mut self) -> Result<(), Error>;
    async fn profile(&mut self) -> Result<Profile, Error>;
    async fn state(&mut self) -> Result<DeviceState, Error>;
    async fn apply(&mut self, capability: Capability) -> Result<(), Error>;
}

pub struct Connector<T> {
    transport: T,
    profile: Option<Profile>,
    logged_in: bool,
}

impl<T> fmt::Debug for Connector<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connector")
            .field("logged_in", &self.logged_in)
            .field("profile", &self.profile)
            .finish()
    }
}

impl<T: Transport> Connector<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            profile: None,
            logged_in: false,
        }
    }
    pub async fn login(
        &mut self,
        username: &str,
        password: SecretString,
    ) -> Result<Profile, Error> {
        self.transport.login(username, &password).await?;
        self.logged_in = true;
        let p = self.transport.profile().await?;
        if p.fingerprint.is_empty() {
            return Err(Error::UnknownProfile);
        }
        self.profile = Some(p.clone());
        Ok(p)
    }
    pub async fn quarantine(
        &mut self,
        request: RequestedQuarantine,
    ) -> Result<MutationReport, Error> {
        let capability = request.capability();
        let profile = self.profile.clone().ok_or(Error::UnknownProfile)?;
        if !profile.advertises(capability) {
            return Err(Error::CapabilityUnavailable);
        }
        let before = self.call_state().await?;
        let used = before.filter_entries;
        let remaining = profile.filter_capacity.map(|c| c.saturating_sub(used));
        if capability == Capability::PersistentFilter && remaining == Some(0) {
            return Err(Error::CapacityExhausted);
        }
        if let Err(Error::SessionExpired) = self.transport.apply(capability).await {
            self.transport.renew().await?;
            self.transport.apply(capability).await?;
        }
        let after = self.call_state().await?;
        let matches = after.quarantined
            || capability == Capability::PersistentFilter
                && after.filter_entries > before.filter_entries;
        if !matches {
            return Err(Error::VerificationFailed);
        }
        Ok(MutationReport {
            verification: Verification::Verified,
            capability,
            previous: Some(before),
            used: after.filter_entries,
            remaining: profile
                .filter_capacity
                .map(|c| c.saturating_sub(after.filter_entries)),
        })
    }
    async fn call_state(&mut self) -> Result<DeviceState, Error> {
        match self.transport.state().await {
            Err(Error::SessionExpired) => {
                self.transport.renew().await?;
                self.transport.state().await
            }
            x => x,
        }
    }
}

#[cfg(test)]
mod tests;
