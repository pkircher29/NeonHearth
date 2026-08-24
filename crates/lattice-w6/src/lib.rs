//! Fixture-driven connector boundary for W6 network quarantine appliances.
//! This crate intentionally contains no production HTTP endpoint mapping.

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Maximum number of persistent filter entries supported by the W6 contract.
pub const W6_PERSISTENT_FILTER_LIMIT: u32 = 32;

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

/// Safe result of profile discovery. Mutation is permitted only for `Trusted` profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DiscoveryStatus {
    Trusted,
    ReadOnly,
    ManualRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    pub disconnect_now: bool,
    pub deny_wifi_association: bool,
    pub deny_internet: bool,
    pub deny_lan: bool,
    pub persistent_filter: bool,
    pub filter_entries: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Verification {
    Verified,
    Unverified,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MutationReport {
    pub verification: Verification,
    pub capability: Capability,
    pub previous: Option<DeviceState>,
    pub used: u32,
    pub remaining: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilterCapacity {
    pub used: u32,
    pub remaining: u32,
    pub limit: u32,
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
    #[error("persistent filter capacity is invalid")]
    InvalidCapacity,
    #[error("verification failed")]
    VerificationFailed,
    #[error("profile requires manual confirmation")]
    ManualRequired,
    #[error("profile is read-only")]
    ReadOnly,
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
    known_profiles: Vec<Profile>,
    status: DiscoveryStatus,
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
        // The fixture transport's documented profile. Production integrations must
        // construct this allowlist from owner configuration; no HTTP assumptions live here.
        let known = Profile {
            fingerprint: "fw-1".into(),
            capabilities: vec![
                Capability::DisconnectNow,
                Capability::DenyWifiAssociation,
                Capability::DenyInternet,
                Capability::DenyLan,
                Capability::PersistentFilter,
            ],
            filter_capacity: Some(W6_PERSISTENT_FILTER_LIMIT),
        };
        Self::with_profiles(transport, vec![known])
    }
    pub fn with_profiles(transport: T, known_profiles: Vec<Profile>) -> Self {
        Self {
            transport,
            profile: None,
            logged_in: false,
            known_profiles,
            status: DiscoveryStatus::ManualRequired,
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
            self.status = DiscoveryStatus::ManualRequired;
            return Err(Error::ManualRequired);
        }
        let Some(known) = self
            .known_profiles
            .iter()
            .find(|k| k.fingerprint == p.fingerprint)
        else {
            self.status = DiscoveryStatus::ManualRequired;
            return Err(Error::ManualRequired);
        };
        if (!known.capabilities.is_empty() && known.capabilities != p.capabilities)
            || known.filter_capacity.is_some() && known.filter_capacity != p.filter_capacity
        {
            self.status = DiscoveryStatus::ReadOnly;
            return Err(Error::ReadOnly);
        }
        self.status = DiscoveryStatus::Trusted;
        self.profile = Some(p.clone());
        Ok(p)
    }
    #[must_use]
    pub fn discovery_status(&self) -> DiscoveryStatus {
        self.status
    }
    /// Read the owner-visible filter budget before attempting a mutation.
    pub async fn persistent_filter_capacity(&mut self) -> Result<FilterCapacity, Error> {
        let profile = self.profile.as_ref().ok_or(Error::UnknownProfile)?;
        let limit = profile.filter_capacity.ok_or(Error::InvalidCapacity)?;
        if limit == 0 || limit > W6_PERSISTENT_FILTER_LIMIT {
            return Err(Error::InvalidCapacity);
        }
        let mut renewed = false;
        let state = self.call_state(&mut renewed).await?;
        Ok(FilterCapacity {
            used: state.filter_entries,
            remaining: limit.saturating_sub(state.filter_entries),
            limit,
        })
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
        let mut renewed = false;
        let before = self.call_state(&mut renewed).await?;
        let used = before.filter_entries;
        if capability == Capability::PersistentFilter {
            let Some(capacity) = profile.filter_capacity else {
                return Err(Error::InvalidCapacity);
            };
            if capacity == 0 || capacity > W6_PERSISTENT_FILTER_LIMIT {
                return Err(Error::InvalidCapacity);
            }
            if used >= capacity {
                return Err(Error::CapacityExhausted);
            }
        }
        self.apply_with_budget(capability, &mut renewed).await?;
        let after = self.call_state(&mut renewed).await?;
        let matches = after.enabled(capability);
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
    async fn call_state(&mut self, renewed: &mut bool) -> Result<DeviceState, Error> {
        match self.transport.state().await {
            Err(Error::SessionExpired) => {
                if *renewed {
                    return Err(Error::SessionExpired);
                }
                self.transport.renew().await?;
                *renewed = true;
                self.transport.state().await
            }
            x => x,
        }
    }
    async fn apply_with_budget(
        &mut self,
        capability: Capability,
        renewed: &mut bool,
    ) -> Result<(), Error> {
        match self.transport.apply(capability).await {
            Err(Error::SessionExpired) => {
                if *renewed {
                    return Err(Error::SessionExpired);
                }
                self.transport.renew().await?;
                *renewed = true;
                self.transport.apply(capability).await
            }
            x => x,
        }
    }
    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl DeviceState {
    fn enabled(&self, capability: Capability) -> bool {
        match capability {
            Capability::DisconnectNow => self.disconnect_now,
            Capability::DenyWifiAssociation => self.deny_wifi_association,
            Capability::DenyInternet => self.deny_internet,
            Capability::DenyLan => self.deny_lan,
            Capability::PersistentFilter => self.persistent_filter,
        }
    }
}

#[cfg(test)]
mod tests;
