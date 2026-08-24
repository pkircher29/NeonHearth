//! Fixture-driven connector boundary for W6 network quarantine appliances.
//! This crate intentionally contains no production HTTP endpoint mapping.

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Maximum number of persistent filter entries supported by the W6 contract.
pub const W6_PERSISTENT_FILTER_LIMIT: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMutation {
    pub capability: Capability,
    pub previous: DeviceState,
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
    /// Restore a previously observed fixture state. Production adapters must
    /// implement this only from documented vendor support; the default refuses
    /// to invent an undo endpoint.
    async fn restore(&mut self, _previous: DeviceState) -> Result<(), Error> {
        Err(Error::ManualRequired)
    }
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
    pub async fn prepare_quarantine(
        &mut self,
        request: RequestedQuarantine,
    ) -> Result<PreparedMutation, Error> {
        self.require_trusted()?;
        let capability = request.capability();
        let profile = self.profile.clone().ok_or(Error::UnknownProfile)?;
        if !profile.advertises(capability) {
            return Err(Error::CapabilityUnavailable);
        }
        let mut renewed = false;
        let previous = self.call_state(&mut renewed).await?;
        if capability == Capability::PersistentFilter {
            let capacity = profile.filter_capacity.ok_or(Error::InvalidCapacity)?;
            if capacity == 0 || capacity > W6_PERSISTENT_FILTER_LIMIT {
                return Err(Error::InvalidCapacity);
            }
            if previous.filter_entries >= capacity {
                return Err(Error::CapacityExhausted);
            }
        }
        Ok(PreparedMutation {
            capability,
            previous,
        })
    }

    pub async fn apply_prepared(
        &mut self,
        prepared: PreparedMutation,
    ) -> Result<MutationReport, Error> {
        self.require_trusted()?;
        let profile = self.profile.clone().ok_or(Error::UnknownProfile)?;
        let mut renewed = false;
        let current = self.call_state(&mut renewed).await?;
        if current != prepared.previous {
            return Err(Error::VerificationFailed);
        }
        self.apply_with_budget(prepared.capability, &mut renewed)
            .await?;
        let after = self.call_state(&mut renewed).await?;
        let matches = if prepared.capability == Capability::PersistentFilter {
            after.persistent_filter
                && prepared.previous.filter_entries.checked_add(1) == Some(after.filter_entries)
                && profile
                    .filter_capacity
                    .is_some_and(|capacity| after.filter_entries <= capacity)
                && after.filter_entries <= W6_PERSISTENT_FILTER_LIMIT
        } else {
            after.enabled(prepared.capability)
        };
        if !matches {
            return Err(Error::VerificationFailed);
        }
        Ok(MutationReport {
            verification: Verification::Verified,
            capability: prepared.capability,
            previous: Some(prepared.previous),
            used: after.filter_entries,
            remaining: profile
                .filter_capacity
                .map(|c| c.saturating_sub(after.filter_entries)),
        })
    }
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
        // A fresh login invalidates every fact learned from the prior session.
        self.profile = None;
        self.logged_in = false;
        self.status = DiscoveryStatus::ManualRequired;
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
        if !same_capability_set(&known.capabilities, &p.capabilities)
            || known.filter_capacity != p.filter_capacity
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
    /// Trusted, read-only appliance state used to reconcile an interrupted
    /// policy mutation.  Callers cannot infer this from an apply response.
    pub async fn read_state(&mut self) -> Result<DeviceState, Error> {
        self.require_trusted()?;
        let mut renewed = false;
        self.call_state(&mut renewed).await
    }
    pub async fn quarantine(
        &mut self,
        request: RequestedQuarantine,
    ) -> Result<MutationReport, Error> {
        self.require_trusted()?;
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
        let matches = if capability == Capability::PersistentFilter {
            after.persistent_filter
                && before.filter_entries.checked_add(1) == Some(after.filter_entries)
                && profile
                    .filter_capacity
                    .is_some_and(|capacity| after.filter_entries <= capacity)
                && after.filter_entries <= W6_PERSISTENT_FILTER_LIMIT
        } else {
            after.enabled(capability)
        };
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
    /// Restore an exact state captured by a verified mutation and verify the
    /// appliance reported it back. This is intentionally an injected transport
    /// capability, not a guessed HTTP reversal.
    pub async fn restore(&mut self, previous: DeviceState) -> Result<Verification, Error> {
        self.require_trusted()?;
        let mut renewed = false;
        match self.transport.restore(previous.clone()).await {
            Ok(()) => {}
            Err(Error::SessionExpired) => {
                self.transport.renew().await?;
                renewed = true;
                self.transport.restore(previous.clone()).await?;
            }
            Err(error) => return Err(error),
        }
        let after = self.call_state(&mut renewed).await?;
        if after == previous {
            Ok(Verification::Verified)
        } else {
            Err(Error::VerificationFailed)
        }
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
    fn require_trusted(&self) -> Result<(), Error> {
        match self.status {
            DiscoveryStatus::Trusted => Ok(()),
            DiscoveryStatus::ReadOnly => Err(Error::ReadOnly),
            DiscoveryStatus::ManualRequired => Err(Error::ManualRequired),
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

fn same_capability_set(left: &[Capability], right: &[Capability]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    right.sort_unstable();
    left.dedup();
    right.dedup();
    left == right
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
