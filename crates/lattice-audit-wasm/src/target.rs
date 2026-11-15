use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TargetError {
    #[error("target is not a numeric private unicast address")]
    InvalidTarget,
    #[error("interface must be nonzero")]
    InvalidInterface,
    #[error("port must be nonzero")]
    InvalidPort,
    #[error("target authorization failed")]
    Rejected,
    #[error("approval is unknown, expired, already used, or for a different target or module")]
    ApprovalRejected,
}

/// Proof that the caller is inside a broker-driven authorization. Only the
/// broker can create one, and it is consumed by [`AuthorizedTarget::new`], so
/// an `AuthorizedTarget` cannot be forged by code that never went through
/// [`TargetAuthorizer::authorize`] as called by the broker.
#[derive(Debug)]
pub struct AuthorizerWitness(());

impl AuthorizerWitness {
    pub(crate) fn new() -> Self {
        Self(())
    }

    /// For tests that exercise target validation directly.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests() -> Self {
        Self(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedTarget {
    target: IpAddr,
    interface: u32,
    port: u16,
}
impl AuthorizedTarget {
    pub fn new(
        _witness: AuthorizerWitness,
        target: IpAddr,
        interface: u32,
        port: u16,
    ) -> Result<Self, TargetError> {
        if interface == 0 {
            return Err(TargetError::InvalidInterface);
        }
        if port == 0 {
            return Err(TargetError::InvalidPort);
        }
        let valid = match target {
            IpAddr::V4(ip) => {
                (ip.is_private() || ip.is_link_local())
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !ip.is_unspecified()
            }
            IpAddr::V6(ip) => {
                !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_unspecified()
                    && (ip.is_unique_local() || ip.is_unicast_link_local())
            }
        };
        if !valid {
            return Err(TargetError::InvalidTarget);
        }
        Ok(Self {
            target,
            interface,
            port,
        })
    }
    pub fn target(&self) -> IpAddr {
        self.target
    }
    pub fn interface(&self) -> u32 {
        self.interface
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

pub trait TargetAuthorizer: Send + Sync {
    /// Decides whether this target may be audited and mints the token that
    /// says so. The witness is consumed to construct the [`AuthorizedTarget`].
    fn authorize(
        &self,
        witness: AuthorizerWitness,
        target: IpAddr,
        interface: u32,
        port: u16,
    ) -> Result<AuthorizedTarget, TargetError>;

    /// Redeems an owner approval for this target and module. Implementations
    /// must make it single-use and time-bound; [`ApprovalLedger`] does both.
    /// There is deliberately no default: an authorizer that cannot verify
    /// approvals must not run audits.
    fn redeem_approval(
        &self,
        approval: Uuid,
        target: &AuthorizedTarget,
        module_sha256: [u8; 32],
    ) -> Result<(), TargetError>;
}

const MAX_OUTSTANDING_APPROVALS: usize = 1024;

struct Grant {
    target: IpAddr,
    interface: u32,
    port: u16,
    module_sha256: [u8; 32],
    expires: Instant,
}

/// Single-use, expiring approvals bound to one target and one module digest.
#[derive(Default)]
pub struct ApprovalLedger {
    grants: Mutex<HashMap<Uuid, Grant>>,
}

impl ApprovalLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an owner approval and returns its id.
    pub fn mint(
        &self,
        target: &AuthorizedTarget,
        module_sha256: [u8; 32],
        ttl: Duration,
    ) -> Result<Uuid, TargetError> {
        self.mint_at(target, module_sha256, ttl, Instant::now())
    }

    pub fn mint_at(
        &self,
        target: &AuthorizedTarget,
        module_sha256: [u8; 32],
        ttl: Duration,
        now: Instant,
    ) -> Result<Uuid, TargetError> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| TargetError::ApprovalRejected)?;
        grants.retain(|_, grant| grant.expires > now);
        if grants.len() >= MAX_OUTSTANDING_APPROVALS || ttl.is_zero() {
            return Err(TargetError::ApprovalRejected);
        }
        let expires = now.checked_add(ttl).ok_or(TargetError::ApprovalRejected)?;
        let id = Uuid::new_v4();
        grants.insert(
            id,
            Grant {
                target: target.target(),
                interface: target.interface(),
                port: target.port(),
                module_sha256,
                expires,
            },
        );
        Ok(id)
    }

    pub fn redeem(
        &self,
        approval: Uuid,
        target: &AuthorizedTarget,
        module_sha256: [u8; 32],
    ) -> Result<(), TargetError> {
        self.redeem_at(approval, target, module_sha256, Instant::now())
    }

    /// A mismatch does not consume the approval, so a wrong guess cannot burn
    /// the owner grant; a match consumes it.
    pub fn redeem_at(
        &self,
        approval: Uuid,
        target: &AuthorizedTarget,
        module_sha256: [u8; 32],
        now: Instant,
    ) -> Result<(), TargetError> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| TargetError::ApprovalRejected)?;
        let matches = grants.get(&approval).is_some_and(|grant| {
            grant.expires > now
                && grant.target == target.target()
                && grant.interface == target.interface()
                && grant.port == target.port()
                && grant.module_sha256 == module_sha256
        });
        if matches {
            grants.remove(&approval);
            Ok(())
        } else {
            Err(TargetError::ApprovalRejected)
        }
    }
}
