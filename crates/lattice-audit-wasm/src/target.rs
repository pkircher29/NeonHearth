use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TargetError {
    #[error("target is not a numeric private unicast address")]
    InvalidTarget,
    #[error("interface must be nonzero")]
    InvalidInterface,
    #[error("port must be nonzero")]
    InvalidPort,
    #[error("target authorization failed: {0}")]
    Rejected(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedTarget {
    target: IpAddr,
    interface: u32,
    port: u16,
}
impl AuthorizedTarget {
    pub fn new(target: IpAddr, interface: u32, port: u16) -> Result<Self, TargetError> {
        if interface == 0 {
            return Err(TargetError::InvalidInterface);
        }
        if port == 0 {
            return Err(TargetError::InvalidPort);
        }
        let valid = match target {
            IpAddr::V4(ip) => {
                ip.is_private()
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
    fn authorize(
        &self,
        target: IpAddr,
        interface: u32,
        port: u16,
    ) -> Result<AuthorizedTarget, TargetError>;
}
