//! Platforms the Doctor has no OS glue for (neither Windows nor Linux): every
//! OS-dependent probe is unsupported, never invented.

use super::model::{
    DefaultRoute, EchoOutcome, EchoRequest, Ipv4Lease, LinkInfo, Mac, OsError,
};
use std::net::Ipv4Addr;
use std::time::Duration;

const UNSUPPORTED: &str = "the Network Doctor has no probes for this operating system";

pub fn enrich_links(_links: &mut [LinkInfo]) {}

pub fn default_routes(_links: &[LinkInfo]) -> Result<Vec<DefaultRoute>, OsError> {
    Err(OsError::Unsupported(UNSUPPORTED))
}

pub async fn ipv4_leases(_link_index: u32) -> Result<Vec<Ipv4Lease>, OsError> {
    Err(OsError::Unsupported(UNSUPPORTED))
}

pub fn wifi_rssi_dbm(_link: &LinkInfo) -> Result<i16, OsError> {
    Err(OsError::Unsupported(UNSUPPORTED))
}

pub async fn echo(_request: EchoRequest) -> Result<EchoOutcome, OsError> {
    Err(OsError::Unsupported(UNSUPPORTED))
}

pub async fn arp_probe(
    _link: &LinkInfo,
    _address: Ipv4Addr,
    _timeout: Duration,
) -> Result<Vec<Mac>, OsError> {
    Err(OsError::Unsupported(UNSUPPORTED))
}
