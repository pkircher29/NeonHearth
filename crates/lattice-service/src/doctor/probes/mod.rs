//! Real network probes for the Network Doctor.
//!
//! [`HostProbeTransport`] answers the engine's typed probe requests from what
//! the operating system exposes. The module tree separates interpretation from
//! OS access:
//!
//! - `decide`, `dns`, `icmp`, `arp`, `procfs`: pure parsing and decision code,
//!   unit-tested with fixtures for both OS shapes;
//! - `model`: the OS-neutral types and [`HostOs`], the one seam every OS call
//!   goes through (tests substitute a fake that answers, or never answers);
//! - `transport`: maps each `ProbeRequest` onto `HostOs` calls under a hard
//!   timeout;
//! - `system`, `linux`, `windows`, `other`: the thin OS glue.
//!
//! Nothing here starts a child process, fabricates a measurement, or decides
//! consent: refusing unconfigured and unconfirmed external targets is the job
//! of `GatedProbes` in the parent module, in front of this transport.

pub mod decide;
pub mod dns;
pub mod icmp;
pub mod model;
mod system;
pub mod transport;

#[cfg(any(target_os = "linux", test))]
pub mod arp;
#[cfg(any(target_os = "linux", test))]
pub mod procfs;
#[cfg(test)]
pub mod testing;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "linux", windows)))]
mod other;
#[cfg(windows)]
mod windows;

#[cfg(not(any(target_os = "linux", windows)))]
use other as platform;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(windows)]
use windows as platform;

pub use model::{HostOs, OsError};
pub use system::{SystemHost, system_local_macs};
#[cfg(windows)]
pub use system::{system_default_gateway, system_resolvers};
pub use transport::HostProbeTransport;
