//! Windows glue over the IP Helper API: link facts, the route table, address
//! lifetimes, ICMP echo with the don't-fragment flag, and the configured DNS
//! servers. No child process and no capture driver is involved.
//!
//! Not measurable here, so reported as unsupported: Wi-Fi signal strength
//! (needs the WLAN API, whose windows-sys feature this build does not enable)
//! and ARP probing (needs a raw link-layer socket).

use super::decide::{mac_from_bytes, parse_c_ipv4, speed_mbps_from_bps};
use super::icmp::{IcmpStatus, classify_status};
use super::model::{
    DefaultRoute, EchoOutcome, EchoRequest, Ipv4Lease, LinkInfo, LinkKind, Mac, OsError,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ptr;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FIXED_INFO_W2KSP1, FreeMibTable, GetIfTable2, GetIpForwardTable2, GetIpInterfaceTable,
    GetNetworkParams, GetUnicastIpAddressTable, ICMP_ECHO_REPLY, IP_ADDR_STRING, IP_FLAG_DF,
    IP_OPTION_INFORMATION, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2, MIB_IF_TABLE2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

/// Most rows read from any one OS table.
const MAX_ROWS: usize = 16_384;
/// `IF_TYPE_PPP` and `IF_TYPE_TUNNEL`.
const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_TUNNEL: u32 = 131;
/// `NlsoManual`: the address suffix was configured by hand.
const SUFFIX_ORIGIN_MANUAL: i32 = 1;

/// Releases a table allocated by an IP Helper `Get*Table*` call.
struct MibAllocation(*mut std::ffi::c_void);

impl Drop for MibAllocation {
    fn drop(&mut self) {
        // SAFETY: only successful, non-null IP Helper allocations enter this guard.
        unsafe { FreeMibTable(self.0) };
    }
}

/// Closes an ICMP handle from `IcmpCreateFile`.
struct IcmpHandle(HANDLE);

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `IcmpCreateFile`.
        unsafe { IcmpCloseHandle(self.0) };
    }
}

fn row_count(entries: u32) -> usize {
    (entries as usize).min(MAX_ROWS)
}

/// Adds hardware address, MTU, link speed and tunnel detection from
/// `GetIfTable2`. A table that cannot be read leaves those facts unknown.
pub fn enrich_links(links: &mut [LinkInfo]) {
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    // SAFETY: an initialised out-pointer; the OS allocates the table.
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return;
    }
    let _guard = MibAllocation(table.cast());
    // SAFETY: `table` is a successful non-null allocation owned by the guard.
    let count = row_count(unsafe { (*table).NumEntries });
    // SAFETY: `Table` begins the variable-length row array of the allocation.
    let first = unsafe { (*table).Table.as_ptr() };
    for index in 0..count {
        // SAFETY: `index` is below the row count the OS reported.
        let row = unsafe { &*first.add(index) };
        let Some(link) = links
            .iter_mut()
            .find(|link| link.index == row.InterfaceIndex)
        else {
            continue;
        };
        let length = row.PhysicalAddressLength as usize;
        if length <= row.PhysicalAddress.len() {
            link.mac = mac_from_bytes(&row.PhysicalAddress[..length]);
        }
        link.speed_mbps = speed_mbps_from_bps(row.TransmitLinkSpeed)
            .or_else(|| speed_mbps_from_bps(row.ReceiveLinkSpeed));
        link.mtu = (row.Mtu != 0 && row.Mtu != u32::MAX).then_some(row.Mtu);
        if link.kind == LinkKind::Other && matches!(row.Type, IF_TYPE_PPP | IF_TYPE_TUNNEL) {
            link.kind = LinkKind::Tunnel;
        }
    }
}

/// IPv4 interface metrics by interface index.
fn interface_metrics() -> Result<HashMap<u32, u32>, OsError> {
    let mut table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
    // SAFETY: an initialised out-pointer; the OS allocates the table.
    let status = unsafe { GetIpInterfaceTable(AF_INET, &mut table) };
    if status != ERROR_SUCCESS || table.is_null() {
        return Err(OsError::failed(format!(
            "the interface metrics could not be read (error {status})"
        )));
    }
    let _guard = MibAllocation(table.cast());
    // SAFETY: `table` is a successful non-null allocation owned by the guard.
    let count = row_count(unsafe { (*table).NumEntries });
    // SAFETY: `Table` begins the variable-length row array of the allocation.
    let first = unsafe { (*table).Table.as_ptr() };
    let mut metrics = HashMap::new();
    for index in 0..count {
        // SAFETY: `index` is below the row count the OS reported.
        let row = unsafe { &*first.add(index) };
        metrics.insert(row.InterfaceIndex, row.Metric);
    }
    Ok(metrics)
}

/// IPv4 default routes. The metric is the route metric plus the interface
/// metric, which is how Windows ranks them.
pub fn default_routes(links: &[LinkInfo]) -> Result<Vec<DefaultRoute>, OsError> {
    let metrics = interface_metrics()?;
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    // SAFETY: an initialised out-pointer; the OS allocates the table.
    let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if status != ERROR_SUCCESS || table.is_null() {
        return Err(OsError::failed(format!(
            "the route table could not be read (error {status})"
        )));
    }
    let _guard = MibAllocation(table.cast());
    // SAFETY: `table` is a successful non-null allocation owned by the guard.
    let count = row_count(unsafe { (*table).NumEntries });
    // SAFETY: `Table` begins the variable-length row array of the allocation.
    let first = unsafe { (*table).Table.as_ptr() };
    let mut routes = Vec::new();
    for index in 0..count {
        // SAFETY: `index` is below the row count the OS reported.
        let row = unsafe { &*first.add(index) };
        if row.DestinationPrefix.PrefixLength != 0 || row.Loopback {
            continue;
        }
        // SAFETY: the table was requested for AF_INET, so the IPv4 variants of
        // the address unions are the initialised ones.
        let (destination, next_hop) = unsafe {
            (
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr,
                row.NextHop.Ipv4.sin_addr.S_un.S_addr,
            )
        };
        if destination != 0 {
            continue;
        }
        let Some(link) = links.iter().find(|link| link.index == row.InterfaceIndex) else {
            continue;
        };
        routes.push(DefaultRoute {
            interface: link.name.clone(),
            // `S_addr` holds the network-order bytes in a native integer.
            gateway: Ipv4Addr::from(next_hop.to_ne_bytes()),
            metric: row
                .Metric
                .saturating_add(metrics.get(&row.InterfaceIndex).copied().unwrap_or(0)),
        });
    }
    Ok(routes)
}

/// IPv4 addresses of an interface with their lifetimes.
pub async fn ipv4_leases(link_index: u32) -> Result<Vec<Ipv4Lease>, OsError> {
    // A plain call: the raw table pointers never live across an await.
    read_ipv4_leases(link_index)
}

fn read_ipv4_leases(link_index: u32) -> Result<Vec<Ipv4Lease>, OsError> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    // SAFETY: an initialised out-pointer; the OS allocates the table.
    let status = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if status != ERROR_SUCCESS || table.is_null() {
        return Err(OsError::failed(format!(
            "the address table could not be read (error {status})"
        )));
    }
    let _guard = MibAllocation(table.cast());
    // SAFETY: `table` is a successful non-null allocation owned by the guard.
    let count = row_count(unsafe { (*table).NumEntries });
    // SAFETY: `Table` begins the variable-length row array of the allocation.
    let first = unsafe { (*table).Table.as_ptr() };
    let mut leases = Vec::new();
    for index in 0..count {
        // SAFETY: `index` is below the row count the OS reported.
        let row = unsafe { &*first.add(index) };
        if row.InterfaceIndex != link_index {
            continue;
        }
        // SAFETY: the table was requested for AF_INET.
        let s_addr = unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr };
        leases.push(Ipv4Lease {
            address: Ipv4Addr::from(s_addr.to_ne_bytes()),
            valid_seconds: row.ValidLifetime,
            permanent: row.SuffixOrigin == SUFFIX_ORIGIN_MANUAL,
        });
    }
    leases.sort_by_key(|lease| lease.address);
    Ok(leases)
}

pub fn wifi_rssi_dbm(_link: &LinkInfo) -> Result<i16, OsError> {
    Err(OsError::Unsupported(
        "Wi-Fi signal strength needs the Windows WLAN API, which this build does not enable",
    ))
}

pub async fn arp_probe(
    _link: &LinkInfo,
    _address: Ipv4Addr,
    _timeout: Duration,
) -> Result<Vec<Mac>, OsError> {
    Err(OsError::Unsupported(
        "an ARP probe needs a raw link-layer socket, which Windows only offers through a capture driver",
    ))
}

fn echo_blocking(request: &EchoRequest) -> Result<EchoOutcome, OsError> {
    // SAFETY: no arguments; the returned handle is checked below.
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reads the calling thread's last-error value.
        let code = unsafe { GetLastError() };
        return Err(OsError::failed(format!(
            "the ICMP interface could not be opened (error {code})"
        )));
    }
    let handle = IcmpHandle(handle);
    let payload = vec![0x61u8; usize::from(request.payload_bytes)];
    let options = IP_OPTION_INFORMATION {
        Ttl: 128,
        Tos: 0,
        Flags: if request.dont_fragment {
            IP_FLAG_DF as u8
        } else {
            0
        },
        OptionsSize: 0,
        OptionsData: ptr::null_mut(),
    };
    // Room for the reply record, the echoed payload and an ICMP error body.
    let reply_bytes = size_of::<ICMP_ECHO_REPLY>() + payload.len() + 256;
    let mut reply = vec![0u64; reply_bytes.div_ceil(8)];
    let reply_size = u32::try_from(reply.len() * 8).unwrap_or(u32::MAX);
    let timeout_ms = u32::try_from(request.timeout.as_millis())
        .unwrap_or(u32::MAX)
        .clamp(1, 10_000);
    let started = Instant::now();
    // SAFETY: the handle is valid for the call; the request, option and reply
    // buffers are live, correctly sized for the lengths passed, and the reply
    // buffer is 8-byte aligned. No event or APC is used, so the call is
    // synchronous.
    let replies = unsafe {
        IcmpSendEcho2(
            handle.0,
            ptr::null_mut(),
            None,
            ptr::null(),
            u32::from_ne_bytes(request.target.octets()),
            payload.as_ptr().cast(),
            request.payload_bytes,
            &options,
            reply.as_mut_ptr().cast(),
            reply_size,
            timeout_ms,
        )
    };
    let elapsed = started.elapsed();
    let status = if replies == 0 {
        // With no reply the status is carried in the thread's last error.
        // SAFETY: reads the calling thread's last-error value.
        classify_status(unsafe { GetLastError() })
    } else {
        // SAFETY: a non-zero count means the OS wrote an `ICMP_ECHO_REPLY` at
        // the start of the 8-byte aligned reply buffer.
        let record = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
        classify_status(record.Status)
    };
    match status {
        IcmpStatus::Reply if replies > 0 => Ok(EchoOutcome::Reply {
            rtt_ms: elapsed.as_secs_f64() * 1000.0,
        }),
        IcmpStatus::Reply => Err(OsError::failed(
            "the ICMP call failed without reporting an error",
        )),
        IcmpStatus::PacketTooBig => Ok(EchoOutcome::FragmentationNeeded { next_hop_mtu: None }),
        IcmpStatus::NoReply => Ok(EchoOutcome::Timeout),
        IcmpStatus::Failure(code) => Err(OsError::failed(format!(
            "the ICMP echo failed (error {code})"
        ))),
    }
}

pub async fn echo(request: EchoRequest) -> Result<EchoOutcome, OsError> {
    tokio::task::spawn_blocking(move || echo_blocking(&request))
        .await
        .map_err(|_| OsError::failed("the echo task was cancelled"))?
}

/// The DNS servers Windows is configured with, in order, deduplicated.
pub fn dns_servers() -> Vec<String> {
    let mut length: u32 = 0;
    // SAFETY: a null buffer with a zero length asks for the required size.
    let status = unsafe { GetNetworkParams(ptr::null_mut(), &mut length) };
    if status != ERROR_BUFFER_OVERFLOW || length == 0 || length > 64 * 1024 {
        return Vec::new();
    }
    let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
    // SAFETY: the buffer is 8-byte aligned and at least `length` bytes long.
    let status =
        unsafe { GetNetworkParams(buffer.as_mut_ptr().cast::<FIXED_INFO_W2KSP1>(), &mut length) };
    if status != ERROR_SUCCESS {
        return Vec::new();
    }
    // SAFETY: the call succeeded, so the buffer starts with a `FIXED_INFO`.
    let info = unsafe { &*buffer.as_ptr().cast::<FIXED_INFO_W2KSP1>() };
    let mut servers: Vec<String> = Vec::new();
    let mut node: *const IP_ADDR_STRING = &info.DnsServerList;
    // The list links live inside `buffer`; bound the walk regardless.
    for _ in 0..16 {
        if node.is_null() {
            break;
        }
        // SAFETY: `node` is the list head or a link the OS wrote in `buffer`.
        let entry = unsafe { &*node };
        if let Some(address) = parse_c_ipv4(&entry.IpAddress.String) {
            let text = address.to_string();
            if !servers.contains(&text) {
                servers.push(text);
            }
        }
        node = entry.Next;
    }
    servers
}
