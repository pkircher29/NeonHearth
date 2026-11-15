//! Linux glue: sysfs/procfs reads, netlink address lifetimes, an unprivileged
//! ICMP "ping socket" with the don't-fragment option, and an `AF_PACKET` ARP
//! probe. Nothing here runs a child process.

use super::arp;
use super::icmp;
use super::model::{
    DefaultRoute, EchoOutcome, EchoRequest, Ipv4Lease, LinkInfo, LinkKind, Mac, OsError, random_u16,
};
use super::procfs;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

const SYSFS_NET: &str = "/sys/class/net";
/// ARP probes sent per run, and the gap between them (RFC 5227 uses 3 probes).
const ARP_PROBES: u32 = 3;
const ARP_SPACING: Duration = Duration::from_millis(300);
/// Time kept back from the probe timeout for teardown.
const ARP_WINDOW_MARGIN: Duration = Duration::from_millis(150);

/// One attribute file of an interface, or `None` when it cannot be read.
fn read_attribute(interface: &str, attribute: &str) -> Option<String> {
    if interface.is_empty() || interface == "." || interface == ".." || interface.contains('/') {
        return None;
    }
    std::fs::read_to_string(format!("{SYSFS_NET}/{interface}/{attribute}")).ok()
}

fn is_wireless(interface: &str) -> bool {
    ["wireless", "phy80211"]
        .iter()
        .any(|entry| Path::new(&format!("{SYSFS_NET}/{interface}/{entry}")).exists())
}

/// Adds carrier state, speed, MTU, hardware address and wireless detection
/// from sysfs. A file that cannot be read leaves that fact unknown.
pub fn enrich_links(links: &mut [LinkInfo]) {
    for link in links.iter_mut() {
        if let Some(state) = read_attribute(&link.name, "operstate") {
            let carrier = read_attribute(&link.name, "carrier");
            if let Some(up) = procfs::link_up(&state, carrier.as_deref()) {
                link.up = up;
            }
        }
        link.speed_mbps = read_attribute(&link.name, "speed")
            .and_then(|text| procfs::parse_speed_mbps(&text));
        link.mtu = read_attribute(&link.name, "mtu").and_then(|text| procfs::parse_mtu(&text));
        link.mac = read_attribute(&link.name, "address").and_then(|text| procfs::parse_mac(&text));
        if matches!(link.kind, LinkKind::Wired | LinkKind::Other) && is_wireless(&link.name) {
            link.kind = LinkKind::Wifi;
        }
    }
}

pub fn default_routes(_links: &[LinkInfo]) -> Result<Vec<DefaultRoute>, OsError> {
    let table = std::fs::read_to_string("/proc/net/route")
        .map_err(|error| OsError::failed(format!("the route table could not be read: {error}")))?;
    Ok(procfs::parse_default_routes(&table))
}

pub fn wifi_rssi_dbm(link: &LinkInfo) -> Result<i16, OsError> {
    let text = std::fs::read_to_string("/proc/net/wireless").map_err(|_| {
        OsError::Unsupported("this kernel does not expose /proc/net/wireless")
    })?;
    procfs::parse_wireless_level(&text, &link.name).ok_or(OsError::Unsupported(
        "the wireless driver does not report signal strength in dBm",
    ))
}

/// IPv4 addresses of an interface with their kernel lifetimes (netlink).
///
/// The kernel omits the cache info of a permanent address with an infinite
/// lifetime, so a missing lifetime is "forever".
pub async fn ipv4_leases(link_index: u32) -> Result<Vec<Ipv4Lease>, OsError> {
    use futures_util::TryStreamExt;
    use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressHeaderFlags};

    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|error| OsError::failed(format!("the netlink socket could not be opened: {error}")))?;
    tokio::spawn(connection);
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(link_index)
        .execute();
    let mut leases = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|error| OsError::failed(format!("the address query failed: {error}")))?
    {
        let mut address = None;
        let mut local = None;
        let mut valid = None;
        let mut permanent = message.header.flags.contains(AddressHeaderFlags::Permanent);
        for attribute in &message.attributes {
            match attribute {
                AddressAttribute::Local(IpAddr::V4(ip)) => local = Some(*ip),
                AddressAttribute::Address(IpAddr::V4(ip)) => address = Some(*ip),
                AddressAttribute::CacheInfo(info) => valid = Some(info.ifa_valid),
                AddressAttribute::Flags(flags) => {
                    permanent |= flags.contains(AddressFlags::Permanent);
                }
                _ => {}
            }
        }
        if let Some(ip) = local.or(address) {
            leases.push(Ipv4Lease {
                address: ip,
                valid_seconds: valid.unwrap_or(u32::MAX),
                permanent,
            });
        }
    }
    leases.sort_by_key(|lease| lease.address);
    Ok(leases)
}

fn set_mtu_discover(socket: &Socket, dont_fragment: bool) -> io::Result<()> {
    let value: libc::c_int = if dont_fragment {
        libc::IP_PMTUDISC_DO
    } else {
        libc::IP_PMTUDISC_DONT
    };
    // SAFETY: the descriptor is owned by `socket` for the whole call, and the
    // pointer and length describe one live `c_int`.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&raw const value).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The path MTU the kernel currently holds for a connected socket.
fn path_mtu(socket: &Socket) -> Option<u16> {
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the descriptor is owned by `socket`; the pointers describe one
    // live `c_int` and its length.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut length,
        )
    };
    if result != 0 {
        return None;
    }
    u16::try_from(value).ok()
}

fn open_echo_socket() -> Result<Socket, OsError> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).map_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            OsError::failed(
                "ICMP echo is not permitted for this account (net.ipv4.ping_group_range \
                 excludes its group)",
            )
        } else {
            OsError::failed(format!("the ICMP socket could not be opened: {error}"))
        }
    })
}

fn echo_blocking(request: &EchoRequest) -> Result<EchoOutcome, OsError> {
    let socket = open_echo_socket()?;
    set_mtu_discover(&socket, request.dont_fragment).map_err(|error| {
        OsError::failed(format!("the don't-fragment option could not be set: {error}"))
    })?;
    socket
        .connect(&SockAddr::from(SocketAddr::new(
            IpAddr::V4(request.target),
            0,
        )))
        .map_err(|error| OsError::failed(format!("the echo target could not be addressed: {error}")))?;
    let identifier = random_u16()?;
    let sequence = random_u16()?;
    let packet = icmp::build_echo_request(identifier, sequence, usize::from(request.payload_bytes));
    let started = Instant::now();
    match socket.send(&packet) {
        Ok(_) => {}
        // With don't-fragment set, a packet larger than the route's MTU is
        // refused locally.
        Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
            return Ok(EchoOutcome::FragmentationNeeded {
                next_hop_mtu: path_mtu(&socket),
            });
        }
        Err(error) => {
            return Err(OsError::failed(format!("the echo could not be sent: {error}")));
        }
    }
    let mut buffer = vec![0u8; usize::from(request.payload_bytes) + 128];
    let mut reader = &socket;
    loop {
        let Some(remaining) = request
            .timeout
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
        else {
            return Ok(EchoOutcome::Timeout);
        };
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|error| OsError::failed(format!("the echo timeout could not be set: {error}")))?;
        match reader.read(&mut buffer) {
            Ok(length) => {
                if icmp::echo_reply_sequence(&buffer[..length]) == Some(sequence) {
                    return Ok(EchoOutcome::Reply {
                        rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                    });
                }
                // Not our reply: keep waiting for the remaining time.
            }
            Err(error) => return recv_failure(&socket, &error),
        }
    }
}

/// A receive error on the connected ping socket. A router saying "too big"
/// shows up as EMSGSIZE; an unreachable or refusing path means no echo reply
/// came back, which is a measurement and not a probe failure.
fn recv_failure(socket: &Socket, error: &io::Error) -> Result<EchoOutcome, OsError> {
    match error.raw_os_error() {
        Some(libc::EMSGSIZE) => Ok(EchoOutcome::FragmentationNeeded {
            next_hop_mtu: path_mtu(socket),
        }),
        Some(code)
            if [
                libc::EHOSTUNREACH,
                libc::ENETUNREACH,
                libc::ECONNREFUSED,
                libc::EHOSTDOWN,
            ]
            .contains(&code) =>
        {
            Ok(EchoOutcome::Timeout)
        }
        _ if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) =>
        {
            Ok(EchoOutcome::Timeout)
        }
        _ => Err(OsError::failed(format!("the echo reply could not be read: {error}"))),
    }
}

pub async fn echo(request: EchoRequest) -> Result<EchoOutcome, OsError> {
    tokio::task::spawn_blocking(move || echo_blocking(&request))
        .await
        .map_err(|_| OsError::failed("the echo task was cancelled"))?
}

pub async fn arp_probe(
    link: &LinkInfo,
    address: Ipv4Addr,
    timeout: Duration,
) -> Result<Vec<Mac>, OsError> {
    let own_mac = link.mac.ok_or_else(|| {
        OsError::failed(format!("interface {} has no hardware address", link.name))
    })?;
    let index = link.index;
    tokio::task::spawn_blocking(move || arp_probe_blocking(index, own_mac, address, timeout))
        .await
        .map_err(|_| OsError::failed("the ARP task was cancelled"))?
}

fn arp_probe_blocking(
    index: u32,
    own_mac: Mac,
    address: Ipv4Addr,
    timeout: Duration,
) -> Result<Vec<Mac>, OsError> {
    let protocol = (libc::ETH_P_ARP as u16).to_be();
    // SAFETY: a plain system call with constant arguments.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::c_int::from(protocol),
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        return Err(OsError::failed(if error.kind() == io::ErrorKind::PermissionDenied {
            "an ARP probe needs the CAP_NET_RAW capability".to_owned()
        } else {
            format!("the packet socket could not be opened: {error}")
        }));
    }
    // SAFETY: `raw` is a freshly created, valid descriptor that nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: an all-zero `sockaddr_ll` is a valid value of this plain C struct.
    let mut link_address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    link_address.sll_family = libc::AF_PACKET as libc::c_ushort;
    link_address.sll_protocol = protocol;
    link_address.sll_ifindex = i32::try_from(index)
        .map_err(|_| OsError::failed("the interface index is out of range"))?;
    link_address.sll_halen = 6;
    link_address.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    // SAFETY: the descriptor is owned by `socket`; the pointer and length
    // describe the live `link_address`.
    let bound = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const link_address).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        return Err(OsError::failed(format!(
            "the packet socket could not be bound to the interface: {}",
            io::Error::last_os_error()
        )));
    }

    let frame = arp::build_probe(own_mac, address);
    let started = Instant::now();
    let deadline = started + timeout.saturating_sub(ARP_WINDOW_MARGIN);
    let mut claimants: Vec<Mac> = Vec::new();
    for round in 0..ARP_PROBES {
        send_frame(&socket, &link_address, &frame)?;
        let round_end = if round + 1 == ARP_PROBES {
            deadline
        } else {
            (started + ARP_SPACING * (round + 1)).min(deadline)
        };
        collect_claims(&socket, round_end, address, own_mac, &mut claimants)?;
        if Instant::now() >= deadline {
            break;
        }
    }
    claimants.sort();
    Ok(claimants)
}

fn send_frame(
    socket: &OwnedFd,
    link_address: &libc::sockaddr_ll,
    frame: &[u8],
) -> Result<(), OsError> {
    // SAFETY: the descriptor is owned by `socket`; the pointers and lengths
    // describe the live `frame` and `link_address`.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            (link_address as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(OsError::failed(format!(
            "the ARP probe could not be sent: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Reads frames until `until`, keeping the hardware address of every other
/// host that claims `address`.
fn collect_claims(
    socket: &OwnedFd,
    until: Instant,
    address: Ipv4Addr,
    own_mac: Mac,
    claimants: &mut Vec<Mac>,
) -> Result<(), OsError> {
    let mut buffer = [0u8; 2048];
    loop {
        let now = Instant::now();
        if now >= until {
            return Ok(());
        }
        let wait_ms = i32::try_from((until - now).as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut poll_fd = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the pointer refers to one live `pollfd` and the count is 1.
        let ready = unsafe { libc::poll(&raw mut poll_fd, 1, wait_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(OsError::failed(format!("waiting for ARP replies failed: {error}")));
        }
        if ready == 0 {
            return Ok(());
        }
        // SAFETY: the descriptor is owned by `socket`; the pointer and length
        // describe the live `buffer`.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(OsError::failed(format!("reading an ARP reply failed: {error}")));
        }
        let length = usize::try_from(received).unwrap_or(0).min(buffer.len());
        if let Some(claimant) = arp::parse_claim(&buffer[..length], address, own_mac)
            && !claimants.contains(&claimant)
        {
            claimants.push(claimant);
        }
    }
}
