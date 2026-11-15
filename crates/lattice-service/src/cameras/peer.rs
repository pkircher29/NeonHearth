//! Loopback peer ownership verification for the RTSP proxy.
//!
//! The proxy's source URL (including its per-session token) is an argument of
//! the spawned ffmpeg process, so it is readable by every process running as
//! the same user (`/proc/<pid>/cmdline`, `ps`, Task Manager). The token alone
//! therefore cannot be the proxy's consumer authentication. Before a loopback
//! connection is served, the accepting side asks the OS which process owns the
//! peer socket and compares it with the pid of the media process this session
//! spawned. Everything here is enum-typed: no address, path, or pid reaches a
//! log line or an error payload.

use std::net::SocketAddr;

/// Why a peer could not be verified. Variants carry no host data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PeerVerifyError {
    /// The OS connection table could not be read.
    TableUnavailable,
    /// The connection was not present in the OS connection table.
    ConnectionNotFound,
    /// The connection exists but belongs to a different process.
    OwnerMismatch,
    /// Peer verification is not implemented on this platform; fail closed.
    #[cfg_attr(any(target_os = "linux", windows), allow(dead_code))]
    Unsupported,
}

/// Returns `Ok(())` only when the loopback TCP connection `peer -> local` is
/// owned by process `pid`. Both addresses must be IPv4 loopback.
pub(super) fn verify_loopback_owner(
    peer: SocketAddr,
    local: SocketAddr,
    pid: u32,
) -> Result<(), PeerVerifyError> {
    if !peer.ip().is_loopback() || !local.ip().is_loopback() {
        return Err(PeerVerifyError::ConnectionNotFound);
    }
    platform::verify(peer.port(), local.port(), pid)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::PeerVerifyError;
    use std::{fs, path::Path};

    /// `/proc/net/tcp` encodes IPv4 addresses as little-endian hex; 127.0.0.1
    /// is `0100007F`. `/proc/net/tcp6` shows the same socket as a v4-mapped
    /// address when the client opened an AF_INET6 socket.
    const V4_LOOPBACK: &str = "0100007F";
    const V6_MAPPED_LOOPBACK: &str = "0000000000000000FFFF00000100007F";
    /// Socket states in which the peer still owns a live connection to us:
    /// ESTABLISHED, FIN_WAIT1, FIN_WAIT2 (peer half-closed its write side, as
    /// a one-shot client does right after sending), and CLOSE_WAIT.
    const LIVE_STATES: [&str; 4] = ["01", "04", "05", "08"];
    const MAX_TABLE_BYTES: u64 = 8 * 1024 * 1024;

    pub(super) fn verify(peer_port: u16, local_port: u16, pid: u32) -> Result<(), PeerVerifyError> {
        let inode = find_inode(peer_port, local_port)?;
        if process_owns_inode(pid, inode) {
            Ok(())
        } else {
            Err(PeerVerifyError::OwnerMismatch)
        }
    }

    fn find_inode(peer_port: u16, local_port: u16) -> Result<u64, PeerVerifyError> {
        let mut any_table = false;
        for (path, loopback) in [
            ("/proc/net/tcp", V4_LOOPBACK),
            ("/proc/net/tcp6", V6_MAPPED_LOOPBACK),
        ] {
            let Ok(table) = read_bounded(Path::new(path)) else {
                continue;
            };
            any_table = true;
            let local = format!("{loopback}:{peer_port:04X}");
            let remote = format!("{loopback}:{local_port:04X}");
            if let Some(inode) = find_in_table(&table, &local, &remote) {
                return Ok(inode);
            }
        }
        if any_table {
            Err(PeerVerifyError::ConnectionNotFound)
        } else {
            Err(PeerVerifyError::TableUnavailable)
        }
    }

    fn read_bounded(path: &Path) -> std::io::Result<String> {
        use std::io::Read as _;
        let file = fs::File::open(path)?;
        let mut text = String::new();
        file.take(MAX_TABLE_BYTES).read_to_string(&mut text)?;
        Ok(text)
    }

    /// Columns: `sl local_address rem_address st tx_queue:rx_queue tr:tm->when
    /// retrnsmt uid timeout inode ...`. The peer's socket is the row whose
    /// *local* side is the peer address and whose *remote* side is our listener.
    pub(super) fn find_in_table(table: &str, local: &str, remote: &str) -> Option<u64> {
        table.lines().skip(1).find_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let _sl = fields.next()?;
            let row_local = fields.next()?;
            let row_remote = fields.next()?;
            let state = fields.next()?;
            if !row_local.eq_ignore_ascii_case(local)
                || !row_remote.eq_ignore_ascii_case(remote)
                || !LIVE_STATES.contains(&state)
            {
                return None;
            }
            // tx/rx queue, tr/when, retrnsmt, uid, timeout, then inode.
            fields.nth(5)?.parse::<u64>().ok()
        })
    }

    fn process_owns_inode(pid: u32, inode: u64) -> bool {
        let wanted = format!("socket:[{inode}]");
        let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            return false;
        };
        entries
            .flatten()
            .take(65_536)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .any(|target| target.as_os_str() == wanted.as_str())
    }

    #[cfg(test)]
    mod tests {
        use super::find_in_table;

        const TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:A8C2 0100007F:22B8 01 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 20 4 30 10 -1\n\
   1: 0100007F:A8C3 0100007F:22B8 06 00000000:00000000 00:00000000 00000000  1000        0 999999 1 0000000000000000 20 4 30 10 -1\n\
   2: 0100007F:A8C4 0100007F:22B8 05 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 20 4 30 10 -1\n";

        #[test]
        fn established_row_yields_its_inode_and_others_do_not() {
            assert_eq!(
                find_in_table(TABLE, "0100007F:A8C2", "0100007F:22B8"),
                Some(123_456)
            );
            // TIME_WAIT (06) row is ignored; a half-closed FIN_WAIT2 row is live.
            assert_eq!(find_in_table(TABLE, "0100007F:A8C3", "0100007F:22B8"), None);
            assert_eq!(
                find_in_table(TABLE, "0100007F:A8C4", "0100007F:22B8"),
                Some(777)
            );
            // Reversed direction is not the peer's socket.
            assert_eq!(find_in_table(TABLE, "0100007F:22B8", "0100007F:A8C2"), None);
            assert_eq!(find_in_table("", "0100007F:A8C2", "0100007F:22B8"), None);
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::PeerVerifyError;
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        },
        Networking::WinSock::AF_INET,
    };

    /// MIB_TCP_STATE_ESTAB, FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT: states in which
    /// the peer still owns a live (possibly half-closed) connection to us.
    const LIVE_STATES: [u32; 4] = [5, 6, 7, 8];
    const MAX_ATTEMPTS: usize = 4;
    const MAX_TABLE_BYTES: u32 = 8 * 1024 * 1024;

    pub(super) fn verify(peer_port: u16, local_port: u16, pid: u32) -> Result<(), PeerVerifyError> {
        let table = read_table()?;
        let loopback = u32::from_ne_bytes([127, 0, 0, 1]);
        let mut found = false;
        for row in rows(&table) {
            // dwLocalPort/dwRemotePort carry the port in network byte order in
            // their low 16 bits.
            let row_local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let row_remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            if row.dwLocalAddr == loopback
                && row.dwRemoteAddr == loopback
                && row_local_port == peer_port
                && row_remote_port == local_port
                && LIVE_STATES.contains(&row.dwState)
            {
                found = true;
                if row.dwOwningPid == pid {
                    return Ok(());
                }
            }
        }
        if found {
            Err(PeerVerifyError::OwnerMismatch)
        } else {
            Err(PeerVerifyError::ConnectionNotFound)
        }
    }

    fn read_table() -> Result<Vec<u8>, PeerVerifyError> {
        let mut size: u32 = 0;
        // SAFETY: a null table with a zero size is the documented size query.
        let rc = unsafe {
            GetExtendedTcpTable(
                ptr::null_mut(),
                &mut size,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return Err(PeerVerifyError::TableUnavailable);
        }
        for _ in 0..MAX_ATTEMPTS {
            if size > MAX_TABLE_BYTES {
                return Err(PeerVerifyError::TableUnavailable);
            }
            let mut buffer = vec![0_u8; size as usize];
            // SAFETY: `buffer` is writable for `size` bytes and `size` is
            // updated by the call to the bytes required.
            let rc = unsafe {
                GetExtendedTcpTable(
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    u32::from(AF_INET),
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            match rc {
                NO_ERROR => return Ok(buffer),
                ERROR_INSUFFICIENT_BUFFER => continue,
                _ => return Err(PeerVerifyError::TableUnavailable),
            }
        }
        Err(PeerVerifyError::TableUnavailable)
    }

    fn rows(table: &[u8]) -> Vec<MIB_TCPROW_OWNER_PID> {
        let header = std::mem::size_of::<u32>();
        let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
        let table_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        if table.len() < header {
            return Vec::new();
        }
        // SAFETY: the buffer was filled by GetExtendedTcpTable and is at least
        // four bytes long; dwNumEntries is the first u32.
        let count = unsafe { ptr::read_unaligned(table.as_ptr().cast::<u32>()) } as usize;
        let available = table.len().saturating_sub(table_offset) / row_size;
        (0..count.min(available))
            .map(|index| {
                let offset = table_offset + index * row_size;
                // SAFETY: `offset + row_size <= table.len()` by construction of
                // `available`; the row type is plain data.
                unsafe {
                    ptr::read_unaligned(table.as_ptr().add(offset).cast::<MIB_TCPROW_OWNER_PID>())
                }
            })
            .collect()
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::PeerVerifyError;

    pub(super) fn verify(_: u16, _: u16, _: u32) -> Result<(), PeerVerifyError> {
        Err(PeerVerifyError::Unsupported)
    }
}
