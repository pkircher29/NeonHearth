use super::*;
use crate::host_monitor::InterfaceCounter;
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::IpHelper::*,
    Networking::WinSock::*,
    System::{ProcessStatus::*, SystemInformation::*, Threading::*},
    UI::Shell::IsUserAnAdmin,
};

const MAX_ROWS: usize = 8192;
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Mib(*mut std::ffi::c_void);
impl Drop for Mib {
    fn drop(&mut self) {
        unsafe {
            FreeMibTable(self.0);
        }
    }
}
fn wide(v: &[u16]) -> String {
    String::from_utf16_lossy(&v[..v.iter().position(|c| *c == 0).unwrap_or(v.len())])
}
fn filetime(v: FILETIME) -> u64 {
    (u64::from(v.dwHighDateTime) << 32) | u64::from(v.dwLowDateTime)
}

fn table<T: Copy>(family: u16, tcp: bool, offset: usize) -> Result<Vec<T>, &'static str> {
    let mut size = 0;
    let read = |p, size: &mut u32| unsafe {
        if tcp {
            GetExtendedTcpTable(p, size, 0, u32::from(family), TCP_TABLE_OWNER_PID_ALL, 0)
        } else {
            GetExtendedUdpTable(p, size, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0)
        }
    };
    if read(ptr::null_mut(), &mut size) != ERROR_INSUFFICIENT_BUFFER {
        return Err("connection table unavailable");
    }
    for _ in 0..4 {
        if size as usize > 8 * 1024 * 1024 || size < 4 {
            return Err("connection table limit");
        }
        // u64 storage supplies alignment required by the native table types.
        let mut data = vec![0u64; (size as usize).div_ceil(8)];
        match read(data.as_mut_ptr().cast(), &mut size) {
            ERROR_SUCCESS => {
                let count = unsafe { ptr::read_unaligned(data.as_ptr().cast::<u32>()) } as usize;
                if count > MAX_ROWS || offset + count * size_of::<T>() > size as usize {
                    return Err("connection count limit");
                }
                return Ok((0..count)
                    .map(|n| unsafe {
                        ptr::read_unaligned(
                            data.as_ptr()
                                .cast::<u8>()
                                .add(offset + n * size_of::<T>())
                                .cast::<T>(),
                        )
                    })
                    .collect());
            }
            ERROR_INSUFFICIENT_BUFFER => continue,
            _ => return Err("connection table unavailable"),
        }
    }
    Err("connection table changed repeatedly")
}
fn process(pid: u32, captured_before: u64) -> Application {
    let mut app = Application {
        pid,
        name: format!("Process {pid}"),
        ..Default::default()
    };
    // This handle never requests termination, injection, or write access.
    let mut raw =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if raw.is_null() {
        raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    }
    if !raw.is_null() {
        let handle = Handle(raw);
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) }
            != 0
        {
            let started = filetime(created);
            // A process born after the table read may have reused an old PID.
            if started <= captured_before {
                app.started = started.to_string();
                app.cpu_time_ms = Some(filetime(kernel).saturating_add(filetime(user)) / 10_000);
                let mut path = vec![0u16; 4096];
                let mut len = path.len() as u32;
                if unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut len) }
                    != 0
                    && len > 0
                    && len < 4096
                {
                    let path = wide(&path[..len as usize]);
                    app.name = path.rsplit('\\').next().unwrap_or(&path).to_owned();
                    app.executable = Some(path);
                }
                let mut memory = PROCESS_MEMORY_COUNTERS {
                    cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                    ..Default::default()
                };
                if unsafe {
                    K32GetProcessMemoryInfo(
                        handle.0,
                        &mut memory,
                        size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                    )
                } != 0
                {
                    app.memory_bytes = Some(memory.WorkingSetSize as u64);
                }
            }
        }
    }
    identify(&mut app);
    app
}
fn interfaces() -> Result<Vec<InterfaceCounter>, &'static str> {
    let mut raw: *mut MIB_IF_TABLE2 = ptr::null_mut();
    if unsafe { GetIfTable2(&mut raw) } != ERROR_SUCCESS || raw.is_null() {
        return Err("interface counters unavailable");
    }
    let _guard = Mib(raw.cast());
    let count = unsafe { (*raw).NumEntries } as usize;
    if count > 4096 {
        return Err("interface limit");
    }
    let mut values = vec![];
    for n in 0..count {
        let row = unsafe { &*(*raw).Table.as_ptr().add(n) };
        if row.OperStatus != 1 {
            continue;
        }
        values.push(InterfaceCounter {
            id: format!(
                "{}-{:?}",
                row.InterfaceIndex,
                &row.PhysicalAddress
                    [..(row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len())]
            ),
            name: wide(&row.Alias),
            physical: row.InterfaceAndOperStatusFlags._bitfield & 1 != 0
                && matches!(row.Type, 6 | 71),
            sent_bytes: row.OutOctets,
            received_bytes: row.InOctets,
        });
    }
    Ok(values)
}
fn state(v: u32) -> &'static str {
    match v {
        1 => "closed",
        2 => "listening",
        3 => "connecting",
        4 => "syn_received",
        5 => "established",
        6 => "fin_wait_1",
        7 => "fin_wait_2",
        8 => "close_wait",
        9 => "closing",
        10 => "last_ack",
        11 => "time_wait",
        12 => "delete",
        _ => "unknown",
    }
}
fn stats4(row: &MIB_TCPROW_OWNER_PID, elevated: bool) -> (Option<u64>, Option<u64>) {
    if row.dwState != 5 {
        return (None, None);
    }
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            dwState: row.dwState,
        },
        dwLocalAddr: row.dwLocalAddr,
        dwLocalPort: row.dwLocalPort,
        dwRemoteAddr: row.dwRemoteAddr,
        dwRemotePort: row.dwRemotePort,
    };
    let mut rw = TCP_ESTATS_DATA_RW_v0::default();
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    let code = unsafe {
        GetPerTcpConnectionEStats(
            &row,
            TcpConnectionEstatsData,
            (&mut rw as *mut TCP_ESTATS_DATA_RW_v0).cast(),
            0,
            size_of_val(&rw) as u32,
            ptr::null_mut(),
            0,
            0,
            (&mut rod as *mut TCP_ESTATS_DATA_ROD_v0).cast(),
            0,
            size_of_val(&rod) as u32,
        )
    };
    if code == ERROR_SUCCESS && rw.EnableCollection {
        return (Some(rod.DataBytesOut), Some(rod.DataBytesIn));
    }
    if elevated {
        rw.EnableCollection = true;
        unsafe {
            SetPerTcpConnectionEStats(
                &row,
                TcpConnectionEstatsData,
                (&rw as *const TCP_ESTATS_DATA_RW_v0).cast(),
                0,
                size_of_val(&rw) as u32,
                0,
            );
        }
    }
    (None, None)
}
fn stats6(row: &MIB_TCP6ROW_OWNER_PID, elevated: bool) -> (Option<u64>, Option<u64>) {
    if row.dwState != 5 {
        return (None, None);
    }
    let row = MIB_TCP6ROW {
        State: row.dwState as i32,
        LocalAddr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: row.ucLocalAddr,
            },
        },
        dwLocalScopeId: row.dwLocalScopeId,
        dwLocalPort: row.dwLocalPort,
        RemoteAddr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: row.ucRemoteAddr,
            },
        },
        dwRemoteScopeId: row.dwRemoteScopeId,
        dwRemotePort: row.dwRemotePort,
    };
    let mut rw = TCP_ESTATS_DATA_RW_v0::default();
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    let code = unsafe {
        GetPerTcp6ConnectionEStats(
            &row,
            TcpConnectionEstatsData,
            (&mut rw as *mut TCP_ESTATS_DATA_RW_v0).cast(),
            0,
            size_of_val(&rw) as u32,
            ptr::null_mut(),
            0,
            0,
            (&mut rod as *mut TCP_ESTATS_DATA_ROD_v0).cast(),
            0,
            size_of_val(&rod) as u32,
        )
    };
    if code == ERROR_SUCCESS && rw.EnableCollection {
        return (Some(rod.DataBytesOut), Some(rod.DataBytesIn));
    }
    if elevated {
        rw.EnableCollection = true;
        unsafe {
            SetPerTcp6ConnectionEStats(
                &row,
                TcpConnectionEstatsData,
                (&rw as *const TCP_ESTATS_DATA_RW_v0).cast(),
                0,
                size_of_val(&rw) as u32,
                0,
            );
        }
    }
    (None, None)
}
fn ipv6(bytes: [u8; 16], scope: u32) -> String {
    let ip = Ipv6Addr::from(bytes);
    if scope > 0 {
        format!("{ip}%{scope}")
    } else {
        ip.to_string()
    }
}
pub fn snapshot() -> Result<HostSnapshot, &'static str> {
    let mut before = FILETIME::default();
    unsafe {
        GetSystemTimeAsFileTime(&mut before);
    }
    let elevated = unsafe { IsUserAnAdmin() } != 0;
    let mut result=HostSnapshot {status:"ready".into(),detail:"This computer only. Physical-interface bytes include all protocols. App bytes cover sampled TCP connections; short connections and UDP bytes are not attributed.".into(),app_counters:if elevated {"sampled_tcp"} else {"requires_elevation"}.into(),firewall_available:elevated,..Default::default()};
    result.interfaces = interfaces()?;
    let mut memory = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut memory) } != 0 {
        result.memory_total_bytes = Some(memory.ullTotalPhys);
        result.memory_available_bytes = Some(memory.ullAvailPhys);
    }
    for row in table::<MIB_TCPROW_OWNER_PID>(
        AF_INET,
        true,
        std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
    )? {
        let (sent_bytes, received_bytes) = stats4(&row, elevated);
        result.connections.push(Connection {
            pid: row.dwOwningPid,
            protocol: "tcp".into(),
            local_address: Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).to_string(),
            local_port: u16::from_be(row.dwLocalPort as u16),
            remote_address: (row.dwRemoteAddr != 0)
                .then(|| Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()).to_string()),
            remote_port: (row.dwRemotePort != 0).then(|| u16::from_be(row.dwRemotePort as u16)),
            state: state(row.dwState).into(),
            sent_bytes,
            received_bytes,
            ..Default::default()
        });
    }
    for row in table::<MIB_TCP6ROW_OWNER_PID>(
        AF_INET6,
        true,
        std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
    )? {
        let (sent_bytes, received_bytes) = stats6(&row, elevated);
        result.connections.push(Connection {
            pid: row.dwOwningPid,
            protocol: "tcp".into(),
            local_address: ipv6(row.ucLocalAddr, row.dwLocalScopeId),
            local_port: u16::from_be(row.dwLocalPort as u16),
            remote_address: (row.ucRemoteAddr != [0; 16])
                .then(|| ipv6(row.ucRemoteAddr, row.dwRemoteScopeId)),
            remote_port: (row.dwRemotePort != 0).then(|| u16::from_be(row.dwRemotePort as u16)),
            state: state(row.dwState).into(),
            sent_bytes,
            received_bytes,
            ..Default::default()
        });
    }
    for row in table::<MIB_UDPROW_OWNER_PID>(
        AF_INET,
        false,
        std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
    )? {
        result.connections.push(Connection {
            pid: row.dwOwningPid,
            protocol: "udp".into(),
            local_address: Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).to_string(),
            local_port: u16::from_be(row.dwLocalPort as u16),
            state: "bound".into(),
            ..Default::default()
        });
    }
    for row in table::<MIB_UDP6ROW_OWNER_PID>(
        AF_INET6,
        false,
        std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
    )? {
        result.connections.push(Connection {
            pid: row.dwOwningPid,
            protocol: "udp".into(),
            local_address: ipv6(row.ucLocalAddr, row.dwLocalScopeId),
            local_port: u16::from_be(row.dwLocalPort as u16),
            state: "bound".into(),
            ..Default::default()
        });
    }
    if result.connections.len() > MAX_ROWS {
        return Err("connection limit");
    }
    let mut apps = BTreeMap::new();
    for connection in &mut result.connections {
        let app = apps
            .entry(connection.pid)
            .or_insert_with(|| process(connection.pid, filetime(before)));
        connection_id(connection, app);
    }
    result.applications = apps.into_values().collect();
    Ok(result)
}
