use super::*;
use crate::host_monitor::InterfaceCounter;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
fn read(path: impl AsRef<Path>, limit: u64) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= limit).then_some(text)
}
fn endpoint(raw: &str) -> Option<(String, u16)> {
    let (address, port) = raw.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = match address.len() {
        8 => Ipv4Addr::from(u32::from_str_radix(address, 16).ok()?.to_ne_bytes()).to_string(),
        32 => {
            let mut bytes = [0; 16];
            for n in 0..4 {
                bytes[n * 4..n * 4 + 4].copy_from_slice(
                    &u32::from_str_radix(&address[n * 8..n * 8 + 8], 16)
                        .ok()?
                        .to_ne_bytes(),
                );
            }
            Ipv6Addr::from(bytes).to_string()
        }
        _ => return None,
    };
    Some((address, port))
}
fn process(pid: u32) -> Application {
    let root = format!("/proc/{pid}");
    let mut app = Application {
        pid,
        name: format!("Process {pid}"),
        ..Default::default()
    };
    if let Some(stat) = read(format!("{root}/stat"), 16384)
        .and_then(|v| v.rsplit_once(") ").map(|(_, s)| s.to_owned()))
    {
        let parts: Vec<_> = stat.split_whitespace().collect();
        app.started = parts.get(19).unwrap_or(&"").to_string();
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks > 0 {
            app.cpu_time_ms = parts
                .get(11)
                .and_then(|v| v.parse::<u64>().ok())
                .zip(parts.get(12).and_then(|v| v.parse::<u64>().ok()))
                .map(|(u, k)| u.saturating_add(k).saturating_mul(1000) / ticks as u64);
        }
    }
    if let Ok(path) = fs::read_link(format!("{root}/exe")) {
        let value = path.to_string_lossy();
        if value.len() <= 4096 && !value.ends_with(" (deleted)") {
            app.executable = Some(value.into_owned());
            app.name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
        }
    }
    if let Some(status) = read(format!("{root}/status"), 65536) {
        app.memory_bytes = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(|v| v.checked_mul(1024));
    }
    identify(&mut app);
    app
}
pub fn snapshot() -> Result<HostSnapshot, &'static str> {
    let mut result=HostSnapshot {status:"ready".into(),detail:"This Linux network namespace only. Connection ownership is limited by /proc permissions. Physical-interface bytes include all protocols; application byte counters are unavailable.".into(),app_counters:"unavailable".into(),..Default::default()};
    let interfaces = read("/proc/net/dev", 1024 * 1024).ok_or("interface counters unavailable")?;
    for line in interfaces.lines().skip(2) {
        let Some((name, data)) = line.trim().split_once(':') else {
            continue;
        };
        let parts: Vec<_> = data.split_whitespace().collect();
        if let (Some(received), Some(sent)) = (
            parts.first().and_then(|s| s.parse::<u64>().ok()),
            parts.get(8).and_then(|s| s.parse::<u64>().ok()),
        ) {
            result.interfaces.push(InterfaceCounter {
                id: name.into(),
                name: name.into(),
                physical: Path::new(&format!("/sys/class/net/{name}/device")).exists(),
                sent_bytes: sent,
                received_bytes: received,
            });
        }
    }
    let memory = read("/proc/meminfo", 65536).unwrap_or_default();
    let kb = |key: &str| {
        memory
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(|v| v.checked_mul(1024))
    };
    result.memory_total_bytes = kb("MemTotal:");
    result.memory_available_bytes = kb("MemAvailable:");
    let mut sockets = BTreeMap::new();
    for (file, protocol) in [
        ("tcp", "tcp"),
        ("tcp6", "tcp"),
        ("udp", "udp"),
        ("udp6", "udp"),
    ] {
        let text = read(format!("/proc/net/{file}"), 4 * 1024 * 1024)
            .ok_or("connection table unavailable")?;
        for line in text.lines().skip(1) {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            let (Some((local_address, local_port)), Some((remote, port))) =
                (endpoint(parts[1]), endpoint(parts[2]))
            else {
                continue;
            };
            let state = if protocol == "udp" {
                "bound"
            } else {
                match parts[3] {
                    "01" => "established",
                    "02" => "connecting",
                    "03" => "syn_received",
                    "04" => "fin_wait_1",
                    "05" => "fin_wait_2",
                    "06" => "time_wait",
                    "07" => "closed",
                    "08" => "close_wait",
                    "09" => "last_ack",
                    "0A" => "listening",
                    "0B" => "closing",
                    _ => "unknown",
                }
            };
            let connection = Connection {
                protocol: protocol.into(),
                local_address,
                local_port,
                remote_address: (port > 0).then_some(remote),
                remote_port: (port > 0).then_some(port),
                state: state.into(),
                ..Default::default()
            };
            let key = if parts[9] == "0" {
                format!("unowned:{protocol}:{}:{}", parts[1], parts[2])
            } else {
                parts[9].to_owned()
            };
            sockets.insert(key, connection);
            if sockets.len() > 8192 {
                return Err("connection count limit");
            }
        }
    }
    let mut apps = BTreeMap::new();
    let mut checked = 0;
    for entry in fs::read_dir("/proc")
        .map_err(|_| "process inventory unavailable")?
        .take(16384)
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.take(8192).flatten() {
            checked += 1;
            if checked > 100_000 {
                return Err("process descriptor limit");
            }
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let text = link.to_string_lossy();
            let Some(inode) = text
                .strip_prefix("socket:[")
                .and_then(|v| v.strip_suffix(']'))
            else {
                continue;
            };
            if let Some(connection) = sockets.get_mut(inode) {
                if connection.pid != 0 && connection.pid != pid {
                    connection.pid = u32::MAX;
                    continue;
                }
                let app = apps.entry(pid).or_insert_with(|| process(pid));
                connection.pid = pid;
                connection_id(connection, app);
            }
        }
    }
    for (inode, mut connection) in sockets {
        if connection.pid == 0 || connection.pid == u32::MAX {
            connection.pid = 0;
            let app = apps.entry(0).or_insert_with(|| {
                let mut app = Application {
                    name: "Unresolved socket owner".into(),
                    ..Default::default()
                };
                identify(&mut app);
                app
            });
            connection_id(&mut connection, app);
            connection.connection_id = digest(&format!("{}|{inode}", connection.connection_id));
        }
        result.connections.push(connection);
    }
    result.applications = apps.into_values().collect();
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_kernel_ipv4_and_ipv6_endianness() {
        assert_eq!(endpoint("0100007F:1F90"), Some(("127.0.0.1".into(), 8080)));
        assert_eq!(
            endpoint("00000000000000000000000001000000:0050"),
            Some(("::1".into(), 80))
        );
        assert!(endpoint("untrusted:port").is_none());
    }
}
