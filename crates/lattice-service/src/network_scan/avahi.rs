//! Optional Linux avahi-daemon adapter, using its fixed, bounded browse utility.
use super::*;

#[derive(Serialize, ToSchema)]
pub struct DiscoveryCapabilities {
    pub mdns: &'static str,
    pub avahi: &'static str,
    pub icmp: &'static str,
    pub snmp: &'static str,
    pub smb: &'static str,
    pub netbios: &'static str,
    pub lldp_cdp: &'static str,
}
pub fn capabilities() -> DiscoveryCapabilities {
    DiscoveryCapabilities {
        mdns: "Multicast DNS / Bonjour on the selected local IPv4 links",
        avahi: if cfg!(target_os = "linux") {
            if std::path::Path::new("/usr/bin/avahi-browse").is_file() {
                "Installed; daemon availability is checked during discovery"
            } else {
                "Install avahi-daemon and avahi-utils to enable the Linux adapter"
            }
        } else {
            "Linux only; native Bonjour-compatible discovery is available here"
        },
        icmp: if cfg!(windows) {
            "Native IPv4 echo; IPv6 raw sockets depend on platform permissions"
        } else {
            "Echo uses platform ICMP socket permissions"
        },
        snmp: "Owner-supplied v2c or v3 SHA-256 / AES-128 credentials; read-only inventory",
        smb: "SMB 2/3 negotiation without sign-in or share access",
        netbios: "UDP node-status names",
        lldp_cdp: "Import an Ethernet PCAP captured on the relevant link; visibility depends on the switch and capture position",
    }
}
#[cfg(target_os = "linux")]
pub(super) async fn browse(targets: &[Target], cancel: &CancellationToken) -> Vec<Finding> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    let mut child = match tokio::process::Command::new("/usr/bin/avahi-browse")
        .args([
            "--all",
            "--resolve",
            "--parsable",
            "--terminate",
            "--ignore-local",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill().await;
        return vec![];
    };
    let mut bytes = vec![];
    let mut bounded = stdout.take(131_073);
    let read = bounded.read_to_end(&mut bytes);
    let result = tokio::select! {biased;()=cancel.cancelled()=>None,r=tokio::time::timeout(Duration::from_secs(6),read)=>r.ok()};
    let _ = child.kill().await;
    let _ = child.wait().await;
    if !matches!(result, Some(Ok(_))) || bytes.len() > 131_072 {
        return vec![];
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return vec![];
    };
    let Ok(inventory) = SystemInterfaceManager.snapshot() else {
        return vec![];
    };
    text.lines()
        .take(1024)
        .filter_map(parse)
        .filter_map(|row| {
            let interface = inventory.interfaces().find(|i| i.name == row.interface)?.id;
            let target = targets
                .iter()
                .find(|t| t.interface == interface && t.ip == row.ip)?;
            target.guard.authorize(interface, row.ip).ok()?;
            Some(Finding {
                device_id: Some(target.device.clone()),
                address: row.ip.to_string(),
                protocol: "avahi_mdns".into(),
                port: Some(row.port),
                status: "advertised".into(),
                service_hint: None,
                facts: BTreeMap::from([
                    ("name".into(), row.name),
                    ("service".into(), row.service),
                    ("hostname".into(), row.hostname),
                ]),
                observed_at: Utc::now().to_rfc3339(),
            })
        })
        .collect()
}
#[cfg(any(target_os = "linux", test))]
struct AvahiRow {
    interface: String,
    ip: IpAddr,
    port: u16,
    name: String,
    service: String,
    hostname: String,
}
#[cfg(any(target_os = "linux", test))]
fn parse(line: &str) -> Option<AvahiRow> {
    if line.len() > 4096 {
        return None;
    }
    let fields: Vec<_> = line.split(';').take(11).collect();
    if fields.len() != 10
        || fields[0] != "="
        || !["IPv4", "IPv6"].contains(&fields[2])
        || fields[5] != "local"
    {
        return None;
    }
    let decode = |s: &str| -> Option<String> {
        let mut out = vec![];
        let mut i = 0;
        let b = s.as_bytes();
        while i < b.len() {
            if b[i] == b'\\' {
                let n = std::str::from_utf8(b.get(i + 1..i + 4)?)
                    .ok()?
                    .parse::<u8>()
                    .ok()?;
                out.push(n);
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
            if out.len() > 256 {
                return None;
            }
        }
        let value = String::from_utf8(out).ok()?;
        (!value.chars().any(char::is_control)).then_some(value)
    };
    Some(AvahiRow {
        interface: decode(fields[1])?,
        ip: fields[7].parse().ok()?,
        port: fields[8].parse().ok().filter(|p| *p != 0)?,
        name: decode(fields[3])?,
        service: decode(fields[4])?,
        hostname: decode(fields[6])?,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_only_resolved_bounded_avahi_rows() {
        let r = parse(
            "=;eth0;IPv4;Desk\\032Light;_hap._tcp;local;desk.local;192.168.1.2;1234;\"model=x\"",
        )
        .unwrap();
        assert_eq!(r.name, "Desk Light");
        assert_eq!(r.interface, "eth0");
        assert_eq!(r.port, 1234);
        assert_eq!(r.service, "_hap._tcp");
        assert_eq!(r.hostname, "desk.local");
        assert!(r.ip.is_ipv4());
        assert!(parse("+;eth0;IPv4;x;_hap._tcp;local").is_none());
        assert!(parse("=;eth0;IPv4;bad\\010name;_hap._tcp;local;x;192.168.1.2;1;").is_none());
    }
}
