//! Strict local-link advertisement decoding. These frames supply untrusted hints.
use super::*;

type Advertisement = (Vec<(&'static str, String)>, i64);

pub(super) fn decode(
    i: &str,
    t: DateTime<Utc>,
    f: &[u8],
    options: &PassiveOptions,
) -> Result<Option<Vec<PassiveObservation>>, PassiveParseError> {
    let mut offset = 14;
    let mut kind = u16::from_be_bytes([f[12], f[13]]);
    for _ in 0..2 {
        if !matches!(kind, 0x8100 | 0x88a8) {
            break;
        }
        let tag = f
            .get(offset..offset + 4)
            .ok_or(PassiveParseError::Truncated)?;
        kind = u16::from_be_bytes([tag[2], tag[3]]);
        offset += 4;
    }
    let (protocol, values, ttl) = if kind == 0x88cc {
        if f[..5] != [1, 0x80, 0xc2, 0, 0] || ![0, 3, 14].contains(&f[5]) {
            return Err(PassiveParseError::Metadata);
        }
        let (v, ttl) = lldp(&f[offset..])?;
        ("lldp", v, ttl)
    } else if kind <= 1500 && f[..6] == [1, 0, 0x0c, 0xcc, 0xcc, 0xcc] {
        let payload = f
            .get(offset..offset + usize::from(kind))
            .ok_or(PassiveParseError::Truncated)?;
        if payload.get(..8) != Some(&[0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0]) {
            return Ok(None);
        }
        let (v, ttl) = cdp(&payload[8..])?;
        ("cdp", v, ttl)
    } else {
        return Ok(None);
    };
    if !options.metadata_enabled {
        return Ok(Some(vec![]));
    }
    if f[6] & 1 != 0 || f[6..12] == [0; 6] {
        return Err(PassiveParseError::Metadata);
    }
    let mut observations = observation(
        i,
        t,
        Some(mac(&f[6..12])?),
        None,
        protocol,
        values
            .into_iter()
            .map(|(key, value)| (key, value, EvidenceFamily::Service, ttl))
            .collect(),
    )?;
    for one in &mut observations {
        for fact in &mut one.facts {
            fact.expires_at = t.checked_add_signed(Duration::seconds(ttl));
        }
    }
    Ok(Some(observations))
}
fn text(b: &[u8]) -> Result<String, PassiveParseError> {
    if b.len() > 512 {
        return Err(PassiveParseError::Metadata);
    }
    Ok(String::from_utf8_lossy(b)
        .chars()
        .filter(|c| !c.is_control())
        .collect())
}
fn identifier(b: &[u8]) -> Result<String, PassiveParseError> {
    if b.len() < 2 || b.len() > 256 || !(1..=7).contains(&b[0]) {
        return Err(PassiveParseError::Metadata);
    }
    if b[1..].iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        text(&b[1..])
    } else {
        Ok(b[1..].iter().map(|v| format!("{v:02x}")).collect())
    }
}
fn lldp(b: &[u8]) -> Result<Advertisement, PassiveParseError> {
    if b.len() > 9000 {
        return Err(PassiveParseError::Metadata);
    }
    let mut offset = 0;
    let mut values = vec![];
    let mut ttl = 0;
    for index in 0..64 {
        let header = b
            .get(offset..offset + 2)
            .ok_or(PassiveParseError::Truncated)?;
        let header = u16::from_be_bytes([header[0], header[1]]);
        let kind = header >> 9;
        let len = (header & 511) as usize;
        offset += 2;
        let value = b
            .get(offset..offset + len)
            .ok_or(PassiveParseError::Truncated)?;
        offset += len;
        if index < 3 && kind != index + 1 {
            return Err(PassiveParseError::Metadata);
        }
        if index >= 3 && (1..=3).contains(&kind) {
            return Err(PassiveParseError::Metadata);
        }
        match kind {
            0 => {
                if len != 0 || index < 3 {
                    return Err(PassiveParseError::Metadata);
                }
                return Ok((values, ttl));
            }
            1 => values.push(("chassis_id", identifier(value)?)),
            2 => values.push(("port_id", identifier(value)?)),
            3 => {
                if len != 2 {
                    return Err(PassiveParseError::Metadata);
                }
                ttl = i64::from(u16::from_be_bytes([value[0], value[1]]));
                values.push(("ttl_seconds", ttl.to_string()));
            }
            4 => values.push(("port_description", text(value)?)),
            5 => values.push(("system_name", text(value)?)),
            6 => values.push(("system_description", text(value)?)),
            7 => {
                if len != 4 {
                    return Err(PassiveParseError::Metadata);
                }
                values.push((
                    "enabled_capabilities",
                    format!("0x{:04x}", u16::from_be_bytes([value[2], value[3]])),
                ));
            }
            _ => {}
        }
        if values.len() > 24 {
            return Err(PassiveParseError::Metadata);
        }
    }
    Err(PassiveParseError::Metadata)
}
fn checksum(b: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in b.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if b.len() % 2 == 1 {
        let last = u32::from(b[b.len() - 1]);
        sum += if last >= 128 { 0xff00 + last - 1 } else { last };
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn cdp(b: &[u8]) -> Result<Advertisement, PassiveParseError> {
    if b.len() < 4 || b.len() > 1500 || ![1, 2].contains(&b[0]) || checksum(b) != 0 {
        return Err(PassiveParseError::Metadata);
    }
    let ttl = i64::from(b[1]);
    let mut values = vec![("ttl_seconds", ttl.to_string())];
    let mut offset = 4;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        if offset == b.len() {
            return if seen.contains(&1) && seen.contains(&3) {
                Ok((values, ttl))
            } else {
                Err(PassiveParseError::Metadata)
            };
        }
        let h = b
            .get(offset..offset + 4)
            .ok_or(PassiveParseError::Truncated)?;
        let kind = u16::from_be_bytes([h[0], h[1]]);
        let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        if len < 4 {
            return Err(PassiveParseError::Metadata);
        }
        let value = b
            .get(offset + 4..offset + len)
            .ok_or(PassiveParseError::Truncated)?;
        offset += len;
        let key = match kind {
            1 => Some("device_id"),
            3 => Some("port_id"),
            5 => Some("software_version"),
            6 => Some("platform"),
            0x14 => Some("system_name"),
            _ => None,
        };
        if let Some(key) = key {
            if !seen.insert(kind) || value.is_empty() {
                return Err(PassiveParseError::Metadata);
            }
            values.push((key, text(value)?));
        }
        if kind == 4 {
            if value.len() != 4 {
                return Err(PassiveParseError::Metadata);
            }
            values.push((
                "capabilities",
                format!(
                    "0x{:08x}",
                    u32::from_be_bytes(value.try_into().map_err(|_| PassiveParseError::Metadata)?)
                ),
            ));
        }
        if values.len() > 24 {
            return Err(PassiveParseError::Metadata);
        }
    }
    Err(PassiveParseError::Metadata)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tlv(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut b = ((kind << 9) | value.len() as u16).to_be_bytes().to_vec();
        b.extend(value);
        b
    }
    #[test]
    fn lldp_requires_order_end_and_bounded_lengths() {
        let mut b = tlv(1, b"\x07switch");
        b.extend(tlv(2, b"\x05Gi1"));
        b.extend(tlv(3, &120u16.to_be_bytes()));
        b.extend(tlv(5, b"Office switch"));
        b.extend([0, 0]);
        let (v, ttl) = lldp(&b).unwrap();
        assert_eq!(ttl, 120);
        assert!(v.contains(&("system_name", "Office switch".into())));
        for end in 0..b.len() {
            assert!(lldp(&b[..end]).is_err());
        }
        b[0] = 4;
        assert!(lldp(&b).is_err());
    }
    #[test]
    fn cdp_verifies_checksum_and_rejects_truncated_tlvs() {
        let mut b = vec![2, 180, 0, 0];
        for (kind, v) in [(1u16, b"switch".as_slice()), (3, b"Gi1".as_slice())] {
            b.extend(kind.to_be_bytes());
            b.extend(((v.len() + 4) as u16).to_be_bytes());
            b.extend(v);
        }
        let sum = checksum(&b);
        b[2..4].copy_from_slice(&sum.to_be_bytes());
        assert!(cdp(&b).is_ok());
        for end in 0..b.len() {
            assert!(cdp(&b[..end]).is_err());
        }
        b[10] ^= 1;
        assert!(cdp(&b).is_err());
    }
    #[test]
    fn vlan_and_withdrawal_keep_capture_time_and_never_confirm_identity() {
        let mut f = vec![
            1, 0x80, 0xc2, 0, 0, 14, 0x02, 1, 2, 3, 4, 5, 0x81, 0, 0, 10, 0x88, 0xcc,
        ];
        f.extend(tlv(1, b"\x07switch"));
        f.extend(tlv(2, b"\x05Gi1"));
        f.extend(tlv(3, &[0, 0]));
        f.extend([0, 0]);
        let now = Utc::now();
        let rows = decode("fixture", now, &f, &PassiveOptions::default())
            .unwrap()
            .unwrap();
        assert_eq!(rows[0].protocol, "lldp");
        assert!(
            rows[0]
                .facts
                .iter()
                .all(|f| !f.owner_confirmed && f.expires_at == Some(now))
        );
    }
}
