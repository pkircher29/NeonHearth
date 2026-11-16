//! Minimal DNS wire codec for the Doctor's resolver probe: one `A` question
//! out, rcode and addresses back. No name compression is ever emitted and
//! every length read from a reply is bounds-checked.

use lattice_doctor::probe::{DnsFailureReason, ProbeResponse};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const HEADER_LEN: usize = 12;
/// Longest name walk (labels plus pointer hops) before a reply is rejected.
const MAX_NAME_STEPS: usize = 128;
const FLAG_RESPONSE: u16 = 0x8000;

/// Why a query could not be built or a reply could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsCodecError {
    InvalidName,
    Malformed,
    WrongTransaction,
    NotAResponse,
}

impl std::fmt::Display for DnsCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "the DNS probe name is not a valid host name",
            Self::Malformed => "the DNS reply was malformed",
            Self::WrongTransaction => "the DNS reply answered a different query",
            Self::NotAResponse => "the DNS datagram was not a response",
        })
    }
}

/// What a well-formed reply says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsReply {
    Answer(Vec<IpAddr>),
    Failure(DnsFailureReason),
}

/// A recursive `A` query for `name` with transaction id `id`.
pub fn build_query(id: u16, name: &str) -> Result<Vec<u8>, DnsCodecError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(DnsCodecError::InvalidName);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    // Standard query, recursion desired.
    out.extend_from_slice(&[0x01, 0x00]);
    // One question, no other records.
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        let length = u8::try_from(label.len()).map_err(|_| DnsCodecError::InvalidName)?;
        if !valid {
            return Err(DnsCodecError::InvalidName);
        }
        out.push(length);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Interprets one reply datagram for the query with transaction id `id`.
///
/// Failure rcodes are reported from the header alone; the answer section is
/// only parsed (and only trusted) for `NOERROR`.
pub fn parse_reply(reply: &[u8], id: u16) -> Result<DnsReply, DnsCodecError> {
    if reply.len() < HEADER_LEN {
        return Err(DnsCodecError::Malformed);
    }
    if u16::from_be_bytes([reply[0], reply[1]]) != id {
        return Err(DnsCodecError::WrongTransaction);
    }
    let flags = u16::from_be_bytes([reply[2], reply[3]]);
    if flags & FLAG_RESPONSE == 0 {
        return Err(DnsCodecError::NotAResponse);
    }
    match flags & 0x000f {
        0 => {}
        // NXDOMAIN: the name does not exist.
        3 => return Ok(DnsReply::Failure(DnsFailureReason::NoAnswer)),
        5 => return Ok(DnsReply::Failure(DnsFailureReason::Refused)),
        // SERVFAIL, FORMERR, NOTIMP and anything unassigned.
        _ => return Ok(DnsReply::Failure(DnsFailureReason::ServFail)),
    }
    let questions = u16::from_be_bytes([reply[4], reply[5]]);
    let answers = u16::from_be_bytes([reply[6], reply[7]]);
    let mut position = HEADER_LEN;
    for _ in 0..questions {
        position = skip_name(reply, position)?;
        position = position
            .checked_add(4)
            .filter(|end| *end <= reply.len())
            .ok_or(DnsCodecError::Malformed)?;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        position = skip_name(reply, position)?;
        let fixed = reply
            .get(position..position + 10)
            .ok_or(DnsCodecError::Malformed)?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let data_len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        position += 10;
        let data = reply
            .get(position..position + data_len)
            .ok_or(DnsCodecError::Malformed)?;
        position += data_len;
        if class != CLASS_IN {
            continue;
        }
        match (record_type, data_len) {
            (TYPE_A, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }
    if addresses.is_empty() {
        Ok(DnsReply::Failure(DnsFailureReason::NoAnswer))
    } else {
        Ok(DnsReply::Answer(addresses))
    }
}

/// Position just past the (possibly compressed) name starting at `start`.
fn skip_name(message: &[u8], start: usize) -> Result<usize, DnsCodecError> {
    let mut position = start;
    for _ in 0..MAX_NAME_STEPS {
        let length = *message.get(position).ok_or(DnsCodecError::Malformed)?;
        if length == 0 {
            return Ok(position + 1);
        }
        if length & 0xc0 == 0xc0 {
            // A compression pointer ends the name in place.
            message.get(position + 1).ok_or(DnsCodecError::Malformed)?;
            return Ok(position + 2);
        }
        if length & 0xc0 != 0 {
            return Err(DnsCodecError::Malformed);
        }
        position += 1 + usize::from(length);
    }
    Err(DnsCodecError::Malformed)
}

/// The Doctor response for a well-formed reply received after `latency_ms`.
pub fn reply_response(reply: DnsReply, latency_ms: f64) -> ProbeResponse {
    match reply {
        DnsReply::Answer(addresses) => ProbeResponse::DnsAnswer {
            addresses: addresses.iter().map(IpAddr::to_string).collect(),
            latency_ms,
        },
        DnsReply::Failure(reason) => ProbeResponse::DnsFailure { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u16 = 0x1234;

    /// A reply to `build_query(ID, "example.com")` with the given rcode and
    /// raw answer records appended.
    fn reply(rcode: u8, answer_count: u16, records: &[u8]) -> Vec<u8> {
        let mut message = build_query(ID, "example.com").unwrap();
        message[2] = 0x81;
        message[3] = 0x80 | rcode;
        message[6..8].copy_from_slice(&answer_count.to_be_bytes());
        message.extend_from_slice(records);
        message
    }

    /// `example.com A 93.184.216.34`, name compressed to the question.
    const A_RECORD: [u8; 16] = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34];

    #[test]
    fn the_query_is_a_recursive_a_question() {
        let query = build_query(ID, "example.com").unwrap();
        let mut expected = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(b"\x07example\x03com\x00");
        expected.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(query, expected);
        assert_eq!(build_query(ID, "example.com.").unwrap(), expected);
    }

    #[test]
    fn hostile_names_never_reach_the_wire() {
        let long_label = "a".repeat(64);
        let long_name = format!("{}com", "a.".repeat(130));
        for bad in [
            "",
            ".",
            "a..b",
            "-x y.example",
            "a b.example",
            "bad/name.example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert_eq!(
                build_query(ID, bad),
                Err(DnsCodecError::InvalidName),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn an_answer_with_a_compressed_name_yields_its_addresses() {
        assert_eq!(
            parse_reply(&reply(0, 1, &A_RECORD), ID),
            Ok(DnsReply::Answer(vec!["93.184.216.34".parse().unwrap()]))
        );
    }

    #[test]
    fn a_and_aaaa_records_are_kept_and_other_types_are_skipped() {
        let mut records = Vec::new();
        // CNAME (type 5) with a 2-byte pointer as data.
        records.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c]);
        records.extend_from_slice(&A_RECORD);
        records.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        records.extend_from_slice(&[
            0x26, 0x06, 0x28, 0, 0x02, 0x20, 0, 1, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
        ]);
        let parsed = parse_reply(&reply(0, 3, &records), ID).unwrap();
        assert_eq!(
            parsed,
            DnsReply::Answer(vec![
                "93.184.216.34".parse().unwrap(),
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
            ])
        );
    }

    #[test]
    fn failure_rcodes_map_to_the_doctors_failure_reasons() {
        for (rcode, reason) in [
            (3, DnsFailureReason::NoAnswer),
            (5, DnsFailureReason::Refused),
            (2, DnsFailureReason::ServFail),
            (1, DnsFailureReason::ServFail),
            (4, DnsFailureReason::ServFail),
        ] {
            assert_eq!(
                parse_reply(&reply(rcode, 0, &[]), ID),
                Ok(DnsReply::Failure(reason)),
                "rcode {rcode}"
            );
        }
        assert_eq!(
            parse_reply(&reply(0, 0, &[]), ID),
            Ok(DnsReply::Failure(DnsFailureReason::NoAnswer))
        );
    }

    #[test]
    fn foreign_truncated_and_non_response_datagrams_are_rejected() {
        let good = reply(0, 1, &A_RECORD);
        assert_eq!(
            parse_reply(&good, ID + 1),
            Err(DnsCodecError::WrongTransaction)
        );
        assert_eq!(parse_reply(&good[..8], ID), Err(DnsCodecError::Malformed));
        assert_eq!(
            parse_reply(&good[..good.len() - 3], ID),
            Err(DnsCodecError::Malformed)
        );
        let mut query = build_query(ID, "example.com").unwrap();
        assert_eq!(parse_reply(&query, ID), Err(DnsCodecError::NotAResponse));
        // A name that never terminates is bounded, not followed forever.
        query[2] = 0x81;
        query[3] = 0x80;
        for byte in &mut query[12..] {
            *byte = 1;
        }
        assert!(parse_reply(&query, ID).is_err());
    }

    #[test]
    fn replies_become_doctor_responses() {
        assert_eq!(
            reply_response(DnsReply::Answer(vec!["10.0.0.9".parse().unwrap()]), 4.5),
            ProbeResponse::DnsAnswer {
                addresses: vec!["10.0.0.9".to_owned()],
                latency_ms: 4.5
            }
        );
        assert_eq!(
            reply_response(DnsReply::Failure(DnsFailureReason::Refused), 1.0),
            ProbeResponse::DnsFailure {
                reason: DnsFailureReason::Refused
            }
        );
    }
}
