//! ICMP helpers: the echo packet codec used with Linux ping sockets, and the
//! interpretation of Windows IP Helper echo status codes.

/// Echo request packet for a Linux ping socket (no IP header). The kernel
/// overwrites the identifier and recomputes the checksum for such sockets, but
/// a correct packet keeps the codec honest.
#[cfg(any(target_os = "linux", test))]
pub fn build_echo_request(identifier: u16, sequence: u16, payload_len: usize) -> Vec<u8> {
    const ECHO_REQUEST: u8 = 8;
    let mut packet = Vec::with_capacity(8 + payload_len);
    packet.extend_from_slice(&[ECHO_REQUEST, 0, 0, 0]);
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend((0..payload_len).map(|index| (index % 251) as u8));
    let sum = checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// The RFC 1071 internet checksum.
#[cfg(any(target_os = "linux", test))]
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The sequence number of an echo reply, or `None` for anything else.
#[cfg(any(target_os = "linux", test))]
pub fn echo_reply_sequence(packet: &[u8]) -> Option<u16> {
    const ECHO_REPLY: u8 = 0;
    if packet.len() < 8 || packet[0] != ECHO_REPLY || packet[1] != 0 {
        return None;
    }
    Some(u16::from_be_bytes([packet[6], packet[7]]))
}

/// What a Windows `IcmpSendEcho2` status means for the Doctor.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpStatus {
    /// `IP_SUCCESS`: an echo reply arrived.
    Reply,
    /// `IP_PACKET_TOO_BIG`: don't-fragment packet exceeds a link on the path.
    PacketTooBig,
    /// The request timed out, was reported unreachable, or its TTL expired:
    /// no echo reply came back.
    NoReply,
    /// A failure of the call itself (no resources, media disconnected,
    /// general failure, ...).
    Failure(u32),
}

/// Classifies an IP Helper status code (`IP_STATUS_BASE` is 11000).
#[cfg(any(windows, test))]
pub fn classify_status(status: u32) -> IcmpStatus {
    const IP_SUCCESS: u32 = 0;
    const IP_DEST_NET_UNREACHABLE: u32 = 11002;
    const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
    const IP_PACKET_TOO_BIG: u32 = 11009;
    const IP_REQ_TIMED_OUT: u32 = 11010;
    const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
    const IP_TTL_EXPIRED_REASSEM: u32 = 11014;
    match status {
        IP_SUCCESS => IcmpStatus::Reply,
        IP_PACKET_TOO_BIG => IcmpStatus::PacketTooBig,
        IP_DEST_NET_UNREACHABLE..=IP_DEST_PORT_UNREACHABLE
        | IP_REQ_TIMED_OUT
        | IP_TTL_EXPIRED_TRANSIT
        | IP_TTL_EXPIRED_REASSEM => IcmpStatus::NoReply,
        other => IcmpStatus::Failure(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checksum_matches_the_rfc_1071_example() {
        // RFC 1071 section 3: 00 01 f2 03 f4 f5 f6 f7 sums to ddf2; its
        // complement is 220d.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        // An odd trailing byte is padded on the right.
        assert_eq!(checksum(&[0x01]), !0x0100);
    }

    #[test]
    fn an_echo_request_verifies_to_zero_and_carries_its_identifiers() {
        for payload in [0usize, 1, 56, 1472] {
            let packet = build_echo_request(0xbeef, 7, payload);
            assert_eq!(packet.len(), 8 + payload);
            assert_eq!(packet[0], 8);
            assert_eq!(&packet[4..6], &0xbeefu16.to_be_bytes());
            assert_eq!(&packet[6..8], &7u16.to_be_bytes());
            // A packet with its checksum filled in sums (complemented) to 0.
            assert_eq!(checksum(&packet), 0, "payload {payload}");
        }
    }

    #[test]
    fn only_well_formed_echo_replies_yield_a_sequence() {
        let mut reply = build_echo_request(1, 0x1234, 8);
        assert_eq!(echo_reply_sequence(&reply), None, "a request is not a reply");
        reply[0] = 0;
        assert_eq!(echo_reply_sequence(&reply), Some(0x1234));
        reply[1] = 3;
        assert_eq!(echo_reply_sequence(&reply), None);
        assert_eq!(echo_reply_sequence(&[0, 0, 0]), None);
        // Destination unreachable (type 3) is not an echo reply.
        assert_eq!(echo_reply_sequence(&[3, 1, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn windows_status_codes_separate_replies_silence_and_call_failures() {
        assert_eq!(classify_status(0), IcmpStatus::Reply);
        assert_eq!(classify_status(11009), IcmpStatus::PacketTooBig);
        for status in [11002, 11003, 11004, 11005, 11010, 11013, 11014] {
            assert_eq!(classify_status(status), IcmpStatus::NoReply, "{status}");
        }
        for status in [11001, 11006, 11018, 11025, 11050, 87] {
            assert_eq!(
                classify_status(status),
                IcmpStatus::Failure(status),
                "{status}"
            );
        }
    }
}
