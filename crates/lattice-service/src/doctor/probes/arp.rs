//! ARP frame codec for the duplicate-address probe (RFC 5227 style): an ARP
//! probe asks "who has my address?" with a zero sender address, and any other
//! host that answers (or announces) the address is a claimant.

use super::model::Mac;
use std::net::Ipv4Addr;

/// Ethernet header (14) plus an IPv4-over-Ethernet ARP payload (28).
pub const FRAME_LEN: usize = 42;
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const BROADCAST: Mac = [0xff; 6];

/// An ARP probe for `target`: broadcast request, sender protocol address
/// `0.0.0.0` so receivers do not learn a mapping from it.
pub fn build_probe(own_mac: Mac, target: Ipv4Addr) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[0..6].copy_from_slice(&BROADCAST);
    frame[6..12].copy_from_slice(&own_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP);
    // Hardware type Ethernet, protocol type IPv4, address lengths 6 and 4.
    frame[14..16].copy_from_slice(&[0, 1]);
    frame[16..18].copy_from_slice(&[0x08, 0x00]);
    frame[18] = 6;
    frame[19] = 4;
    // Operation: request.
    frame[20..22].copy_from_slice(&[0, 1]);
    frame[22..28].copy_from_slice(&own_mac);
    // Sender protocol address stays 0.0.0.0; target hardware address is unknown.
    frame[38..42].copy_from_slice(&target.octets());
    frame
}

/// The hardware address of a host claiming `address` in `frame`, if it is one:
/// an ARP request or reply whose sender protocol address is `address` and
/// whose sender is not this machine.
pub fn parse_claim(frame: &[u8], address: Ipv4Addr, own_mac: Mac) -> Option<Mac> {
    if frame.len() < FRAME_LEN || frame[12..14] != ETHERTYPE_ARP {
        return None;
    }
    let well_formed = frame[14..16] == [0, 1]
        && frame[16..18] == [0x08, 0x00]
        && frame[18] == 6
        && frame[19] == 4;
    let operation = u16::from_be_bytes([frame[20], frame[21]]);
    if !well_formed || !(operation == 1 || operation == 2) {
        return None;
    }
    if frame[28..32] != address.octets() {
        return None;
    }
    let mut sender: Mac = [0; 6];
    sender.copy_from_slice(&frame[22..28]);
    let mut ethernet_source: Mac = [0; 6];
    ethernet_source.copy_from_slice(&frame[6..12]);
    let usable = sender != [0; 6] && sender != BROADCAST && sender[0] & 1 == 0;
    (usable && sender != own_mac && ethernet_source != own_mac).then_some(sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: Mac = [0x02, 0, 0, 0, 0, 0x01];
    const OTHER: Mac = [0x02, 0, 0, 0, 0, 0x99];
    const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

    /// An ARP packet from `sender` claiming `address`.
    fn claim(operation: u8, sender: Mac, address: Ipv4Addr) -> [u8; FRAME_LEN] {
        let mut frame = build_probe(sender, ADDRESS);
        frame[0..6].copy_from_slice(&OWN);
        frame[21] = operation;
        frame[28..32].copy_from_slice(&address.octets());
        frame
    }

    #[test]
    fn the_probe_is_a_broadcast_request_with_a_zero_sender_address() {
        let frame = build_probe(OWN, ADDRESS);
        assert_eq!(&frame[0..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &OWN);
        assert_eq!(&frame[12..14], &[0x08, 0x06]);
        assert_eq!(&frame[20..22], &[0, 1]);
        assert_eq!(&frame[22..28], &OWN);
        assert_eq!(&frame[28..32], &[0, 0, 0, 0]);
        assert_eq!(&frame[32..38], &[0; 6]);
        assert_eq!(&frame[38..42], &[192, 168, 1, 10]);
    }

    #[test]
    fn another_hosts_reply_or_announcement_for_the_address_is_a_claim() {
        assert_eq!(
            parse_claim(&claim(2, OTHER, ADDRESS), ADDRESS, OWN),
            Some(OTHER)
        );
        assert_eq!(
            parse_claim(&claim(1, OTHER, ADDRESS), ADDRESS, OWN),
            Some(OTHER)
        );
    }

    #[test]
    fn our_own_frames_other_addresses_and_junk_are_not_claims() {
        // Our own outgoing frame looped back to the socket.
        assert_eq!(parse_claim(&claim(2, OWN, ADDRESS), ADDRESS, OWN), None);
        // Someone claiming a different address.
        assert_eq!(
            parse_claim(
                &claim(2, OTHER, Ipv4Addr::new(192, 168, 1, 11)),
                ADDRESS,
                OWN
            ),
            None
        );
        // Our own probe: sender protocol address is zero.
        assert_eq!(
            parse_claim(&build_probe(OTHER, ADDRESS), ADDRESS, OWN),
            None
        );
        // Unusable sender hardware addresses.
        for sender in [[0; 6], [0xff; 6], [0x03, 0, 0, 0, 0, 1]] {
            assert_eq!(parse_claim(&claim(2, sender, ADDRESS), ADDRESS, OWN), None);
        }
        // Not ARP, wrong operation, truncated.
        let mut not_arp = claim(2, OTHER, ADDRESS);
        not_arp[12] = 0x08;
        not_arp[13] = 0x00;
        assert_eq!(parse_claim(&not_arp, ADDRESS, OWN), None);
        assert_eq!(parse_claim(&claim(3, OTHER, ADDRESS), ADDRESS, OWN), None);
        assert_eq!(
            parse_claim(&claim(2, OTHER, ADDRESS)[..30], ADDRESS, OWN),
            None
        );
    }
}
