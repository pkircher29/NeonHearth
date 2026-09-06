//! RFC 6762 one-shot discovery. Replies are advisory and restricted to approved peers.
use super::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, RecordType},
};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct MdnsResult {
    pub address: IpAddr,
    pub facts: Vec<(String, String)>,
}

pub async fn browse(
    guard: &TargetGuard,
    interface: InterfaceId,
    target: IpAddr,
) -> Result<Vec<MdnsResult>, ActiveError> {
    let binding = guard
        .authorized_binding(interface, target)
        .map_err(|_| ActiveError::Unauthorized)?;
    let IpAddr::V4(source) = binding.source else {
        return Err(ActiveError::Unavailable);
    };
    let socket = UdpSocket::bind(binding.source_socket())
        .await
        .map_err(|_| ActiveError::Unavailable)?;
    pin_socket_to_interface(&socket, binding)?;
    let raw = socket2::SockRef::from(&socket);
    raw.set_multicast_if_v4(&source)
        .map_err(|_| ActiveError::Unavailable)?;
    raw.set_multicast_ttl_v4(255)
        .map_err(|_| ActiveError::Unavailable)?;
    let mut types = BTreeSet::from(["_services._dns-sd._udp.local.".to_owned()]);
    let mut results: BTreeMap<IpAddr, Vec<(String, String)>> = BTreeMap::new();
    for _ in 0..2 {
        let mut nonce = [0; 2];
        getrandom::fill(&mut nonce).map_err(|_| ActiveError::Internal)?;
        let id = u16::from_ne_bytes(nonce);
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        for name in types.iter().take(8) {
            query.add_query(Query::query(
                Name::from_ascii(name).map_err(|_| ActiveError::Protocol)?,
                RecordType::PTR,
            ));
        }
        let bytes = query.to_vec().map_err(|_| ActiveError::Protocol)?;
        guard
            .authorize(interface, target)
            .map_err(|_| ActiveError::Unauthorized)?;
        socket
            .send_to(&bytes, (Ipv4Addr::new(224, 0, 0, 251), 5353))
            .await
            .map_err(|_| ActiveError::Network)?;
        let end = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut next_types = BTreeSet::new();
        for _ in 0..128 {
            let received =
                tokio::time::timeout_at(end, recv_bounded_datagram(&socket, MAX_RESPONSE_BYTES))
                    .await;
            let Ok(Ok((bytes, peer))) = received else {
                break;
            };
            if peer.port() != 5353 || guard.authorize(interface, peer.ip()).is_err() {
                continue;
            }
            let Ok(message) = Message::from_vec(&bytes) else {
                continue;
            };
            if message.id != id
                || message.message_type != MessageType::Response
                || message.truncation
                || message.queries != query.queries
            {
                continue;
            }
            let Ok(facts) = message_facts(&message) else {
                continue;
            };
            for record in &message.answers {
                if record.name.to_ascii() == "_services._dns-sd._udp.local."
                    && let RData::PTR(ptr) = &record.data
                {
                    let name = ptr.0.to_ascii();
                    if service_type(&name) && next_types.len() < 8 {
                        next_types.insert(name);
                    }
                }
            }
            let entries = results.entry(peer.ip()).or_default();
            for fact in facts {
                if entries.len() < 24 && !entries.contains(&fact) {
                    entries.push(fact);
                }
            }
            if results.len() >= 1024 {
                break;
            }
        }
        if next_types.is_empty() {
            break;
        }
        types = next_types;
    }
    Ok(results
        .into_iter()
        .filter(|(_, facts)| !facts.is_empty())
        .map(|(address, facts)| MdnsResult { address, facts })
        .collect())
}
fn service_type(name: &str) -> bool {
    name.len() <= 128
        && name.starts_with('_')
        && (name.ends_with("._tcp.local.") || name.ends_with("._udp.local."))
}
pub(super) fn message_facts(message: &Message) -> Result<Vec<(String, String)>, ActiveError> {
    if message.answers.len() + message.additionals.len() > 64 {
        return Err(ActiveError::ResponseLimit);
    }
    let mut facts = vec![];
    for record in message.answers.iter().chain(&message.additionals) {
        if record.ttl == 0 || !record.name.to_ascii().ends_with(".local.") {
            continue;
        }
        let value = match &record.data {
            RData::PTR(ptr) => Some(("service", ptr.0.to_ascii())),
            RData::SRV(srv) => Some(("endpoint", format!("{}:{}", srv.target, srv.port))),
            RData::TXT(txt) => {
                for entry in txt.txt_data.iter().take(8) {
                    if let Ok(text) = std::str::from_utf8(entry)
                        && let Some((key, value)) = text.split_once('=')
                        && ["md", "model", "manufacturer", "ty", "fn", "am"].contains(&key)
                        && value.len() <= 256
                        && facts.len() < 24
                    {
                        facts.push((
                            key.into(),
                            value.chars().filter(|c| !c.is_control()).collect(),
                        ));
                    }
                }
                None
            }
            _ => None,
        };
        if let Some((key, value)) = value
            && value.len() <= MAX_FACT_VALUE_BYTES
            && facts.len() < 24
        {
            facts.push((key.into(), value));
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_service_followups() {
        assert!(service_type("_hap._tcp.local."));
        assert!(!service_type("http://internet.example/"));
        assert!(!service_type(&format!("_{}._tcp.local.", "x".repeat(200))));
    }
}
