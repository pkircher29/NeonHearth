//! Offline IEEE assignment lookup. An interface maker is not a product identity.
use serde::Serialize;
use std::sync::LazyLock;
use utoipa::ToSchema;

static ASSIGNMENTS: LazyLock<Vec<(&str, &str, &str)>> = LazyLock::new(|| {
    include_str!("../data/mac-assignments.tsv")
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            Some((parts.next()?, parts.next()?, parts.next()?))
        })
        .collect()
});
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct MacAssignment {
    pub mac_address: String,
    pub organization: Option<String>,
    pub registry: Option<String>,
    pub status: String,
}
pub fn lookup(mac: &str) -> MacAssignment {
    let mut result = MacAssignment {
        mac_address: mac.to_owned(),
        organization: None,
        registry: None,
        status: "unknown".into(),
    };
    if mac.len() != 17
        || !mac
            .split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return result;
    }
    let first = u8::from_str_radix(&mac[..2], 16).unwrap_or(255);
    if first & 1 != 0 {
        result.status = "group_address".into();
        return result;
    }
    if first & 2 != 0 {
        result.status = "locally_administered".into();
        return result;
    }
    let compact = mac.replace(':', "").to_ascii_uppercase();
    for len in [9, 7, 6] {
        if let Ok(index) = ASSIGNMENTS.binary_search_by_key(&&compact[..len], |r| r.0) {
            let (_, organization, registry) = ASSIGNMENTS[index];
            result.status = if organization == "Ambiguous IEEE assignment" {
                "ambiguous"
            } else {
                "assigned"
            }
            .into();
            if result.status == "assigned" {
                result.organization = Some(organization.to_owned());
            }
            result.registry = Some(registry.to_owned());
            break;
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_is_sorted_unique_and_longest_match_wins() {
        assert!(ASSIGNMENTS.len() > 40000);
        assert!(ASSIGNMENTS.windows(2).all(|w| w[0].0 < w[1].0));
        for (prefix, organization, registry) in
            ASSIGNMENTS.iter().filter(|r| r.0.len() == 9).take(30)
        {
            let value = format!("{prefix:0<12}");
            let mac = (0..6)
                .map(|n| &value[n * 2..n * 2 + 2])
                .collect::<Vec<_>>()
                .join(":");
            let found = lookup(&mac);
            assert_eq!(found.organization.as_deref(), Some(*organization));
            assert_eq!(found.registry.as_deref(), Some(*registry));
        }
    }
    #[test]
    fn randomized_group_and_invalid_macs_do_not_claim_a_manufacturer() {
        assert_eq!(lookup("02:00:00:00:00:01").status, "locally_administered");
        assert_eq!(lookup("FF:FF:FF:FF:FF:FF").status, "group_address");
        assert!(lookup("AA:BB:CC:DD:EE:GG").organization.is_none());
        assert!(
            lookup("48:55:19:00:00:01")
                .organization
                .unwrap()
                .to_lowercase()
                .contains("espressif")
        );
    }
}
