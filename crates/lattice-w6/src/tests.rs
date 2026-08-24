use super::*;
use secrecy::{ExposeSecret, SecretString};

struct Fixture {
    profile: Profile,
    state: DeviceState,
    expired: bool,
    mismatch: bool,
    renewals: u32,
    expire_on: Vec<&'static str>,
}
#[async_trait]
impl Transport for Fixture {
    async fn login(&mut self, _: &str, password: &SecretString) -> Result<(), Error> {
        if password.expose_secret() == "bad" {
            Err(Error::Authentication)
        } else {
            Ok(())
        }
    }
    async fn renew(&mut self) -> Result<(), Error> {
        self.renewals += 1;
        self.expired = false;
        Ok(())
    }
    async fn profile(&mut self) -> Result<Profile, Error> {
        Ok(self.profile.clone())
    }
    async fn state(&mut self) -> Result<DeviceState, Error> {
        if self.expired || self.expire_on.first() == Some(&"state") {
            self.expired = false;
            if self.expire_on.first() == Some(&"state") {
                self.expire_on.remove(0);
            }
            Err(Error::SessionExpired)
        } else {
            Ok(self.state.clone())
        }
    }
    async fn apply(&mut self, c: Capability) -> Result<(), Error> {
        if self.expired || self.expire_on.first() == Some(&"apply") {
            self.expired = false;
            if self.expire_on.first() == Some(&"apply") {
                self.expire_on.remove(0);
            }
            return Err(Error::SessionExpired);
        };
        if self.mismatch {
            return Ok(());
        };
        if c == Capability::PersistentFilter {
            self.state.filter_entries += 1;
            self.state.persistent_filter = true;
        } else {
            match c {
                Capability::DisconnectNow => self.state.disconnect_now = true,
                Capability::DenyWifiAssociation => self.state.deny_wifi_association = true,
                Capability::DenyInternet => self.state.deny_internet = true,
                Capability::DenyLan => self.state.deny_lan = true,
                Capability::PersistentFilter => self.state.persistent_filter = true,
            }
        };
        Ok(())
    }
}
fn fixture(c: Vec<Capability>, used: u32) -> Fixture {
    Fixture {
        profile: Profile {
            fingerprint: "fw-1".into(),
            capabilities: c,
            filter_capacity: Some(32),
        },
        state: DeviceState {
            filter_entries: used,
            disconnect_now: false,
            deny_wifi_association: false,
            deny_internet: false,
            deny_lan: false,
            persistent_filter: false,
        },
        expired: false,
        mismatch: false,
        renewals: 0,
        expire_on: Vec::new(),
    }
}

fn trusted(f: Fixture) -> Connector<Fixture> {
    let profile = f.profile.clone();
    Connector::with_profiles(f, vec![profile])
}

#[tokio::test]
async fn login_and_exact_mapping_never_exposes_secret() {
    let mut c = trusted(fixture(vec![Capability::DenyInternet], 0));
    c.login("u", SecretString::from("secret")).await.unwrap();
    let r = c
        .quarantine(RequestedQuarantine::DenyInternet)
        .await
        .unwrap();
    assert_eq!(r.capability, Capability::DenyInternet);
    assert!(!format!("{c:?}").contains("secret"));
    assert!(!format!("{:?}", Error::Authentication).contains("secret"));
}
#[tokio::test]
async fn unavailable_and_capacity_are_rejected() {
    let mut c = trusted(fixture(vec![Capability::DenyInternet], 0));
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.quarantine(RequestedQuarantine::DenyWifiAssociation).await,
        Err(Error::CapabilityUnavailable)
    );
    let mut c = trusted(fixture(vec![Capability::PersistentFilter], 32));
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.quarantine(RequestedQuarantine::PersistentFilter).await,
        Err(Error::CapacityExhausted)
    );
}
#[tokio::test]
async fn renewal_is_once_and_readback_verified() {
    let mut f = fixture(vec![Capability::DenyLan], 0);
    f.expired = true;
    let mut c = trusted(f);
    c.login("u", SecretString::from("x")).await.unwrap();
    c.quarantine(RequestedQuarantine::DenyLan).await.unwrap();
    let f = c.into_transport();
    assert_eq!(f.renewals, 1);
}
#[tokio::test]
async fn mismatch_fails_without_success_claim() {
    let mut f = fixture(vec![Capability::DenyInternet], 0);
    f.mismatch = true;
    let mut c = trusted(f);
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.quarantine(RequestedQuarantine::DenyInternet).await,
        Err(Error::VerificationFailed)
    );
}

#[tokio::test]
async fn prior_internet_denial_does_not_verify_wifi_or_lan() {
    let mut f = fixture(
        vec![Capability::DenyWifiAssociation, Capability::DenyLan],
        0,
    );
    f.state.deny_internet = true;
    f.mismatch = true;
    let mut c = trusted(f);
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.quarantine(RequestedQuarantine::DenyWifiAssociation).await,
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        c.quarantine(RequestedQuarantine::DenyLan).await,
        Err(Error::VerificationFailed)
    );
}

#[tokio::test]
async fn unknown_fingerprint_is_manual_required_and_drift_is_read_only() {
    let mut f = fixture(vec![Capability::DenyInternet], 0);
    f.profile.fingerprint = "fw-unknown".into();
    let mut c = Connector::new(f);
    assert_eq!(
        c.login("u", SecretString::from("x")).await,
        Err(Error::ManualRequired)
    );
    assert_eq!(c.discovery_status(), DiscoveryStatus::ManualRequired);

    let mut f = fixture(vec![Capability::DenyInternet], 0);
    f.profile.capabilities.push(Capability::DenyLan);
    let mut c = Connector::with_profiles(
        f,
        vec![Profile {
            fingerprint: "fw-1".into(),
            capabilities: vec![Capability::DenyInternet],
            filter_capacity: Some(32),
        }],
    );
    assert_eq!(
        c.login("u", SecretString::from("x")).await,
        Err(Error::ReadOnly)
    );
    assert_eq!(c.discovery_status(), DiscoveryStatus::ReadOnly);
}

#[tokio::test]
async fn one_renewal_budget_covers_state_apply_readback() {
    let mut f = fixture(vec![Capability::DenyInternet], 0);
    f.expire_on = vec!["apply", "state"];
    let mut c = trusted(f);
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.quarantine(RequestedQuarantine::DenyInternet).await,
        Err(Error::SessionExpired)
    );
    let f = c.into_transport();
    assert_eq!(f.renewals, 1);
}

#[tokio::test]
async fn persistent_filter_limit_is_fail_closed_and_surfaces_remaining() {
    let mut c = trusted(fixture(vec![Capability::PersistentFilter], 31));
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.persistent_filter_capacity().await.unwrap(),
        FilterCapacity {
            used: 31,
            remaining: 1,
            limit: 32
        }
    );
    let report = c
        .quarantine(RequestedQuarantine::PersistentFilter)
        .await
        .unwrap();
    assert_eq!((report.used, report.remaining), (32, Some(0)));
    let mut c = trusted(fixture(vec![Capability::PersistentFilter], 32));
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.persistent_filter_capacity().await.unwrap(),
        FilterCapacity {
            used: 32,
            remaining: 0,
            limit: 32
        }
    );
    assert_eq!(
        c.quarantine(RequestedQuarantine::PersistentFilter).await,
        Err(Error::CapacityExhausted)
    );
    for cap in [None, Some(0), Some(33)] {
        let mut f = fixture(vec![Capability::PersistentFilter], 0);
        f.profile.filter_capacity = cap;
        let mut c = Connector::with_profiles(
            f,
            vec![Profile {
                fingerprint: "fw-1".into(),
                capabilities: vec![Capability::PersistentFilter],
                filter_capacity: Some(32),
            }],
        );
        assert_eq!(
            c.login("u", SecretString::from("x")).await,
            Err(Error::ReadOnly)
        );
    }
}
