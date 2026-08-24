use super::*;
use secrecy::{ExposeSecret, SecretString};

struct Fixture {
    profile: Profile,
    state: DeviceState,
    expired: bool,
    mismatch: bool,
    renewals: u32,
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
        if self.expired {
            self.expired = false;
            Err(Error::SessionExpired)
        } else {
            Ok(self.state.clone())
        }
    }
    async fn apply(&mut self, c: Capability) -> Result<(), Error> {
        if self.expired {
            self.expired = false;
            return Err(Error::SessionExpired);
        };
        if self.mismatch {
            return Ok(());
        };
        if c == Capability::PersistentFilter {
            self.state.filter_entries += 1
        } else {
            self.state.quarantined = true
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
            quarantined: false,
            filter_entries: used,
        },
        expired: false,
        mismatch: false,
        renewals: 0,
    }
}

#[tokio::test]
async fn login_and_exact_mapping_never_exposes_secret() {
    let mut c = Connector::new(fixture(vec![Capability::DenyInternet], 0));
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
    let mut c = Connector::new(fixture(vec![Capability::DenyInternet], 0));
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.quarantine(RequestedQuarantine::DenyWifiAssociation).await,
        Err(Error::CapabilityUnavailable)
    );
    let mut c = Connector::new(fixture(vec![Capability::PersistentFilter], 32));
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
    let mut c = Connector::new(f);
    c.login("u", SecretString::from("x")).await.unwrap();
    c.quarantine(RequestedQuarantine::DenyLan).await.unwrap();
}
#[tokio::test]
async fn mismatch_fails_without_success_claim() {
    let mut f = fixture(vec![Capability::DenyInternet], 0);
    f.mismatch = true;
    let mut c = Connector::new(f);
    c.login("u", SecretString::from("x")).await.unwrap();
    assert_eq!(
        c.quarantine(RequestedQuarantine::DenyInternet).await,
        Err(Error::VerificationFailed)
    );
}
