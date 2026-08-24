use async_trait::async_trait;
use lattice_domain::{DeviceId, RequestedAction};
use lattice_service::policy::{EnforcementResult, PolicyActuator, W6PolicyActuator};
use lattice_w6::{Capability, Connector, DeviceState, Profile, Transport};
use secrecy::SecretString;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Fixture(Arc<Mutex<DeviceState>>);

struct FailureFixture;

#[async_trait]
impl Transport for Fixture {
    async fn login(&mut self, _: &str, _: &SecretString) -> Result<(), lattice_w6::Error> {
        Ok(())
    }
    async fn renew(&mut self) -> Result<(), lattice_w6::Error> {
        Ok(())
    }
    async fn profile(&mut self) -> Result<Profile, lattice_w6::Error> {
        Ok(Profile {
            fingerprint: "fw-1".into(),
            capabilities: vec![
                Capability::DisconnectNow,
                Capability::DenyWifiAssociation,
                Capability::DenyInternet,
                Capability::DenyLan,
                Capability::PersistentFilter,
            ],
            filter_capacity: Some(32),
        })
    }
    async fn state(&mut self) -> Result<DeviceState, lattice_w6::Error> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn apply(&mut self, capability: Capability) -> Result<(), lattice_w6::Error> {
        let mut s = self.0.lock().unwrap();
        match capability {
            Capability::DenyInternet => s.deny_internet = true,
            Capability::PersistentFilter => {
                s.persistent_filter = true;
                s.filter_entries += 1
            }
            _ => {}
        }
        Ok(())
    }
    async fn restore(&mut self, previous: DeviceState) -> Result<(), lattice_w6::Error> {
        *self.0.lock().unwrap() = previous;
        Ok(())
    }
}

#[async_trait]
impl Transport for FailureFixture {
    async fn login(&mut self, _: &str, _: &SecretString) -> Result<(), lattice_w6::Error> {
        Ok(())
    }
    async fn renew(&mut self) -> Result<(), lattice_w6::Error> {
        Ok(())
    }
    async fn profile(&mut self) -> Result<Profile, lattice_w6::Error> {
        Ok(Profile {
            fingerprint: "fw-1".into(),
            capabilities: vec![
                Capability::DisconnectNow,
                Capability::DenyWifiAssociation,
                Capability::DenyInternet,
                Capability::DenyLan,
                Capability::PersistentFilter,
            ],
            filter_capacity: Some(32),
        })
    }
    async fn state(&mut self) -> Result<DeviceState, lattice_w6::Error> {
        Err(lattice_w6::Error::Transport)
    }
    async fn apply(&mut self, _: Capability) -> Result<(), lattice_w6::Error> {
        Ok(())
    }
}

#[tokio::test]
async fn maps_policy_actions_and_only_verified_mutations_succeed() {
    let state = Arc::new(Mutex::new(DeviceState {
        disconnect_now: false,
        deny_wifi_association: false,
        deny_internet: false,
        deny_lan: false,
        persistent_filter: false,
        filter_entries: 0,
    }));
    let mut connector = Connector::new(Fixture(state.clone()));
    connector
        .login("owner", SecretString::new("fixture".into()))
        .await
        .unwrap();
    let actuator = W6PolicyActuator::new(connector);
    assert_eq!(
        actuator
            .enforce(DeviceId::new(), RequestedAction::Quarantine)
            .await,
        EnforcementResult::Verified
    );
    assert!(state.lock().unwrap().deny_internet);
    assert_eq!(
        actuator
            .enforce(DeviceId::new(), RequestedAction::PermanentBan)
            .await,
        EnforcementResult::Verified
    );
    assert!(state.lock().unwrap().persistent_filter);
    assert_eq!(
        actuator
            .undo(DeviceId::new(), RequestedAction::Quarantine)
            .await,
        EnforcementResult::ManualRequired,
        "undo is scoped to the exact device that was verified"
    );
}

#[tokio::test]
async fn verified_undo_restores_the_saved_pre_enforcement_state() -> Result<(), lattice_w6::Error> {
    let device = DeviceId::new();
    let state = Arc::new(Mutex::new(DeviceState {
        disconnect_now: false,
        deny_wifi_association: false,
        deny_internet: false,
        deny_lan: false,
        persistent_filter: false,
        filter_entries: 0,
    }));
    let mut connector = Connector::new(Fixture(state.clone()));
    connector
        .login("owner", SecretString::new("fixture".into()))
        .await?;
    let actuator = W6PolicyActuator::new(connector);
    assert_eq!(
        actuator.enforce(device, RequestedAction::Quarantine).await,
        EnforcementResult::Verified
    );
    assert_eq!(
        actuator.undo(device, RequestedAction::Quarantine).await,
        EnforcementResult::Verified
    );
    assert!(!state.lock().unwrap().deny_internet);
    Ok(())
}

#[tokio::test]
async fn untrusted_connector_is_manual_and_transport_failures_are_failed() {
    let manual_state = Arc::new(Mutex::new(DeviceState {
        disconnect_now: false,
        deny_wifi_association: false,
        deny_internet: false,
        deny_lan: false,
        persistent_filter: false,
        filter_entries: 0,
    }));
    let manual = W6PolicyActuator::new(Connector::new(Fixture(manual_state)));
    assert_eq!(
        manual
            .enforce(DeviceId::new(), RequestedAction::Quarantine)
            .await,
        EnforcementResult::ManualRequired
    );
    let mut connector = Connector::new(FailureFixture);
    connector
        .login("owner", SecretString::new("fixture".into()))
        .await
        .unwrap();
    let failed = W6PolicyActuator::new(connector);
    assert_eq!(
        failed
            .enforce(DeviceId::new(), RequestedAction::Quarantine)
            .await,
        EnforcementResult::Failed
    );
}
