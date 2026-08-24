use async_trait::async_trait;
use lattice_audit_wasm::Limits;
use lattice_audit_wasm::TargetAuthorizer;
use lattice_audit_wasm::broker::{
    Broker, BrokerError, BrokerRequest, ExchangeRequest, ExchangeResponse, TargetBoundExchange,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
use uuid::Uuid;

struct Auth;
impl TargetAuthorizer for Auth {
    fn authorize(
        &self,
        target: IpAddr,
        interface: u32,
        port: u16,
    ) -> Result<lattice_audit_wasm::AuthorizedTarget, lattice_audit_wasm::TargetError> {
        lattice_audit_wasm::AuthorizedTarget::new(target, interface, port)
    }
}
struct Exchange;
#[async_trait]
impl TargetBoundExchange for Exchange {
    async fn exchange(
        &self,
        target: &lattice_audit_wasm::AuthorizedTarget,
        _request: ExchangeRequest,
        budget: &mut lattice_audit_wasm::Budget,
    ) -> Result<ExchangeResponse, BrokerError> {
        budget.charge(1, 1)?;
        Ok(ExchangeResponse {
            target: target.target(),
            bytes: vec![1],
        })
    }
}

#[tokio::test]
async fn broker_accepts_one_owner_selected_target_only() {
    let broker = Broker::new(Arc::new(Auth), Arc::new(Exchange));
    let request = BrokerRequest {
        target: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 44)),
        interface: 7,
        port: 80,
        approval_id: Uuid::new_v4(),
        limits: Limits {
            max_bytes: 10,
            max_requests: 1,
            max_time: std::time::Duration::from_secs(1),
            max_fuel: 1,
            max_memory_pages: 1,
        },
        module: None,
    };
    let result = broker.execute(request).await.unwrap();
    assert_eq!(result.target, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 44)));
}
