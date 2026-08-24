use crate::target::{AuthorizedTarget, TargetAuthorizer, TargetError};
use crate::{Limits, VerifiedManifest};
use async_trait::async_trait;
use std::{net::IpAddr, sync::Arc, time::Instant};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("target authorization failed: {0}")]
    Target(#[from] TargetError),
    #[error("budget exhausted")]
    BudgetExhausted,
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("cancelled")]
    Cancelled,
    #[error("exchange failed: {0}")]
    Exchange(String),
}
pub struct Budget {
    requests: u32,
    bytes: u64,
    max_requests: u32,
    max_bytes: u64,
    deadline: Instant,
}
impl Budget {
    pub fn charge(&mut self, requests: u32, bytes: u64) -> Result<(), BrokerError> {
        if Instant::now() >= self.deadline
            || requests > self.max_requests.saturating_sub(self.requests)
            || bytes > self.max_bytes.saturating_sub(self.bytes)
        {
            return Err(BrokerError::BudgetExhausted);
        }
        self.requests += requests;
        self.bytes += bytes;
        Ok(())
    }
    pub fn remaining(&self) -> (u32, u64) {
        (
            self.max_requests - self.requests,
            self.max_bytes - self.bytes,
        )
    }
}
pub struct ExchangeRequest {
    pub payload: Vec<u8>,
}
pub struct ExchangeResponse {
    pub target: IpAddr,
    pub bytes: Vec<u8>,
}
#[async_trait]
pub trait TargetBoundExchange: Send + Sync {
    async fn exchange(
        &self,
        target: &AuthorizedTarget,
        request: ExchangeRequest,
        budget: &mut Budget,
    ) -> Result<ExchangeResponse, BrokerError>;
}
pub struct BrokerRequest {
    pub target: IpAddr,
    pub interface: u32,
    pub port: u16,
    pub approval_id: Uuid,
    pub limits: Limits,
    pub module: Option<VerifiedManifest>,
}
pub struct BrokerResult {
    pub target: IpAddr,
    pub bytes: Vec<u8>,
}
pub struct Broker {
    authorizer: Arc<dyn TargetAuthorizer>,
    exchange: Arc<dyn TargetBoundExchange>,
}
impl Broker {
    pub fn new(
        authorizer: Arc<dyn TargetAuthorizer>,
        exchange: Arc<dyn TargetBoundExchange>,
    ) -> Self {
        Self {
            authorizer,
            exchange,
        }
    }
    pub async fn execute(&self, request: BrokerRequest) -> Result<BrokerResult, BrokerError> {
        let target = self
            .authorizer
            .authorize(request.target, request.interface, request.port)?;
        let limits = request.limits;
        let mut budget = Budget {
            requests: 0,
            bytes: 0,
            max_requests: limits.max_requests,
            max_bytes: limits.max_bytes,
            deadline: Instant::now() + limits.max_time,
        };
        let response = tokio::select! { _ = tokio::time::sleep(limits.max_time) => return Err(BrokerError::DeadlineExceeded), result = self.exchange.exchange(&target, ExchangeRequest { payload: Vec::new() }, &mut budget) => result? };
        Ok(BrokerResult {
            target: response.target,
            bytes: response.bytes,
        })
    }
}
