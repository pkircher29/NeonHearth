use crate::{
    AuditError, AuditHost, AuditHostError, AuthorizedTarget, Capability, Limits, Sandbox,
    TargetAuthorizer, TargetError, VerifiedManifest,
};
use async_trait::async_trait;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("target authorization failed")]
    Target(#[from] TargetError),
    #[error("approval is required")]
    MissingApproval,
    #[error("selected capability is not declared for the target port")]
    CapabilityDenied,
    #[error("budget exhausted")]
    BudgetExhausted,
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("cancelled")]
    Cancelled,
    #[error("sandbox failed: {0}")]
    Sandbox(#[from] AuditError),
    #[error("target-bound exchange failed")]
    ExchangeFailed,
}

struct BudgetState {
    requests: u32,
    bytes: u64,
    max_requests: u32,
    max_bytes: u64,
    deadline: Instant,
}
pub struct Budget {
    inner: Mutex<BudgetState>,
}
impl Budget {
    fn new(limits: &Limits, deadline: Instant) -> Self {
        Self {
            inner: Mutex::new(BudgetState {
                requests: 0,
                bytes: 0,
                max_requests: limits.max_requests,
                max_bytes: limits.max_bytes,
                deadline,
            }),
        }
    }
    fn reserve(&self, request_bytes: usize, response_cap: usize) -> Result<(), BrokerError> {
        let mut b = self.inner.lock().expect("budget mutex");
        let total = (request_bytes as u64)
            .checked_add(response_cap as u64)
            .ok_or(BrokerError::BudgetExhausted)?;
        if Instant::now() >= b.deadline
            || b.requests >= b.max_requests
            || total > b.max_bytes.saturating_sub(b.bytes)
        {
            return Err(BrokerError::BudgetExhausted);
        }
        b.requests += 1;
        b.bytes += total;
        Ok(())
    }
    fn refund(&self, response_cap: usize, actual: usize) {
        let mut b = self.inner.lock().expect("budget mutex");
        b.bytes = b.bytes.saturating_sub((response_cap - actual) as u64)
    }
    fn release(&self, request_bytes: usize, response_cap: usize) {
        let mut b = self.inner.lock().expect("budget mutex");
        b.requests = b.requests.saturating_sub(1);
        b.bytes = b
            .bytes
            .saturating_sub((request_bytes + response_cap) as u64);
    }
}
pub struct ExchangeRequest {
    pub payload: Vec<u8>,
}
pub struct ExchangeResponse {
    pub bytes: Vec<u8>,
}
#[async_trait]
pub trait TargetBoundExchange: Send + Sync {
    async fn exchange(
        &self,
        target: &AuthorizedTarget,
        request: ExchangeRequest,
    ) -> Result<ExchangeResponse, BrokerError>;
}
pub struct BrokerRequest {
    pub module: VerifiedManifest,
    pub input: Vec<u8>,
    pub target: IpAddr,
    pub interface: u32,
    pub port: u16,
    pub capability: Capability,
    pub approval_id: Option<Uuid>,
    pub limits: Limits,
    pub cancellation: CancellationToken,
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
        if request.approval_id.is_none() {
            return Err(BrokerError::MissingApproval);
        }
        if capability_port(&request.capability) != request.port
            || !request
                .module
                .manifest()
                .capabilities
                .contains(&request.capability)
        {
            return Err(BrokerError::CapabilityDenied);
        }
        let target = self
            .authorizer
            .authorize(request.target, request.interface, request.port)?;
        let limits = intersect_limits(request.module.limits(), &request.limits);
        if request.input.len() as u64 > limits.max_bytes {
            return Err(BrokerError::BudgetExhausted);
        }
        let deadline = Instant::now() + limits.max_time;
        if request.cancellation.is_cancelled() {
            return Err(BrokerError::Cancelled);
        }
        let sandbox = Sandbox::new(request.module).await?;
        let host = BrokerHost {
            target,
            capability: request.capability,
            authorizer: Arc::clone(&self.authorizer),
            exchange: Arc::clone(&self.exchange),
            budget: Budget::new(&limits, deadline),
            deadline,
            cancellation: request.cancellation.clone(),
        };
        let output = tokio::select! { _=request.cancellation.cancelled()=>return Err(BrokerError::Cancelled), value=sandbox.execute(&request.input,&host)=>value? };
        if request.cancellation.is_cancelled() {
            return Err(BrokerError::Cancelled);
        }
        Ok(BrokerResult {
            target: request.target,
            bytes: output.output,
        })
    }
}
fn capability_port(capability: &Capability) -> u16 {
    match capability {
        Capability::TcpExchange { port }
        | Capability::HttpExchange { port }
        | Capability::TlsMetadata { port } => *port,
    }
}
fn intersect_limits(a: &Limits, b: &Limits) -> Limits {
    Limits {
        max_bytes: a.max_bytes.min(b.max_bytes),
        max_requests: a.max_requests.min(b.max_requests),
        max_time: a.max_time.min(b.max_time),
        max_fuel: a.max_fuel.min(b.max_fuel),
        max_memory_pages: a.max_memory_pages.min(b.max_memory_pages),
    }
}
struct BrokerHost {
    target: AuthorizedTarget,
    capability: Capability,
    authorizer: Arc<dyn TargetAuthorizer>,
    exchange: Arc<dyn TargetBoundExchange>,
    budget: Budget,
    deadline: Instant,
    cancellation: CancellationToken,
}
#[async_trait]
impl AuditHost for BrokerHost {
    async fn deterministic(&self) -> u32 {
        0
    }
    async fn exchange(
        &self,
        request: Vec<u8>,
        response_cap: usize,
    ) -> Result<Vec<u8>, AuditHostError> {
        let _selected_capability = &self.capability;
        if self.cancellation.is_cancelled() {
            return Err(AuditHostError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(AuditHostError::DeadlineExceeded);
        }
        self.budget
            .reserve(request.len(), response_cap)
            .map_err(|e| match e {
                BrokerError::BudgetExhausted => AuditHostError::BudgetExhausted,
                _ => AuditHostError::ExchangeFailed,
            })?;
        let refreshed = self
            .authorizer
            .authorize(
                self.target.target(),
                self.target.interface(),
                self.target.port(),
            )
            .map_err(|_| {
                self.budget.release(request.len(), response_cap);
                AuditHostError::Denied
            })?;
        if refreshed != self.target {
            self.budget.release(request.len(), response_cap);
            return Err(AuditHostError::Denied);
        }
        let call = self
            .exchange
            .exchange(&self.target, ExchangeRequest { payload: request });
        let response = tokio::select! {_=self.cancellation.cancelled()=>return Err(AuditHostError::Cancelled),r=tokio::time::timeout_at(tokio::time::Instant::from_std(self.deadline),call)=>match r{Ok(Ok(v))=>v,Ok(Err(_))=>return Err(AuditHostError::ExchangeFailed),Err(_)=>return Err(AuditHostError::DeadlineExceeded)}};
        if response.bytes.len() > response_cap {
            return Err(AuditHostError::ExchangeFailed);
        }
        self.budget.refund(response_cap, response.bytes.len());
        Ok(response.bytes)
    }
}
