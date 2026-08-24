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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeProtocol {
    Tcp,
    Http,
    TlsMetadata,
}

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
    fn reserve(
        &self,
        request_bytes: usize,
        response_cap: usize,
    ) -> Result<Reservation<'_>, BrokerError> {
        let mut b = self
            .inner
            .lock()
            .map_err(|_| BrokerError::BudgetExhausted)?;
        let total = (request_bytes as u64)
            .checked_add(response_cap as u64)
            .ok_or(BrokerError::BudgetExhausted)?;
        if Instant::now() >= b.deadline
            || b.requests >= b.max_requests
            || total > b.max_bytes.saturating_sub(b.bytes)
        {
            return Err(BrokerError::BudgetExhausted);
        }
        b.requests = b
            .requests
            .checked_add(1)
            .ok_or(BrokerError::BudgetExhausted)?;
        b.bytes = b
            .bytes
            .checked_add(total)
            .ok_or(BrokerError::BudgetExhausted)?;
        Ok(Reservation {
            budget: self,
            request_bytes,
            response_cap,
            committed: false,
        })
    }
    fn refund(&self, response_cap: usize, actual: usize) {
        let Ok(mut b) = self.inner.lock() else { return };
        b.bytes = b.bytes.saturating_sub((response_cap - actual) as u64)
    }
    fn release(&self, request_bytes: usize, response_cap: usize) {
        let Ok(mut b) = self.inner.lock() else { return };
        b.requests = b.requests.saturating_sub(1);
        b.bytes = b
            .bytes
            .saturating_sub((request_bytes + response_cap) as u64);
    }
    fn charge_bytes(&self, bytes: usize) -> Result<(), BrokerError> {
        let mut b = self
            .inner
            .lock()
            .map_err(|_| BrokerError::BudgetExhausted)?;
        let bytes = u64::try_from(bytes).map_err(|_| BrokerError::BudgetExhausted)?;
        if bytes > b.max_bytes.saturating_sub(b.bytes) {
            return Err(BrokerError::BudgetExhausted);
        }
        b.bytes = b
            .bytes
            .checked_add(bytes)
            .ok_or(BrokerError::BudgetExhausted)?;
        Ok(())
    }
}
struct Reservation<'a> {
    budget: &'a Budget,
    request_bytes: usize,
    response_cap: usize,
    committed: bool,
}
impl Reservation<'_> {
    fn commit(mut self, actual: usize) {
        self.budget.refund(self.response_cap, actual);
        self.committed = true;
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.budget.release(self.request_bytes, self.response_cap);
        }
    }
}
pub struct ExchangeRequest {
    pub payload: Vec<u8>,
    pub protocol: ExchangeProtocol,
    pub response_limit: usize,
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}
pub struct ExchangeResponse {
    bytes: Vec<u8>,
}
impl ExchangeResponse {
    pub fn try_new(bytes: Vec<u8>, response_limit: usize) -> Result<Self, BrokerError> {
        if bytes.len() > response_limit {
            return Err(BrokerError::ExchangeFailed);
        }
        Ok(Self { bytes })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
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
    pub approval_id: Uuid,
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
        if request.approval_id.is_nil() {
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
        if limits.max_bytes == 0
            || limits.max_requests == 0
            || limits.max_time.is_zero()
            || limits.max_fuel == 0
            || limits.max_memory_pages == 0
        {
            return Err(BrokerError::BudgetExhausted);
        }
        let deadline = Instant::now()
            .checked_add(limits.max_time)
            .ok_or(BrokerError::DeadlineExceeded)?;
        if request.cancellation.is_cancelled() {
            return Err(BrokerError::Cancelled);
        }
        let sandbox = Sandbox::new_with_limits(request.module, &limits).await?;
        if Instant::now() >= deadline {
            return Err(BrokerError::DeadlineExceeded);
        }
        let budget = Budget::new(&limits, deadline);
        budget.charge_bytes(request.input.len())?;
        let host = BrokerHost {
            target,
            capability: request.capability,
            authorizer: Arc::clone(&self.authorizer),
            exchange: Arc::clone(&self.exchange),
            budget,
            deadline,
            cancellation: request.cancellation.clone(),
        };
        let output = tokio::select! { _=request.cancellation.cancelled()=>return Err(BrokerError::Cancelled), value=tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), sandbox.execute(&request.input,&host))=>match value { Ok(Ok(value))=>value, Ok(Err(AuditError::TimedOut))=>return Err(BrokerError::DeadlineExceeded), Ok(Err(AuditError::Cancelled))=>return Err(BrokerError::Cancelled), Ok(Err(AuditError::BudgetExhausted|AuditError::RequestLimitExceeded))=>return Err(BrokerError::BudgetExhausted), Ok(Err(AuditError::HostRejected))=>return Err(BrokerError::ExchangeFailed), Ok(Err(error))=>return Err(BrokerError::Sandbox(error)), Err(_)=>return Err(BrokerError::DeadlineExceeded) } };
        if request.cancellation.is_cancelled() {
            return Err(BrokerError::Cancelled);
        }
        host.budget.charge_bytes(output.output.len())?;
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
fn protocol(capability: &Capability) -> ExchangeProtocol {
    match capability {
        Capability::TcpExchange { .. } => ExchangeProtocol::Tcp,
        Capability::HttpExchange { .. } => ExchangeProtocol::Http,
        Capability::TlsMetadata { .. } => ExchangeProtocol::TlsMetadata,
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
        let selected_protocol = protocol(&self.capability);
        if self.cancellation.is_cancelled() {
            return Err(AuditHostError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(AuditHostError::DeadlineExceeded);
        }
        let reservation =
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
            .map_err(|_| AuditHostError::Denied)?;
        if refreshed != self.target {
            return Err(AuditHostError::Denied);
        }
        let call = self.exchange.exchange(
            &self.target,
            ExchangeRequest {
                payload: request,
                protocol: selected_protocol,
                response_limit: response_cap,
                deadline: self.deadline,
                cancellation: self.cancellation.clone(),
            },
        );
        let response = tokio::select! {_=self.cancellation.cancelled()=>return Err(AuditHostError::Cancelled),r=tokio::time::timeout_at(tokio::time::Instant::from_std(self.deadline),call)=>match r{Ok(Ok(v))=>v,Ok(Err(_))=>return Err(AuditHostError::ExchangeFailed),Err(_)=>return Err(AuditHostError::DeadlineExceeded)}};
        if response.bytes.len() > response_cap {
            return Err(AuditHostError::ExchangeFailed);
        }
        reservation.commit(response.bytes.len());
        Ok(response.bytes)
    }
}
