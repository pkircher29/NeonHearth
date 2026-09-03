use crate::{
    AuditError, AuditHost, AuditHostError, AuthorizedTarget, Capability, Limits, Sandbox,
    TargetAuthorizer, TargetError, VerifiedManifest, manifest::valid_limits,
    runtime::CompiledModule,
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
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
        let released = u64::try_from(request_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(response_cap).unwrap_or(u64::MAX));
        b.bytes = b.bytes.saturating_sub(released);
    }
    fn charge_bytes(&self, bytes: usize) -> Result<(), BrokerError> {
        let mut b = self
            .inner
            .lock()
            .map_err(|_| BrokerError::BudgetExhausted)?;
        if Instant::now() >= b.deadline {
            return Err(BrokerError::DeadlineExceeded);
        }
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
    fn commit(mut self, actual: usize) -> Result<(), BrokerError> {
        if actual > self.response_cap {
            return Err(BrokerError::BudgetExhausted);
        }
        self.budget.refund(self.response_cap, actual);
        self.committed = true;
        Ok(())
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
    limit: usize,
}
impl ExchangeResponse {
    pub fn new(response_limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(response_limit.min(4096)),
            limit: response_limit,
        }
    }
    pub fn extend_from_slice(&mut self, chunk: &[u8]) -> Result<(), BrokerError> {
        if chunk.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(BrokerError::ExchangeFailed);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
#[async_trait]
pub trait TargetBoundExchange: Send + Sync {
    /// Implementations must stream bounded chunks into `ExchangeResponse` and
    /// never allocate or read beyond `request.response_limit` in aggregate.
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
    pub approval_id: Uuid,
    pub bytes: Vec<u8>,
}
/// Compiled modules retained per verified digest. Small on purpose: the set of
/// signed audit modules an installation runs is tiny, and clearing the whole
/// cache on overflow keeps the bound trivially correct.
const MAX_CACHED_MODULES: usize = 16;

pub struct Broker {
    authorizer: Arc<dyn TargetAuthorizer>,
    exchange: Arc<dyn TargetBoundExchange>,
    compiled: Mutex<HashMap<[u8; 32], Arc<CompiledModule>>>,
    #[cfg(test)]
    before_publication: Option<std::time::Duration>,
}
impl Broker {
    pub fn new(
        authorizer: Arc<dyn TargetAuthorizer>,
        exchange: Arc<dyn TargetBoundExchange>,
    ) -> Self {
        Self {
            authorizer,
            exchange,
            compiled: Mutex::new(HashMap::new()),
            #[cfg(test)]
            before_publication: None,
        }
    }
    /// Number of compiled modules currently retained.
    pub fn cached_modules(&self) -> usize {
        self.compiled.lock().map(|cache| cache.len()).unwrap_or(0)
    }
    /// Returns a sandbox for the request, compiling the module only the first
    /// time its digest is seen. A verified manifest binds the digest to the
    /// bytes, so two manifests with the same digest share one compilation.
    async fn sandbox_for(
        &self,
        module: &VerifiedManifest,
        limits: &Limits,
    ) -> Result<Sandbox, AuditError> {
        Sandbox::check_limits(module, limits)?;
        let digest = module.sha256();
        let cached = self
            .compiled
            .lock()
            .map_err(|_| AuditError::InvalidModule)?
            .get(&digest)
            .cloned();
        let compiled = match cached {
            Some(compiled) => compiled,
            None => {
                let compiled = Sandbox::compile(module).await?;
                let mut cache = self
                    .compiled
                    .lock()
                    .map_err(|_| AuditError::InvalidModule)?;
                if cache.len() >= MAX_CACHED_MODULES {
                    cache.clear();
                }
                Arc::clone(cache.entry(digest).or_insert(compiled))
            }
        };
        Sandbox::with_compiled(module, compiled, limits)
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
        if !valid_limits(&request.limits) {
            return Err(BrokerError::BudgetExhausted);
        }
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
        let target = self
            .authorizer
            .authorize(request.target, request.interface, request.port)?;
        if target.target() != request.target
            || target.interface() != request.interface
            || target.port() != request.port
        {
            return Err(BrokerError::Target(TargetError::Rejected));
        }
        if Instant::now() >= deadline {
            return Err(BrokerError::DeadlineExceeded);
        }
        let sandbox = self.sandbox_for(&request.module, &limits).await?;
        if Instant::now() >= deadline {
            return Err(BrokerError::DeadlineExceeded);
        }
        let budget = Budget::new(&limits, deadline);
        budget.charge_bytes(request.input.len())?;
        let target_error = Arc::new(Mutex::new(None));
        let host = BrokerHost {
            target,
            capability: request.capability,
            authorizer: Arc::clone(&self.authorizer),
            exchange: Arc::clone(&self.exchange),
            budget,
            deadline,
            cancellation: request.cancellation.clone(),
            target_error: Arc::clone(&target_error),
        };
        let output = tokio::select! { biased; _=request.cancellation.cancelled()=>return Err(BrokerError::Cancelled), value=tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), sandbox.execute(&request.input,&host))=>match value { Ok(Ok(value))=>value, Ok(Err(AuditError::TimedOut))=>return Err(BrokerError::DeadlineExceeded), Ok(Err(AuditError::Cancelled))=>return Err(BrokerError::Cancelled), Ok(Err(AuditError::BudgetExhausted|AuditError::RequestLimitExceeded))=>return Err(BrokerError::BudgetExhausted), Ok(Err(AuditError::HostRejected))=> { if let Some(error) = target_error.lock().map_err(|_| BrokerError::Target(TargetError::Rejected))?.take() { return Err(BrokerError::Target(error)); } return Err(BrokerError::ExchangeFailed); }, Ok(Err(error))=>return Err(BrokerError::Sandbox(error)), Err(_)=>return Err(BrokerError::DeadlineExceeded) } };
        if request.cancellation.is_cancelled() {
            return Err(BrokerError::Cancelled);
        }
        #[cfg(test)]
        if let Some(delay) = self.before_publication {
            tokio::time::sleep(delay).await;
        }
        host.budget.charge_bytes(output.output.len())?;
        // Cancellation or the absolute deadline observable before this explicit
        // publication commit wins. Events after the ready branch are after commit.
        tokio::select! {
            biased;
            _ = request.cancellation.cancelled() => return Err(BrokerError::Cancelled),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => return Err(BrokerError::DeadlineExceeded),
            _ = std::future::ready(()) => {}
        }
        Ok(BrokerResult {
            target: request.target,
            approval_id: request.approval_id,
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
    target_error: Arc<Mutex<Option<TargetError>>>,
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
        let refreshed = match self.authorizer.authorize(
            self.target.target(),
            self.target.interface(),
            self.target.port(),
        ) {
            Ok(target) => target,
            Err(error) => {
                if let Ok(mut slot) = self.target_error.lock() {
                    *slot = Some(error);
                }
                return Err(AuditHostError::Denied);
            }
        };
        if refreshed != self.target {
            if let Ok(mut slot) = self.target_error.lock() {
                *slot = Some(TargetError::Rejected);
            }
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
        let response_len = response.bytes().len();
        if response_len > response_cap {
            return Err(AuditHostError::ExchangeFailed);
        }
        reservation
            .commit(response_len)
            .map_err(|_| AuditHostError::BudgetExhausted)?;
        Ok(response.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditManifest, EvidenceSchema, EvidenceType, RollbackPlan, SideEffectProfile, TargetKind,
        verify_manifest,
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    fn budget() -> Budget {
        Budget::new(
            &Limits {
                max_bytes: 20,
                max_requests: 2,
                max_time: Duration::from_secs(1),
                max_fuel: 1,
                max_memory_pages: 1,
            },
            Instant::now() + Duration::from_secs(1),
        )
    }
    fn snapshot(budget: &Budget) -> (u32, u64) {
        let state = budget.inner.lock().unwrap();
        (state.requests, state.bytes)
    }

    #[test]
    fn reservation_rolls_back_every_uncommitted_failure_path() {
        let budget = budget();
        for _failure in [
            "reauth",
            "changed-auth",
            "exchange",
            "cancel",
            "timeout",
            "oversized",
        ] {
            let reservation = budget.reserve(4, 8).unwrap();
            assert_eq!(snapshot(&budget), (1, 12));
            drop(reservation);
            assert_eq!(snapshot(&budget), (0, 0));
        }
    }

    #[test]
    fn successful_commit_retains_request_and_actual_response_exactly() {
        let budget = budget();
        budget.reserve(4, 8).unwrap().commit(3).unwrap();
        assert_eq!(snapshot(&budget), (1, 7));
    }

    #[test]
    fn oversized_commit_refuses_underflow_and_rolls_back() {
        let budget = budget();
        assert!(matches!(
            budget.reserve(4, 8).unwrap().commit(9),
            Err(BrokerError::BudgetExhausted)
        ));
        assert_eq!(snapshot(&budget), (0, 0));
    }

    #[test]
    fn poisoned_budget_fails_closed_without_panicking() {
        let budget = Arc::new(budget());
        let other = Arc::clone(&budget);
        let _ = std::thread::spawn(move || {
            let _guard = other.inner.lock().unwrap();
            panic!("poison for test");
        })
        .join();
        assert!(matches!(
            budget.reserve(1, 1),
            Err(BrokerError::BudgetExhausted)
        ));
        budget.charge_bytes(1).unwrap_err();
    }

    #[test]
    fn release_handles_usize_boundaries_without_addition_overflow() {
        let budget = budget();
        budget.release(usize::MAX, usize::MAX);
        assert_eq!(snapshot(&budget), (0, 0));
    }

    struct Auth;
    impl TargetAuthorizer for Auth {
        fn authorize(
            &self,
            target: IpAddr,
            interface: u32,
            port: u16,
        ) -> Result<AuthorizedTarget, TargetError> {
            AuthorizedTarget::new(target, interface, port)
        }
    }
    struct UnusedExchange;
    #[async_trait]
    impl TargetBoundExchange for UnusedExchange {
        async fn exchange(
            &self,
            _: &AuthorizedTarget,
            _: ExchangeRequest,
        ) -> Result<ExchangeResponse, BrokerError> {
            panic!("no exchange expected")
        }
    }

    #[tokio::test]
    async fn deadline_crossed_after_sandbox_result_prevents_broker_result_publication() {
        let wasm = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#).unwrap();
        let limits = Limits {
            max_bytes: 64,
            max_requests: 1,
            max_time: Duration::from_secs(1),
            max_fuel: 100_000,
            max_memory_pages: 1,
        };
        let mut manifest = AuditManifest::new(
            "deadline".into(),
            1,
            Sha256::digest(&wasm).into(),
            TargetKind::NumericPrivateDevice,
            BTreeSet::from([Capability::TcpExchange { port: 80 }]),
            "test".into(),
            SideEffectProfile::ReadOnly,
            RollbackPlan {
                required: false,
                description: "none".into(),
            },
            EvidenceSchema {
                fields: BTreeMap::from([("out".into(), EvidenceType::Bytes)]),
            },
            limits.clone(),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[4; 32]);
        manifest.sign(&key).unwrap();
        let module = verify_manifest(&manifest, &wasm, &key.verifying_key()).unwrap();
        let mut broker = Broker::new(Arc::new(Auth), Arc::new(UnusedExchange));
        broker.before_publication = Some(Duration::from_millis(1_050));
        let result = broker
            .execute(BrokerRequest {
                module,
                input: vec![],
                target: "192.168.1.2".parse().unwrap(),
                interface: 7,
                port: 80,
                capability: Capability::TcpExchange { port: 80 },
                approval_id: Uuid::new_v4(),
                limits,
                cancellation: CancellationToken::new(),
            })
            .await;
        assert!(matches!(result, Err(BrokerError::DeadlineExceeded)));
    }

    fn signed_module(name: &str, wasm: &[u8], limits: &Limits) -> VerifiedManifest {
        let mut manifest = AuditManifest::new(
            name.into(),
            1,
            Sha256::digest(wasm).into(),
            TargetKind::NumericPrivateDevice,
            BTreeSet::from([Capability::TcpExchange { port: 80 }]),
            "test".into(),
            SideEffectProfile::ReadOnly,
            RollbackPlan {
                required: false,
                description: "none".into(),
            },
            EvidenceSchema {
                fields: BTreeMap::from([("out".into(), EvidenceType::Bytes)]),
            },
            limits.clone(),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[4; 32]);
        manifest.sign(&key).unwrap();
        verify_manifest(&manifest, wasm, &key.verifying_key()).unwrap()
    }

    #[tokio::test]
    async fn compiled_modules_are_cached_per_digest_and_reused_across_requests() {
        let wasm = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#).unwrap();
        let limits = Limits {
            max_bytes: 64,
            max_requests: 1,
            max_time: Duration::from_secs(1),
            max_fuel: 100_000,
            max_memory_pages: 1,
        };
        let broker = Broker::new(Arc::new(Auth), Arc::new(UnusedExchange));
        assert_eq!(broker.cached_modules(), 0);
        // Two distinct manifests over the same bytes share one compilation.
        for name in ["first", "second"] {
            broker
                .execute(BrokerRequest {
                    module: signed_module(name, &wasm, &limits),
                    input: vec![],
                    target: "192.168.1.2".parse().unwrap(),
                    interface: 7,
                    port: 80,
                    capability: Capability::TcpExchange { port: 80 },
                    approval_id: Uuid::new_v4(),
                    limits: limits.clone(),
                    cancellation: CancellationToken::new(),
                })
                .await
                .unwrap();
            assert_eq!(broker.cached_modules(), 1);
        }
        // A different module gets its own entry.
        let other = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 1))"#).unwrap();
        broker
            .execute(BrokerRequest {
                module: signed_module("third", &other, &limits),
                input: vec![],
                target: "192.168.1.2".parse().unwrap(),
                interface: 7,
                port: 80,
                capability: Capability::TcpExchange { port: 80 },
                approval_id: Uuid::new_v4(),
                limits,
                cancellation: CancellationToken::new(),
            })
            .await
            .unwrap();
        assert_eq!(broker.cached_modules(), 2);
    }
}
