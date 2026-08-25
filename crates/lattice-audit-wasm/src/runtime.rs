use crate::{AuditError, Limits, VerifiedManifest, manifest::valid_limits};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use wasmparser::{Parser, Payload, TypeRef};
use wasmtime::{Config, Engine, ExternType, Linker, Module, ResourceLimiter, Store, Trap};

const WASM_PAGE_SIZE: u64 = 65_536;
const MAX_TABLE_ELEMENTS: u64 = 64;

#[async_trait::async_trait]
pub trait AuditHost: Send + Sync {
    async fn deterministic(&self) -> u32;
    /// The guest supplies bytes and a bounded output buffer only.  It never
    /// supplies an address, name, URL, CIDR, redirect, protocol, or port.
    async fn exchange(
        &self,
        _request: Vec<u8>,
        _response_cap: usize,
    ) -> Result<Vec<u8>, AuditHostError> {
        Err(AuditHostError::ExchangeFailed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditHostError {
    Denied,
    BudgetExhausted,
    DeadlineExceeded,
    Cancelled,
    ExchangeFailed,
}

#[derive(Debug)]
pub struct AuditResult {
    pub output: Vec<u8>,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox").finish()
    }
}

pub struct Sandbox {
    engine: Engine,
    module: Module,
    limits: Limits,
    /// A module runs in a fresh store, but an engine epoch is global. Serialize
    /// admissions so one invocation's deadline cannot interrupt another one.
    execution: tokio::sync::Mutex<()>,
}

#[derive(Clone, Copy)]
enum ExecutionFailure {
    Memory,
    Table,
    Request,
    Bytes,
    InvalidAbi,
    Host(AuditHostError),
}

struct StoreState<'a, H: AuditHost> {
    host: &'a H,
    limiter: LimitsState,
    requests: u32,
    max_requests: u32,
    max_bytes: u64,
    bytes: u64,
    failure: Option<ExecutionFailure>,
}

struct LimitsState {
    max_memory: usize,
    failure: Option<ExecutionFailure>,
}

impl LimitsState {
    fn reject(&mut self, failure: ExecutionFailure) -> anyhow::Result<bool> {
        self.failure = Some(failure);
        Err(anyhow::anyhow!("resource limit"))
    }
}

impl ResourceLimiter for LimitsState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired > self.max_memory {
            return self.reject(ExecutionFailure::Memory);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired as u64 > MAX_TABLE_ELEMENTS {
            return self.reject(ExecutionFailure::Table);
        }
        Ok(true)
    }

    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
}

struct EpochTicker {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl EpochTicker {
    fn start(engine: Engine, limit: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let ticker_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            let deadline = Instant::now() + limit;
            while !ticker_stop.load(Ordering::Acquire) {
                let now = Instant::now();
                if now >= deadline {
                    engine.increment_epoch();
                    return;
                }
                thread::sleep((deadline - now).min(Duration::from_millis(1)));
            }
        });
        Self {
            stop,
            join: Some(join),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Sandbox {
    pub async fn new(verified: VerifiedManifest) -> Result<Self, AuditError> {
        let limits = verified.limits().clone();
        Self::new_with_limits(verified, &limits).await
    }
    pub(crate) async fn new_with_limits(
        verified: VerifiedManifest,
        limits: &Limits,
    ) -> Result<Self, AuditError> {
        let signed = verified.limits();
        if !valid_limits(limits)
            || limits.max_bytes > signed.max_bytes
            || limits.max_requests > signed.max_requests
            || limits.max_time > signed.max_time
            || limits.max_fuel > signed.max_fuel
            || limits.max_memory_pages > signed.max_memory_pages
        {
            return Err(AuditError::InvalidManifest(
                "invalid effective limits".into(),
            ));
        }
        let mut config = Config::new();
        config.consume_fuel(true);
        config.async_support(true);
        config.epoch_interruption(true);
        validate_static_limits(verified.wasm(), limits)?;
        let engine = Engine::new(&config).map_err(|_| AuditError::InvalidModule)?;
        let module =
            Module::new(&engine, verified.wasm()).map_err(|_| AuditError::InvalidModule)?;
        validate_abi(&module)?;
        Ok(Self {
            engine,
            module,
            limits: limits.clone(),
            execution: tokio::sync::Mutex::new(()),
        })
    }

    pub async fn execute<H: AuditHost>(
        &self,
        input: &[u8],
        host: &H,
    ) -> Result<AuditResult, AuditError> {
        if input.len() as u64 > self.limits.max_bytes || input.len() > i32::MAX as usize {
            return Err(AuditError::InputLimitExceeded);
        }
        // Tokio's mutex is not poisonable. The guard covers the epoch ticker's
        // entire lifetime, and max_time begins only after this admission.
        let _execution = self.execution.lock().await;
        let ticker = EpochTicker::start(self.engine.clone(), self.limits.max_time);
        let result =
            tokio::time::timeout(self.limits.max_time, self.execute_inner(input, host)).await;
        drop(ticker);
        match result {
            Ok(result) => result,
            Err(_) => Err(AuditError::TimedOut),
        }
    }

    async fn execute_inner<H: AuditHost>(
        &self,
        input: &[u8],
        host: &H,
    ) -> Result<AuditResult, AuditError> {
        let max_memory = page_bytes(self.limits.max_memory_pages)?;
        let mut store = Store::new(
            &self.engine,
            StoreState {
                host,
                limiter: LimitsState {
                    max_memory,
                    failure: None,
                },
                requests: 0,
                max_requests: self.limits.max_requests,
                max_bytes: self.limits.max_bytes,
                bytes: input.len() as u64,
                failure: None,
            },
        );
        store.limiter(|state| &mut state.limiter);
        store
            .set_fuel(self.limits.max_fuel)
            .map_err(|_| AuditError::FuelExhausted)?;
        store
            .fuel_async_yield_interval(Some(1_000))
            .map_err(|_| AuditError::FuelExhausted)?;
        store.set_epoch_deadline(1);
        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap_async(
                "audit",
                "deterministic",
                |mut caller: wasmtime::Caller<'_, StoreState<'_, H>>, ()| {
                    Box::new(async move {
                        let host = {
                            let data = caller.data_mut();
                            if data.requests >= data.max_requests {
                                data.failure = Some(ExecutionFailure::Request);
                                return Err(anyhow::anyhow!("request limit"));
                            }
                            data.requests = data
                                .requests
                                .checked_add(1)
                                .ok_or_else(|| anyhow::anyhow!("request counter overflow"))?;
                            data.host
                        };
                        Ok(host.deterministic().await as i32)
                    })
                },
            )
            .map_err(|_| AuditError::InvalidAbi)?;
        linker
            .func_wrap_async(
                "audit",
                "exchange",
                |mut caller: wasmtime::Caller<'_, StoreState<'_, H>>,
                 (req_ptr, req_len, out_ptr, out_cap): (i32, i32, i32, i32)| {
                    Box::new(async move {
                        let (req_ptr, req_len, out_ptr, out_cap) = match (
                            usize::try_from(req_ptr),
                            usize::try_from(req_len),
                            usize::try_from(out_ptr),
                            usize::try_from(out_cap),
                        ) {
                            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
                            _ => {
                                caller.data_mut().failure = Some(ExecutionFailure::InvalidAbi);
                                return Err(anyhow::anyhow!("invalid exchange pointers"));
                            }
                        };
                        let memory = match caller.get_export("memory").and_then(|e| e.into_memory())
                        {
                            Some(memory) => memory,
                            None => return Err(anyhow::anyhow!("missing memory")),
                        };
                        let end = |ptr: usize, len: usize| {
                            ptr.checked_add(len)
                                .filter(|end| *end <= memory.data_size(&caller))
                        };
                        if end(req_ptr, req_len).is_none() || end(out_ptr, out_cap).is_none() {
                            caller.data_mut().failure = Some(ExecutionFailure::InvalidAbi);
                            return Err(anyhow::anyhow!("exchange bounds"));
                        }
                        let exchange_bytes = req_len
                            .checked_add(out_cap)
                            .and_then(|n| u64::try_from(n).ok());
                        if exchange_bytes.is_none_or(|n| {
                            n > caller.data().max_bytes.saturating_sub(caller.data().bytes)
                        }) {
                            caller.data_mut().failure = Some(ExecutionFailure::Bytes);
                            return Err(anyhow::anyhow!("exchange byte budget"));
                        }
                        {
                            let data = caller.data_mut();
                            if data.requests >= data.max_requests {
                                data.failure = Some(ExecutionFailure::Request);
                                return Err(anyhow::anyhow!("request limit"));
                            }
                            data.requests += 1;
                            data.bytes += exchange_bytes.expect("validated exchange byte count");
                        }
                        let request = memory.data(&caller)[req_ptr..req_ptr + req_len].to_vec();
                        let host = caller.data().host;
                        let response = match host.exchange(request, out_cap).await {
                            Ok(response) if response.len() <= out_cap => response,
                            Ok(_) | Err(AuditHostError::ExchangeFailed) => {
                                caller.data_mut().failure =
                                    Some(ExecutionFailure::Host(AuditHostError::ExchangeFailed));
                                return Err(anyhow::anyhow!("exchange failed"));
                            }
                            Err(error) => {
                                caller.data_mut().failure = Some(ExecutionFailure::Host(error));
                                return Err(anyhow::anyhow!("exchange rejected"));
                            }
                        };
                        caller.data_mut().bytes -= (out_cap - response.len()) as u64;
                        memory
                            .write(&mut caller, out_ptr, &response)
                            .map_err(|_| anyhow::anyhow!("exchange write"))?;
                        i32::try_from(response.len())
                            .map_err(|_| anyhow::anyhow!("response too large"))
                    })
                },
            )
            .map_err(|_| AuditError::InvalidAbi)?;

        let instance = linker
            .instantiate_async(&mut store, &self.module)
            .await
            .map_err(|error| map_error(&store, &error))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(AuditError::InvalidAbi)?;
        if input.len() > memory.data_size(&store) {
            return Err(AuditError::MemoryLimitExceeded);
        }
        memory
            .write(&mut store, 0, input)
            .map_err(|_| AuditError::MemoryLimitExceeded)?;
        let run = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "run")
            .map_err(|_| AuditError::InvalidAbi)?;
        let packed = run
            .call_async(&mut store, (0, input.len() as i32))
            .await
            .map_err(|error| map_error(&store, &error))?;
        let ptr = (packed >> 32) as u64;
        let len = packed as u32 as u64;
        if len > self.limits.max_bytes {
            return Err(AuditError::OutputLimitExceeded);
        }
        if len > store.data().max_bytes.saturating_sub(store.data().bytes) {
            return Err(AuditError::BudgetExhausted);
        }
        let end = ptr.checked_add(len).ok_or(AuditError::InvalidAbi)?;
        let data = memory.data(&store);
        if end > data.len() as u64 {
            return Err(AuditError::InvalidAbi);
        }
        Ok(AuditResult {
            output: data[ptr as usize..end as usize].to_vec(),
        })
    }
}

fn validate_static_limits(wasm: &[u8], limits: &Limits) -> Result<(), AuditError> {
    let mut memories = 0_u32;
    let mut tables = 0_u32;
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.map_err(|_| AuditError::InvalidModule)? {
            Payload::StartSection { .. } => return Err(AuditError::InvalidAbi),
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import.map_err(|_| AuditError::InvalidModule)?;
                    if import.module == "audit"
                        && matches!(import.name, "deterministic" | "exchange")
                    {
                        if !matches!(import.ty, TypeRef::Func(_)) {
                            return Err(AuditError::InvalidAbi);
                        }
                    } else {
                        return Err(AuditError::ForbiddenImport(format!(
                            "{}::{}",
                            import.module, import.name
                        )));
                    }
                }
            }
            Payload::MemorySection(section) => {
                for memory in section {
                    memories = memories
                        .checked_add(1)
                        .ok_or(AuditError::MemoryLimitExceeded)?;
                    let memory = memory.map_err(|_| AuditError::InvalidModule)?;
                    if memory.memory64
                        || memory.shared
                        || memory.page_size_log2.is_some()
                        || memory.initial > limits.max_memory_pages as u64
                        || memory
                            .maximum
                            .is_some_and(|maximum| maximum > limits.max_memory_pages as u64)
                    {
                        return Err(AuditError::MemoryLimitExceeded);
                    }
                }
            }
            Payload::TableSection(section) => {
                for table in section {
                    tables = tables
                        .checked_add(1)
                        .ok_or(AuditError::TableLimitExceeded)?;
                    let table = table.map_err(|_| AuditError::InvalidModule)?;
                    if table.ty.table64
                        || table.ty.shared
                        || table.ty.initial > MAX_TABLE_ELEMENTS
                        || table
                            .ty
                            .maximum
                            .is_some_and(|maximum| maximum > MAX_TABLE_ELEMENTS)
                    {
                        return Err(AuditError::TableLimitExceeded);
                    }
                }
            }
            _ => {}
        }
    }
    if memories != 1 {
        return Err(AuditError::InvalidAbi);
    }
    if tables > 1 {
        return Err(AuditError::TableLimitExceeded);
    }
    Ok(())
}

fn page_bytes(pages: u32) -> Result<usize, AuditError> {
    usize::try_from(pages)
        .ok()
        .and_then(|pages| pages.checked_mul(WASM_PAGE_SIZE as usize))
        .ok_or(AuditError::MemoryLimitExceeded)
}

fn validate_abi(module: &Module) -> Result<(), AuditError> {
    for import in module.imports() {
        if import.module() == "audit" && import.name() == "deterministic" {
            if !matches!(import.ty(), ExternType::Func(ref function) if function.params().len() == 0 && function.results().len() == 1 && function.results().next().is_some_and(|result| matches!(result, wasmtime::ValType::I32)))
            {
                return Err(AuditError::InvalidAbi);
            }
        } else if import.module() == "audit" && import.name() == "exchange" {
            if !matches!(import.ty(), ExternType::Func(ref function) if function.params().len() == 4 && function.params().all(|p| matches!(p, wasmtime::ValType::I32)) && function.results().len() == 1 && function.results().next().is_some_and(|r| matches!(r, wasmtime::ValType::I32)))
            {
                return Err(AuditError::InvalidAbi);
            }
        } else {
            return Err(AuditError::ForbiddenImport(format!(
                "{}::{}",
                import.module(),
                import.name()
            )));
        }
    }
    let run = module
        .exports()
        .find(|export_| export_.name() == "run")
        .ok_or(AuditError::InvalidAbi)?;
    let memory = module
        .exports()
        .find(|export_| export_.name() == "memory")
        .ok_or(AuditError::InvalidAbi)?;
    if !matches!(memory.ty(), ExternType::Memory(_))
        || !matches!(run.ty(), ExternType::Func(ref function) if function.params().len() == 2 && function.params().all(|param| matches!(param, wasmtime::ValType::I32)) && function.results().len() == 1 && function.results().next().is_some_and(|result| matches!(result, wasmtime::ValType::I64)))
    {
        return Err(AuditError::InvalidAbi);
    }
    Ok(())
}

fn map_error<H: AuditHost>(store: &Store<StoreState<'_, H>>, error: &anyhow::Error) -> AuditError {
    match store.data().failure.or(store.data().limiter.failure) {
        Some(ExecutionFailure::Memory) => AuditError::MemoryLimitExceeded,
        Some(ExecutionFailure::Table) => AuditError::TableLimitExceeded,
        Some(ExecutionFailure::Request) => AuditError::RequestLimitExceeded,
        Some(ExecutionFailure::Bytes) => AuditError::BudgetExhausted,
        Some(ExecutionFailure::InvalidAbi) => AuditError::InvalidAbi,
        Some(ExecutionFailure::Host(AuditHostError::BudgetExhausted)) => {
            AuditError::RequestLimitExceeded
        }
        Some(ExecutionFailure::Host(AuditHostError::DeadlineExceeded)) => AuditError::TimedOut,
        Some(ExecutionFailure::Host(AuditHostError::Cancelled)) => AuditError::Cancelled,
        Some(ExecutionFailure::Host(_)) => AuditError::HostRejected,
        None => match error.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel) => AuditError::FuelExhausted,
            Some(Trap::Interrupt) => AuditError::TimedOut,
            _ => AuditError::Trap,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditManifest, Capability, EvidenceSchema, EvidenceType, RollbackPlan, SideEffectProfile,
        TargetKind, verify_manifest,
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};

    #[tokio::test]
    async fn effective_limits_cannot_broaden_the_signed_manifest() {
        let wasm = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#).unwrap();
        let signed = Limits {
            max_bytes: 64,
            max_requests: 2,
            max_time: Duration::from_secs(1),
            max_fuel: 100_000,
            max_memory_pages: 1,
        };
        let mut manifest = AuditManifest::new(
            "limits".into(),
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
            signed.clone(),
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[3; 32]);
        manifest.sign(&key).unwrap();
        let verified = verify_manifest(&manifest, &wasm, &key.verifying_key()).unwrap();
        let broader = Limits {
            max_bytes: 65,
            ..signed
        };
        assert!(matches!(
            Sandbox::new_with_limits(verified, &broader).await,
            Err(AuditError::InvalidManifest(_))
        ));
    }
}
