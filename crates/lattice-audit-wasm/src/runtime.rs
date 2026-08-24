use crate::{AuditError, Limits, VerifiedManifest};
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
}

struct StoreState<'a, H: AuditHost> {
    host: &'a H,
    limiter: LimitsState,
    requests: u32,
    max_requests: u32,
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
        let mut config = Config::new();
        config.consume_fuel(true);
        config.async_support(true);
        config.epoch_interruption(true);
        validate_static_limits(verified.wasm(), verified.limits())?;
        let engine = Engine::new(&config).map_err(|_| AuditError::InvalidModule)?;
        let module =
            Module::new(&engine, verified.wasm()).map_err(|_| AuditError::InvalidModule)?;
        validate_abi(&module)?;
        Ok(Self {
            engine,
            module,
            limits: verified.limits().clone(),
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
                    if import.module == "audit" && import.name == "deterministic" {
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
        None => match error.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel) => AuditError::FuelExhausted,
            Some(Trap::Interrupt) => AuditError::TimedOut,
            _ => AuditError::Trap,
        },
    }
}
