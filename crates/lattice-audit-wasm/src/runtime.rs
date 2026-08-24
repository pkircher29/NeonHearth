use crate::{AuditError, Limits, VerifiedManifest};
use wasmtime::{Config, Engine, ExternType, Linker, Module, ResourceLimiter, Store};

pub trait AuditHost: Send + Sync {
    fn deterministic(&self) -> Vec<u8>;
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
}

struct StoreState<'a, H: AuditHost> {
    host: &'a H,
    limiter: LimitsState,
    requests: u32,
}
struct LimitsState {
    max_memory: usize,
    memory: usize,
}
impl ResourceLimiter for LimitsState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired > self.max_memory || maximum.is_some_and(|m| m > self.max_memory) {
            return Ok(false);
        }
        self.memory = desired;
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= 64 && maximum.unwrap_or(64) <= 64)
    }
}

impl Sandbox {
    pub async fn new(verified: VerifiedManifest) -> Result<Self, AuditError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|_| AuditError::Trap)?;
        let module =
            Module::new(&engine, verified.wasm()).map_err(|_| AuditError::InvalidModule)?;
        for import in module.imports() {
            let allowed = import.module() == "audit"
                && import.name() == "deterministic"
                && matches!(import.ty(), ExternType::Func(ref f) if f.params().len() == 0 && f.results().len() == 1 && f.results().next().is_some_and(|v| matches!(v, wasmtime::ValType::I32)));
            if !allowed {
                return Err(AuditError::ForbiddenImport(format!(
                    "{}::{}",
                    import.module(),
                    import.name()
                )));
            }
        }
        let run = module
            .exports()
            .find(|e| e.name() == "run")
            .ok_or(AuditError::InvalidAbi)?;
        let memory = module.exports().find(|e| e.name() == "memory");
        if !matches!(run.ty(), ExternType::Func(ref f) if f.params().len()==2 && f.params().all(|v| matches!(v, wasmtime::ValType::I32)) && f.results().len()==1 && f.results().next().is_some_and(|v| matches!(v, wasmtime::ValType::I64)))
            || memory.is_none()
        {
            return Err(AuditError::InvalidAbi);
        }
        Ok(Self {
            engine,
            module,
            limits: verified.limits().clone(),
        })
    }

    pub async fn execute<H: AuditHost>(
        &self,
        input: &[u8],
        host: &H,
    ) -> Result<AuditResult, AuditError> {
        let mut store = Store::new(
            &self.engine,
            StoreState {
                host,
                limiter: LimitsState {
                    max_memory: self.limits.max_memory_pages as usize * 65536,
                    memory: 0,
                },
                requests: 0,
            },
        );
        store.limiter(|s| &mut s.limiter);
        store
            .set_fuel(self.limits.max_fuel)
            .map_err(|_| AuditError::Trap)?;
        store.set_epoch_deadline(1);
        if input.len() as u64 > self.limits.max_bytes {
            return Err(AuditError::InputLimitExceeded);
        }
        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap(
                "audit",
                "deterministic",
                |mut caller: wasmtime::Caller<'_, StoreState<'_, H>>| -> i32 {
                    caller.data_mut().requests += 1;
                    caller.data().host.deterministic();
                    0
                },
            )
            .map_err(|_| AuditError::Trap)?;
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|_| AuditError::Trap)?;
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
        let packed = run.call(&mut store, (0, input.len() as i32)).map_err(|_| {
            if store.get_fuel().unwrap_or(1) == 0 {
                AuditError::FuelExhausted
            } else {
                AuditError::Trap
            }
        })?;
        if store.data().requests > self.limits.max_requests {
            return Err(AuditError::RequestLimitExceeded);
        }
        let ptr = (packed >> 32) as u64;
        let len = (packed as u32) as u64;
        let end = ptr
            .checked_add(len)
            .ok_or(AuditError::OutputLimitExceeded)?;
        if len > self.limits.max_bytes {
            return Err(AuditError::OutputLimitExceeded);
        }
        let data = memory.data(&store);
        if end > data.len() as u64 {
            return Err(AuditError::Trap);
        }
        let output = data[ptr as usize..end as usize].to_vec();
        Ok(AuditResult { output })
    }
}
