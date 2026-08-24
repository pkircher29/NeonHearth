use crate::{AuditError, Limits, VerifiedManifest};
use std::time::Duration;
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
        let module = Module::new(&engine, verified.wasm())
            .map_err(|e| AuditError::ForbiddenImport(e.to_string()))?;
        for import in module.imports() {
            let allowed = import.module() == "audit"
                && import.name() == "deterministic"
                && matches!(import.ty(), ExternType::Func(_));
            if !allowed {
                return Err(AuditError::ForbiddenImport(format!(
                    "{}::{}",
                    import.module(),
                    import.name()
                )));
            }
        }
        Ok(Self {
            engine,
            module,
            limits: verified.limits().clone(),
        })
    }

    pub async fn execute<H: AuditHost>(
        &self,
        _input: &[u8],
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
            },
        );
        store.limiter(|s| &mut s.limiter);
        store
            .set_fuel(self.limits.max_fuel)
            .map_err(|_| AuditError::Trap)?;
        store.set_epoch_deadline(1);
        let engine = self.engine.clone();
        let _ticker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            engine.increment_epoch();
        });
        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap(
                "audit",
                "deterministic",
                |caller: wasmtime::Caller<'_, StoreState<'_, H>>| {
                    let _ = caller.data().host.deterministic();
                },
            )
            .map_err(|_| AuditError::Trap)?;
        let instance = linker.instantiate(&mut store, &self.module).map_err(|e| {
            if e.to_string().contains("memory") {
                AuditError::MemoryLimitExceeded
            } else {
                AuditError::Trap
            }
        })?;
        if let Some(run) = instance.get_func(&mut store, "run") {
            run.call(&mut store, &[], &mut []).map_err(|e| {
                let s = e.to_string();
                if s.contains("fuel") {
                    AuditError::FuelExhausted
                } else if s.contains("memory") {
                    AuditError::MemoryLimitExceeded
                } else {
                    AuditError::TimedOut
                }
            })?;
        }
        let output = host.deterministic();
        if output.len() as u64 > self.limits.max_bytes {
            return Err(AuditError::OutputLimitExceeded);
        }
        Ok(AuditResult { output })
    }
}
