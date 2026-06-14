//! WASM sandbox runtime baseline for Swarm P0-4.

use thiserror::Error;
use wasmparser::{Parser, Payload};
use wasmtime::{
    AsContextMut, Caller, Config, Engine, ExternType, Linker, Memory, Module, OptLevel, Store,
    StoreLimits, StoreLimitsBuilder, TypedFunc,
};

pub const MAX_MODULE_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_OUTPUT_JSON_BYTES: usize = 256 * 1024;
pub const MAX_WASM_MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_WASM_MEMORY_PAGES: u32 = (MAX_WASM_MEMORY_BYTES / 65_536) as u32;
pub const MAX_FUEL: u64 = 10_000_000;
pub const DEFAULT_EPOCH_DEADLINE_TICKS: u64 = 1;
pub const DEFAULT_HOST_CALLS_PER_TICK: u32 = 1_000;
pub const DEFAULT_PATH_FIND_PER_TICK: u32 = 10;
pub const DEFAULT_OBJECTS_IN_RANGE_PER_TICK: u32 = 5;

const RESULT_STRUCT_BYTES: i32 = 8;
const ALLOWED_IMPORTS: &[(&str, &str)] = &[
    ("env", "host_get_terrain"),
    ("env", "host_get_objects_in_range"),
    ("env", "host_path_find"),
    ("env", "host_get_world_config"),
    ("env", "host_get_world_rules"),
];

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub max_fuel: u64,
    pub epoch_deadline_ticks: u64,
    pub max_host_calls_per_tick: u32,
    pub max_path_find_per_tick: u32,
    pub max_objects_in_range_per_tick: u32,
    pub max_output_json_bytes: usize,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_fuel: MAX_FUEL,
            epoch_deadline_ticks: DEFAULT_EPOCH_DEADLINE_TICKS,
            max_host_calls_per_tick: DEFAULT_HOST_CALLS_PER_TICK,
            max_path_find_per_tick: DEFAULT_PATH_FIND_PER_TICK,
            max_objects_in_range_per_tick: DEFAULT_OBJECTS_IN_RANGE_PER_TICK,
            max_output_json_bytes: MAX_OUTPUT_JSON_BYTES,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostCallBudget {
    pub total_calls: u32,
    pub path_find_calls: u32,
    pub objects_in_range_calls: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickOutput {
    pub command_json: Vec<u8>,
    pub host_call_budget: HostCallBudget,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("module exceeds 5MB limit: {actual} bytes")]
    ModuleTooLarge { actual: usize },
    #[error("invalid wasm module: {0}")]
    InvalidWasm(String),
    #[error("start section is forbidden")]
    StartSectionForbidden,
    #[error("missing required export `{0}`")]
    MissingExport(&'static str),
    #[error("export `{name}` has wrong type: expected {expected}")]
    WrongExportType {
        name: &'static str,
        expected: &'static str,
    },
    #[error("illegal import `{module}::{name}`")]
    IllegalImport { module: String, name: String },
    #[error("unsupported import type for `{module}::{name}`")]
    UnsupportedImportType { module: String, name: String },
    #[error("wasmtime error: {0}")]
    Wasmtime(#[from] wasmtime::Error),
    #[error("memory access error: {0}")]
    MemoryAccess(String),
    #[error("linear memory export `memory` is required")]
    MissingMemory,
    #[error("integer pointer must be non-negative")]
    NegativePointer,
    #[error("pointer/length overflow")]
    PointerOverflow,
    #[error("memory access out of bounds: ptr={ptr} len={len} memory={memory_len}")]
    MemoryOutOfBounds {
        ptr: u32,
        len: u32,
        memory_len: usize,
    },
    #[error("tick returned non-zero status {0}")]
    TickFailed(i32),
    #[error("output JSON exceeds 256KB limit: {actual} bytes")]
    OutputTooLarge { actual: usize },
    #[error("host call budget exceeded")]
    HostCallBudgetExceeded,
}

#[derive(Clone)]
pub struct SandboxRuntime {
    engine: Engine,
    config: SandboxConfig,
}

#[derive(Clone)]
pub struct CompiledModule {
    module: Module,
}

struct StoreState {
    limits: StoreLimits,
    host_budget: HostCallBudget,
    config: SandboxConfig,
}

impl SandboxRuntime {
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let mut wasmtime_config = Config::new();
        wasmtime_config.consume_fuel(true);
        // Wasmtime 30 enforces hard instance/memory/table ceilings through StoreLimits.
        // Keep guard pages and zero growth reservation at engine level, then install the
        // Store limiter before instantiation so active data/table initialization is bounded.
        wasmtime_config.memory_reservation_for_growth(0);
        wasmtime_config.memory_guard_size(2 * 1024 * 1024);
        wasmtime_config.guard_before_linear_memory(true);
        wasmtime_config.max_wasm_stack(1 * 1024 * 1024);
        wasmtime_config.cranelift_opt_level(OptLevel::Speed);
        wasmtime_config.wasm_threads(false);
        wasmtime_config.wasm_simd(true);
        wasmtime_config.wasm_relaxed_simd(false);
        wasmtime_config.epoch_interruption(true);

        Ok(Self {
            engine: Engine::new(&wasmtime_config)?,
            config,
        })
    }

    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<CompiledModule, SandboxError> {
        validate_wasmparser(wasm_bytes)?;
        let module = Module::from_binary(&self.engine, wasm_bytes)?;
        validate_module_exports(&module)?;
        validate_module_imports(&module)?;
        Ok(CompiledModule { module })
    }

    pub fn execute_tick(
        &self,
        compiled: &CompiledModule,
        snapshot_json: &[u8],
    ) -> Result<TickOutput, SandboxError> {
        let mut store = Store::new(
            &self.engine,
            StoreState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(MAX_WASM_MEMORY_BYTES)
                    .instances(1)
                    .memories(1)
                    .tables(10)
                    .build(),
                host_budget: HostCallBudget::default(),
                config: self.config.clone(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(self.config.max_fuel)?;
        store.set_epoch_deadline(self.config.epoch_deadline_ticks);

        let mut linker = Linker::new(&self.engine);
        define_read_only_host_imports(&mut linker)?;

        let instance = linker.instantiate(&mut store, &compiled.module)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(SandboxError::MissingMemory)?;
        let alloc: TypedFunc<i32, i32> = instance.get_typed_func(&mut store, "alloc")?;
        let free: TypedFunc<(i32, i32), ()> = instance.get_typed_func(&mut store, "free")?;
        let tick: TypedFunc<(i32, i32, i32), i32> = instance.get_typed_func(&mut store, "tick")?;

        let snapshot_len = usize_to_i32(snapshot_json.len())?;
        let snapshot_ptr = alloc.call(&mut store, snapshot_len)?;
        checked_range(memory, &mut store, snapshot_ptr, snapshot_len)?;
        memory
            .write(&mut store, snapshot_ptr as usize, snapshot_json)
            .map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;

        let result_ptr = alloc.call(&mut store, RESULT_STRUCT_BYTES)?;
        let result_range = checked_range(memory, &mut store, result_ptr, RESULT_STRUCT_BYTES)?;
        ensure_aligned(result_range.start, 4)?;

        let tick_status = tick.call(&mut store, (snapshot_ptr, snapshot_len, result_ptr))?;
        if tick_status != 0 {
            let _ = free.call(&mut store, (snapshot_ptr, snapshot_len));
            let _ = free.call(&mut store, (result_ptr, RESULT_STRUCT_BYTES));
            return Err(SandboxError::TickFailed(tick_status));
        }

        let mut result = [0_u8; RESULT_STRUCT_BYTES as usize];
        memory
            .read(&mut store, result_range.start, &mut result)
            .map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;
        let output_ptr = u32::from_le_bytes(result[0..4].try_into().expect("slice length"));
        let output_len = u32::from_le_bytes(result[4..8].try_into().expect("slice length"));
        if output_len as usize > self.config.max_output_json_bytes {
            let _ = free.call(&mut store, (output_ptr as i32, output_len as i32));
            let _ = free.call(&mut store, (snapshot_ptr, snapshot_len));
            let _ = free.call(&mut store, (result_ptr, RESULT_STRUCT_BYTES));
            return Err(SandboxError::OutputTooLarge {
                actual: output_len as usize,
            });
        }

        let output_range = checked_u32_range(memory, &mut store, output_ptr, output_len)?;
        let mut command_json = vec![0_u8; output_len as usize];
        memory
            .read(&mut store, output_range.start, &mut command_json)
            .map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;

        free.call(&mut store, (output_ptr as i32, output_len as i32))?;
        free.call(&mut store, (snapshot_ptr, snapshot_len))?;
        free.call(&mut store, (result_ptr, RESULT_STRUCT_BYTES))?;

        Ok(TickOutput {
            command_json,
            host_call_budget: store.data().host_budget.clone(),
        })
    }

    pub fn increment_epoch(&self) {
        self.engine.increment_epoch();
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl Default for SandboxRuntime {
    fn default() -> Self {
        Self::new(SandboxConfig::default()).expect("default sandbox runtime config must be valid")
    }
}

pub fn validate_wasmparser(wasm_bytes: &[u8]) -> Result<(), SandboxError> {
    if wasm_bytes.len() > MAX_MODULE_BYTES {
        return Err(SandboxError::ModuleTooLarge {
            actual: wasm_bytes.len(),
        });
    }

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        match payload.map_err(|err| SandboxError::InvalidWasm(err.to_string()))? {
            Payload::StartSection { .. } => return Err(SandboxError::StartSectionForbidden),
            _ => {}
        }
    }

    Ok(())
}

fn validate_module_exports(module: &Module) -> Result<(), SandboxError> {
    require_func_export(module, "tick")?;
    require_func_export(module, "alloc")?;
    require_func_export(module, "free")?;
    Ok(())
}

fn require_func_export(module: &Module, name: &'static str) -> Result<(), SandboxError> {
    match module
        .get_export(name)
        .ok_or(SandboxError::MissingExport(name))?
    {
        ExternType::Func(_) => Ok(()),
        _ => Err(SandboxError::WrongExportType {
            name,
            expected: "function",
        }),
    }
}

fn validate_module_imports(module: &Module) -> Result<(), SandboxError> {
    for import in module.imports() {
        if !ALLOWED_IMPORTS.contains(&(import.module(), import.name())) {
            return Err(SandboxError::IllegalImport {
                module: import.module().to_owned(),
                name: import.name().to_owned(),
            });
        }
        if !matches!(import.ty(), ExternType::Func(_)) {
            return Err(SandboxError::UnsupportedImportType {
                module: import.module().to_owned(),
                name: import.name().to_owned(),
            });
        }
    }
    Ok(())
}

fn define_read_only_host_imports(linker: &mut Linker<StoreState>) -> Result<(), SandboxError> {
    linker.func_wrap(
        "env",
        "host_get_terrain",
        |mut caller: Caller<'_, StoreState>, _x: i32, _y: i32| -> i32 {
            charge_host_call(&mut caller, HostCallKind::Terrain).unwrap_or(-1)
        },
    )?;
    linker.func_wrap(
        "env",
        "host_get_objects_in_range",
        |mut caller: Caller<'_, StoreState>,
         _x: i32,
         _y: i32,
         _range: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            match charge_host_call(&mut caller, HostCallKind::ObjectsInRange)
                .and_then(|_| checked_caller_range(&mut caller, out_ptr, out_len).map(|_| ()))
            {
                Ok(()) => 0,
                Err(_) => -1,
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_path_find",
        |mut caller: Caller<'_, StoreState>,
         _from_x: i32,
         _from_y: i32,
         _to_x: i32,
         _to_y: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            match charge_host_call(&mut caller, HostCallKind::PathFind)
                .and_then(|_| checked_caller_range(&mut caller, out_ptr, out_len).map(|_| ()))
            {
                Ok(()) => 0,
                Err(_) => -1,
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_get_world_config",
        |mut caller: Caller<'_, StoreState>,
         key_ptr: i32,
         key_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            match checked_caller_range(&mut caller, key_ptr, key_len)
                .and_then(|_| charge_host_call(&mut caller, HostCallKind::WorldConfig))
                .and_then(|_| checked_caller_range(&mut caller, out_ptr, out_len).map(|_| ()))
            {
                Ok(()) => 0,
                Err(_) => -1,
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_get_world_rules",
        |mut caller: Caller<'_, StoreState>, out_ptr: i32, out_len: i32| -> i32 {
            match charge_host_call(&mut caller, HostCallKind::WorldRules)
                .and_then(|_| checked_caller_range(&mut caller, out_ptr, out_len).map(|_| ()))
            {
                Ok(()) => 0,
                Err(_) => -1,
            }
        },
    )?;
    Ok(())
}

enum HostCallKind {
    Terrain,
    ObjectsInRange,
    PathFind,
    WorldConfig,
    WorldRules,
}

fn charge_host_call(
    caller: &mut Caller<'_, StoreState>,
    kind: HostCallKind,
) -> Result<i32, SandboxError> {
    let state = caller.data_mut();
    state.host_budget.total_calls = state
        .host_budget
        .total_calls
        .checked_add(1)
        .ok_or(SandboxError::HostCallBudgetExceeded)?;
    if state.host_budget.total_calls > state.config.max_host_calls_per_tick {
        return Err(SandboxError::HostCallBudgetExceeded);
    }

    match kind {
        HostCallKind::Terrain => Ok(0),
        HostCallKind::ObjectsInRange => {
            state.host_budget.objects_in_range_calls = state
                .host_budget
                .objects_in_range_calls
                .checked_add(1)
                .ok_or(SandboxError::HostCallBudgetExceeded)?;
            if state.host_budget.objects_in_range_calls > state.config.max_objects_in_range_per_tick
            {
                return Err(SandboxError::HostCallBudgetExceeded);
            }
            Ok(0)
        }
        HostCallKind::PathFind => {
            state.host_budget.path_find_calls = state
                .host_budget
                .path_find_calls
                .checked_add(1)
                .ok_or(SandboxError::HostCallBudgetExceeded)?;
            if state.host_budget.path_find_calls > state.config.max_path_find_per_tick {
                return Err(SandboxError::HostCallBudgetExceeded);
            }
            Ok(0)
        }
        HostCallKind::WorldConfig | HostCallKind::WorldRules => Ok(0),
    }
}

fn checked_caller_range(
    caller: &mut Caller<'_, StoreState>,
    ptr: i32,
    len: i32,
) -> Result<std::ops::Range<usize>, SandboxError> {
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(SandboxError::MissingMemory)?;
    checked_range(memory, caller, ptr, len)
}

fn checked_range(
    memory: Memory,
    store: impl AsContextMut,
    ptr: i32,
    len: i32,
) -> Result<std::ops::Range<usize>, SandboxError> {
    if ptr < 0 || len < 0 {
        return Err(SandboxError::NegativePointer);
    }
    checked_u32_range(memory, store, ptr as u32, len as u32)
}

fn checked_u32_range(
    memory: Memory,
    mut store: impl AsContextMut,
    ptr: u32,
    len: u32,
) -> Result<std::ops::Range<usize>, SandboxError> {
    let start = ptr as usize;
    let len = len as usize;
    let end = start
        .checked_add(len)
        .ok_or(SandboxError::PointerOverflow)?;
    let memory_len = memory.data_size(&mut store);
    if end > memory_len {
        return Err(SandboxError::MemoryOutOfBounds {
            ptr,
            len: len as u32,
            memory_len,
        });
    }
    Ok(start..end)
}

fn ensure_aligned(ptr: usize, align: usize) -> Result<(), SandboxError> {
    if ptr % align == 0 {
        Ok(())
    } else {
        Err(SandboxError::PointerOverflow)
    }
}

fn usize_to_i32(value: usize) -> Result<i32, SandboxError> {
    i32::try_from(value).map_err(|_| SandboxError::PointerOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wasm(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("valid wat")
    }

    fn valid_echo_module() -> Vec<u8> {
        wasm(
            r#"
            (module
              (memory (export "memory") 1 1024)
              (global $heap (mut i32) (i32.const 4096))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $heap))
                (global.set $heap
                  (i32.and
                    (i32.add (i32.add (global.get $heap) (local.get $len)) (i32.const 3))
                    (i32.const -4)))
                (local.get $ptr))
              (func (export "free") (param i32) (param i32))
              (data (i32.const 1024) "[]")
              (func (export "tick") (param $snapshot_ptr i32) (param $snapshot_len i32) (param $result_ptr i32) (result i32)
                (i32.store (local.get $result_ptr) (i32.const 1024))
                (i32.store offset=4 (local.get $result_ptr) (i32.const 2))
                (i32.const 0)))
            "#,
        )
    }

    #[test]
    fn rejects_module_larger_than_5mb() {
        let bytes = vec![0; MAX_MODULE_BYTES + 1];
        assert!(matches!(
            validate_wasmparser(&bytes),
            Err(SandboxError::ModuleTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_start_section() {
        let bytes = wasm(
            r#"
            (module
              (func $start)
              (start $start)
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32) (i32.const 0)))
            "#,
        );
        assert!(matches!(
            SandboxRuntime::default().compile(&bytes),
            Err(SandboxError::StartSectionForbidden)
        ));
    }

    #[test]
    fn rejects_missing_tick_export() {
        let bytes = wasm(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "free") (param i32) (param i32)))
            "#,
        );
        assert!(matches!(
            SandboxRuntime::default().compile(&bytes),
            Err(SandboxError::MissingExport("tick"))
        ));
    }

    #[test]
    fn rejects_illegal_import() {
        let bytes = wasm(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write" (func $fd_write))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32) (i32.const 0)))
            "#,
        );
        assert!(matches!(
            SandboxRuntime::default().compile(&bytes),
            Err(SandboxError::IllegalImport { .. })
        ));
    }

    #[test]
    fn executes_deferred_tick_and_reads_output() {
        let runtime = SandboxRuntime::default();
        let module = runtime.compile(&valid_echo_module()).unwrap();
        let output = runtime.execute_tick(&module, br#"{"tick":1}"#).unwrap();
        assert_eq!(output.command_json, b"[]");
        assert_eq!(output.host_call_budget, HostCallBudget::default());
    }

    #[test]
    fn rejects_output_over_256kb() {
        let bytes = wasm(
            r#"
            (module
              (memory (export "memory") 5 1024)
              (global $heap (mut i32) (i32.const 4096))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $heap))
                (global.set $heap
                  (i32.and
                    (i32.add (i32.add (global.get $heap) (local.get $len)) (i32.const 3))
                    (i32.const -4)))
                (local.get $ptr))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32)
                (i32.store (local.get 2) (i32.const 4096))
                (i32.store offset=4 (local.get 2) (i32.const 262145))
                (i32.const 0)))
            "#,
        );
        let runtime = SandboxRuntime::default();
        let module = runtime.compile(&bytes).unwrap();
        assert!(matches!(
            runtime.execute_tick(&module, b"{}"),
            Err(SandboxError::OutputTooLarge { actual: 262145 })
        ));
    }

    #[test]
    fn rejects_out_of_bounds_result_pointer() {
        let bytes = wasm(
            r#"
            (module
              (memory (export "memory") 1 1024)
              (func (export "alloc") (param i32) (result i32) (i32.const 65532))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32) (i32.const 0)))
            "#,
        );
        let runtime = SandboxRuntime::default();
        let module = runtime.compile(&bytes).unwrap();
        assert!(matches!(
            runtime.execute_tick(&module, b"{}"),
            Err(SandboxError::MemoryOutOfBounds { .. })
        ));
    }

    #[test]
    fn host_budget_limits_are_enforced() {
        let bytes = wasm(
            r#"
            (module
              (import "env" "host_path_find" (func $host_path_find (param i32 i32 i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1 1024)
              (global $heap (mut i32) (i32.const 4096))
              (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $heap))
                (global.set $heap
                  (i32.and
                    (i32.add (i32.add (global.get $heap) (local.get $len)) (i32.const 3))
                    (i32.const -4)))
                (local.get $ptr))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32)
                (drop (call $host_path_find (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 1) (i32.const 2048) (i32.const 8)))
                (drop (call $host_path_find (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 1) (i32.const 2048) (i32.const 8)))
                (i32.store (local.get 2) (i32.const 1024))
                (i32.store offset=4 (local.get 2) (i32.const 2))
                (i32.const 0))
              (data (i32.const 1024) "[]"))
            "#,
        );
        let runtime = SandboxRuntime::new(SandboxConfig {
            max_path_find_per_tick: 1,
            ..SandboxConfig::default()
        })
        .unwrap();
        let module = runtime.compile(&bytes).unwrap();
        let output = runtime.execute_tick(&module, b"{}").unwrap();
        assert_eq!(output.host_call_budget.path_find_calls, 2);
    }

    #[test]
    fn fuel_exhaustion_traps_infinite_loop() {
        let bytes = wasm(
            r#"
            (module
              (memory (export "memory") 1 1024)
              (func (export "alloc") (param i32) (result i32) (i32.const 1024))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32)
                (loop $again br $again)
                (i32.const 0)))
            "#,
        );
        let runtime = SandboxRuntime::new(SandboxConfig {
            max_fuel: 10_000,
            ..SandboxConfig::default()
        })
        .unwrap();
        let module = runtime.compile(&bytes).unwrap();
        assert!(runtime.execute_tick(&module, b"{}").is_err());
    }
}
