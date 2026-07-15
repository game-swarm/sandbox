//! WASM sandbox runtime baseline for Swarm P0-4.

use std::collections::{HashMap, VecDeque};

use thiserror::Error;
use wasmparser::{Parser, Payload};
use wasmtime::{
    AsContextMut, Caller, Config, Engine, ExternType, Linker, Memory, Module, OptLevel, Store,
    StoreLimits, StoreLimitsBuilder, TypedFunc,
};

pub const DEFAULT_VALIDATION_POLICY_VERSION: &str = "raw-wasm-v1";

#[cfg(all(feature = "os-isolation", target_os = "linux"))]
use std::io::{Read, Write};
#[cfg(all(feature = "os-isolation", target_os = "linux"))]
use std::os::unix::process::CommandExt;
#[cfg(all(feature = "os-isolation", target_os = "linux"))]
use std::process::{Command, Stdio};
#[cfg(all(feature = "os-isolation", target_os = "linux"))]
use std::time::{Duration, Instant};

pub const MAX_MODULE_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_OUTPUT_JSON_BYTES: usize = 256 * 1024;
pub const MAX_WASM_MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_WASM_MEMORY_PAGES: u32 = (MAX_WASM_MEMORY_BYTES / 65_536) as u32;
pub const MAX_FUEL: u64 = 10_000_000;
pub const DEFAULT_EPOCH_DEADLINE_TICKS: u64 = 1;
pub const DEFAULT_HOST_CALLS_PER_TICK: u32 = 1_000;
pub const DEFAULT_PATH_FIND_PER_TICK: u32 = 10;
pub const DEFAULT_OBJECTS_IN_RANGE_PER_TICK: u32 = 5;
pub const DEFAULT_WORLD_CONFIG_PER_TICK: u32 = 5;
pub const DEFAULT_WORLD_RULES_PER_TICK: u32 = 1;
pub const DEFAULT_RANDOM_PER_TICK: u32 = 10;
pub const DEFAULT_TICK_TIMEOUT_MS: u64 = 2_500;
pub const MAX_RANDOM_BYTES: i32 = 256;

const RESULT_STRUCT_BYTES: i32 = 16;
#[cfg(all(feature = "os-isolation", target_os = "linux"))]
const CHILD_ENV: &str = "SWARM_WASM_SANDBOX_CHILD";
#[cfg(all(feature = "os-isolation", target_os = "linux"))]
const PROTOCOL_MAGIC: u32 = 0x5357_5342;
#[cfg(all(feature = "os-isolation", target_os = "linux"))]
const PROTOCOL_VERSION: u32 = 1;
const ALLOWED_IMPORTS: &[(&str, &str)] = &[
    ("env", "host_get_terrain"),
    ("env", "host_get_objects_in_range"),
    ("env", "host_path_find"),
    ("env", "host_get_world_config"),
    ("env", "host_get_world_rules"),
    ("env", "host_get_random"),
    ("env", "host_get_fuel_remaining"),
];

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub max_fuel: u64,
    pub epoch_deadline_ticks: u64,
    pub max_host_calls_per_tick: u32,
    pub max_path_find_per_tick: u32,
    pub max_objects_in_range_per_tick: u32,
    pub max_output_json_bytes: usize,
    pub tick_timeout_ms: u64,
    pub wasm_simd: bool,
    pub isolation: IsolationMode,
    pub os_isolation: OsIsolationPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationMode {
    InProcess,
    OsProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsIsolationPolicy {
    pub seccomp: bool,
    pub cgroup: bool,
    pub network_namespace: bool,
    pub read_only_root: bool,
    pub tmpfs_tmp: bool,
    pub allow_permission_fallback: bool,
}

impl Default for OsIsolationPolicy {
    fn default() -> Self {
        Self {
            seccomp: true,
            cgroup: true,
            network_namespace: true,
            read_only_root: true,
            tmpfs_tmp: true,
            allow_permission_fallback: false,
        }
    }
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
            tick_timeout_ms: DEFAULT_TICK_TIMEOUT_MS,
            wasm_simd: false,
            isolation: IsolationMode::OsProcess,
            os_isolation: OsIsolationPolicy::default(),
        }
    }
}

impl SandboxConfig {
    pub fn development() -> Self {
        Self {
            wasm_simd: false,
            isolation: IsolationMode::InProcess,
            os_isolation: OsIsolationPolicy::development(),
            ..Self::default()
        }
    }
}

impl OsIsolationPolicy {
    pub fn development() -> Self {
        Self {
            seccomp: false,
            cgroup: false,
            network_namespace: false,
            read_only_root: false,
            tmpfs_tmp: false,
            allow_permission_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostCallBudget {
    pub total_calls: u32,
    pub path_find_calls: u32,
    pub objects_in_range_calls: u32,
    pub world_config_calls: u32,
    pub world_rules_calls: u32,
    pub random_calls: u32,
    pub fuel_remaining_calls: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickOutput {
    pub command_json: Vec<u8>,
    pub messages: Vec<u8>,
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
    #[error("compiled module cache miss for hash {module_hash} and wasmtime {wasmtime_version}")]
    ModuleCacheMiss {
        module_hash: String,
        wasmtime_version: String,
    },
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
    #[error("OS process isolation is unavailable on this build/target")]
    OsIsolationUnavailable,
    #[error("OS process isolation I/O error: {0}")]
    OsIsolationIo(String),
    #[error("OS process isolation protocol error: {0}")]
    OsIsolationProtocol(String),
    #[error("OS process isolation child failed: {0}")]
    OsIsolationChildFailed(String),
    #[error("OS process isolation timed out after {timeout_ms}ms")]
    OsIsolationTimedOut { timeout_ms: u64 },
    #[error("host RNG requires snapshot field `{0}`")]
    MissingHostRandomField(&'static str),
}

impl SandboxError {
    pub fn abi_error_code(&self) -> i32 {
        match self {
            SandboxError::MissingMemory
            | SandboxError::NegativePointer
            | SandboxError::PointerOverflow
            | SandboxError::MemoryOutOfBounds { .. }
            | SandboxError::MemoryAccess(_) => -2,
            SandboxError::HostCallBudgetExceeded => -4,
            SandboxError::ModuleTooLarge { .. }
            | SandboxError::InvalidWasm(_)
            | SandboxError::StartSectionForbidden
            | SandboxError::MissingExport(_)
            | SandboxError::WrongExportType { .. }
            | SandboxError::IllegalImport { .. }
            | SandboxError::UnsupportedImportType { .. }
            | SandboxError::MissingHostRandomField(_)
            | SandboxError::TickFailed(_)
            | SandboxError::OutputTooLarge { .. }
            | SandboxError::OsIsolationProtocol(_) => -5,
            SandboxError::OsIsolationTimedOut { .. } => -7,
            SandboxError::OsIsolationUnavailable => -9,
            SandboxError::Wasmtime(_)
            | SandboxError::ModuleCacheMiss { .. }
            | SandboxError::OsIsolationIo(_)
            | SandboxError::OsIsolationChildFailed(_) => -1,
        }
    }
}

#[derive(Clone)]
pub struct SandboxRuntime {
    engine: Engine,
    config: SandboxConfig,
}

#[derive(Clone)]
pub struct CompiledModule {
    module: Module,
    #[cfg_attr(
        not(all(feature = "os-isolation", target_os = "linux")),
        allow(dead_code)
    )]
    wasm_bytes: Vec<u8>,
    module_hash: String,
    wasmtime_version: String,
    validation_policy_version: String,
}

impl CompiledModule {
    pub fn module_hash(&self) -> &str {
        &self.module_hash
    }

    pub fn wasmtime_version(&self) -> &str {
        &self.wasmtime_version
    }

    pub fn validation_policy_version(&self) -> &str {
        &self.validation_policy_version
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleCacheKey {
    pub module_hash: String,
    pub wasmtime_version: String,
    pub validation_policy_version: String,
}

impl ModuleCacheKey {
    pub fn new(module_hash: impl Into<String>, wasmtime_version: impl Into<String>) -> Self {
        Self::new_with_policy(
            module_hash,
            wasmtime_version,
            DEFAULT_VALIDATION_POLICY_VERSION,
        )
    }

    pub fn new_with_policy(
        module_hash: impl Into<String>,
        wasmtime_version: impl Into<String>,
        validation_policy_version: impl Into<String>,
    ) -> Self {
        Self {
            module_hash: module_hash.into(),
            wasmtime_version: wasmtime_version.into(),
            validation_policy_version: validation_policy_version.into(),
        }
    }

    pub fn for_wasm(wasm_bytes: &[u8]) -> Self {
        Self::for_wasm_with_version(wasm_bytes, wasmtime_version())
    }

    pub fn for_wasm_with_version(wasm_bytes: &[u8], wasmtime_version: impl Into<String>) -> Self {
        Self::new(wasm_hash(wasm_bytes), wasmtime_version)
    }

    pub fn for_wasm_with_policy(
        wasm_bytes: &[u8],
        validation_policy_version: impl Into<String>,
    ) -> Self {
        Self::for_wasm_with_version_and_policy(
            wasm_bytes,
            wasmtime_version(),
            validation_policy_version,
        )
    }

    pub fn for_wasm_with_version_and_policy(
        wasm_bytes: &[u8],
        wasmtime_version: impl Into<String>,
        validation_policy_version: impl Into<String>,
    ) -> Self {
        Self::new_with_policy(
            wasm_hash(wasm_bytes),
            wasmtime_version,
            validation_policy_version,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedNativeModule {
    key: ModuleCacheKey,
    native_bytes: Vec<u8>,
}

impl CachedNativeModule {
    pub fn key(&self) -> &ModuleCacheKey {
        &self.key
    }

    pub fn compiled_artifact_hash(&self) -> String {
        wasm_hash(&self.native_bytes)
    }

    #[cfg(test)]
    fn with_wasmtime_version(mut self, wasmtime_version: impl Into<String>) -> Self {
        self.key.wasmtime_version = wasmtime_version.into();
        self
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModuleCacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub recompiles: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledModuleCache {
    entries: HashMap<ModuleCacheKey, CachedNativeModule>,
    hits: u64,
    misses: u64,
    recompiles: u64,
}

impl CompiledModuleCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &ModuleCacheKey) -> Option<&CachedNativeModule> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, cached: CachedNativeModule) -> Option<CachedNativeModule> {
        self.entries.insert(cached.key.clone(), cached)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn stats(&self) -> ModuleCacheStats {
        ModuleCacheStats {
            entries: self.entries.len(),
            hits: self.hits,
            misses: self.misses,
            recompiles: self.recompiles,
        }
    }

    pub fn record_miss(&mut self) {
        self.misses = self.misses.saturating_add(1);
    }
}

pub fn wasmtime_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn wasm_hash(wasm_bytes: &[u8]) -> String {
    blake3::hash(wasm_bytes).to_hex().to_string()
}

struct StoreState {
    limits: StoreLimits,
    host_budget: HostCallBudget,
    config: SandboxConfig,
    snapshot: serde_json::Value,
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
        wasmtime_config.max_wasm_stack(1024 * 1024);
        wasmtime_config.cranelift_opt_level(OptLevel::Speed);
        wasmtime_config.wasm_threads(false);
        wasmtime_config.wasm_simd(config.wasm_simd);
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
        Ok(CompiledModule {
            module,
            wasm_bytes: wasm_bytes.to_vec(),
            module_hash: wasm_hash(wasm_bytes),
            wasmtime_version: wasmtime_version().to_string(),
            validation_policy_version: DEFAULT_VALIDATION_POLICY_VERSION.to_string(),
        })
    }

    pub fn precompile_native(&self, wasm_bytes: &[u8]) -> Result<CachedNativeModule, SandboxError> {
        self.precompile_native_with_policy(wasm_bytes, DEFAULT_VALIDATION_POLICY_VERSION)
    }

    pub fn precompile_native_with_policy(
        &self,
        wasm_bytes: &[u8],
        validation_policy_version: &str,
    ) -> Result<CachedNativeModule, SandboxError> {
        validate_wasmparser(wasm_bytes)?;
        let native_bytes = self.engine.precompile_module(wasm_bytes)?;
        // The bytes passed to Wasmtime deserialization are generated by this engine in this
        // process. Callers cannot construct CachedNativeModule directly.
        let module = unsafe { Module::deserialize(&self.engine, &native_bytes)? };
        validate_module_exports(&module)?;
        validate_module_imports(&module)?;
        Ok(CachedNativeModule {
            key: ModuleCacheKey::for_wasm_with_policy(wasm_bytes, validation_policy_version),
            native_bytes,
        })
    }

    pub fn compile_from_cached_native(
        &self,
        cached: &CachedNativeModule,
        wasm_bytes: &[u8],
    ) -> Result<CompiledModule, SandboxError> {
        self.compile_from_cached_native_with_policy(
            cached,
            wasm_bytes,
            DEFAULT_VALIDATION_POLICY_VERSION,
        )
    }

    pub fn compile_from_cached_native_with_policy(
        &self,
        cached: &CachedNativeModule,
        wasm_bytes: &[u8],
        validation_policy_version: &str,
    ) -> Result<CompiledModule, SandboxError> {
        let expected = ModuleCacheKey::for_wasm_with_policy(wasm_bytes, validation_policy_version);
        if cached.key != expected {
            return Err(SandboxError::ModuleCacheMiss {
                module_hash: expected.module_hash,
                wasmtime_version: expected.wasmtime_version,
            });
        }
        // CachedNativeModule is only produced by precompile_native, so these bytes are same-process
        // Wasmtime cache bytes rather than caller-provided native code.
        let module = unsafe { Module::deserialize(&self.engine, &cached.native_bytes)? };
        validate_module_exports(&module)?;
        validate_module_imports(&module)?;
        Ok(CompiledModule {
            module,
            wasm_bytes: wasm_bytes.to_vec(),
            module_hash: cached.key.module_hash.clone(),
            wasmtime_version: cached.key.wasmtime_version.clone(),
            validation_policy_version: cached.key.validation_policy_version.clone(),
        })
    }

    pub fn compile_cached(
        &self,
        cache: &mut CompiledModuleCache,
        wasm_bytes: &[u8],
    ) -> Result<CompiledModule, SandboxError> {
        self.compile_cached_with_version_and_policy(
            cache,
            wasm_bytes,
            wasmtime_version(),
            DEFAULT_VALIDATION_POLICY_VERSION,
        )
    }

    pub fn compile_cached_with_version(
        &self,
        cache: &mut CompiledModuleCache,
        wasm_bytes: &[u8],
        stored_wasmtime_version: &str,
    ) -> Result<CompiledModule, SandboxError> {
        self.compile_cached_with_version_and_policy(
            cache,
            wasm_bytes,
            stored_wasmtime_version,
            DEFAULT_VALIDATION_POLICY_VERSION,
        )
    }

    pub fn compile_cached_with_policy(
        &self,
        cache: &mut CompiledModuleCache,
        wasm_bytes: &[u8],
        validation_policy_version: &str,
    ) -> Result<CompiledModule, SandboxError> {
        self.compile_cached_with_version_and_policy(
            cache,
            wasm_bytes,
            wasmtime_version(),
            validation_policy_version,
        )
    }

    pub fn compile_cached_with_version_and_policy(
        &self,
        cache: &mut CompiledModuleCache,
        wasm_bytes: &[u8],
        stored_wasmtime_version: &str,
        validation_policy_version: &str,
    ) -> Result<CompiledModule, SandboxError> {
        validate_wasmparser(wasm_bytes)?;
        let current_key =
            ModuleCacheKey::for_wasm_with_policy(wasm_bytes, validation_policy_version);
        let requested_key = ModuleCacheKey::for_wasm_with_version_and_policy(
            wasm_bytes,
            stored_wasmtime_version,
            validation_policy_version,
        );

        if stored_wasmtime_version == wasmtime_version() {
            if let Some(cached) = cache.get(&current_key).cloned() {
                cache.hits = cache.hits.saturating_add(1);
                return self.compile_from_cached_native_with_policy(
                    &cached,
                    wasm_bytes,
                    validation_policy_version,
                );
            }
            cache.misses = cache.misses.saturating_add(1);
        } else {
            cache.misses = cache.misses.saturating_add(1);
            cache.recompiles = cache.recompiles.saturating_add(1);
            cache.entries.remove(&requested_key);
        }

        let cached = self.precompile_native_with_policy(wasm_bytes, validation_policy_version)?;
        let compiled = self.compile_from_cached_native_with_policy(
            &cached,
            wasm_bytes,
            validation_policy_version,
        )?;
        cache.insert(cached);
        Ok(compiled)
    }

    pub fn execute_tick(
        &self,
        compiled: &CompiledModule,
        snapshot_json: &[u8],
    ) -> Result<TickOutput, SandboxError> {
        match self.config.isolation {
            IsolationMode::InProcess => self.execute_tick_in_process(compiled, snapshot_json),
            IsolationMode::OsProcess => self.execute_tick_os_process(compiled, snapshot_json),
        }
    }

    fn execute_tick_in_process(
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
                snapshot: serde_json::from_slice(snapshot_json).unwrap_or(serde_json::Value::Null),
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
        let message_ptr = u32::from_le_bytes(result[8..12].try_into().expect("slice length"));
        let message_len = u32::from_le_bytes(result[12..16].try_into().expect("slice length"));
        let total_output_len = output_len as usize + message_len as usize;
        if total_output_len > self.config.max_output_json_bytes {
            if output_len != 0 {
                let _ = free.call(&mut store, (output_ptr as i32, output_len as i32));
            }
            if message_len != 0 {
                let _ = free.call(&mut store, (message_ptr as i32, message_len as i32));
            }
            let _ = free.call(&mut store, (snapshot_ptr, snapshot_len));
            let _ = free.call(&mut store, (result_ptr, RESULT_STRUCT_BYTES));
            return Err(SandboxError::OutputTooLarge {
                actual: total_output_len,
            });
        }

        let output_range = checked_u32_range(memory, &mut store, output_ptr, output_len)?;
        let mut command_json = vec![0_u8; output_len as usize];
        memory
            .read(&mut store, output_range.start, &mut command_json)
            .map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;
        let messages = if message_len == 0 {
            Vec::new()
        } else {
            let message_range = checked_u32_range(memory, &mut store, message_ptr, message_len)?;
            let mut messages = vec![0_u8; message_len as usize];
            memory
                .read(&mut store, message_range.start, &mut messages)
                .map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;
            messages
        };

        if output_len != 0 {
            free.call(&mut store, (output_ptr as i32, output_len as i32))?;
        }
        if message_len != 0 {
            free.call(&mut store, (message_ptr as i32, message_len as i32))?;
        }
        free.call(&mut store, (snapshot_ptr, snapshot_len))?;
        free.call(&mut store, (result_ptr, RESULT_STRUCT_BYTES))?;

        Ok(TickOutput {
            command_json,
            messages,
            host_call_budget: store.data().host_budget.clone(),
        })
    }

    #[cfg(all(feature = "os-isolation", target_os = "linux"))]
    fn execute_tick_os_process(
        &self,
        compiled: &CompiledModule,
        snapshot_json: &[u8],
    ) -> Result<TickOutput, SandboxError> {
        linux_os_isolation::execute_tick(self.config.clone(), &compiled.wasm_bytes, snapshot_json)
    }

    #[cfg(not(all(feature = "os-isolation", target_os = "linux")))]
    fn execute_tick_os_process(
        &self,
        _compiled: &CompiledModule,
        _snapshot_json: &[u8],
    ) -> Result<TickOutput, SandboxError> {
        Err(SandboxError::OsIsolationUnavailable)
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
        Self::new(SandboxConfig::development())
            .expect("development sandbox runtime config must be valid")
    }
}

pub fn validate_wasmparser(wasm_bytes: &[u8]) -> Result<(), SandboxError> {
    if wasm_bytes.len() > MAX_MODULE_BYTES {
        return Err(SandboxError::ModuleTooLarge {
            actual: wasm_bytes.len(),
        });
    }

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        if let Payload::StartSection { .. } =
            payload.map_err(|err| SandboxError::InvalidWasm(err.to_string()))?
        {
            return Err(SandboxError::StartSectionForbidden);
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
        |mut caller: Caller<'_, StoreState>, room_id: u32, out_ptr: i32, out_len: i32| -> i32 {
            match charge_host_call(&mut caller, HostCallKind::Terrain).and_then(|_| {
                let payload = terrain_payload(caller.data().snapshot(), room_id);
                write_json_to_guest(&mut caller, out_ptr, out_len, &payload)
            }) {
                Ok(bytes) => bytes,
                Err(err) => err.abi_error_code(),
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_get_objects_in_range",
        |mut caller: Caller<'_, StoreState>,
         x: i32,
         y: i32,
         range: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            if range < 0 {
                return SandboxError::NegativePointer.abi_error_code();
            }
            match charge_host_call(&mut caller, HostCallKind::ObjectsInRange).and_then(|_| {
                let payload = objects_in_range(caller.data().snapshot(), x, y, range);
                write_json_to_guest(&mut caller, out_ptr, out_len, &payload)
            }) {
                Ok(bytes) => bytes,
                Err(err) => err.abi_error_code(),
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_path_find",
        |mut caller: Caller<'_, StoreState>,
         from_x: i32,
         from_y: i32,
         to_x: i32,
         to_y: i32,
         opts_ptr: i32,
         opts_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            match charge_host_call(&mut caller, HostCallKind::PathFind).and_then(|_| {
                let _opts = read_guest_bytes(&mut caller, opts_ptr, opts_len)?;
                let payload = path_find(caller.data().snapshot(), from_x, from_y, to_x, to_y);
                write_json_to_guest(&mut caller, out_ptr, out_len, &payload)
            }) {
                Ok(bytes) => bytes,
                Err(err) => err.abi_error_code(),
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
            match charge_host_call(&mut caller, HostCallKind::WorldConfig).and_then(|_| {
                let key = read_guest_string(&mut caller, key_ptr, key_len)?;
                let payload = world_config_lookup(caller.data().snapshot(), &key);
                write_json_to_guest(&mut caller, out_ptr, out_len, &payload)
            }) {
                Ok(bytes) => bytes,
                Err(err) => err.abi_error_code(),
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_get_world_rules",
        |mut caller: Caller<'_, StoreState>,
         rule_id_ptr: i32,
         rule_id_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> i32 {
            match charge_host_call(&mut caller, HostCallKind::WorldRules).and_then(|_| {
                let rule_id = read_guest_string(&mut caller, rule_id_ptr, rule_id_len)?;
                let payload = world_rules(caller.data().snapshot(), &rule_id);
                write_json_to_guest(&mut caller, out_ptr, out_len, &payload)
            }) {
                Ok(bytes) => bytes,
                Err(err) => err.abi_error_code(),
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_get_random",
        |mut caller: Caller<'_, StoreState>, sequence: u64, out_ptr: i32, out_len: i32| -> i32 {
            if out_len > MAX_RANDOM_BYTES {
                return SandboxError::MemoryOutOfBounds {
                    ptr: out_ptr as u32,
                    len: out_len as u32,
                    memory_len: MAX_RANDOM_BYTES as usize,
                }
                .abi_error_code();
            }
            match charge_host_call(&mut caller, HostCallKind::Random).and_then(|_| {
                let bytes = derive_random_bytes(caller.data().snapshot(), sequence, out_len)?;
                write_bytes_to_guest(&mut caller, out_ptr, out_len, &bytes)
            }) {
                Ok(bytes) => bytes,
                Err(err) => err.abi_error_code(),
            }
        },
    )?;
    linker.func_wrap(
        "env",
        "host_get_fuel_remaining",
        |mut caller: Caller<'_, StoreState>| -> u64 {
            if charge_host_call(&mut caller, HostCallKind::FuelRemaining).is_err() {
                return 0;
            }
            caller.get_fuel().unwrap_or(0)
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
    Random,
    FuelRemaining,
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
        HostCallKind::WorldConfig => {
            state.host_budget.world_config_calls = state
                .host_budget
                .world_config_calls
                .checked_add(1)
                .ok_or(SandboxError::HostCallBudgetExceeded)?;
            if state.host_budget.world_config_calls > DEFAULT_WORLD_CONFIG_PER_TICK {
                return Err(SandboxError::HostCallBudgetExceeded);
            }
            Ok(0)
        }
        HostCallKind::WorldRules => {
            state.host_budget.world_rules_calls = state
                .host_budget
                .world_rules_calls
                .checked_add(1)
                .ok_or(SandboxError::HostCallBudgetExceeded)?;
            if state.host_budget.world_rules_calls > DEFAULT_WORLD_RULES_PER_TICK {
                return Err(SandboxError::HostCallBudgetExceeded);
            }
            Ok(0)
        }
        HostCallKind::Random => {
            state.host_budget.random_calls = state
                .host_budget
                .random_calls
                .checked_add(1)
                .ok_or(SandboxError::HostCallBudgetExceeded)?;
            if state.host_budget.random_calls > DEFAULT_RANDOM_PER_TICK {
                return Err(SandboxError::HostCallBudgetExceeded);
            }
            Ok(0)
        }
        HostCallKind::FuelRemaining => {
            state.host_budget.fuel_remaining_calls = state
                .host_budget
                .fuel_remaining_calls
                .checked_add(1)
                .ok_or(SandboxError::HostCallBudgetExceeded)?;
            Ok(0)
        }
    }
}

fn caller_memory(caller: &mut Caller<'_, StoreState>) -> Result<Memory, SandboxError> {
    caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(SandboxError::MissingMemory)
}

fn read_guest_string(
    caller: &mut Caller<'_, StoreState>,
    ptr: i32,
    len: i32,
) -> Result<String, SandboxError> {
    if len == 0 {
        return Ok(String::new());
    }
    let bytes = read_guest_bytes(caller, ptr, len)?;
    String::from_utf8(bytes).map_err(|err| SandboxError::MemoryAccess(err.to_string()))
}

fn read_guest_bytes(
    caller: &mut Caller<'_, StoreState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, SandboxError> {
    let memory = caller_memory(caller)?;
    let range = checked_range(memory, &mut *caller, ptr, len)?;
    let mut bytes = vec![0_u8; range.len()];
    memory
        .read(&mut *caller, range.start, &mut bytes)
        .map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;
    Ok(bytes)
}

fn write_json_to_guest(
    caller: &mut Caller<'_, StoreState>,
    out_ptr: i32,
    out_len: i32,
    value: &serde_json::Value,
) -> Result<i32, SandboxError> {
    let bytes =
        serde_json::to_vec(value).map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;
    write_bytes_to_guest(caller, out_ptr, out_len, &bytes)
}

fn write_bytes_to_guest(
    caller: &mut Caller<'_, StoreState>,
    out_ptr: i32,
    out_len: i32,
    bytes: &[u8],
) -> Result<i32, SandboxError> {
    let memory = caller_memory(caller)?;
    let range = checked_range(memory, &mut *caller, out_ptr, out_len)?;
    if bytes.len() > range.len() {
        return Err(SandboxError::MemoryOutOfBounds {
            ptr: out_ptr as u32,
            len: bytes.len() as u32,
            memory_len: range.len(),
        });
    }
    memory
        .write(&mut *caller, range.start, bytes)
        .map_err(|err| SandboxError::MemoryAccess(err.to_string()))?;
    usize_to_i32(bytes.len())
}

fn terrain_payload(snapshot: &serde_json::Value, room_id: u32) -> serde_json::Value {
    let room = snapshot.get("room").unwrap_or(snapshot);
    serde_json::json!({
        "room_id": room_id,
        "terrain": room.get("terrain").cloned().unwrap_or(serde_json::Value::Null),
    })
}

impl StoreState {
    fn snapshot(&self) -> &serde_json::Value {
        &self.snapshot
    }
}

fn terrain_at(snapshot: &serde_json::Value, x: i32, y: i32) -> Option<&str> {
    snapshot
        .get("visible_tiles")
        .and_then(serde_json::Value::as_array)
        .and_then(|tiles| {
            tiles.iter().find_map(|tile| {
                (json_i32(tile.get("x"))? == x && json_i32(tile.get("y"))? == y)
                    .then(|| tile.get("terrain")?.as_str())
                    .flatten()
            })
        })
        .or_else(|| {
            snapshot
                .get("room")
                .and_then(|room| room.get("terrain"))
                .and_then(|terrain| terrain.get(y as usize))
                .and_then(|row| {
                    row.as_array()
                        .and_then(|items| items.get(x as usize))
                        .and_then(serde_json::Value::as_str)
                        .or_else(|| {
                            row.as_str()
                                .and_then(|line| line.as_bytes().get(x as usize).copied())
                                .and_then(|byte| match byte {
                                    b'.' => Some("Plain"),
                                    b'~' => Some("Swamp"),
                                    b'#' => Some("Wall"),
                                    _ => None,
                                })
                        })
                })
        })
}

fn terrain_code(terrain: &str) -> i32 {
    match terrain {
        "Plain" | "plain" => 0,
        "Swamp" | "swamp" => 1,
        "Wall" | "wall" => 2,
        _ => -1,
    }
}

fn objects_in_range(snapshot: &serde_json::Value, x: i32, y: i32, range: i32) -> serde_json::Value {
    let entities = snapshot
        .get("entities")
        .and_then(serde_json::Value::as_array)
        .map(|entities| {
            entities
                .iter()
                .filter(|entity| {
                    entity_position(entity)
                        .is_some_and(|(ex, ey)| hex_distance_axial(x, y, ex, ey) <= range)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::Value::Array(entities)
}

fn path_find(
    snapshot: &serde_json::Value,
    from_x: i32,
    from_y: i32,
    to_x: i32,
    to_y: i32,
) -> serde_json::Value {
    if from_x == to_x && from_y == to_y {
        return serde_json::json!([{ "x": from_x, "y": from_y }]);
    }
    let mut queue = VecDeque::from([(from_x, from_y)]);
    let mut came_from: HashMap<(i32, i32), (i32, i32)> = HashMap::new();
    came_from.insert((from_x, from_y), (from_x, from_y));
    while let Some((x, y)) = queue.pop_front() {
        for (nx, ny) in hex_neighbors(x, y) {
            if came_from.contains_key(&(nx, ny)) || !is_passable_snapshot(snapshot, nx, ny) {
                continue;
            }
            came_from.insert((nx, ny), (x, y));
            if nx == to_x && ny == to_y {
                let mut path = Vec::new();
                let mut current = (to_x, to_y);
                path.push(serde_json::json!({ "x": current.0, "y": current.1 }));
                while current != (from_x, from_y) {
                    current = came_from[&current];
                    path.push(serde_json::json!({ "x": current.0, "y": current.1 }));
                }
                path.reverse();
                return serde_json::Value::Array(path);
            }
            queue.push_back((nx, ny));
        }
    }
    serde_json::Value::Array(Vec::new())
}

fn is_passable_snapshot(snapshot: &serde_json::Value, x: i32, y: i32) -> bool {
    terrain_at(snapshot, x, y).is_some_and(|terrain| terrain_code(terrain) != 2)
}

fn hex_neighbors(x: i32, y: i32) -> [(i32, i32); 6] {
    [
        (x, y - 1),
        (x + 1, y - 1),
        (x + 1, y),
        (x, y + 1),
        (x - 1, y + 1),
        (x - 1, y),
    ]
}

fn hex_distance_axial(ax: i32, ay: i32, bx: i32, by: i32) -> i32 {
    let dq = (ax - bx).abs();
    let dr = (ay - by).abs();
    let ds = (ax + ay - bx - by).abs();
    dq.max(dr).max(ds)
}

fn entity_position(entity: &serde_json::Value) -> Option<(i32, i32)> {
    let position = entity.get("position").or_else(|| {
        entity
            .as_object()
            .and_then(|object| object.values().find_map(|value| value.get("position")))
    })?;
    Some((json_i32(position.get("x"))?, json_i32(position.get("y"))?))
}

fn json_i32(value: Option<&serde_json::Value>) -> Option<i32> {
    value
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
}

fn world_config_lookup(snapshot: &serde_json::Value, key: &str) -> serde_json::Value {
    let config = snapshot
        .pointer("/world_config/config")
        .or_else(|| snapshot.get("world_config"))
        .or_else(|| snapshot.get("config"));
    if key.trim().is_empty() {
        return config.cloned().unwrap_or(serde_json::Value::Null);
    }
    config
        .and_then(|config| config.get(key))
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

fn world_rules(snapshot: &serde_json::Value, rule_id: &str) -> serde_json::Value {
    let rules = serde_json::json!({
        "ruleset": "snapshot",
        "room_size": snapshot.get("room").and_then(|room| room.get("size")).cloned().unwrap_or(serde_json::json!(50)),
        "visibility_radius": snapshot.get("visibility_radius").cloned().unwrap_or(serde_json::json!(0)),
        "snapshot_tick": snapshot.get("tick").cloned().unwrap_or(serde_json::Value::Null),
        "active_mods": snapshot.pointer("/world_config/config/custom_actions").cloned().unwrap_or(serde_json::json!([])),
    });
    if rule_id.trim().is_empty() {
        return rules;
    }
    rules
        .get(rule_id)
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

fn derive_random_bytes(
    snapshot: &serde_json::Value,
    sequence: u64,
    out_len: i32,
) -> Result<Vec<u8>, SandboxError> {
    if out_len < 0 {
        return Err(SandboxError::NegativePointer);
    }
    if out_len > MAX_RANDOM_BYTES {
        return Err(SandboxError::MemoryOutOfBounds {
            ptr: 0,
            len: out_len as u32,
            memory_len: MAX_RANDOM_BYTES as usize,
        });
    }
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, 1, b"swarm.host_random.v1");
    hash_field(
        &mut hasher,
        2,
        &required_snapshot_u64(snapshot, "world_seed")?.to_le_bytes(),
    );
    hash_field(
        &mut hasher,
        3,
        &required_snapshot_u64(snapshot, "tick")?.to_le_bytes(),
    );
    hash_field(
        &mut hasher,
        4,
        &required_snapshot_u64(snapshot, "actor_id")?.to_le_bytes(),
    );
    hash_field(&mut hasher, 5, &sequence.to_le_bytes());

    let mut output = vec![0_u8; out_len as usize];
    hasher.finalize_xof().fill(&mut output);
    Ok(output)
}

fn hash_field(hasher: &mut blake3::Hasher, tag: u8, bytes: &[u8]) {
    hasher.update(&[tag]);
    write_uleb128(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn write_uleb128(hasher: &mut blake3::Hasher, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        hasher.update(&[byte]);
        if value == 0 {
            break;
        }
    }
}

fn required_snapshot_u64(
    snapshot: &serde_json::Value,
    key: &'static str,
) -> Result<u64, SandboxError> {
    snapshot
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
        })
        .ok_or(SandboxError::MissingHostRandomField(key))
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
    if ptr.is_multiple_of(align) {
        Ok(())
    } else {
        Err(SandboxError::PointerOverflow)
    }
}

fn usize_to_i32(value: usize) -> Result<i32, SandboxError> {
    i32::try_from(value).map_err(|_| SandboxError::PointerOverflow)
}

#[cfg(all(feature = "os-isolation", target_os = "linux"))]
mod linux_os_isolation {
    use super::*;

    #[ctor::ctor(unsafe)]
    fn maybe_run_child_worker() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }

        let code = match child_main() {
            Ok(()) => 0,
            Err(err) => {
                let _ = write_error_response(&err.to_string());
                1
            }
        };
        std::process::exit(code);
    }

    pub(super) fn execute_tick(
        config: SandboxConfig,
        wasm_bytes: &[u8],
        snapshot_json: &[u8],
    ) -> Result<TickOutput, SandboxError> {
        let current_exe =
            std::env::current_exe().map_err(|err| SandboxError::OsIsolationIo(err.to_string()))?;
        let mut child = unsafe {
            let mut command = Command::new(current_exe);
            command
                .env(CHILD_ENV, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .pre_exec(|| {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            command
                .spawn()
                .map_err(|err| SandboxError::OsIsolationIo(err.to_string()))?
        };

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| SandboxError::OsIsolationIo("child stdin unavailable".into()))?;
        write_request(&mut stdin, &config, wasm_bytes, snapshot_json)?;
        drop(stdin);

        let deadline = Instant::now() + Duration::from_millis(config.tick_timeout_ms);
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|err| SandboxError::OsIsolationIo(err.to_string()))?
            {
                let mut stdout = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    out.read_to_end(&mut stdout)
                        .map_err(|err| SandboxError::OsIsolationIo(err.to_string()))?;
                }
                let mut stderr = String::new();
                if let Some(mut err_pipe) = child.stderr.take() {
                    let _ = err_pipe.read_to_string(&mut stderr);
                }

                let response = read_response(&stdout)?;
                return match response {
                    ChildResponse::Ok(output) => Ok(output),
                    ChildResponse::Err(message) => {
                        let detail = if stderr.trim().is_empty() {
                            message
                        } else {
                            format!("{message}; stderr: {}", stderr.trim())
                        };
                        if status.success() {
                            Err(SandboxError::OsIsolationChildFailed(detail))
                        } else {
                            Err(SandboxError::OsIsolationChildFailed(format!(
                                "{detail}; exit status: {status}"
                            )))
                        }
                    }
                };
            }

            if Instant::now() >= deadline {
                kill_process_group(child.id());
                let _ = child.wait();
                return Err(SandboxError::OsIsolationTimedOut {
                    timeout_ms: config.tick_timeout_ms,
                });
            }

            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn child_main() -> Result<(), SandboxError> {
        let mut input = Vec::new();
        std::io::stdin()
            .read_to_end(&mut input)
            .map_err(|err| SandboxError::OsIsolationIo(err.to_string()))?;
        let (mut config, wasm_bytes, snapshot_json) = parse_request(&input)?;
        config.isolation = IsolationMode::InProcess;
        apply_policy(config.os_isolation)?;

        let runtime = SandboxRuntime::new(config)?;
        let module = runtime.compile(&wasm_bytes)?;
        let output = runtime.execute_tick_in_process(&module, &snapshot_json)?;
        write_ok_response(&output)
    }

    enum ChildResponse {
        Ok(TickOutput),
        Err(String),
    }

    fn write_request(
        writer: &mut impl Write,
        config: &SandboxConfig,
        wasm_bytes: &[u8],
        snapshot_json: &[u8],
    ) -> Result<(), SandboxError> {
        writer.write_all(&PROTOCOL_MAGIC.to_le_bytes())?;
        writer.write_all(&PROTOCOL_VERSION.to_le_bytes())?;
        write_config(writer, config)?;
        write_bytes(writer, wasm_bytes)?;
        write_bytes(writer, snapshot_json)?;
        Ok(())
    }

    fn parse_request(input: &[u8]) -> Result<(SandboxConfig, Vec<u8>, Vec<u8>), SandboxError> {
        let mut cursor = Cursor::new(input);
        let magic = cursor.u32()?;
        if magic != PROTOCOL_MAGIC {
            return Err(SandboxError::OsIsolationProtocol("bad magic".into()));
        }
        let version = cursor.u32()?;
        if version != PROTOCOL_VERSION {
            return Err(SandboxError::OsIsolationProtocol(format!(
                "unsupported protocol version {version}"
            )));
        }
        let config = read_config(&mut cursor)?;
        let wasm_bytes = cursor.bytes()?;
        let snapshot_json = cursor.bytes()?;
        if cursor.remaining() != 0 {
            return Err(SandboxError::OsIsolationProtocol("trailing bytes".into()));
        }
        Ok((config, wasm_bytes, snapshot_json))
    }

    fn write_config(writer: &mut impl Write, config: &SandboxConfig) -> Result<(), SandboxError> {
        writer.write_all(&config.max_fuel.to_le_bytes())?;
        writer.write_all(&config.epoch_deadline_ticks.to_le_bytes())?;
        writer.write_all(&config.max_host_calls_per_tick.to_le_bytes())?;
        writer.write_all(&config.max_path_find_per_tick.to_le_bytes())?;
        writer.write_all(&config.max_objects_in_range_per_tick.to_le_bytes())?;
        writer.write_all(&(config.max_output_json_bytes as u64).to_le_bytes())?;
        writer.write_all(&config.tick_timeout_ms.to_le_bytes())?;
        writer.write_all(&[config.wasm_simd as u8])?;
        writer.write_all(&[config.os_isolation.seccomp as u8])?;
        writer.write_all(&[config.os_isolation.cgroup as u8])?;
        writer.write_all(&[config.os_isolation.network_namespace as u8])?;
        writer.write_all(&[config.os_isolation.read_only_root as u8])?;
        writer.write_all(&[config.os_isolation.tmpfs_tmp as u8])?;
        writer.write_all(&[config.os_isolation.allow_permission_fallback as u8])?;
        Ok(())
    }

    fn read_config(cursor: &mut Cursor<'_>) -> Result<SandboxConfig, SandboxError> {
        Ok(SandboxConfig {
            max_fuel: cursor.u64()?,
            epoch_deadline_ticks: cursor.u64()?,
            max_host_calls_per_tick: cursor.u32()?,
            max_path_find_per_tick: cursor.u32()?,
            max_objects_in_range_per_tick: cursor.u32()?,
            max_output_json_bytes: cursor.u64()? as usize,
            tick_timeout_ms: cursor.u64()?,
            wasm_simd: cursor.bool()?,
            isolation: IsolationMode::InProcess,
            os_isolation: OsIsolationPolicy {
                seccomp: cursor.bool()?,
                cgroup: cursor.bool()?,
                network_namespace: cursor.bool()?,
                read_only_root: cursor.bool()?,
                tmpfs_tmp: cursor.bool()?,
                allow_permission_fallback: cursor.bool()?,
            },
        })
    }

    fn write_ok_response(output: &TickOutput) -> Result<(), SandboxError> {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&PROTOCOL_MAGIC.to_le_bytes())?;
        stdout.write_all(&PROTOCOL_VERSION.to_le_bytes())?;
        stdout.write_all(&[0])?;
        stdout.write_all(&output.host_call_budget.total_calls.to_le_bytes())?;
        stdout.write_all(&output.host_call_budget.path_find_calls.to_le_bytes())?;
        stdout.write_all(&output.host_call_budget.objects_in_range_calls.to_le_bytes())?;
        stdout.write_all(&output.host_call_budget.world_config_calls.to_le_bytes())?;
        stdout.write_all(&output.host_call_budget.world_rules_calls.to_le_bytes())?;
        stdout.write_all(&output.host_call_budget.random_calls.to_le_bytes())?;
        stdout.write_all(&output.host_call_budget.fuel_remaining_calls.to_le_bytes())?;
        write_bytes(&mut stdout, &output.command_json)?;
        write_bytes(&mut stdout, &output.messages)?;
        Ok(())
    }

    fn write_error_response(message: &str) -> Result<(), SandboxError> {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&PROTOCOL_MAGIC.to_le_bytes())?;
        stdout.write_all(&PROTOCOL_VERSION.to_le_bytes())?;
        stdout.write_all(&[1])?;
        write_bytes(&mut stdout, message.as_bytes())?;
        Ok(())
    }

    fn read_response(input: &[u8]) -> Result<ChildResponse, SandboxError> {
        let mut cursor = Cursor::new(input);
        let magic = cursor.u32()?;
        if magic != PROTOCOL_MAGIC {
            return Err(SandboxError::OsIsolationProtocol(
                "bad response magic".into(),
            ));
        }
        let version = cursor.u32()?;
        if version != PROTOCOL_VERSION {
            return Err(SandboxError::OsIsolationProtocol(format!(
                "unsupported response version {version}"
            )));
        }
        match cursor.u8()? {
            0 => {
                let host_call_budget = HostCallBudget {
                    total_calls: cursor.u32()?,
                    path_find_calls: cursor.u32()?,
                    objects_in_range_calls: cursor.u32()?,
                    world_config_calls: cursor.u32()?,
                    world_rules_calls: cursor.u32()?,
                    random_calls: cursor.u32()?,
                    fuel_remaining_calls: cursor.u32()?,
                };
                let command_json = cursor.bytes()?;
                let messages = if cursor.remaining() == 0 {
                    Vec::new()
                } else {
                    cursor.bytes()?
                };
                Ok(ChildResponse::Ok(TickOutput {
                    command_json,
                    messages,
                    host_call_budget,
                }))
            }
            1 => Ok(ChildResponse::Err(
                String::from_utf8(cursor.bytes()?).unwrap_or_else(|err| err.to_string()),
            )),
            tag => Err(SandboxError::OsIsolationProtocol(format!(
                "unknown response tag {tag}"
            ))),
        }
    }

    fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<(), SandboxError> {
        let len = u64::try_from(bytes.len()).map_err(|_| SandboxError::PointerOverflow)?;
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(bytes)?;
        Ok(())
    }

    fn apply_policy(_policy: OsIsolationPolicy) -> Result<(), SandboxError> {
        #[cfg(feature = "os-network-namespace")]
        if _policy.network_namespace {
            allow_permission_failure(
                unsafe { libc::unshare(libc::CLONE_NEWNET) },
                "unshare(CLONE_NEWNET)",
                _policy.allow_permission_fallback,
            )?;
        }

        #[cfg(feature = "os-readonly-root")]
        if _policy.read_only_root {
            allow_permission_failure(
                unsafe { libc::unshare(libc::CLONE_NEWNS) },
                "unshare(CLONE_NEWNS)",
                _policy.allow_permission_fallback,
            )?;
            allow_permission_failure(
                unsafe {
                    libc::mount(
                        std::ptr::null(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        (libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
                        std::ptr::null(),
                    )
                },
                "mount(/, MS_REMOUNT|MS_RDONLY)",
                _policy.allow_permission_fallback,
            )?;
        }

        #[cfg(feature = "os-tmpfs")]
        if _policy.tmpfs_tmp {
            allow_permission_failure(
                unsafe { libc::unshare(libc::CLONE_NEWNS) },
                "unshare(CLONE_NEWNS)",
                _policy.allow_permission_fallback,
            )?;
            allow_permission_failure(
                unsafe {
                    libc::mount(
                        c"tmpfs".as_ptr(),
                        c"/tmp".as_ptr(),
                        c"tmpfs".as_ptr(),
                        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
                        c"size=16m,mode=1777".as_ptr().cast(),
                    )
                },
                "mount(tmpfs, /tmp)",
                _policy.allow_permission_fallback,
            )?;
        }

        #[cfg(feature = "os-seccomp")]
        if _policy.seccomp {
            apply_seccomp_policy(_policy.allow_permission_fallback)?;
        }

        #[cfg(feature = "os-cgroup")]
        if _policy.cgroup {
            apply_cgroup_policy(_policy.allow_permission_fallback)?;
        }

        Ok(())
    }

    #[cfg(feature = "os-seccomp")]
    fn apply_seccomp_policy(allow_fallback: bool) -> Result<(), SandboxError> {
        allow_permission_failure(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            "prctl(PR_SET_NO_NEW_PRIVS)",
            allow_fallback,
        )?;

        let Some(mut filters) = seccomp_filters_for_current_arch() else {
            if allow_fallback {
                return Ok(());
            }
            return Err(SandboxError::OsIsolationIo(
                "seccomp syscall allowlist is unavailable for this architecture".into(),
            ));
        };
        let mut program = libc::sock_fprog {
            len: filters
                .len()
                .try_into()
                .map_err(|_| SandboxError::PointerOverflow)?,
            filter: filters.as_mut_ptr(),
        };
        allow_permission_failure(
            unsafe {
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &mut program as *mut libc::sock_fprog,
                    0,
                    0,
                )
            },
            "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)",
            allow_fallback,
        )
    }

    #[cfg(all(feature = "os-seccomp", target_arch = "x86_64"))]
    fn seccomp_filters_for_current_arch() -> Option<Vec<libc::sock_filter>> {
        const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
        Some(build_seccomp_allowlist(
            AUDIT_ARCH_X86_64,
            &[
                libc::SYS_arch_prctl,
                libc::SYS_brk,
                libc::SYS_clock_gettime,
                libc::SYS_clone,
                libc::SYS_clone3,
                libc::SYS_close,
                libc::SYS_epoll_create1,
                libc::SYS_epoll_ctl,
                libc::SYS_epoll_pwait,
                libc::SYS_eventfd2,
                libc::SYS_exit,
                libc::SYS_exit_group,
                libc::SYS_fcntl,
                libc::SYS_fstat,
                libc::SYS_futex,
                libc::SYS_getcwd,
                libc::SYS_getdents64,
                libc::SYS_getpid,
                libc::SYS_getrandom,
                libc::SYS_gettid,
                libc::SYS_madvise,
                libc::SYS_mmap,
                libc::SYS_mprotect,
                libc::SYS_mremap,
                libc::SYS_munmap,
                libc::SYS_nanosleep,
                libc::SYS_newfstatat,
                libc::SYS_openat,
                libc::SYS_prctl,
                libc::SYS_read,
                libc::SYS_readlink,
                libc::SYS_rseq,
                libc::SYS_rt_sigaction,
                libc::SYS_rt_sigprocmask,
                libc::SYS_rt_sigreturn,
                libc::SYS_sched_getaffinity,
                libc::SYS_sched_yield,
                libc::SYS_set_robust_list,
                libc::SYS_set_tid_address,
                libc::SYS_sigaltstack,
                libc::SYS_statx,
                libc::SYS_write,
            ],
        ))
    }

    #[cfg(all(feature = "os-seccomp", not(target_arch = "x86_64")))]
    fn seccomp_filters_for_current_arch() -> Option<Vec<libc::sock_filter>> {
        None
    }

    #[cfg(feature = "os-seccomp")]
    pub(super) fn build_seccomp_allowlist(
        arch: u32,
        syscalls: &[libc::c_long],
    ) -> Vec<libc::sock_filter> {
        const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        const BPF_JMP_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
        const SECCOMP_DATA_NR_OFFSET: u32 = 0;
        const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

        let mut filters = Vec::with_capacity(syscalls.len() * 2 + 5);
        filters.push(bpf_stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET));
        filters.push(bpf_jump(BPF_JMP_JEQ_K, arch, 1, 0));
        filters.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filters.push(bpf_stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
        for &syscall in syscalls {
            filters.push(bpf_jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
            filters.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        }
        filters.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filters
    }

    #[cfg(feature = "os-seccomp")]
    fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    #[cfg(feature = "os-seccomp")]
    fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    #[cfg(feature = "os-cgroup")]
    fn apply_cgroup_policy(allow_fallback: bool) -> Result<(), SandboxError> {
        let root = match writable_cgroup_root() {
            Ok(root) => root,
            Err(err) if allow_fallback && err.is_permission_fallback => return Ok(()),
            Err(err) => return Err(SandboxError::OsIsolationIo(err.message)),
        };
        let child = root.join(format!("swarm-wasm-sandbox-{}", std::process::id()));
        create_cgroup_dir(&child, allow_fallback)?;
        write_cgroup_file(&child.join("memory.max"), "134217728", allow_fallback)?;
        write_cgroup_file(&child.join("memory.swap.max"), "0", allow_fallback)?;
        write_cgroup_file(&child.join("cpu.max"), "250000 3000000", allow_fallback)?;
        write_cgroup_file(&child.join("pids.max"), "32", allow_fallback)?;
        write_cgroup_file(
            &child.join("cgroup.procs"),
            &std::process::id().to_string(),
            allow_fallback,
        )
    }

    #[cfg(feature = "os-cgroup")]
    fn writable_cgroup_root() -> Result<std::path::PathBuf, CgroupRootError> {
        let roots = std::env::var_os("SWARM_WASM_SANDBOX_CGROUP_ROOT")
            .map(std::path::PathBuf::from)
            .into_iter()
            .chain(std::iter::once(std::path::PathBuf::from("/sys/fs/cgroup")));
        let mut fallback_err = None;
        for path in roots {
            if !path.is_dir() {
                continue;
            }
            match is_writable_dir(&path) {
                Ok(()) => return Ok(path),
                Err(err) if is_cgroup_permission_fallback(&err) => fallback_err = Some(err),
                Err(err) => {
                    return Err(CgroupRootError {
                        message: format!("probe cgroup root {}: {err}", path.display()),
                        is_permission_fallback: false,
                    });
                }
            }
        }
        Err(CgroupRootError {
            is_permission_fallback: fallback_err.is_some(),
            message: match fallback_err {
                Some(err) => format!("no writable cgroup v2 root found: {err}"),
                None => "no writable cgroup v2 root found".into(),
            },
        })
    }

    #[cfg(feature = "os-cgroup")]
    struct CgroupRootError {
        message: String,
        is_permission_fallback: bool,
    }

    #[cfg(feature = "os-cgroup")]
    fn is_writable_dir(path: &std::path::Path) -> Result<(), std::io::Error> {
        let probe = path.join(format!(
            ".swarm-wasm-sandbox-write-test-{}",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
        {
            Ok(_) => {
                let _ = std::fs::remove_file(probe);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "os-cgroup")]
    fn create_cgroup_dir(path: &std::path::Path, allow_fallback: bool) -> Result<(), SandboxError> {
        match std::fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => handle_cgroup_io_error(err, "create cgroup", allow_fallback),
        }
    }

    #[cfg(feature = "os-cgroup")]
    fn write_cgroup_file(
        path: &std::path::Path,
        value: &str,
        allow_fallback: bool,
    ) -> Result<(), SandboxError> {
        std::fs::write(path, value)
            .map_err(|err| (err, path.display().to_string()))
            .or_else(|(err, path)| handle_cgroup_io_error(err, &path, allow_fallback))
    }

    #[cfg(feature = "os-cgroup")]
    fn handle_cgroup_io_error(
        err: std::io::Error,
        operation: &str,
        allow_fallback: bool,
    ) -> Result<(), SandboxError> {
        if allow_fallback && is_cgroup_permission_fallback(&err) {
            return Ok(());
        }
        Err(SandboxError::OsIsolationIo(format!("{operation}: {err}")))
    }

    #[cfg(feature = "os-cgroup")]
    pub(super) fn is_cgroup_permission_fallback(err: &std::io::Error) -> bool {
        matches!(err.raw_os_error(), Some(libc::EPERM | libc::EROFS))
    }

    #[cfg(any(
        feature = "os-network-namespace",
        feature = "os-readonly-root",
        feature = "os-seccomp",
        feature = "os-tmpfs"
    ))]
    fn allow_permission_failure(
        result: libc::c_int,
        operation: &'static str,
        allow_fallback: bool,
    ) -> Result<(), SandboxError> {
        if result == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if allow_fallback && matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
            return Ok(());
        }
        Err(SandboxError::OsIsolationIo(format!("{operation}: {err}")))
    }

    fn kill_process_group(pid: u32) {
        if let Ok(pid) = i32::try_from(pid) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }

    struct Cursor<'a> {
        input: &'a [u8],
        offset: usize,
    }

    impl<'a> Cursor<'a> {
        fn new(input: &'a [u8]) -> Self {
            Self { input, offset: 0 }
        }

        fn remaining(&self) -> usize {
            self.input.len().saturating_sub(self.offset)
        }

        fn take(&mut self, len: usize) -> Result<&'a [u8], SandboxError> {
            let end = self
                .offset
                .checked_add(len)
                .ok_or(SandboxError::PointerOverflow)?;
            if end > self.input.len() {
                return Err(SandboxError::OsIsolationProtocol(
                    "truncated message".into(),
                ));
            }
            let bytes = &self.input[self.offset..end];
            self.offset = end;
            Ok(bytes)
        }

        fn u8(&mut self) -> Result<u8, SandboxError> {
            Ok(self.take(1)?[0])
        }

        fn bool(&mut self) -> Result<bool, SandboxError> {
            match self.u8()? {
                0 => Ok(false),
                1 => Ok(true),
                value => Err(SandboxError::OsIsolationProtocol(format!(
                    "invalid bool {value}"
                ))),
            }
        }

        fn u32(&mut self) -> Result<u32, SandboxError> {
            Ok(u32::from_le_bytes(
                self.take(4)?.try_into().expect("slice length"),
            ))
        }

        fn u64(&mut self) -> Result<u64, SandboxError> {
            Ok(u64::from_le_bytes(
                self.take(8)?.try_into().expect("slice length"),
            ))
        }

        fn bytes(&mut self) -> Result<Vec<u8>, SandboxError> {
            let len = usize::try_from(self.u64()?).map_err(|_| SandboxError::PointerOverflow)?;
            Ok(self.take(len)?.to_vec())
        }
    }

    impl From<std::io::Error> for SandboxError {
        fn from(err: std::io::Error) -> Self {
            SandboxError::OsIsolationIo(err.to_string())
        }
    }
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

    fn simd_module() -> Vec<u8> {
        wasm(
            r#"
            (module
              (memory (export "memory") 1)
              (func $uses_simd (result i32)
                (i32x4.extract_lane 0 (v128.const i32x4 1 2 3 4)))
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32) (i32.const 0)))
            "#,
        )
    }

    #[test]
    fn production_config_defaults_to_required_os_isolation_without_simd() {
        let config = SandboxConfig::default();

        assert_eq!(config.isolation, IsolationMode::OsProcess);
        assert!(!config.wasm_simd);
        assert!(config.os_isolation.seccomp);
        assert!(config.os_isolation.cgroup);
        assert!(config.os_isolation.network_namespace);
        assert!(config.os_isolation.read_only_root);
        assert!(config.os_isolation.tmpfs_tmp);
        assert!(!config.os_isolation.allow_permission_fallback);
    }

    #[test]
    fn development_config_is_explicitly_in_process_and_permissive() {
        let config = SandboxConfig::development();

        assert_eq!(config.isolation, IsolationMode::InProcess);
        assert!(!config.wasm_simd);
        assert!(!config.os_isolation.seccomp);
        assert!(!config.os_isolation.cgroup);
        assert!(!config.os_isolation.network_namespace);
        assert!(!config.os_isolation.read_only_root);
        assert!(!config.os_isolation.tmpfs_tmp);
        assert!(config.os_isolation.allow_permission_fallback);
    }

    #[test]
    fn wasm_simd_is_default_off_and_config_controlled() {
        let wasm = simd_module();
        let default_runtime = SandboxRuntime::new(SandboxConfig::development()).unwrap();
        assert!(default_runtime.compile(&wasm).is_err());

        let simd_runtime = SandboxRuntime::new(SandboxConfig {
            wasm_simd: true,
            ..SandboxConfig::development()
        })
        .unwrap();
        assert!(simd_runtime.compile(&wasm).is_ok());
    }

    #[test]
    fn host_rng_requires_seed_tick_and_actor_fields() {
        let complete = serde_json::json!({
            "world_seed": 42,
            "tick": 7,
            "actor_id": 99
        });
        assert_eq!(derive_random_bytes(&complete, 1, 16).unwrap().len(), 16);

        for (field, snapshot) in [
            (
                "world_seed",
                serde_json::json!({ "tick": 7, "actor_id": 99 }),
            ),
            (
                "tick",
                serde_json::json!({ "world_seed": 42, "actor_id": 99 }),
            ),
            (
                "actor_id",
                serde_json::json!({ "world_seed": 42, "tick": 7 }),
            ),
        ] {
            assert!(matches!(
                derive_random_bytes(&snapshot, 1, 16),
                Err(SandboxError::MissingHostRandomField(missing)) if missing == field
            ));
        }
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
    fn cache_key_includes_wasm_hash_wasmtime_version_and_validation_policy() {
        let wasm = valid_echo_module();
        let key = ModuleCacheKey::for_wasm(&wasm);
        assert_eq!(key.module_hash, wasm_hash(&wasm));
        assert_eq!(key.wasmtime_version, wasmtime_version());
        assert_eq!(
            key.validation_policy_version,
            DEFAULT_VALIDATION_POLICY_VERSION
        );

        let other_version = ModuleCacheKey::for_wasm_with_version(&wasm, "wasmtime-next");
        assert_eq!(other_version.module_hash, key.module_hash);
        assert_ne!(other_version.wasmtime_version, key.wasmtime_version);

        let other_policy = ModuleCacheKey::for_wasm_with_policy(&wasm, "policy-v2");
        assert_eq!(other_policy.module_hash, key.module_hash);
        assert_eq!(other_policy.wasmtime_version, key.wasmtime_version);
        assert_ne!(
            other_policy.validation_policy_version,
            key.validation_policy_version
        );
    }

    #[test]
    fn compile_cache_isolated_by_validation_policy_version() {
        let runtime = SandboxRuntime::default();
        let wasm = valid_echo_module();
        let mut cache = CompiledModuleCache::new();

        let first = runtime
            .compile_cached_with_policy(&mut cache, &wasm, "policy-v1")
            .unwrap();
        let second = runtime
            .compile_cached_with_policy(&mut cache, &wasm, "policy-v2")
            .unwrap();
        let first_again = runtime
            .compile_cached_with_policy(&mut cache, &wasm, "policy-v1")
            .unwrap();

        assert_eq!(first.validation_policy_version(), "policy-v1");
        assert_eq!(second.validation_policy_version(), "policy-v2");
        assert_eq!(first_again.validation_policy_version(), "policy-v1");
        assert_eq!(cache.stats().entries, 2);
        assert_eq!(cache.stats().misses, 2);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn compile_cached_hits_after_deploy_time_precompile() {
        let runtime = SandboxRuntime::default();
        let wasm = valid_echo_module();
        let mut cache = CompiledModuleCache::new();

        let first = runtime.compile_cached(&mut cache, &wasm).unwrap();
        assert_eq!(first.module_hash(), wasm_hash(&wasm));
        assert_eq!(first.wasmtime_version(), wasmtime_version());
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);

        let second = runtime.compile_cached(&mut cache, &wasm).unwrap();
        assert_eq!(second.module_hash(), first.module_hash());
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn compile_cached_recompiles_when_wasmtime_version_changes() {
        let runtime = SandboxRuntime::default();
        let wasm = valid_echo_module();
        let mut cache = CompiledModuleCache::new();
        let old_key = ModuleCacheKey::for_wasm_with_version(&wasm, "wasmtime-old");
        let old_cached = runtime
            .precompile_native(&wasm)
            .unwrap()
            .with_wasmtime_version("wasmtime-old");
        cache.insert(old_cached);

        let compiled = runtime
            .compile_cached_with_version(&mut cache, &wasm, &old_key.wasmtime_version)
            .unwrap();
        assert_eq!(compiled.wasmtime_version(), wasmtime_version());
        assert!(cache.get(&old_key).is_none());
        assert!(cache.get(&ModuleCacheKey::for_wasm(&wasm)).is_some());
        assert_eq!(cache.stats().recompiles, 1);
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn executes_tick_from_cached_native_module() {
        let runtime = SandboxRuntime::default();
        let wasm = valid_echo_module();
        let mut cache = CompiledModuleCache::new();
        let module = runtime.compile_cached(&mut cache, &wasm).unwrap();

        let output = runtime.execute_tick(&module, br#"{"tick":7}"#).unwrap();
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
              (import "env" "host_path_find" (func $host_path_find (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
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
                (drop (call $host_path_find (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 2048) (i32.const 8)))
                (drop (call $host_path_find (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 2048) (i32.const 8)))
                (i32.store (local.get 2) (i32.const 1024))
                (i32.store offset=4 (local.get 2) (i32.const 2))
                (i32.const 0))
              (data (i32.const 1024) "[]"))
            "#,
        );
        let runtime = SandboxRuntime::new(SandboxConfig {
            max_path_find_per_tick: 1,
            ..SandboxConfig::development()
        })
        .unwrap();
        let module = runtime.compile(&bytes).unwrap();
        let output = runtime.execute_tick(&module, b"{}").unwrap();
        assert_eq!(output.host_call_budget.path_find_calls, 2);
    }

    #[test]
    fn host_reference_abi_imports_execute() {
        let bytes = wasm(
            r#"
            (module
              (import "env" "host_get_terrain" (func $host_get_terrain (param i32 i32 i32) (result i32)))
              (import "env" "host_get_world_rules" (func $host_get_world_rules (param i32 i32 i32 i32) (result i32)))
              (import "env" "host_get_random" (func $host_get_random (param i64 i32 i32) (result i32)))
              (import "env" "host_get_fuel_remaining" (func $host_get_fuel_remaining (result i64)))
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
                (local $terrain_len i32)
                (local $rules_len i32)
                (local $random_len i32)
                (local $fuel i64)
                (local.set $terrain_len (call $host_get_terrain (i32.const 7) (i32.const 2048) (i32.const 512)))
                (local.set $rules_len (call $host_get_world_rules (i32.const 0) (i32.const 0) (i32.const 2560) (i32.const 512)))
                (local.set $random_len (call $host_get_random (i64.const 42) (i32.const 3072) (i32.const 32)))
                (local.set $fuel (call $host_get_fuel_remaining))
                (if
                  (i32.or
                    (i32.or (i32.lt_s (local.get $terrain_len) (i32.const 1)) (i32.lt_s (local.get $rules_len) (i32.const 1)))
                    (i32.or (i32.ne (local.get $random_len) (i32.const 32)) (i64.eqz (local.get $fuel))))
                  (then (return (i32.const 9))))
                (i32.store (local.get 2) (i32.const 1024))
                (i32.store offset=4 (local.get 2) (i32.const 2))
                (i32.const 0))
              (data (i32.const 1024) "[]"))
            "#,
        );
        let runtime = SandboxRuntime::default();
        let module = runtime.compile(&bytes).unwrap();
        let output = runtime
            .execute_tick(
                &module,
                br#"{"world_seed":123,"tick":9,"actor_id":5,"room":{"terrain":[".."]}}"#,
            )
            .unwrap();
        assert_eq!(output.host_call_budget.total_calls, 4);
        assert_eq!(output.host_call_budget.world_rules_calls, 1);
        assert_eq!(output.host_call_budget.random_calls, 1);
        assert_eq!(output.host_call_budget.fuel_remaining_calls, 1);
    }

    #[test]
    fn rejects_removed_random_seed_import() {
        let bytes = wasm(
            r#"
            (module
              (import "env" "host_set_random_seed" (func $host_set_random_seed (param i64) (result i32)))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32) (i32.const 0)))
            "#,
        );
        assert!(matches!(
            SandboxRuntime::default().compile(&bytes),
            Err(SandboxError::IllegalImport { name, .. }) if name == "host_set_random_seed"
        ));
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

    #[test]
    #[cfg(all(feature = "os-cgroup", target_os = "linux"))]
    fn cgroup_fallback_only_allows_permission_or_read_only_errors() {
        assert!(linux_os_isolation::is_cgroup_permission_fallback(
            &std::io::Error::from_raw_os_error(libc::EPERM)
        ));
        assert!(linux_os_isolation::is_cgroup_permission_fallback(
            &std::io::Error::from_raw_os_error(libc::EROFS)
        ));
        assert!(!linux_os_isolation::is_cgroup_permission_fallback(
            &std::io::Error::from_raw_os_error(libc::ENOENT)
        ));
    }

    #[test]
    #[cfg(all(feature = "os-seccomp", target_os = "linux"))]
    fn seccomp_allowlist_builds_arch_check_and_default_kill() {
        const ARCH: u32 = 0xc000_003e;
        const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
        const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
        let filters = linux_os_isolation::build_seccomp_allowlist(ARCH, &[libc::SYS_read]);
        assert_eq!(filters.len(), 7);
        assert_eq!(filters[0].code, BPF_LD_W_ABS);
        assert_eq!(filters[1].k, ARCH);
        assert_eq!(filters[2].code, BPF_RET_K);
        assert_eq!(filters[2].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(filters[4].k, libc::SYS_read as u32);
        assert_eq!(filters[6].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    #[cfg(all(feature = "os-isolation", target_os = "linux"))]
    fn os_process_isolation_executes_tick_in_child_process() {
        let runtime = SandboxRuntime::new(SandboxConfig {
            isolation: IsolationMode::OsProcess,
            ..SandboxConfig::default()
        })
        .unwrap();
        let module = runtime.compile(&valid_echo_module()).unwrap();
        let output = runtime.execute_tick(&module, br#"{"tick":1}"#).unwrap();
        assert_eq!(output.command_json, b"[]");
        assert_eq!(output.host_call_budget, HostCallBudget::default());
    }

    #[test]
    #[cfg(all(feature = "os-isolation", target_os = "linux"))]
    fn os_process_isolation_kills_timed_out_process_group() {
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
            isolation: IsolationMode::OsProcess,
            max_fuel: u64::MAX,
            tick_timeout_ms: 50,
            ..SandboxConfig::default()
        })
        .unwrap();
        let module = runtime.compile(&bytes).unwrap();
        assert!(matches!(
            runtime.execute_tick(&module, b"{}"),
            Err(SandboxError::OsIsolationTimedOut { timeout_ms: 50 })
        ));
    }

    #[test]
    #[cfg(not(all(feature = "os-isolation", target_os = "linux")))]
    fn os_process_isolation_reports_unavailable_without_linux_feature() {
        let runtime = SandboxRuntime::new(SandboxConfig {
            isolation: IsolationMode::OsProcess,
            ..SandboxConfig::default()
        })
        .unwrap();
        let module = runtime.compile(&valid_echo_module()).unwrap();
        assert!(matches!(
            runtime.execute_tick(&module, b"{}"),
            Err(SandboxError::OsIsolationUnavailable)
        ));
    }
}
