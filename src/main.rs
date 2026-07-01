use std::{
    collections::HashMap,
    env,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use swarm_wasm_sandbox::{
    CachedNativeModule, CompiledModule, CompiledModuleCache, HostCallBudget, ModuleCacheKey,
    SandboxConfig, SandboxRuntime, wasmtime_version,
};
use tokio::{signal, sync::Mutex, time};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct SandboxTickRequest {
    tick: u64,
    player_id: String,
    snapshot_json: String,
    module_hash: Vec<u8>,
    fuel_budget: u64,
    collect_timeout_ms: u64,
}

#[derive(Debug, Serialize)]
struct SandboxTickReply {
    tick: u64,
    player_id: String,
    commands: Vec<Value>,
    metrics: SandboxExecutionMetrics,
    status: String,
}

#[derive(Debug, Default, Serialize)]
struct SandboxExecutionMetrics {
    fuel_consumed: u64,
    wall_clock_ms: u64,
    memory_peak_bytes: u64,
    host_function_calls: u32,
}

#[derive(Debug, Deserialize)]
struct DeployRequest {
    module_hash: Vec<u8>,
    compiled_artifact_hash: Vec<u8>,
    module_bytes: Vec<u8>,
    compiled_native_bytes: Vec<u8>,
    wasmtime_version: String,
    validation_policy_version: String,
}

#[derive(Debug, Serialize)]
struct DeployAck {
    instance_id: String,
    module_hash: String,
    status: String,
}

#[derive(Clone)]
struct CachedModule {
    wasm_bytes: Vec<u8>,
    cached_native: CachedNativeModule,
}

struct ServiceState {
    cache: CompiledModuleCache,
    modules: HashMap<String, CachedModule>,
    started_at: Instant,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let instance_id = env::var("INSTANCE_ID").unwrap_or_else(|_| default_instance_id());
    let client = async_nats::connect(&nats_url).await?;

    let state = Arc::new(Mutex::new(ServiceState {
        cache: CompiledModuleCache::new(),
        modules: HashMap::new(),
        started_at: Instant::now(),
    }));

    let tick_sub = client
        .queue_subscribe(
            "swarm.tick.*.player.*".to_string(),
            "sandbox-workers".to_string(),
        )
        .await?;
    let deploy_sub = client.subscribe("swarm.deploy.*".to_string()).await?;

    let tick_task = tokio::spawn(handle_ticks(client.clone(), Arc::clone(&state), tick_sub));
    let deploy_task = tokio::spawn(handle_deploys(
        client.clone(),
        Arc::clone(&state),
        instance_id.clone(),
        deploy_sub,
    ));
    let heartbeat_task = tokio::spawn(heartbeat(
        client.clone(),
        Arc::clone(&state),
        instance_id.clone(),
    ));

    wait_for_shutdown().await;
    tick_task.abort();
    deploy_task.abort();
    heartbeat_task.abort();
    client.drain().await?;
    Ok(())
}

async fn handle_ticks(
    client: async_nats::Client,
    state: Arc<Mutex<ServiceState>>,
    mut sub: async_nats::Subscriber,
) {
    while let Some(message) = sub.next().await {
        let Some(reply_subject) = message.reply.clone() else {
            continue;
        };
        let reply = match serde_json::from_slice::<SandboxTickRequest>(&message.payload) {
            Ok(request) => execute_request(Arc::clone(&state), request).await,
            Err(error) => SandboxTickReply {
                tick: 0,
                player_id: String::new(),
                commands: Vec::new(),
                metrics: SandboxExecutionMetrics::default(),
                status: format!("Trap({error})"),
            },
        };
        if let Ok(payload) = serde_json::to_vec(&reply) {
            let _ = client.publish(reply_subject, payload.into()).await;
        }
    }
}

async fn execute_request(
    state: Arc<Mutex<ServiceState>>,
    request: SandboxTickRequest,
) -> SandboxTickReply {
    let started_at = Instant::now();
    let module_hash = bytes_to_hex(&request.module_hash);
    let module = {
        let state = state.lock().await;
        state.modules.get(&module_hash).cloned()
    };
    let Some(module) = module else {
        let mut state = state.lock().await;
        state.cache.record_miss();
        return tick_reply(
            request,
            Vec::new(),
            SandboxExecutionMetrics::default(),
            "ModuleNotFound",
        );
    };

    let mut request_config = SandboxConfig::default();
    request_config.max_fuel = request.fuel_budget;
    request_config.tick_timeout_ms = request.collect_timeout_ms;
    let runtime = match SandboxRuntime::new(request_config) {
        Ok(runtime) => runtime,
        Err(error) => {
            return tick_reply(
                request,
                Vec::new(),
                metrics(started_at, HostCallBudget::default()),
                format!("Trap({error})"),
            );
        }
    };
    let compiled = match compile_module(Arc::clone(&state), &runtime, &module).await {
        Ok(compiled) => compiled,
        Err(error) => {
            return tick_reply(
                request,
                Vec::new(),
                metrics(started_at, HostCallBudget::default()),
                format!("Trap({error})"),
            );
        }
    };

    let timeout_ms = request.collect_timeout_ms;
    let snapshot_json = request.snapshot_json.clone().into_bytes();
    let execution =
        tokio::task::spawn_blocking(move || runtime.execute_tick(&compiled, &snapshot_json));
    let output = match time::timeout(Duration::from_millis(timeout_ms), execution).await {
        Ok(Ok(Ok(output))) => output,
        Ok(Ok(Err(error))) => {
            let status = sandbox_status(&error.to_string());
            return tick_reply(
                request,
                Vec::new(),
                metrics(started_at, HostCallBudget::default()),
                status,
            );
        }
        Ok(Err(error)) => {
            return tick_reply(
                request,
                Vec::new(),
                metrics(started_at, HostCallBudget::default()),
                format!("Trap({error})"),
            );
        }
        Err(_) => {
            return tick_reply(
                request,
                Vec::new(),
                metrics(started_at, HostCallBudget::default()),
                "Timeout",
            );
        }
    };

    let commands = serde_json::from_slice::<Vec<Value>>(&output.command_json).unwrap_or_default();
    tick_reply(
        request,
        commands,
        metrics(started_at, output.host_call_budget),
        "Ok",
    )
}

async fn compile_module(
    state: Arc<Mutex<ServiceState>>,
    runtime: &SandboxRuntime,
    module: &CachedModule,
) -> Result<CompiledModule, swarm_wasm_sandbox::SandboxError> {
    let mut state = state.lock().await;
    let stored_version = module.cached_native.key.wasmtime_version.clone();
    runtime.compile_cached_with_version(&mut state.cache, &module.wasm_bytes, &stored_version)
}

async fn handle_deploys(
    client: async_nats::Client,
    state: Arc<Mutex<ServiceState>>,
    instance_id: String,
    mut sub: async_nats::Subscriber,
) {
    while let Some(message) = sub.next().await {
        let Ok(request) = serde_json::from_slice::<DeployRequest>(&message.payload) else {
            continue;
        };
        let module_hash = bytes_to_hex(&request.module_hash);
        let artifact_hash = bytes_to_hex(&request.compiled_artifact_hash);
        let key = ModuleCacheKey::new(module_hash.clone(), request.wasmtime_version.clone());
        let cached_native = CachedNativeModule {
            key,
            native_bytes: request.compiled_native_bytes,
        };

        {
            let mut state = state.lock().await;
            state.cache.insert(cached_native.clone());
            state.modules.insert(
                module_hash.clone(),
                CachedModule {
                    wasm_bytes: request.module_bytes,
                    cached_native,
                },
            );
        }

        let ack = DeployAck {
            instance_id: instance_id.clone(),
            module_hash,
            status: if request.wasmtime_version == wasmtime_version() {
                "cached".to_string()
            } else {
                format!(
                    "cached_version_mismatch:{}",
                    request.validation_policy_version
                )
            },
        };
        if let Ok(payload) = serde_json::to_vec(&ack) {
            let subject = format!("swarm.deploy.{artifact_hash}.ack");
            let _ = client.publish(subject, payload.into()).await;
        }
    }
}

async fn heartbeat(
    client: async_nats::Client,
    state: Arc<Mutex<ServiceState>>,
    instance_id: String,
) {
    let mut interval = time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let payload = {
            let state = state.lock().await;
            let stats = state.cache.stats();
            json!({
                "instance_id": instance_id,
                "uptime_seconds": state.started_at.elapsed().as_secs(),
                "cache": {
                    "entries": stats.entries,
                    "hits": stats.hits,
                    "misses": stats.misses,
                    "recompiles": stats.recompiles,
                }
            })
        };
        let subject = format!("swarm.sandbox.heartbeat.{instance_id}");
        if let Ok(payload) = serde_json::to_vec(&payload) {
            let _ = client.publish(subject, payload.into()).await;
        }
    }
}

fn tick_reply(
    request: SandboxTickRequest,
    commands: Vec<Value>,
    metrics: SandboxExecutionMetrics,
    status: impl Into<String>,
) -> SandboxTickReply {
    SandboxTickReply {
        tick: request.tick,
        player_id: request.player_id,
        commands,
        metrics,
        status: status.into(),
    }
}

fn metrics(started_at: Instant, host_call_budget: HostCallBudget) -> SandboxExecutionMetrics {
    SandboxExecutionMetrics {
        fuel_consumed: 0,
        wall_clock_ms: started_at.elapsed().as_millis() as u64,
        memory_peak_bytes: 0,
        host_function_calls: host_call_budget.total_calls,
    }
}

fn sandbox_status(error: &str) -> String {
    if error.contains("timed out") {
        "Timeout".to_string()
    } else if error.contains("fuel") {
        "FuelExhausted".to_string()
    } else {
        format!("Trap({error})")
    }
}

fn default_instance_id() -> String {
    let host = env::var("HOSTNAME").unwrap_or_else(|_| "sandbox".to_string());
    format!("{host}-{}", Uuid::new_v4())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}
