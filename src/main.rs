use std::{
    collections::HashMap,
    env, fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use swarm_wasm_sandbox::{
    CompiledModule, CompiledModuleCache, HostCallBudget, SandboxConfig, SandboxRuntime,
};
use tokio::{signal, sync::Mutex, time};
use uuid::Uuid;

const DEPLOY_SCHEMA: &str = "swarm.sandbox.deploy.v1";
const TICK_SCHEMA: &str = "swarm.sandbox.tick.v1";
const AUTH_FRESHNESS_MS: u64 = 60_000;
const AUTH_FUTURE_SKEW_MS: u64 = 5_000;
const DEFAULT_NATS_CONNECT_RETRY_MS: u64 = 1_000;
const DEFAULT_SANDBOX_NONCE_PATH: &str = "/tmp/swarm-sandbox-nonces.db";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedRequest<T> {
    request_id: String,
    nonce: String,
    timestamp_ms: u64,
    payload: T,
    auth_tag_hex: String,
}

#[derive(Debug, Serialize)]
struct AuthenticatedSigningMessage<'a, T: Serialize> {
    request_id: &'a str,
    nonce: &'a str,
    timestamp_ms: u64,
    payload: &'a T,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxTickRequest {
    schema: String,
    tick: u64,
    player_id: String,
    room_id: String,
    module_hash: [u8; 32],
    snapshot_json: String,
    fuel_budget: u64,
    collect_timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxTickReply {
    tick: u64,
    player_id: String,
    commands: Vec<Value>,
    metrics: SandboxExecutionMetrics,
    status: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SandboxExecutionMetrics {
    fuel_consumed: u64,
    wall_clock_ms: u64,
    memory_peak_bytes: u64,
    host_function_calls: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployRequest {
    schema: String,
    module_hash: [u8; 32],
    module_bytes: Vec<u8>,
    validation_policy_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeployAck {
    instance_id: String,
    module_hash: String,
    status: String,
}

#[derive(Clone)]
struct CachedModule {
    wasm_bytes: Vec<u8>,
}

struct ServiceState {
    cache: CompiledModuleCache,
    modules: HashMap<String, CachedModule>,
    nonce_store: DurableNonceStore,
    started_at: Instant,
}

#[derive(Debug)]
struct DurableNonceStore {
    path: PathBuf,
    seen: HashMap<String, u64>,
}

impl DurableNonceStore {
    fn load(path: PathBuf) -> Result<Self, String> {
        let now = current_time_ms()?;
        let seen = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<HashMap<String, u64>>(&bytes)
                .map_err(|err| format!("failed to parse nonce store {}: {err}", path.display()))?,
            Err(error) if error.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(error) => {
                return Err(format!(
                    "failed to read nonce store {}: {error}",
                    path.display()
                ));
            }
        };

        let mut store = Self { path, seen };
        store.prune(now);
        store.persist()?;
        Ok(store)
    }

    fn record(&mut self, key: String, timestamp_ms: u64, now: u64) -> Result<(), String> {
        self.prune(now);
        if self.seen.contains_key(&key) {
            return Err("replay detected".to_string());
        }
        self.seen.insert(key.clone(), timestamp_ms);
        if let Err(error) = self.persist() {
            self.seen.remove(&key);
            return Err(error);
        }
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        self.seen
            .retain(|_, timestamp_ms| now.saturating_sub(*timestamp_ms) <= AUTH_FRESHNESS_MS);
    }

    fn persist(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec(&self.seen).map_err(|err| err.to_string())?;
        let temp_path = nonce_store_temp_path(&self.path);
        fs::write(&temp_path, bytes)
            .map_err(|err| format!("failed to write nonce store {}: {err}", temp_path.display()))?;
        fs::rename(&temp_path, &self.path).map_err(|err| {
            let _ = fs::remove_file(&temp_path);
            format!(
                "failed to replace nonce store {}: {err}",
                self.path.display()
            )
        })?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let instance_id = env::var("INSTANCE_ID").unwrap_or_else(|_| default_instance_id());
    let retry_delay = nats_connect_retry_delay();
    let nonce_store_path = sandbox_nonce_store_path();
    validated_nats_auth_secret().map_err(std::io::Error::other)?;
    let nonce_store = DurableNonceStore::load(nonce_store_path).map_err(std::io::Error::other)?;
    let client = connect_nats_with_retry(&nats_url, retry_delay).await;

    let state = Arc::new(Mutex::new(ServiceState {
        cache: CompiledModuleCache::new(),
        modules: HashMap::new(),
        nonce_store,
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

async fn connect_nats_with_retry(nats_url: &str, retry_delay: Duration) -> async_nats::Client {
    let safe_url = redact_nats_url(nats_url);
    let mut attempt = 1_u64;
    loop {
        let result = async_nats::connect(nats_url).await;
        if !should_retry_nats_connect(&result) {
            let client = result.expect("successful NATS connection checked above");
            eprintln!("connected to NATS at {safe_url} after {attempt} attempt(s)");
            return client;
        }

        let error = result.expect_err("failed NATS connection checked above");
        eprintln!(
            "failed to connect to NATS at {safe_url} on attempt {attempt}: {error}; retrying in {}ms",
            retry_delay.as_millis()
        );
        time::sleep(retry_delay).await;
        attempt = attempt.saturating_add(1);
    }
}

fn nats_connect_retry_delay() -> Duration {
    let value = env::var("NATS_CONNECT_RETRY_MS").ok();
    connect_retry_delay_from_env(value.as_deref())
}

fn connect_retry_delay_from_env(value: Option<&str>) -> Duration {
    let millis = value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .unwrap_or(DEFAULT_NATS_CONNECT_RETRY_MS);
    Duration::from_millis(millis)
}

fn sandbox_nonce_store_path() -> PathBuf {
    env::var("SWARM_SANDBOX_NONCE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SANDBOX_NONCE_PATH))
}

fn nonce_store_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("swarm-sandbox-nonces.db");
    path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
}

fn should_retry_nats_connect<T, E>(result: &Result<T, E>) -> bool {
    result.is_err()
}

fn validated_nats_auth_secret() -> Result<String, String> {
    let secret = env::var("SWARM_NATS_AUTH_SECRET")
        .map_err(|_| "missing SWARM_NATS_AUTH_SECRET".to_string())?;
    if secret.trim().is_empty() {
        return Err("SWARM_NATS_AUTH_SECRET must not be empty".to_string());
    }
    Ok(secret)
}

fn redact_nats_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let suffix = &rest[authority_end..];

    let Some(credentials_end) = authority.rfind('@') else {
        return url.to_string();
    };
    format!(
        "{}***@{}{}",
        &url[..authority_start],
        &authority[credentials_end + 1..],
        suffix
    )
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
        let reply = match decode_authenticated::<SandboxTickRequest>(&message.payload, TICK_SCHEMA)
        {
            Ok(request) => match reject_replay(Arc::clone(&state), &request).await {
                Ok(()) => execute_request(Arc::clone(&state), request.payload).await,
                Err(error) => SandboxTickReply {
                    tick: request.payload.tick,
                    player_id: request.payload.player_id,
                    commands: Vec::new(),
                    metrics: SandboxExecutionMetrics::default(),
                    status: format!("Trap({error})"),
                },
            },
            Err(error) => SandboxTickReply {
                tick: 0,
                player_id: String::new(),
                commands: Vec::new(),
                metrics: SandboxExecutionMetrics::default(),
                status: format!("Trap({error})"),
            },
        };
        let Ok(request_id) = request_id_from_bytes(&message.payload) else {
            continue;
        };
        if let Ok(payload) = encode_authenticated(&reply, &request_id) {
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

    let request_config = SandboxConfig {
        max_fuel: request.fuel_budget,
        tick_timeout_ms: request.collect_timeout_ms,
        ..SandboxConfig::default()
    };
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
    runtime.compile_cached(&mut state.cache, &module.wasm_bytes)
}

async fn handle_deploys(
    client: async_nats::Client,
    state: Arc<Mutex<ServiceState>>,
    instance_id: String,
    mut sub: async_nats::Subscriber,
) {
    while let Some(message) = sub.next().await {
        let Some(reply_subject) = message.reply.clone() else {
            continue;
        };
        let Ok(request) = decode_authenticated::<DeployRequest>(&message.payload, DEPLOY_SCHEMA)
        else {
            continue;
        };

        let request_id = request.request_id.clone();
        let ack = match reject_replay(Arc::clone(&state), &request).await {
            Ok(()) => deploy_request(Arc::clone(&state), &instance_id, request.payload).await,
            Err(error) => DeployAck {
                instance_id: instance_id.clone(),
                module_hash: String::new(),
                status: format!("rejected:{error}"),
            },
        };

        if let Ok(payload) = encode_authenticated(&ack, &request_id) {
            let _ = client.publish(reply_subject, payload.into()).await;
        }
    }
}

async fn deploy_request(
    state: Arc<Mutex<ServiceState>>,
    instance_id: &str,
    request: DeployRequest,
) -> DeployAck {
    if !deploy_module_hash_matches(&request) {
        return DeployAck {
            instance_id: instance_id.to_string(),
            module_hash: bytes_to_hex(&request.module_hash),
            status: "rejected:module_hash mismatch".to_string(),
        };
    }

    let module_hash = bytes_to_hex(&request.module_hash);
    let runtime = SandboxRuntime::default();
    let cached_native = match runtime.precompile_native(&request.module_bytes) {
        Ok(cached_native) => cached_native,
        Err(error) => {
            return DeployAck {
                instance_id: instance_id.to_string(),
                module_hash,
                status: format!("rejected:{error}"),
            };
        }
    };

    {
        let mut state = state.lock().await;
        state.cache.insert(cached_native);
        state.modules.insert(
            module_hash.clone(),
            CachedModule {
                wasm_bytes: request.module_bytes,
            },
        );
    }

    DeployAck {
        instance_id: instance_id.to_string(),
        module_hash,
        status: format!("cached:{}", request.validation_policy_version),
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

fn deploy_module_hash_matches(request: &DeployRequest) -> bool {
    blake3::hash(&request.module_bytes).as_bytes() == &request.module_hash
}

fn decode_authenticated<T>(
    bytes: &[u8],
    expected_schema: &str,
) -> Result<AuthenticatedRequest<T>, String>
where
    T: for<'de> Deserialize<'de> + Serialize + SchemaName,
{
    let request: AuthenticatedRequest<T> =
        serde_json::from_slice(bytes).map_err(|err| err.to_string())?;
    validate_envelope_fields(&request)?;
    verify_fresh_timestamp(request.timestamp_ms)?;
    if request.payload.schema_name() != expected_schema {
        return Err("schema mismatch".to_string());
    }
    verify_auth_tag(&request)?;
    Ok(request)
}

fn encode_authenticated<T: Serialize>(payload: &T, request_id: &str) -> Result<Vec<u8>, String> {
    let nonce = new_hex_id(16)?;
    let timestamp_ms = current_time_ms()?;
    let secret = validated_nats_auth_secret()?;
    let signing = AuthenticatedSigningMessage {
        request_id,
        nonce: &nonce,
        timestamp_ms,
        payload,
    };
    let payload_bytes = serde_json::to_vec(&signing).map_err(|err| err.to_string())?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|err| err.to_string())?;
    mac.update(&payload_bytes);
    let response = AuthenticatedRequest {
        request_id: request_id.to_string(),
        nonce,
        timestamp_ms,
        payload,
        auth_tag_hex: bytes_to_hex(&mac.finalize().into_bytes()),
    };
    serde_json::to_vec(&response).map_err(|err| err.to_string())
}

fn verify_auth_tag<T: Serialize>(request: &AuthenticatedRequest<T>) -> Result<(), String> {
    let secret = validated_nats_auth_secret()?;
    if request.auth_tag_hex.len() != 64 {
        return Err("invalid auth tag".to_string());
    }
    let signing = AuthenticatedSigningMessage {
        request_id: &request.request_id,
        nonce: &request.nonce,
        timestamp_ms: request.timestamp_ms,
        payload: &request.payload,
    };
    let payload_bytes = serde_json::to_vec(&signing).map_err(|err| err.to_string())?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|err| err.to_string())?;
    mac.update(&payload_bytes);
    let expected = bytes_to_hex(&mac.finalize().into_bytes());
    if constant_time_eq(expected.as_bytes(), request.auth_tag_hex.as_bytes()) {
        Ok(())
    } else {
        Err("invalid auth tag".to_string())
    }
}

async fn reject_replay<T>(
    state: Arc<Mutex<ServiceState>>,
    request: &AuthenticatedRequest<T>,
) -> Result<(), String> {
    let mut state = state.lock().await;
    let now = current_time_ms()?;
    let replay_key = format!("{}:{}", request.request_id, request.nonce);
    state
        .nonce_store
        .record(replay_key, request.timestamp_ms, now)
}

fn validate_envelope_fields<T>(request: &AuthenticatedRequest<T>) -> Result<(), String> {
    if request.request_id.len() != 32 || request.nonce.len() != 32 {
        return Err("invalid request envelope".to_string());
    }
    if !request
        .request_id
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        || !request.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid request envelope".to_string());
    }
    Ok(())
}

fn request_id_from_bytes(bytes: &[u8]) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|err| err.to_string())?;
    value
        .get("request_id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| "missing request_id".to_string())
}

fn verify_fresh_timestamp(timestamp_ms: u64) -> Result<(), String> {
    let now = current_time_ms()?;
    if timestamp_ms > now.saturating_add(AUTH_FUTURE_SKEW_MS) {
        return Err("timestamp is in the future".to_string());
    }
    if now.saturating_sub(timestamp_ms) > AUTH_FRESHNESS_MS {
        return Err("timestamp is stale".to_string());
    }
    Ok(())
}

fn current_time_ms() -> Result<u64, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?;
    Ok(elapsed.as_millis() as u64)
}

fn new_hex_id(byte_len: usize) -> Result<String, String> {
    if byte_len != 16 {
        return Err("only 16-byte ids are supported".to_string());
    }
    Ok(Uuid::new_v4().simple().to_string())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
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

trait SchemaName {
    fn schema_name(&self) -> &str;
}

impl SchemaName for SandboxTickRequest {
    fn schema_name(&self) -> &str {
        &self.schema
    }
}

impl SchemaName for DeployRequest {
    fn schema_name(&self) -> &str {
        &self.schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    fn deploy_payload() -> DeployRequest {
        let module_bytes = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "free") (param i32) (param i32))
              (func (export "tick") (param i32 i32 i32) (result i32) (i32.const 0)))
            "#,
        )
        .expect("valid wat");
        DeployRequest {
            schema: DEPLOY_SCHEMA.to_string(),
            module_hash: *blake3::hash(&module_bytes).as_bytes(),
            module_bytes,
            validation_policy_version: "policy-v1".to_string(),
        }
    }

    fn tick_payload() -> SandboxTickRequest {
        SandboxTickRequest {
            schema: TICK_SCHEMA.to_string(),
            tick: 7,
            player_id: "player-1".to_string(),
            room_id: "room-1".to_string(),
            module_hash: [9; 32],
            snapshot_json: "{}".to_string(),
            fuel_budget: 100,
            collect_timeout_ms: 250,
        }
    }

    fn signed<T: Serialize>(payload: T, secret: &str) -> Vec<u8> {
        signed_at(payload, secret, current_time_ms().unwrap())
    }

    fn signed_at<T: Serialize>(payload: T, secret: &str, timestamp_ms: u64) -> Vec<u8> {
        let request_id = "0123456789abcdef0123456789abcdef";
        let nonce = "abcdef0123456789abcdef0123456789";
        let signing = AuthenticatedSigningMessage {
            request_id,
            nonce,
            timestamp_ms,
            payload: &payload,
        };
        let payload_bytes = serde_json::to_vec(&signing).expect("payload serializes");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts key");
        mac.update(&payload_bytes);
        serde_json::to_vec(&AuthenticatedRequest {
            request_id: request_id.to_string(),
            nonce: nonce.to_string(),
            timestamp_ms,
            payload,
            auth_tag_hex: bytes_to_hex(&mac.finalize().into_bytes()),
        })
        .expect("wrapper serializes")
    }

    fn signed_value(payload: serde_json::Value, secret: &str) -> Vec<u8> {
        signed_at(payload, secret, current_time_ms().unwrap())
    }

    fn test_nonce_path(test_name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "swarm-sandbox-{test_name}-{}-{}.db",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn test_state(nonce_path: PathBuf) -> ServiceState {
        ServiceState {
            cache: CompiledModuleCache::new(),
            modules: HashMap::new(),
            nonce_store: DurableNonceStore::load(nonce_path).unwrap(),
            started_at: Instant::now(),
        }
    }

    #[test]
    fn redact_nats_url_removes_userinfo_credentials() {
        assert_eq!(
            redact_nats_url("nats://user:password@example.com:4222"),
            "nats://***@example.com:4222"
        );
        assert_eq!(
            redact_nats_url("tls://token@example.com:4222/path?x=1"),
            "tls://***@example.com:4222/path?x=1"
        );
    }

    #[test]
    fn redact_nats_url_leaves_credential_free_urls_unchanged() {
        assert_eq!(
            redact_nats_url("nats://127.0.0.1:4222"),
            "nats://127.0.0.1:4222"
        );
        assert_eq!(redact_nats_url("localhost:4222"), "localhost:4222");
    }

    #[test]
    fn connect_retry_delay_uses_positive_millis_or_default() {
        assert_eq!(
            connect_retry_delay_from_env(Some("250")),
            Duration::from_millis(250)
        );
        assert_eq!(
            connect_retry_delay_from_env(Some("0")),
            Duration::from_millis(DEFAULT_NATS_CONNECT_RETRY_MS)
        );
        assert_eq!(
            connect_retry_delay_from_env(Some("not-a-number")),
            Duration::from_millis(DEFAULT_NATS_CONNECT_RETRY_MS)
        );
        assert_eq!(
            connect_retry_delay_from_env(None),
            Duration::from_millis(DEFAULT_NATS_CONNECT_RETRY_MS)
        );
    }

    #[test]
    fn should_retry_nats_connect_only_retries_errors() {
        assert!(should_retry_nats_connect::<(), _>(&Err(
            "connection refused"
        )));
        assert!(!should_retry_nats_connect::<_, &str>(&Ok(())));
    }

    #[test]
    fn validated_nats_auth_secret_rejects_missing_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::remove_var("SWARM_NATS_AUTH_SECRET");
        }

        let error = validated_nats_auth_secret().unwrap_err();

        assert_eq!(error, "missing SWARM_NATS_AUTH_SECRET");
    }

    #[test]
    fn validated_nats_auth_secret_rejects_empty_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "");
        }

        let error = validated_nats_auth_secret().unwrap_err();

        assert_eq!(error, "SWARM_NATS_AUTH_SECRET must not be empty");
    }

    #[test]
    fn validated_nats_auth_secret_rejects_whitespace_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "  \t\n  ");
        }

        let error = validated_nats_auth_secret().unwrap_err();

        assert_eq!(error, "SWARM_NATS_AUTH_SECRET must not be empty");
    }

    #[test]
    fn encode_authenticated_rejects_whitespace_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "   ");
        }

        let error =
            encode_authenticated(&tick_payload(), "0123456789abcdef0123456789abcdef").unwrap_err();

        assert_eq!(error, "SWARM_NATS_AUTH_SECRET must not be empty");
    }

    #[test]
    fn decode_authenticated_rejects_missing_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::remove_var("SWARM_NATS_AUTH_SECRET");
        }
        let bytes = signed(tick_payload(), "secret");

        let error = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap_err();
        assert!(error.contains("missing SWARM_NATS_AUTH_SECRET"));
    }

    #[test]
    fn decode_authenticated_rejects_bad_hmac() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let mut wrapper: serde_json::Value =
            serde_json::from_slice(&signed(tick_payload(), "secret")).unwrap();
        wrapper["auth_tag_hex"] = serde_json::Value::String("00".repeat(32));
        let bytes = serde_json::to_vec(&wrapper).unwrap();

        let error = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap_err();
        assert_eq!(error, "invalid auth tag");
    }

    #[test]
    fn decode_authenticated_rejects_schema_mismatch() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let bytes = signed(tick_payload(), "secret");

        let error = decode_authenticated::<SandboxTickRequest>(&bytes, DEPLOY_SCHEMA).unwrap_err();
        assert_eq!(error, "schema mismatch");
    }

    #[test]
    fn deploy_payload_rejects_caller_native_bytes() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let payload = deploy_payload();
        let mut payload_json = serde_json::to_value(&payload).unwrap();
        payload_json["compiled_native_bytes"] = serde_json::json!([1, 2, 3]);
        let bytes = signed_value(payload_json, "secret");

        assert!(decode_authenticated::<DeployRequest>(&bytes, DEPLOY_SCHEMA).is_err());
    }

    #[test]
    fn decode_authenticated_rejects_stale_timestamp() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let stale = current_time_ms().unwrap() - AUTH_FRESHNESS_MS - 1;
        let bytes = signed_at(tick_payload(), "secret", stale);

        let error = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap_err();
        assert_eq!(error, "timestamp is stale");
    }

    #[test]
    fn encode_authenticated_reply_uses_request_id_and_valid_hmac() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let reply = SandboxTickReply {
            tick: 7,
            player_id: "player-1".to_string(),
            commands: Vec::new(),
            metrics: SandboxExecutionMetrics::default(),
            status: "Ok".to_string(),
        };
        let bytes = encode_authenticated(&reply, "0123456789abcdef0123456789abcdef").unwrap();
        let envelope: AuthenticatedRequest<SandboxTickReply> =
            serde_json::from_slice(&bytes).unwrap();

        assert_eq!(envelope.request_id, "0123456789abcdef0123456789abcdef");
        assert!(verify_auth_tag(&envelope).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reject_replay_rejects_duplicate_request_nonce() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let bytes = signed(tick_payload(), "secret");
        let request = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap();
        let nonce_path = test_nonce_path("reject-replay-duplicate");
        let state = Arc::new(Mutex::new(test_state(nonce_path.clone())));

        drop(_guard);

        assert!(reject_replay(Arc::clone(&state), &request).await.is_ok());
        assert_eq!(
            reject_replay(Arc::clone(&state), &request)
                .await
                .unwrap_err(),
            "replay detected"
        );
        let _ = fs::remove_file(nonce_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reject_replay_persists_nonce_across_restart() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let nonce_path = test_nonce_path("reject-replay-restart");
        let bytes = signed(tick_payload(), "secret");
        let request = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap();
        let first_state = Arc::new(Mutex::new(test_state(nonce_path.clone())));

        drop(_guard);

        assert!(
            reject_replay(Arc::clone(&first_state), &request)
                .await
                .is_ok()
        );
        drop(first_state);

        let restarted_state = Arc::new(Mutex::new(test_state(nonce_path.clone())));
        assert_eq!(
            reject_replay(Arc::clone(&restarted_state), &request)
                .await
                .unwrap_err(),
            "replay detected"
        );
        let _ = fs::remove_file(nonce_path);
    }

    #[test]
    fn nonce_store_load_prunes_stale_nonces_on_reload() {
        let nonce_path = test_nonce_path("nonce-prune-reload");
        let now = current_time_ms().unwrap();
        let stale_key = "stale:abcdef0123456789abcdef0123456789";
        let fresh_key = "fresh:abcdef0123456789abcdef0123456789";
        let mut entries = HashMap::new();
        entries.insert(stale_key.to_string(), now - AUTH_FRESHNESS_MS - 1);
        entries.insert(fresh_key.to_string(), now);
        fs::write(&nonce_path, serde_json::to_vec(&entries).unwrap()).unwrap();

        let store = DurableNonceStore::load(nonce_path.clone()).unwrap();

        assert!(!store.seen.contains_key(stale_key));
        assert!(store.seen.contains_key(fresh_key));
        let persisted: HashMap<String, u64> =
            serde_json::from_slice(&fs::read(&nonce_path).unwrap()).unwrap();
        assert!(!persisted.contains_key(stale_key));
        assert!(persisted.contains_key(fresh_key));
        let _ = fs::remove_file(nonce_path);
    }

    #[test]
    fn nonce_store_load_fails_closed_on_malformed_file() {
        let nonce_path = test_nonce_path("nonce-malformed");
        fs::write(&nonce_path, b"not-json").unwrap();

        let error = DurableNonceStore::load(nonce_path.clone()).unwrap_err();

        assert!(error.contains("failed to parse nonce store"));
        let _ = fs::remove_file(nonce_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reject_replay_fails_closed_when_nonce_store_cannot_persist() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let nonce_path = env::temp_dir()
            .join(format!("swarm-sandbox-missing-{}", Uuid::new_v4().simple()))
            .join("nonces.db");
        let bytes = signed(tick_payload(), "secret");
        let request = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap();
        let state = Arc::new(Mutex::new(ServiceState {
            cache: CompiledModuleCache::new(),
            modules: HashMap::new(),
            nonce_store: DurableNonceStore {
                path: nonce_path,
                seen: HashMap::new(),
            },
            started_at: Instant::now(),
        }));

        drop(_guard);

        let error = reject_replay(Arc::clone(&state), &request)
            .await
            .unwrap_err();
        assert!(error.contains("failed to write nonce store"));
        assert!(state.lock().await.nonce_store.seen.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deploy_request_returns_rejected_ack_before_cache_insert() {
        let nonce_path = test_nonce_path("deploy-rejected-cache");
        let state = Arc::new(Mutex::new(test_state(nonce_path.clone())));
        let mut request = deploy_payload();
        request.module_hash[0] ^= 0xff;

        let ack = deploy_request(Arc::clone(&state), "sandbox-1", request).await;

        assert_eq!(ack.instance_id, "sandbox-1");
        assert!(ack.status.starts_with("rejected:"));
        assert!(state.lock().await.modules.is_empty());
        let _ = fs::remove_file(nonce_path);
    }

    #[test]
    fn deploy_hash_must_match_blake3_module_bytes() {
        let mut payload = deploy_payload();
        assert!(deploy_module_hash_matches(&payload));

        payload.module_hash[0] ^= 0xff;
        assert!(!deploy_module_hash_matches(&payload));
    }

    #[test]
    fn tick_payload_serializes_in_documented_hmac_order() {
        let payload = tick_payload();
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                r#"{"schema":"swarm.sandbox.tick.v1","tick":7,"player_id":"player-1","#,
                r#""room_id":"room-1","module_hash":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"#,
                r#""snapshot_json":"{}","fuel_budget":100,"collect_timeout_ms":250}"#
            )
        );
    }

    #[test]
    fn deploy_payload_serializes_in_documented_hmac_order() {
        let payload = DeployRequest {
            schema: DEPLOY_SCHEMA.to_string(),
            module_hash: [1; 32],
            module_bytes: vec![0, 97, 115, 109],
            validation_policy_version: "policy-v1".to_string(),
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                r#"{"schema":"swarm.sandbox.deploy.v1","module_hash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"#,
                r#""module_bytes":[0,97,115,109],"validation_policy_version":"policy-v1"}"#
            )
        );
    }
}
