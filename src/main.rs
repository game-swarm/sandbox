use std::{
    collections::HashMap,
    env, fs,
    fs::OpenOptions,
    io::{ErrorKind, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use swarm_wasm_sandbox::{
    CompiledModule, CompiledModuleCache, HostCallBudget, IsolationMode, OsIsolationPolicy,
    SandboxConfig, SandboxRuntime,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::Mutex,
    time,
};
use uuid::Uuid;

const DEPLOY_SCHEMA: &str = "swarm.sandbox.deploy.v1";
const TICK_SCHEMA: &str = "swarm.sandbox.tick.v1";
const MODULE_FETCH_SCHEMA: &str = "swarm.sandbox.module-fetch.v1";
const AUTH_FRESHNESS_MS: u64 = 60_000;
const AUTH_FUTURE_SKEW_MS: u64 = 5_000;
const DEFAULT_NATS_CONNECT_RETRY_MS: u64 = 1_000;
const DEFAULT_SANDBOX_HEALTH_ADDR: &str = "127.0.0.1:8083";
const NONCE_STORE_FILE_NAME: &str = "nonces.db";
const NONCE_STORE_DIR_NAME: &str = "swarm-sandbox";
const JSON_CONTENT_TYPE: &str = "application/json";

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
    collect_deadline_ms: u64,
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
    compiled_artifact_hash: String,
    status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleFetchRequest {
    schema: String,
    module_hash: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleFetchReply {
    schema: String,
    module_hash: [u8; 32],
    module_bytes: Vec<u8>,
    validation_policy_version: String,
}

#[derive(Clone, Debug)]
struct CachedModule {
    wasm_bytes: Vec<u8>,
    validation_policy_version: String,
}

struct ServiceState {
    cache: CompiledModuleCache,
    modules: HashMap<String, CachedModule>,
    nonce_store: DurableNonceStore,
    sandbox_config: SandboxConfig,
    started_at: Instant,
}

#[derive(Debug, Default)]
struct ReadinessState {
    tick_subscribed: AtomicBool,
    deploy_subscribed: AtomicBool,
}

impl ReadinessState {
    fn set_tick_subscribed(&self, ready: bool) {
        self.tick_subscribed.store(ready, Ordering::Relaxed);
    }

    fn set_deploy_subscribed(&self, ready: bool) {
        self.deploy_subscribed.store(ready, Ordering::Relaxed);
    }

    fn is_ready(&self) -> bool {
        self.tick_subscribed.load(Ordering::Relaxed)
            && self.deploy_subscribed.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
struct NatsConfig {
    url: String,
    tls_required: bool,
    ca_file: Option<PathBuf>,
    client_cert_file: Option<PathBuf>,
    client_key_file: Option<PathBuf>,
    credentials_file: Option<PathBuf>,
}

#[derive(Debug)]
struct DurableNonceStore {
    path: PathBuf,
    seen: HashMap<String, u64>,
}

impl DurableNonceStore {
    fn load(path: PathBuf) -> Result<Self, String> {
        validate_nonce_store_path(&path)?;
        let _lock = lock_nonce_store(&path)?;
        let now = current_time_ms()?;
        let seen = read_nonce_store(&path)?;

        let mut store = Self { path, seen };
        store.prune(now);
        store.persist_unlocked()?;
        Ok(store)
    }

    fn record(&mut self, key: String, timestamp_ms: u64, now: u64) -> Result<(), String> {
        let _lock = lock_nonce_store(&self.path)?;
        self.seen = read_nonce_store(&self.path)?;
        self.prune(now);
        if self.seen.contains_key(&key) {
            return Err("replay detected".to_string());
        }
        self.seen.insert(key.clone(), timestamp_ms);
        if let Err(error) = self.persist_unlocked() {
            self.seen.remove(&key);
            return Err(error);
        }
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        self.seen
            .retain(|_, timestamp_ms| now.saturating_sub(*timestamp_ms) <= AUTH_FRESHNESS_MS);
    }

    fn persist_unlocked(&self) -> Result<(), String> {
        validate_nonce_store_path(&self.path)?;
        let bytes = serde_json::to_vec(&self.seen).map_err(|err| err.to_string())?;
        let temp_path = create_nonce_store_temp_path(&self.path)?;
        let write_result = write_nonce_store_temp_file(&temp_path, &bytes)
            .and_then(|_| fs::rename(&temp_path, &self.path).map_err(|err| err.to_string()))
            .and_then(|_| sync_nonce_store_parent(&self.path));
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(format!(
                "failed to replace nonce store {}: {error}",
                self.path.display()
            ));
        }
        Ok(())
    }
}

fn read_nonce_store(path: &Path) -> Result<HashMap<String, u64>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<HashMap<String, u64>>(&bytes)
            .map_err(|err| format!("failed to parse nonce store {}: {err}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(HashMap::new()),
        Err(error) => Err(format!(
            "failed to read nonce store {}: {error}",
            path.display()
        )),
    }
}

fn nonce_store_lock_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "nonce store path {} must have a parent directory",
            path.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(NONCE_STORE_FILE_NAME);
    Ok(parent.join(format!(".{file_name}.lock")))
}

fn lock_nonce_store(path: &Path) -> Result<fs::File, String> {
    validate_nonce_store_path(path)?;
    let lock_path = nonce_store_lock_path(path)?;
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "nonce store lock path {} must not be a symlink",
                lock_path.display()
            ));
        }
        Ok(metadata) if metadata.is_dir() => {
            return Err(format!(
                "nonce store lock path {} must not be a directory",
                lock_path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect nonce store lock path {}: {error}",
                lock_path.display()
            ));
        }
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let file = options.open(&lock_path).map_err(|err| {
        format!(
            "failed to open nonce store lock {}: {err}",
            lock_path.display()
        )
    })?;
    file.lock().map_err(|err| {
        format!(
            "failed to lock nonce store {} via {}: {err}",
            path.display(),
            lock_path.display()
        )
    })?;
    Ok(file)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let instance_id = env::var("INSTANCE_ID").unwrap_or_else(|_| default_instance_id());
    let retry_delay = nats_connect_retry_delay();
    let health_addr =
        configured_sandbox_health_addr(env::var("SANDBOX_HEALTH_ADDR").ok().as_deref());
    let readiness = Arc::new(ReadinessState::default());
    tokio::spawn(readiness_server(health_addr, Arc::clone(&readiness)));
    let sandbox_config = startup_sandbox_config().map_err(std::io::Error::other)?;
    let nonce_store_path = sandbox_nonce_store_path().map_err(std::io::Error::other)?;
    let nats_config = NatsConfig::from_env().map_err(std::io::Error::other)?;
    validated_nats_auth_secret().map_err(std::io::Error::other)?;
    let nonce_store = DurableNonceStore::load(nonce_store_path).map_err(std::io::Error::other)?;
    let client = connect_nats_with_retry(&nats_config, retry_delay).await?;

    let state = Arc::new(Mutex::new(ServiceState {
        cache: CompiledModuleCache::new(),
        modules: HashMap::new(),
        nonce_store,
        sandbox_config,
        started_at: Instant::now(),
    }));

    let tick_sub = client
        .queue_subscribe(
            "swarm.tick.*.player.*".to_string(),
            "sandbox-workers".to_string(),
        )
        .await?;
    let deploy_sub = client.subscribe("swarm.deploy.*".to_string()).await?;
    readiness.set_tick_subscribed(true);
    readiness.set_deploy_subscribed(true);

    let tick_readiness = Arc::clone(&readiness);
    let tick_client = client.clone();
    let tick_state = Arc::clone(&state);
    let tick_task = tokio::spawn(async move {
        handle_ticks(tick_client, tick_state, tick_sub).await;
        tick_readiness.set_tick_subscribed(false);
    });
    let deploy_readiness = Arc::clone(&readiness);
    let deploy_state = Arc::clone(&state);
    let deploy_client = client.clone();
    let deploy_instance_id = instance_id.clone();
    let deploy_task = tokio::spawn(async move {
        handle_deploys(deploy_client, deploy_state, deploy_instance_id, deploy_sub).await;
        deploy_readiness.set_deploy_subscribed(false);
    });
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

fn configured_sandbox_health_addr(value: Option<&str>) -> String {
    value.unwrap_or(DEFAULT_SANDBOX_HEALTH_ADDR).to_string()
}

async fn readiness_server(addr: String, readiness: Arc<ReadinessState>) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("sandbox health server bind failed addr={addr} error={error}");
            return;
        }
    };
    println!("sandbox health server listening addr={addr}");

    serve_readiness(listener, readiness).await;
}

async fn serve_readiness(listener: TcpListener, readiness: Arc<ReadinessState>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let readiness = Arc::clone(&readiness);
                tokio::spawn(async move {
                    respond_readiness_http(stream, readiness).await;
                });
            }
            Err(error) => eprintln!("sandbox health server connection failed error={error}"),
        }
    }
}

async fn respond_readiness_http(mut stream: TcpStream, readiness: Arc<ReadinessState>) {
    let mut buffer = [0_u8; 1024];
    let Ok(bytes_read) = stream.read(&mut buffer).await else {
        return;
    };
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let Some(request_line) = request.lines().next() else {
        let _ = write_http_response(
            &mut stream,
            "HTTP/1.1 400 Bad Request",
            "text/plain; charset=utf-8",
            b"bad request\n",
        )
        .await;
        return;
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    if !method.eq_ignore_ascii_case("GET") {
        let _ = write_http_response(
            &mut stream,
            "HTTP/1.1 405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed\n",
        )
        .await;
        return;
    }

    match path {
        "/" | "/healthz" | "/readyz" => {
            let (status_line, body) = render_readiness_body(&readiness);
            let _ =
                write_http_response(&mut stream, status_line, JSON_CONTENT_TYPE, body.as_bytes())
                    .await;
        }
        _ => {
            let _ = write_http_response(
                &mut stream,
                "HTTP/1.1 404 Not Found",
                "text/plain; charset=utf-8",
                b"not found\n",
            )
            .await;
        }
    }
}

fn render_readiness_body(readiness: &ReadinessState) -> (&'static str, String) {
    let tick_ready = readiness.tick_subscribed.load(Ordering::Relaxed);
    let deploy_ready = readiness.deploy_subscribed.load(Ordering::Relaxed);
    let ready = readiness.is_ready();
    let status = if ready { "ok" } else { "degraded" };
    let nats = if ready { "ready" } else { "unavailable" };
    let tick = if tick_ready { "ready" } else { "unavailable" };
    let deploy = if deploy_ready { "ready" } else { "unavailable" };
    let status_line = if ready {
        "HTTP/1.1 200 OK"
    } else {
        "HTTP/1.1 503 Service Unavailable"
    };
    let body = json!({
        "status": status,
        "nats": nats,
        "subscriptions": {
            "tick": tick,
            "deploy": deploy,
        }
    })
    .to_string();
    (status_line, format!("{body}\n"))
}

async fn write_http_response(
    stream: &mut TcpStream,
    status_line: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await
}

async fn connect_nats_with_retry(
    config: &NatsConfig,
    retry_delay: Duration,
) -> Result<async_nats::Client, Box<dyn std::error::Error + Send + Sync>> {
    let safe_url = redact_nats_url(&config.url);
    let options = nats_connect_options(config).await?;
    let mut attempt = 1_u64;
    loop {
        let result = options.clone().connect(config.url.clone()).await;
        if !should_retry_nats_connect(&result) {
            let client = result.expect("successful NATS connection checked above");
            eprintln!("connected to NATS at {safe_url} after {attempt} attempt(s)");
            return Ok(client);
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

async fn nats_connect_options(
    config: &NatsConfig,
) -> Result<async_nats::ConnectOptions, Box<dyn std::error::Error + Send + Sync>> {
    let mut options = async_nats::ConnectOptions::new().require_tls(config.tls_required);
    if let Some(path) = &config.ca_file {
        options = options.add_root_certificates(path.clone());
    }
    if let (Some(cert), Some(key)) = (&config.client_cert_file, &config.client_key_file) {
        options = options.add_client_certificate(cert.clone(), key.clone());
    }
    if let Some(path) = &config.credentials_file {
        options = options.credentials_file(path).await?;
    }
    Ok(options)
}

impl NatsConfig {
    fn from_env() -> Result<Self, String> {
        let mode = env::var("SWARM_SANDBOX_MODE").unwrap_or_else(|_| "production".to_string());
        let url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
        let tls_required = env::var("NATS_TLS_REQUIRED").ok();
        Self::from_values_for_mode(
            &mode,
            &url,
            tls_required.as_deref(),
            configured_file("NATS_TLS_CA_FILE")?,
            configured_file("NATS_TLS_CERT_FILE")?,
            configured_file("NATS_TLS_KEY_FILE")?,
            configured_file("NATS_CREDENTIALS_FILE")?,
        )
    }

    fn from_values_for_mode(
        mode: &str,
        url: &str,
        tls_required: Option<&str>,
        ca_file: Option<PathBuf>,
        client_cert_file: Option<PathBuf>,
        client_key_file: Option<PathBuf>,
        credentials_file: Option<PathBuf>,
    ) -> Result<Self, String> {
        let mode = mode.trim().to_ascii_lowercase();
        if !matches!(mode.as_str(), "production" | "development" | "test") {
            return Err(format!("invalid SWARM_SANDBOX_MODE `{mode}`"));
        }
        let config = Self::from_values(
            url,
            tls_required,
            ca_file,
            client_cert_file,
            client_key_file,
            credentials_file,
        )?;
        if mode == "production" && !config.tls_required {
            return Err("production sandbox requires NATS TLS".to_string());
        }
        if mode == "production" && config.credentials_file.is_none() {
            return Err("production sandbox requires NATS role credentials".to_string());
        }
        if matches!(mode.as_str(), "development" | "test")
            && !config.tls_required
            && !is_local_nats_url(&config.url)
        {
            return Err(
                "development/test sandbox plaintext NATS is limited to local URLs".to_string(),
            );
        }
        Ok(config)
    }

    fn from_values(
        url: &str,
        tls_required: Option<&str>,
        ca_file: Option<PathBuf>,
        client_cert_file: Option<PathBuf>,
        client_key_file: Option<PathBuf>,
        credentials_file: Option<PathBuf>,
    ) -> Result<Self, String> {
        let url = url.trim();
        if url.is_empty() {
            return Err("NATS_URL must be non-empty".to_string());
        }
        if client_cert_file.is_some() != client_key_file.is_some() {
            return Err(
                "NATS_TLS_CERT_FILE and NATS_TLS_KEY_FILE must be configured together".to_string(),
            );
        }

        let explicitly_disabled = tls_required.is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        });
        let configured_tls = ca_file.is_some()
            || client_cert_file.is_some()
            || credentials_file.is_some()
            || url.starts_with("tls://");
        if explicitly_disabled && configured_tls {
            return Err(
                "NATS_TLS_REQUIRED cannot be false when TLS or credentials are configured"
                    .to_string(),
            );
        }
        let tls_required = match tls_required.map(str::trim) {
            None => configured_tls,
            Some(value)
                if matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                ) =>
            {
                true
            }
            Some(value)
                if matches!(
                    value.to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                ) =>
            {
                false
            }
            Some(_) => return Err("NATS_TLS_REQUIRED must be a boolean".to_string()),
        };

        for (name, path) in [
            ("NATS_TLS_CA_FILE", ca_file.as_ref()),
            ("NATS_TLS_CERT_FILE", client_cert_file.as_ref()),
            ("NATS_TLS_KEY_FILE", client_key_file.as_ref()),
            ("NATS_CREDENTIALS_FILE", credentials_file.as_ref()),
        ] {
            if let Some(path) = path {
                let metadata = fs::metadata(path).map_err(|error| {
                    format!("{name} is not readable ({}): {error}", path.display())
                })?;
                if !metadata.is_file() {
                    return Err(format!("{name} must reference a file: {}", path.display()));
                }
            }
        }

        Ok(Self {
            url: url.to_string(),
            tls_required,
            ca_file,
            client_cert_file,
            client_key_file,
            credentials_file,
        })
    }
}

fn configured_file(name: &str) -> Result<Option<PathBuf>, String> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Err(format!("{name} must be non-empty when set")),
        Ok(value) => Ok(Some(PathBuf::from(value.trim()))),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!("failed to read {name}: {error}")),
    }
}

fn is_local_nats_url(url: &str) -> bool {
    let url = url.trim();
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .or_else(|| host_port.split_once(':').map(|(host, _)| host))
        .unwrap_or(host_port);
    matches!(host, "127.0.0.1" | "::1" | "localhost")
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

fn sandbox_nonce_store_path() -> Result<PathBuf, String> {
    let mode = env::var("SWARM_SANDBOX_MODE").unwrap_or_else(|_| "production".to_string());
    sandbox_nonce_store_path_for_mode(&mode, env::var("SWARM_SANDBOX_NONCE_PATH").ok())
}

fn sandbox_nonce_store_path_for_mode(
    mode: &str,
    configured_path: Option<String>,
) -> Result<PathBuf, String> {
    let mode = mode.trim().to_ascii_lowercase();
    if !matches!(mode.as_str(), "production" | "development" | "test") {
        return Err(format!("invalid SWARM_SANDBOX_MODE `{mode}`"));
    }
    let path = match configured_path {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        Some(_) => return Err("SWARM_SANDBOX_NONCE_PATH must not be empty".to_string()),
        None if mode == "production" => {
            return Err(
                "production sandbox requires SWARM_SANDBOX_NONCE_PATH outside shared /tmp"
                    .to_string(),
            );
        }
        None => default_development_nonce_store_path()?,
    };
    if mode == "production" && path_is_in_shared_tmp(&path) {
        return Err("production sandbox nonce store must be outside shared /tmp".to_string());
    }
    validate_nonce_store_path(&path)?;
    Ok(path)
}

fn default_development_nonce_store_path() -> Result<PathBuf, String> {
    let base = env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local").join("state"))
        })
        .unwrap_or_else(|| {
            env::temp_dir().join(format!("{NONCE_STORE_DIR_NAME}-{}", current_uid()))
        });
    let dir = base.join(NONCE_STORE_DIR_NAME);
    create_private_dir_all(&dir)?;
    Ok(dir.join(NONCE_STORE_FILE_NAME))
}

fn create_private_dir_all(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|err| {
        format!(
            "failed to create nonce store directory {}: {err}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!(
                "failed to set nonce store directory permissions {}: {err}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn validate_nonce_store_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("nonce store path must not be empty".to_string());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "nonce store path {} must have a parent directory",
                path.display()
            )
        })?;
    reject_symlink_path_components(parent)?;
    validate_private_nonce_store_parent(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "nonce store path {} must not be a symlink",
            path.display()
        )),
        Ok(metadata) if metadata.is_dir() => Err(format!(
            "nonce store path {} must not be a directory",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect nonce store path {}: {error}",
            path.display()
        )),
    }
}

fn reject_symlink_path_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "nonce store parent path {} must not contain .. components",
                    path.display()
                ));
            }
            Component::Normal(part) => current.push(part),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "nonce store parent component {} must not be a symlink",
                    current.display()
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "nonce store parent component {} must be a directory",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect nonce store parent component {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

fn validate_private_nonce_store_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let uid = current_uid();
        for ancestor in path.ancestors() {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let metadata = fs::symlink_metadata(ancestor).map_err(|err| {
                format!(
                    "failed to inspect nonce store parent component {}: {err}",
                    ancestor.display()
                )
            })?;
            if !metadata.is_dir() {
                return Err(format!(
                    "nonce store parent component {} must be a directory",
                    ancestor.display()
                ));
            }
            let owner = metadata.uid();
            if owner != uid && owner != 0 {
                return Err(format!(
                    "nonce store parent component {} must be owned by the sandbox user or root",
                    ancestor.display()
                ));
            }
            let mode = metadata.mode();
            let writable_by_others = mode & 0o022 != 0;
            let sticky = mode & 0o1000 != 0;
            if ancestor == path {
                if writable_by_others {
                    return Err(format!(
                        "nonce store parent directory {} must not be group- or world-writable",
                        ancestor.display()
                    ));
                }
            } else if writable_by_others && !sticky {
                return Err(format!(
                    "nonce store ancestor directory {} must not be group- or world-writable without sticky bit",
                    ancestor.display()
                ));
            }
        }
    }
    Ok(())
}

fn path_is_in_shared_tmp(path: &Path) -> bool {
    let tmp = Path::new("/tmp");
    path == tmp || path.starts_with(tmp)
}

fn create_nonce_store_temp_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "nonce store path {} must have a parent directory",
            path.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(NONCE_STORE_FILE_NAME);
    reject_existing_nonce_store_temp_symlinks(parent, file_name)?;
    for _ in 0..16 {
        let temp_path = parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4().simple()));
        match fs::symlink_metadata(&temp_path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(temp_path),
            Ok(_) => continue,
            Err(error) => {
                return Err(format!(
                    "failed to inspect nonce store temp path {}: {error}",
                    temp_path.display()
                ));
            }
        }
    }
    Err(format!(
        "failed to choose symlink-free nonce store temp path for {}",
        path.display()
    ))
}

fn reject_existing_nonce_store_temp_symlinks(parent: &Path, file_name: &str) -> Result<(), String> {
    let prefix = format!(".{file_name}.");
    let entries = fs::read_dir(parent).map_err(|err| {
        format!(
            "failed to inspect nonce store directory {}: {err}",
            parent.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "failed to inspect nonce store directory entry {}: {err}",
                parent.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(&prefix) && name.ends_with(".tmp") {
            let metadata = fs::symlink_metadata(entry.path()).map_err(|err| {
                format!(
                    "failed to inspect nonce store temp path {}: {err}",
                    entry.path().display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "nonce store temp path {} must not be a symlink",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(())
}

fn write_nonce_store_temp_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        format!(
            "failed to create nonce store temp file {}: {err}",
            path.display()
        )
    })?;
    file.write_all(bytes).map_err(|err| {
        format!(
            "failed to write nonce store temp file {}: {err}",
            path.display()
        )
    })?;
    file.flush().map_err(|err| {
        format!(
            "failed to flush nonce store temp file {}: {err}",
            path.display()
        )
    })?;
    file.sync_all().map_err(|err| {
        format!(
            "failed to sync nonce store temp file {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn sync_nonce_store_parent(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let directory = fs::File::open(parent).map_err(|err| {
        format!(
            "failed to open nonce store directory {}: {err}",
            parent.display()
        )
    })?;
    directory.sync_all().map_err(|err| {
        format!(
            "failed to sync nonce store directory {}: {err}",
            parent.display()
        )
    })
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    unsafe { geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
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

fn startup_sandbox_config() -> Result<SandboxConfig, String> {
    let mode = env::var("SWARM_SANDBOX_MODE").unwrap_or_else(|_| "production".to_string());
    let config = match mode.as_str() {
        "production" => SandboxConfig {
            wasm_simd: env_bool("SWARM_SANDBOX_WASM_SIMD")?,
            ..SandboxConfig::default()
        },
        "development" | "test" => SandboxConfig {
            wasm_simd: env_bool("SWARM_SANDBOX_WASM_SIMD")?,
            ..SandboxConfig::development()
        },
        _ => return Err(format!("invalid SWARM_SANDBOX_MODE `{mode}`")),
    };
    validate_startup_sandbox_config(&config, &mode)?;
    Ok(config)
}

fn env_bool(name: &str) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => parse_bool(name, &value),
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn parse_bool(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

fn validate_startup_sandbox_config(config: &SandboxConfig, mode: &str) -> Result<(), String> {
    if mode != "production" {
        return Ok(());
    }
    if config.isolation != IsolationMode::OsProcess {
        return Err("production sandbox requires OS process isolation".to_string());
    }
    validate_required_os_policy(config.os_isolation)
}

fn validate_required_os_policy(policy: OsIsolationPolicy) -> Result<(), String> {
    if !policy.seccomp {
        return Err("production sandbox requires seccomp".to_string());
    }
    if !policy.cgroup {
        return Err("production sandbox requires cgroup limits".to_string());
    }
    if !policy.network_namespace {
        return Err("production sandbox requires a network namespace".to_string());
    }
    if !policy.read_only_root {
        return Err("production sandbox requires a read-only root".to_string());
    }
    if !policy.tmpfs_tmp {
        return Err("production sandbox requires tmpfs /tmp".to_string());
    }
    if policy.allow_permission_fallback {
        return Err(
            "production sandbox must not allow OS isolation permission fallback".to_string(),
        );
    }
    Ok(())
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
                Ok(()) => execute_request(&client, Arc::clone(&state), request.payload).await,
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
    client: &async_nats::Client,
    state: Arc<Mutex<ServiceState>>,
    request: SandboxTickRequest,
) -> SandboxTickReply {
    let started_at = Instant::now();
    let initial_timeout_ms = match remaining_collect_ms(request.collect_deadline_ms) {
        Ok(remaining_ms) => remaining_ms.min(request.collect_timeout_ms),
        Err(_) => {
            return tick_reply(
                request,
                Vec::new(),
                SandboxExecutionMetrics::default(),
                "Timeout",
            );
        }
    };
    let module_hash = bytes_to_hex(&request.module_hash);
    let (module, sandbox_config) = {
        let state = state.lock().await;
        (
            state.modules.get(&module_hash).cloned(),
            state.sandbox_config.clone(),
        )
    };
    let module = if let Some(module) = module {
        module
    } else {
        {
            let mut locked_state = state.lock().await;
            locked_state.cache.record_miss();
        }
        match fetch_module(
            client,
            Arc::clone(&state),
            request.module_hash,
            request.collect_deadline_ms,
        )
        .await
        {
            Ok(module) => module,
            Err(_) => {
                let status = if remaining_collect_ms(request.collect_deadline_ms).is_err() {
                    "Timeout"
                } else {
                    "ModuleNotFound"
                };
                return tick_reply(
                    request,
                    Vec::new(),
                    metrics(started_at, HostCallBudget::default()),
                    status,
                );
            }
        }
    };

    let request_config = SandboxConfig {
        max_fuel: request.fuel_budget,
        tick_timeout_ms: initial_timeout_ms,
        ..sandbox_config
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

    let timeout_ms = match remaining_collect_ms(request.collect_deadline_ms) {
        Ok(remaining_ms) => remaining_ms,
        Err(_) => {
            return tick_reply(
                request,
                Vec::new(),
                metrics(started_at, HostCallBudget::default()),
                "Timeout",
            );
        }
    };
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
    runtime.compile_cached_with_policy(
        &mut state.cache,
        &module.wasm_bytes,
        &module.validation_policy_version,
    )
}

async fn fetch_module(
    client: &async_nats::Client,
    state: Arc<Mutex<ServiceState>>,
    module_hash: [u8; 32],
    collect_deadline_ms: u64,
) -> Result<CachedModule, String> {
    let request = ModuleFetchRequest {
        schema: MODULE_FETCH_SCHEMA.to_string(),
        module_hash,
    };
    let request_id = new_hex_id(16)?;
    let payload = encode_authenticated(&request, &request_id)?;
    let subject = format!("swarm.module.fetch.{}", bytes_to_hex(&module_hash));
    let response = time::timeout(
        Duration::from_millis(remaining_collect_ms(collect_deadline_ms)?),
        client.request(subject, payload.into()),
    )
    .await
    .map_err(|_| "module fetch timed out".to_string())?
    .map_err(|error| error.to_string())?;
    let reply = decode_authenticated::<ModuleFetchReply>(&response.payload, MODULE_FETCH_SCHEMA)?;
    if reply.request_id != request_id {
        return Err("module fetch reply request_id mismatch".to_string());
    }
    reject_replay(Arc::clone(&state), &reply).await?;
    let module = validate_module_fetch_reply(reply.payload, module_hash)?;

    let runtime = SandboxRuntime::default();
    let cached_native = runtime
        .precompile_native_with_policy(&module.wasm_bytes, &module.validation_policy_version)
        .map_err(|error| error.to_string())?;
    let mut state = state.lock().await;
    state.cache.insert(cached_native);
    state
        .modules
        .insert(bytes_to_hex(&module_hash), module.clone());
    Ok(module)
}

fn validate_module_fetch_reply(
    reply: ModuleFetchReply,
    expected_module_hash: [u8; 32],
) -> Result<CachedModule, String> {
    if reply.module_hash != expected_module_hash
        || blake3::hash(&reply.module_bytes).as_bytes() != &expected_module_hash
    {
        return Err("module fetch reply hash mismatch".to_string());
    }
    if reply.validation_policy_version.trim().is_empty() {
        return Err("module fetch reply validation policy is empty".to_string());
    }
    Ok(CachedModule {
        wasm_bytes: reply.module_bytes,
        validation_policy_version: reply.validation_policy_version,
    })
}

fn remaining_collect_ms(collect_deadline_ms: u64) -> Result<u64, String> {
    let remaining_ms = collect_deadline_ms.saturating_sub(current_time_ms()?);
    if remaining_ms == 0 {
        return Err("collect deadline exceeded".to_string());
    }
    Ok(remaining_ms)
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
                compiled_artifact_hash: String::new(),
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
            compiled_artifact_hash: String::new(),
            status: "rejected:module_hash mismatch".to_string(),
        };
    }

    let module_hash = bytes_to_hex(&request.module_hash);
    let runtime = SandboxRuntime::default();
    let cached_native = match runtime
        .precompile_native_with_policy(&request.module_bytes, &request.validation_policy_version)
    {
        Ok(cached_native) => cached_native,
        Err(error) => {
            return DeployAck {
                instance_id: instance_id.to_string(),
                module_hash,
                compiled_artifact_hash: String::new(),
                status: format!("rejected:{error}"),
            };
        }
    };
    let compiled_artifact_hash = cached_native.compiled_artifact_hash();

    {
        let mut state = state.lock().await;
        state.cache.insert(cached_native);
        state.modules.insert(
            module_hash.clone(),
            CachedModule {
                wasm_bytes: request.module_bytes,
                validation_policy_version: request.validation_policy_version.clone(),
            },
        );
    }

    DeployAck {
        instance_id: instance_id.to_string(),
        module_hash,
        compiled_artifact_hash,
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

impl SchemaName for ModuleFetchRequest {
    fn schema_name(&self) -> &str {
        &self.schema
    }
}

impl SchemaName for ModuleFetchReply {
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
            collect_deadline_ms: current_time_ms().unwrap().saturating_add(5_000),
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
        let dir = env::temp_dir().join(format!(
            "swarm-sandbox-{test_name}-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.join(NONCE_STORE_FILE_NAME);
        let _ = fs::remove_file(&path);
        path
    }

    fn test_nonce_dir(test_name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "swarm-sandbox-{test_name}-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn temp_existing_file(test_name: &str, contents: &str) -> PathBuf {
        let path = test_nonce_path(test_name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn replay_key(request: &AuthenticatedRequest<SandboxTickRequest>) -> String {
        format!("{}:{}", request.request_id, request.nonce)
    }

    fn test_state(nonce_path: PathBuf) -> ServiceState {
        ServiceState {
            cache: CompiledModuleCache::new(),
            modules: HashMap::new(),
            nonce_store: DurableNonceStore::load(nonce_path).unwrap(),
            sandbox_config: SandboxConfig::development(),
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
    fn sandbox_health_addr_defaults_to_loopback() {
        assert_eq!(
            configured_sandbox_health_addr(None),
            DEFAULT_SANDBOX_HEALTH_ADDR
        );
        assert_eq!(
            configured_sandbox_health_addr(Some("0.0.0.0:9000")),
            "0.0.0.0:9000"
        );
    }

    #[test]
    fn readiness_body_reports_degraded_until_all_subscriptions_ready() {
        let readiness = ReadinessState::default();

        let (status, degraded_body) = render_readiness_body(&readiness);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable");
        assert!(degraded_body.contains(r#""status":"degraded""#));
        assert!(degraded_body.contains(r#""nats":"unavailable""#));

        readiness.set_tick_subscribed(true);
        let (status, partially_ready_body) = render_readiness_body(&readiness);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable");
        assert!(partially_ready_body.contains(r#""tick":"ready""#));
        assert!(partially_ready_body.contains(r#""deploy":"unavailable""#));

        readiness.set_deploy_subscribed(true);
        let (status, ready_body) = render_readiness_body(&readiness);
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert!(ready_body.contains(r#""status":"ok""#));
        assert!(ready_body.contains(r#""nats":"ready""#));
        assert!(ready_body.len() < 512);
    }

    #[tokio::test]
    async fn readiness_endpoint_returns_503_then_200_from_subscription_state() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let readiness = Arc::new(ReadinessState::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(serve_readiness(listener, Arc::clone(&readiness)));

        let degraded = http_get(addr, "/healthz").await;
        assert!(degraded.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(degraded.contains(r#""status":"degraded""#));

        readiness.set_tick_subscribed(true);
        readiness.set_deploy_subscribed(true);
        let ready = http_get(addr, "/readyz").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK"));
        assert!(ready.contains(r#""status":"ok""#));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let response = String::from_utf8(bytes).unwrap();
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));

        handle.abort();
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn nats_config_production_requires_tls_and_role_credentials() {
        assert_eq!(
            NatsConfig::from_values_for_mode(
                "production",
                "nats://127.0.0.1:4222",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "production sandbox requires NATS TLS"
        );
        assert_eq!(
            NatsConfig::from_values_for_mode(
                "production",
                "tls://nats.example.test:4222",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "production sandbox requires NATS role credentials"
        );

        let credentials = temp_existing_file("nats-production-creds", "not-valid-creds");
        let config = NatsConfig::from_values_for_mode(
            "production",
            "tls://nats.example.test:4222",
            None,
            None,
            None,
            None,
            Some(credentials.clone()),
        )
        .unwrap();
        assert!(config.tls_required);
        assert_eq!(config.credentials_file, Some(credentials.clone()));
        let _ = fs::remove_file(credentials);
    }

    #[test]
    fn nats_config_development_and_test_permit_only_local_plaintext() {
        for mode in ["development", "test"] {
            let config = NatsConfig::from_values_for_mode(
                mode,
                "nats://localhost:4222",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert!(!config.tls_required);

            assert_eq!(
                NatsConfig::from_values_for_mode(
                    mode,
                    "nats://nats.example.test:4222",
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap_err(),
                "development/test sandbox plaintext NATS is limited to local URLs"
            );
        }
    }

    #[test]
    fn nats_config_rejects_invalid_or_partial_security_settings() {
        let missing = test_nonce_path("missing-nats-file");
        assert_eq!(
            NatsConfig::from_values_for_mode(
                "staging",
                "nats://127.0.0.1:4222",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "invalid SWARM_SANDBOX_MODE `staging`"
        );
        assert_eq!(
            NatsConfig::from_values(
                "nats://127.0.0.1:4222",
                Some("sometimes"),
                None,
                None,
                None,
                None,
            )
            .unwrap_err(),
            "NATS_TLS_REQUIRED must be a boolean"
        );
        assert_eq!(
            NatsConfig::from_values(
                "nats://127.0.0.1:4222",
                Some("true"),
                None,
                Some(missing.clone()),
                None,
                None,
            )
            .unwrap_err(),
            "NATS_TLS_CERT_FILE and NATS_TLS_KEY_FILE must be configured together"
        );
        assert!(
            NatsConfig::from_values(
                "nats://127.0.0.1:4222",
                Some("true"),
                None,
                None,
                None,
                Some(missing),
            )
            .unwrap_err()
            .contains("NATS_CREDENTIALS_FILE is not readable")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_nats_credentials_fail_closed_before_connect() {
        let credentials =
            temp_existing_file("invalid-nats-credentials", "not a nats credentials file");
        let config = NatsConfig::from_values_for_mode(
            "production",
            "tls://nats.example.test:4222",
            None,
            None,
            None,
            None,
            Some(credentials.clone()),
        )
        .unwrap();

        assert!(nats_connect_options(&config).await.is_err());
        let _ = fs::remove_file(credentials);
    }

    #[test]
    fn startup_defaults_to_fail_closed_production_os_isolation() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::remove_var("SWARM_SANDBOX_MODE");
            env::remove_var("SWARM_SANDBOX_WASM_SIMD");
        }

        let config = startup_sandbox_config().unwrap();

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
    fn startup_development_and_test_modes_are_explicitly_permissive() {
        let _guard = ENV_LOCK.lock().unwrap();
        for mode in ["development", "test"] {
            unsafe {
                env::set_var("SWARM_SANDBOX_MODE", mode);
                env::remove_var("SWARM_SANDBOX_WASM_SIMD");
            }

            let config = startup_sandbox_config().unwrap();

            assert_eq!(config.isolation, IsolationMode::InProcess);
            assert!(!config.wasm_simd);
            assert!(!config.os_isolation.seccomp);
            assert!(!config.os_isolation.cgroup);
            assert!(!config.os_isolation.network_namespace);
            assert!(!config.os_isolation.read_only_root);
            assert!(!config.os_isolation.tmpfs_tmp);
            assert!(config.os_isolation.allow_permission_fallback);
        }
    }

    #[test]
    fn startup_simd_is_config_controlled_and_default_off() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_SANDBOX_MODE", "test");
            env::remove_var("SWARM_SANDBOX_WASM_SIMD");
        }
        assert!(!startup_sandbox_config().unwrap().wasm_simd);

        unsafe {
            env::set_var("SWARM_SANDBOX_WASM_SIMD", "true");
        }
        assert!(startup_sandbox_config().unwrap().wasm_simd);
    }

    #[test]
    fn production_nonce_path_requires_explicit_safe_config() {
        let missing = sandbox_nonce_store_path_for_mode("production", None).unwrap_err();
        assert!(missing.contains("requires SWARM_SANDBOX_NONCE_PATH"));

        let tmp_path = format!("/tmp/swarm-sandbox-{}.db", Uuid::new_v4().simple());
        let unsafe_tmp =
            sandbox_nonce_store_path_for_mode("production", Some(tmp_path)).unwrap_err();
        assert!(unsafe_tmp.contains("outside shared /tmp"));
    }

    #[test]
    fn development_nonce_path_has_private_ergonomic_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        let state_home = test_nonce_dir("default-state-home");
        unsafe {
            env::set_var("XDG_STATE_HOME", &state_home);
            env::remove_var("SWARM_SANDBOX_NONCE_PATH");
        }

        let path = sandbox_nonce_store_path_for_mode("test", None).unwrap();

        assert_eq!(
            path,
            state_home
                .join(NONCE_STORE_DIR_NAME)
                .join(NONCE_STORE_FILE_NAME)
        );
        assert!(path.parent().unwrap().is_dir());
        let _ = fs::remove_dir_all(state_home);
        unsafe {
            env::remove_var("XDG_STATE_HOME");
        }
    }

    #[test]
    fn production_policy_validation_rejects_missing_os_isolation_controls() {
        let config = SandboxConfig {
            isolation: IsolationMode::InProcess,
            ..SandboxConfig::default()
        };
        assert_eq!(
            validate_startup_sandbox_config(&config, "production").unwrap_err(),
            "production sandbox requires OS process isolation"
        );

        for (policy, expected) in [
            (
                OsIsolationPolicy {
                    seccomp: false,
                    ..OsIsolationPolicy::default()
                },
                "production sandbox requires seccomp",
            ),
            (
                OsIsolationPolicy {
                    cgroup: false,
                    ..OsIsolationPolicy::default()
                },
                "production sandbox requires cgroup limits",
            ),
            (
                OsIsolationPolicy {
                    network_namespace: false,
                    ..OsIsolationPolicy::default()
                },
                "production sandbox requires a network namespace",
            ),
            (
                OsIsolationPolicy {
                    read_only_root: false,
                    ..OsIsolationPolicy::default()
                },
                "production sandbox requires a read-only root",
            ),
            (
                OsIsolationPolicy {
                    tmpfs_tmp: false,
                    ..OsIsolationPolicy::default()
                },
                "production sandbox requires tmpfs /tmp",
            ),
            (
                OsIsolationPolicy {
                    allow_permission_fallback: true,
                    ..OsIsolationPolicy::default()
                },
                "production sandbox must not allow OS isolation permission fallback",
            ),
        ] {
            let config = SandboxConfig {
                os_isolation: policy,
                ..SandboxConfig::default()
            };
            assert_eq!(
                validate_startup_sandbox_config(&config, "production").unwrap_err(),
                expected
            );
        }
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

    #[tokio::test(flavor = "current_thread")]
    async fn reject_replay_reloads_nonce_store_under_lock() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let nonce_path = test_nonce_path("reject-replay-cross-process");
        let bytes = signed(tick_payload(), "secret");
        let request = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap();
        let first_state = Arc::new(Mutex::new(test_state(nonce_path.clone())));
        let second_state = Arc::new(Mutex::new(test_state(nonce_path.clone())));

        drop(_guard);

        assert!(
            reject_replay(Arc::clone(&first_state), &request)
                .await
                .is_ok()
        );
        assert_eq!(
            reject_replay(Arc::clone(&second_state), &request)
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

    #[cfg(unix)]
    #[test]
    fn nonce_store_rejects_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_nonce_dir("nonce-world-writable-parent");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let nonce_path = dir.join(NONCE_STORE_FILE_NAME);

        let error = DurableNonceStore::load(nonce_path).unwrap_err();

        assert!(error.contains("must not be group- or world-writable"));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn nonce_store_rejects_symlink_lock_file() {
        let nonce_path = test_nonce_path("nonce-lock-symlink");
        let lock_path = nonce_store_lock_path(&nonce_path).unwrap();
        let external_path = test_nonce_path("nonce-lock-external");
        fs::write(&external_path, b"external-lock-target-must-not-change").unwrap();
        std::os::unix::fs::symlink(&external_path, &lock_path).unwrap();

        let error = DurableNonceStore::load(nonce_path.clone()).unwrap_err();

        assert!(error.contains("lock path"));
        let _ = fs::remove_file(lock_path);
        let _ = fs::remove_file(nonce_path);
        let _ = fs::remove_file(external_path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn reject_replay_rejects_symlink_target_and_rolls_back_nonce() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let nonce_path = test_nonce_path("nonce-target-symlink");
        let external_path = test_nonce_path("nonce-target-external");
        let external_contents = b"external-file-must-not-change";
        fs::write(&external_path, external_contents).unwrap();
        std::os::unix::fs::symlink(&external_path, &nonce_path).unwrap();
        let bytes = signed(tick_payload(), "secret");
        let request = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap();
        let key = replay_key(&request);
        let state = Arc::new(Mutex::new(ServiceState {
            cache: CompiledModuleCache::new(),
            modules: HashMap::new(),
            nonce_store: DurableNonceStore {
                path: nonce_path.clone(),
                seen: HashMap::new(),
            },
            sandbox_config: SandboxConfig::development(),
            started_at: Instant::now(),
        }));

        drop(_guard);

        let error = reject_replay(Arc::clone(&state), &request)
            .await
            .unwrap_err();
        assert!(error.contains("must not be a symlink"));
        assert_eq!(fs::read(&external_path).unwrap(), external_contents);
        assert!(!state.lock().await.nonce_store.seen.contains_key(&key));
        let _ = fs::remove_file(nonce_path);
        let _ = fs::remove_file(external_path);
    }

    #[cfg(unix)]
    #[test]
    fn nonce_store_rejects_symlink_parent() {
        let real_dir = test_nonce_dir("nonce-real-parent");
        let symlink_dir = env::temp_dir().join(format!(
            "swarm-sandbox-parent-link-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
        let nonce_path = symlink_dir.join(NONCE_STORE_FILE_NAME);

        let error = DurableNonceStore::load(nonce_path).unwrap_err();

        assert!(error.contains("parent component"));
        let _ = fs::remove_file(symlink_dir);
        let _ = fs::remove_dir_all(real_dir);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn reject_replay_rejects_preexisting_temp_symlink_and_rolls_back_nonce() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            env::set_var("SWARM_NATS_AUTH_SECRET", "secret");
        }
        let dir = test_nonce_dir("nonce-temp-symlink");
        let nonce_path = dir.join(NONCE_STORE_FILE_NAME);
        let external_path = test_nonce_path("nonce-temp-external");
        let external_contents = b"external-temp-target-must-not-change";
        fs::write(&external_path, external_contents).unwrap();
        let temp_symlink = dir.join(format!(".{NONCE_STORE_FILE_NAME}.precreated.tmp"));
        std::os::unix::fs::symlink(&external_path, &temp_symlink).unwrap();
        let bytes = signed(tick_payload(), "secret");
        let request = decode_authenticated::<SandboxTickRequest>(&bytes, TICK_SCHEMA).unwrap();
        let key = replay_key(&request);
        let state = Arc::new(Mutex::new(ServiceState {
            cache: CompiledModuleCache::new(),
            modules: HashMap::new(),
            nonce_store: DurableNonceStore {
                path: nonce_path,
                seen: HashMap::new(),
            },
            sandbox_config: SandboxConfig::development(),
            started_at: Instant::now(),
        }));

        drop(_guard);

        let error = reject_replay(Arc::clone(&state), &request)
            .await
            .unwrap_err();
        assert!(error.contains("must not be a symlink"));
        assert_eq!(fs::read(&external_path).unwrap(), external_contents);
        assert!(!state.lock().await.nonce_store.seen.contains_key(&key));
        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_file(external_path);
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
            sandbox_config: SandboxConfig::development(),
            started_at: Instant::now(),
        }));

        drop(_guard);

        let error = reject_replay(Arc::clone(&state), &request)
            .await
            .unwrap_err();
        assert!(error.contains("failed to inspect nonce store parent component"));
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
        assert!(ack.compiled_artifact_hash.is_empty());
        assert!(state.lock().await.modules.is_empty());
        let _ = fs::remove_file(nonce_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deploy_request_returns_server_derived_compiled_artifact_hash() {
        let nonce_path = test_nonce_path("deploy-compiled-artifact-hash");
        let state = Arc::new(Mutex::new(test_state(nonce_path.clone())));
        let request = deploy_payload();
        let expected_module_hash = bytes_to_hex(&request.module_hash);
        let expected_artifact_hash = SandboxRuntime::default()
            .precompile_native(&request.module_bytes)
            .unwrap()
            .compiled_artifact_hash();

        let ack = deploy_request(Arc::clone(&state), "sandbox-1", request).await;

        assert_eq!(ack.instance_id, "sandbox-1");
        assert_eq!(ack.module_hash, expected_module_hash);
        assert_eq!(ack.compiled_artifact_hash, expected_artifact_hash);
        assert_ne!(ack.compiled_artifact_hash, ack.module_hash);
        assert_eq!(ack.status, "cached:policy-v1");
        let state = state.lock().await;
        assert_eq!(state.modules.len(), 1);
        assert_eq!(state.cache.stats().entries, 1);
        drop(state);
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
        let mut expected = concat!(
            r#"{"schema":"swarm.sandbox.tick.v1","tick":7,"player_id":"player-1","#,
            r#""room_id":"room-1","module_hash":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"#,
            r#""snapshot_json":"{}","fuel_budget":100,"collect_timeout_ms":250,"collect_deadline_ms":"#,
        )
        .to_string();
        expected.push_str(&payload.collect_deadline_ms.to_string());
        expected.push('}');
        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }

    #[test]
    fn absolute_collect_deadline_rejects_expired_work() {
        assert_eq!(
            remaining_collect_ms(current_time_ms().unwrap().saturating_sub(1)).unwrap_err(),
            "collect deadline exceeded"
        );
    }

    #[test]
    fn module_fetch_reply_requires_matching_hash_and_nonempty_policy() {
        let module_bytes = deploy_payload().module_bytes;
        let module_hash = *blake3::hash(&module_bytes).as_bytes();
        let valid = ModuleFetchReply {
            schema: MODULE_FETCH_SCHEMA.to_string(),
            module_hash,
            module_bytes: module_bytes.clone(),
            validation_policy_version: "policy-v1".to_string(),
        };
        let module = validate_module_fetch_reply(valid, module_hash).unwrap();
        assert_eq!(module.validation_policy_version, "policy-v1");

        let wrong_hash = ModuleFetchReply {
            schema: MODULE_FETCH_SCHEMA.to_string(),
            module_hash: [7; 32],
            module_bytes: module_bytes.clone(),
            validation_policy_version: "policy-v1".to_string(),
        };
        assert_eq!(
            validate_module_fetch_reply(wrong_hash, module_hash).unwrap_err(),
            "module fetch reply hash mismatch"
        );

        let empty_policy = ModuleFetchReply {
            schema: MODULE_FETCH_SCHEMA.to_string(),
            module_hash,
            module_bytes,
            validation_policy_version: " ".to_string(),
        };
        assert_eq!(
            validate_module_fetch_reply(empty_policy, module_hash).unwrap_err(),
            "module fetch reply validation policy is empty"
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
