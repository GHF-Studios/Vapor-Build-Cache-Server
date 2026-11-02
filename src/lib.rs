mod admin;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 128;
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const OPERATION_TTL: Duration = Duration::from_secs(15 * 60);
const TARGETS: [&str; 2] = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-gnullvm"];
const DEFAULT_ROOT: &str = "/var/lib/vapor-server/build-cache";

#[derive(Clone)]
pub struct BuildCacheConfig {
    pub root: PathBuf,
    client_version: Option<String>,
    vapor_lock_sha256: Option<String>,
    toolchain_lock_sha256: Option<String>,
    build_recipe_id: Option<String>,
    key_id: Option<String>,
    signing_public_key: Option<[u8; 32]>,
    builder_environment: HashMap<String, String>,
    orchestrator_token: Option<String>,
    max_archive_bytes: u64,
    admin_authorization: Option<admin::AuthorizationClient>,
}

impl BuildCacheConfig {
    pub fn from_env() -> Self {
        let mut builder_environment = HashMap::new();
        for (target, variable) in [
            (
                "x86_64-unknown-linux-gnu",
                "VAPOR_BUILD_CACHE_LINUX_ENVIRONMENT_DIGEST",
            ),
            (
                "x86_64-pc-windows-gnullvm",
                "VAPOR_BUILD_CACHE_WINDOWS_ENVIRONMENT_DIGEST",
            ),
        ] {
            if let Ok(value) = env::var(variable) {
                builder_environment.insert(target.to_owned(), value);
            }
        }
        let signing_public_key = env::var("VAPOR_BUILD_CACHE_SIGNING_PUBLIC_KEY")
            .ok()
            .and_then(|value| decode_hex::<32>(&value));
        let max_archive_bytes = env::var("VAPOR_BUILD_CACHE_MAX_ARCHIVE_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0 && *value <= MAX_ARCHIVE_BYTES)
            .unwrap_or(MAX_ARCHIVE_BYTES);
        Self {
            root: PathBuf::from(
                env::var("VAPOR_BUILD_CACHE_ROOT").unwrap_or_else(|_| DEFAULT_ROOT.to_owned()),
            ),
            client_version: env::var("VAPOR_BUILD_CACHE_CLIENT_VERSION").ok(),
            vapor_lock_sha256: env::var("VAPOR_BUILD_CACHE_VAPOR_LOCK_SHA256").ok(),
            toolchain_lock_sha256: env::var("VAPOR_BUILD_CACHE_TOOLCHAIN_LOCK_SHA256").ok(),
            build_recipe_id: env::var("VAPOR_BUILD_CACHE_RECIPE_ID").ok(),
            key_id: env::var("VAPOR_BUILD_CACHE_KEY_ID").ok(),
            signing_public_key,
            builder_environment,
            orchestrator_token: env::var("VAPOR_BUILD_CACHE_ORCHESTRATOR_TOKEN")
                .ok()
                .filter(|value| valid_service_token(value)),
            max_archive_bytes,
            admin_authorization: admin::AuthorizationClient::from_env(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: PathBuf,
        client_version: String,
        vapor_lock_sha256: String,
        toolchain_lock_sha256: String,
        build_recipe_id: String,
        key_id: String,
        signing_public_key: [u8; 32],
        builder_environment: HashMap<String, String>,
        orchestrator_token: String,
    ) -> Self {
        Self {
            root,
            client_version: Some(client_version),
            vapor_lock_sha256: Some(vapor_lock_sha256),
            toolchain_lock_sha256: Some(toolchain_lock_sha256),
            build_recipe_id: Some(build_recipe_id),
            key_id: Some(key_id),
            signing_public_key: Some(signing_public_key),
            builder_environment,
            orchestrator_token: Some(orchestrator_token),
            max_archive_bytes: MAX_ARCHIVE_BYTES,
            admin_authorization: admin::AuthorizationClient::from_env(),
        }
    }

    fn ready_for_target(&self, target: &str) -> bool {
        self.client_version.as_deref().is_some_and(valid_version)
            && self.vapor_lock_sha256.as_deref().is_some_and(valid_digest)
            && self
                .toolchain_lock_sha256
                .as_deref()
                .is_some_and(valid_digest)
            && self.build_recipe_id.as_deref().is_some_and(valid_segment)
            && self.key_id.as_deref().is_some_and(valid_segment)
            && self.signing_public_key.is_some()
            && self
                .builder_environment
                .get(target)
                .is_some_and(|value| valid_digest(value))
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<BuildCacheConfig>,
    tickets: Arc<Mutex<HashMap<String, OperationTicket>>>,
    promotions: Arc<HashMap<&'static str, Mutex<()>>>,
}

#[derive(Clone)]
struct OperationTicket {
    operation_id: String,
    target: String,
    expires_at: Instant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSnapshotManifest {
    pub schema_version: u32,
    pub key_id: String,
    pub vapor_version: String,
    pub vapor_lock_sha256: String,
    pub toolchain_lock_sha256: String,
    pub target_triple: String,
    pub build_recipe_id: String,
    pub builder_environment_digest: String,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub created_at_utc: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRequest {
    operation_id: String,
    target_triple: String,
    vapor_version: String,
    vapor_lock_sha256: String,
    toolchain_lock_sha256: String,
}

#[derive(Serialize)]
struct OperationResponse {
    credential: String,
    expires_in_seconds: u64,
}

pub fn router(config: BuildCacheConfig) -> Router {
    let admin_config = config.clone();
    let state = AppState {
        config: Arc::new(config),
        tickets: Arc::new(Mutex::new(HashMap::new())),
        promotions: Arc::new(HashMap::from([
            (TARGETS[0], Mutex::new(())),
            (TARGETS[1], Mutex::new(())),
        ])),
    };
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/status", get(status))
        .route(
            "/v1/targets/{target}/current/manifest.json",
            get(current_manifest),
        )
        .route(
            "/v1/targets/{target}/current/manifest.json.sig",
            get(current_signature),
        )
        .route(
            "/v1/targets/{target}/current/snapshot.tar.zst",
            get(current_archive),
        )
        .route("/v1/internal/operations", post(issue_operation))
        .route(
            "/v1/internal/targets/{target}/candidate",
            post(submit_candidate),
        )
        .with_state(state)
        .merge(admin::router(admin_config))
}

pub async fn app_router_from_env() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(router(BuildCacheConfig::from_env()))
}

pub fn standalone_admin_router_from_env() -> Router {
    let config = BuildCacheConfig::from_env();
    admin::router(config)
}

pub fn standalone_api_router_from_env() -> Router {
    let config = BuildCacheConfig::from_env();
    api_router(config)
}

fn api_router(config: BuildCacheConfig) -> Router {
    let state = AppState {
        config: Arc::new(config),
        tickets: Arc::new(Mutex::new(HashMap::new())),
        promotions: Arc::new(HashMap::from([
            (TARGETS[0], Mutex::new(())),
            (TARGETS[1], Mutex::new(())),
        ])),
    };
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/status", get(status))
        .route(
            "/v1/targets/{target}/current/manifest.json",
            get(current_manifest),
        )
        .route(
            "/v1/targets/{target}/current/manifest.json.sig",
            get(current_signature),
        )
        .route(
            "/v1/targets/{target}/current/snapshot.tar.zst",
            get(current_archive),
        )
        .route("/v1/internal/operations", post(issue_operation))
        .route(
            "/v1/internal/targets/{target}/candidate",
            post(submit_candidate),
        )
        .with_state(state)
}

pub struct BuildCacheRouters {
    pub api: Router,
    pub admin: Router,
}

pub fn routers_from_env() -> BuildCacheRouters {
    let config = BuildCacheConfig::from_env();
    BuildCacheRouters {
        api: api_router(config.clone()),
        admin: admin::router(config),
    }
}

async fn status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut targets = Vec::with_capacity(TARGETS.len());
    for target in TARGETS {
        let current = current_snapshot(&state.config, target).await.ok().flatten();
        targets.push(serde_json::json!({
            "target_triple": target,
            "configured": state.config.ready_for_target(target),
            "current": current.is_some(),
            "archive_sha256": current.as_ref().map(|snapshot| snapshot.manifest.archive_sha256.as_str()),
            "archive_size": current.as_ref().map(|snapshot| snapshot.manifest.archive_size),
            "vapor_version": current.as_ref().map(|snapshot| snapshot.manifest.vapor_version.as_str()),
        }));
    }
    Json(serde_json::json!({"targets": targets}))
}

async fn current_manifest(
    State(state): State<AppState>,
    Path(target): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_target(&target) {
        return not_found();
    }
    if !state.config.ready_for_target(&target) {
        return unavailable();
    }
    if !client_identity_matches(&state.config, &headers) {
        return upgrade_required();
    }
    let Some(snapshot) = current_snapshot(&state.config, &target)
        .await
        .ok()
        .flatten()
    else {
        return not_found();
    };
    private_bytes(StatusCode::OK, "application/json", snapshot.manifest_bytes)
}

async fn current_signature(
    State(state): State<AppState>,
    Path(target): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_target(&target) {
        return not_found();
    }
    if !state.config.ready_for_target(&target) {
        return unavailable();
    }
    if !client_identity_matches(&state.config, &headers) {
        return upgrade_required();
    }
    let Some(snapshot) = current_snapshot(&state.config, &target)
        .await
        .ok()
        .flatten()
    else {
        return not_found();
    };
    private_bytes(
        StatusCode::OK,
        "text/plain; charset=utf-8",
        snapshot.signature.into_bytes(),
    )
}

async fn current_archive(
    State(state): State<AppState>,
    Path(target): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_target(&target) {
        return not_found();
    }
    if !state.config.ready_for_target(&target) {
        return unavailable();
    }
    if !client_identity_matches(&state.config, &headers) {
        return upgrade_required();
    }
    let Some(snapshot) = current_snapshot(&state.config, &target)
        .await
        .ok()
        .flatten()
    else {
        return not_found();
    };
    let Ok(path) = existing_file_under_root(&state.config.root, &snapshot.archive_path).await
    else {
        return not_found();
    };
    let Ok(file) = fs::File::open(path).await else {
        return not_found();
    };
    let Ok(metadata) = file.metadata().await else {
        return not_found();
    };
    if metadata.len() != snapshot.manifest.archive_size {
        return unavailable();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zstd")
        .header(CONTENT_LENGTH, metadata.len().to_string())
        .header(CACHE_CONTROL, "no-store")
        .body(Body::from_stream(ReaderStream::new(BufReader::new(file))))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn issue_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Result<Json<OperationRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Some(expected_token) = state.config.orchestrator_token.as_deref() else {
        return unavailable();
    };
    if !bearer_matches(&headers, expected_token) {
        return unauthorized();
    }
    let Ok(Json(request)) = request else {
        return (StatusCode::BAD_REQUEST, "invalid operation request\n").into_response();
    };
    let target = request.target_triple.as_str();
    if !valid_operation_id(&request.operation_id)
        || !valid_target(target)
        || !state.config.ready_for_target(target)
        || state.config.client_version.as_deref() != Some(request.vapor_version.as_str())
        || state.config.vapor_lock_sha256.as_deref() != Some(request.vapor_lock_sha256.as_str())
        || state.config.toolchain_lock_sha256.as_deref()
            != Some(request.toolchain_lock_sha256.as_str())
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "operation does not match the current target lock\n",
        )
            .into_response();
    }
    let mut token_bytes = [0_u8; 32];
    if SystemRandom::new().fill(&mut token_bytes).is_err() {
        return unavailable();
    }
    let token = encode_hex(&token_bytes);
    let token_hash = digest_hex(token.as_bytes());
    let ticket = OperationTicket {
        operation_id: request.operation_id,
        target: request.target_triple,
        expires_at: Instant::now() + OPERATION_TTL,
    };
    let mut tickets = state.tickets.lock().await;
    tickets.retain(|_, existing| existing.expires_at > Instant::now());
    tickets.insert(token_hash, ticket);
    let mut response = (
        StatusCode::CREATED,
        Json(OperationResponse {
            credential: token,
            expires_in_seconds: OPERATION_TTL.as_secs(),
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn submit_candidate(
    State(state): State<AppState>,
    Path(target): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !valid_target(&target) || !state.config.ready_for_target(&target) {
        return not_found();
    }
    let Some(ticket_value) = headers
        .get("x-vapor-builder-ticket")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    else {
        return unauthorized();
    };
    let token_hash = digest_hex(ticket_value.as_bytes());
    let ticket = state.tickets.lock().await.remove(&token_hash);
    let Some(ticket) =
        ticket.filter(|ticket| ticket.expires_at > Instant::now() && ticket.target == target)
    else {
        return unauthorized();
    };
    let Some(manifest_b64) = headers
        .get("x-vapor-candidate-manifest")
        .and_then(|value| value.to_str().ok())
    else {
        return (StatusCode::BAD_REQUEST, "candidate manifest is required\n").into_response();
    };
    if manifest_b64.len() > MAX_MANIFEST_BYTES * 2 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "candidate manifest is too large\n",
        )
            .into_response();
    }
    let Ok(manifest_bytes) = base64::engine::general_purpose::STANDARD.decode(manifest_b64) else {
        return (
            StatusCode::BAD_REQUEST,
            "candidate manifest encoding is invalid\n",
        )
            .into_response();
    };
    let Some(signature_hex) = headers
        .get("x-vapor-candidate-signature")
        .and_then(|value| value.to_str().ok())
    else {
        return (StatusCode::BAD_REQUEST, "candidate signature is required\n").into_response();
    };
    let Some(signature_bytes) = decode_hex::<64>(signature_hex) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "candidate signature is invalid\n",
        )
            .into_response();
    };
    let Ok(manifest) = serde_json::from_slice::<BuildSnapshotManifest>(&manifest_bytes) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "candidate manifest is invalid\n",
        )
            .into_response();
    };
    if !manifest_matches(&state.config, &target, &manifest)
        || verify_signature(&state.config, &manifest_bytes, &signature_bytes).is_err()
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "candidate does not match the trusted snapshot identity\n",
        )
            .into_response();
    }
    if manifest.archive_size == 0 || manifest.archive_size > state.config.max_archive_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "candidate archive size is outside the permitted range\n",
        )
            .into_response();
    }
    let root = &state.config.root;
    if ensure_managed_directories(root).await.is_err() {
        return unavailable();
    }
    let stage = root.join("staging").join(&ticket.operation_id);
    if fs::create_dir(&stage).await.is_err() {
        return (
            StatusCode::CONFLICT,
            "operation staging area already exists\n",
        )
            .into_response();
    }
    let archive_path = stage.join("snapshot.tar.zst");
    let mut archive = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&archive_path)
        .await
    {
        Ok(file) => file,
        Err(_) => {
            let _ = fs::remove_dir_all(&stage).await;
            return unavailable();
        }
    };
    let mut stream = body.into_data_stream();
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = std::future::poll_fn(|context| {
        futures_core::Stream::poll_next(Pin::new(&mut stream), context)
    })
    .await
    {
        let Ok(chunk) = chunk else {
            let _ = fs::remove_dir_all(&stage).await;
            return (
                StatusCode::BAD_REQUEST,
                "candidate upload was interrupted\n",
            )
                .into_response();
        };
        size = size.saturating_add(chunk.len() as u64);
        if size > manifest.archive_size || size > state.config.max_archive_bytes {
            let _ = fs::remove_dir_all(&stage).await;
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "candidate archive exceeds its declared size\n",
            )
                .into_response();
        }
        digest.update(&chunk);
        if archive.write_all(&chunk).await.is_err() {
            let _ = fs::remove_dir_all(&stage).await;
            return unavailable();
        }
    }
    if archive.flush().await.is_err() || archive.sync_all().await.is_err() {
        let _ = fs::remove_dir_all(&stage).await;
        return unavailable();
    }
    drop(archive);
    let archive_digest = encode_hex(&digest.finalize());
    if size != manifest.archive_size || archive_digest != manifest.archive_sha256 {
        let _ = fs::remove_dir_all(&stage).await;
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "candidate archive size or digest does not match its manifest\n",
        )
            .into_response();
    }
    if fs::write(stage.join("manifest.json"), &manifest_bytes)
        .await
        .is_err()
        || fs::write(stage.join("manifest.json.sig"), signature_hex.as_bytes())
            .await
            .is_err()
    {
        let _ = fs::remove_dir_all(&stage).await;
        return unavailable();
    }
    let manifest_id = digest_hex(&manifest_bytes);
    let Some(promotion_lock) = state.promotions.get(target.as_str()) else {
        let _ = fs::remove_dir_all(&stage).await;
        return (StatusCode::NOT_FOUND, "unsupported target\n").into_response();
    };
    let _promotion_guard = promotion_lock.lock().await;
    let target_root = root.join("targets").join(&target);
    let snapshots = target_root.join("snapshots");
    if ensure_directory(target_root.clone()).await.is_err()
        || ensure_directory(snapshots.clone()).await.is_err()
    {
        let _ = fs::remove_dir_all(&stage).await;
        return unavailable();
    }
    let snapshot = snapshots.join(&manifest_id);
    if fs::try_exists(&snapshot).await.unwrap_or(true) {
        let _ = fs::remove_dir_all(&stage).await;
        return (StatusCode::CONFLICT, "candidate snapshot already exists\n").into_response();
    }
    if fs::rename(&stage, &snapshot).await.is_err() {
        let _ = fs::remove_dir_all(&stage).await;
        return unavailable();
    }
    let pointer = target_root.join("current");
    let pointer_tmp = target_root.join(format!(".current-{}", ticket.operation_id));
    if fs::write(&pointer_tmp, format!("{manifest_id}\n"))
        .await
        .is_err()
        || fs::rename(&pointer_tmp, &pointer).await.is_err()
    {
        let _ = fs::remove_file(&pointer_tmp).await;
        let _ = fs::remove_dir_all(&snapshot).await;
        return unavailable();
    }
    cleanup_unreferenced_snapshots(&snapshots, &manifest_id).await;
    let mut response = (StatusCode::CREATED, "candidate promoted\n").into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Clone)]
struct CurrentSnapshot {
    manifest: BuildSnapshotManifest,
    manifest_bytes: Vec<u8>,
    signature: String,
    archive_path: PathBuf,
}

async fn current_snapshot(
    config: &BuildCacheConfig,
    target: &str,
) -> std::io::Result<Option<CurrentSnapshot>> {
    let target_root = config.root.join("targets").join(target);
    let pointer = target_root.join("current");
    let pointer = match existing_file_under_root(&config.root, &pointer).await {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if fs::metadata(&pointer).await?.len() > 65 {
        return Ok(None);
    }
    let id = fs::read_to_string(pointer).await?;
    let id = id.trim();
    if !valid_digest(id) {
        return Ok(None);
    }
    let snapshot = target_root.join("snapshots").join(id);
    let manifest_path =
        match existing_file_under_root(&config.root, &snapshot.join("manifest.json")).await {
            Ok(path) => path,
            Err(_) => return Ok(None),
        };
    if fs::metadata(&manifest_path).await?.len() > MAX_MANIFEST_BYTES as u64 {
        return Ok(None);
    }
    let manifest_bytes = fs::read(&manifest_path).await?;
    if digest_hex(&manifest_bytes) != id {
        return Ok(None);
    }
    let Ok(manifest) = serde_json::from_slice::<BuildSnapshotManifest>(&manifest_bytes) else {
        return Ok(None);
    };
    if !manifest_matches(config, target, &manifest) {
        return Ok(None);
    }
    let signature_path =
        match existing_file_under_root(&config.root, &snapshot.join("manifest.json.sig")).await {
            Ok(path) => path,
            Err(_) => return Ok(None),
        };
    if fs::metadata(&signature_path).await?.len() != MAX_SIGNATURE_BYTES as u64 {
        return Ok(None);
    }
    let signature = fs::read_to_string(&signature_path).await?;
    let Some(signature_bytes) = decode_hex::<64>(&signature) else {
        return Ok(None);
    };
    if verify_signature(config, &manifest_bytes, &signature_bytes).is_err() {
        return Ok(None);
    }
    let archive_path =
        match existing_file_under_root(&config.root, &snapshot.join("snapshot.tar.zst")).await {
            Ok(path) => path,
            Err(_) => return Ok(None),
        };
    if fs::metadata(&archive_path).await?.len() != manifest.archive_size {
        return Ok(None);
    }
    Ok(Some(CurrentSnapshot {
        manifest,
        manifest_bytes,
        signature,
        archive_path,
    }))
}

fn manifest_matches(
    config: &BuildCacheConfig,
    target: &str,
    manifest: &BuildSnapshotManifest,
) -> bool {
    manifest.schema_version == 1
        && manifest.key_id == config.key_id.as_deref().unwrap_or_default()
        && manifest.vapor_version == config.client_version.as_deref().unwrap_or_default()
        && manifest.vapor_lock_sha256 == config.vapor_lock_sha256.as_deref().unwrap_or_default()
        && manifest.toolchain_lock_sha256
            == config.toolchain_lock_sha256.as_deref().unwrap_or_default()
        && manifest.target_triple == target
        && manifest.build_recipe_id == config.build_recipe_id.as_deref().unwrap_or_default()
        && config
            .builder_environment
            .get(target)
            .is_some_and(|value| value == &manifest.builder_environment_digest)
        && valid_digest(&manifest.archive_sha256)
        && manifest.archive_size > 0
        && manifest.archive_size <= config.max_archive_bytes
        && valid_utc_timestamp(&manifest.created_at_utc)
}

fn verify_signature(
    config: &BuildCacheConfig,
    manifest: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), ()> {
    let key = config.signing_public_key.as_ref().ok_or(())?;
    UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(manifest, signature_bytes)
        .map_err(|_| ())
}

fn client_identity_matches(config: &BuildCacheConfig, headers: &HeaderMap) -> bool {
    header_equals(
        headers,
        "x-vapor-client-version",
        config.client_version.as_deref(),
    ) && header_equals(
        headers,
        "x-vapor-lock-sha256",
        config.vapor_lock_sha256.as_deref(),
    ) && header_equals(
        headers,
        "x-vapor-toolchain-lock-sha256",
        config.toolchain_lock_sha256.as_deref(),
    )
}

fn header_equals(headers: &HeaderMap, name: &str, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    headers.get(name).and_then(|value| value.to_str().ok()) == Some(expected)
}

async fn ensure_managed_directories(root: &PathBuf) -> std::io::Result<()> {
    fs::create_dir_all(root).await?;
    ensure_real_directory(root).await?;
    for path in [root.join("staging"), root.join("targets")] {
        ensure_directory(path).await?;
    }
    Ok(())
}

async fn ensure_real_directory(path: &FsPath) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path).await?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed path is not a directory",
        ));
    }
    Ok(())
}

async fn ensure_directory(path: PathBuf) -> std::io::Result<()> {
    match fs::symlink_metadata(&path).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed path is not a directory",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::create_dir(&path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_real_directory(&path).await
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

async fn cleanup_unreferenced_snapshots(snapshots: &FsPath, current_id: &str) {
    let Ok(mut entries) = fs::read_dir(snapshots).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != current_id && entry.file_type().await.is_ok_and(|kind| kind.is_dir()) {
            let _ = fs::remove_dir_all(entry.path()).await;
        }
    }
}

async fn existing_file_under_root(root: &FsPath, path: &FsPath) -> std::io::Result<PathBuf> {
    let root = fs::canonicalize(root).await?;
    let canonical = fs::canonicalize(path).await?;
    if !canonical.starts_with(&root) || !fs::metadata(&canonical).await?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "managed file is outside the cache root",
        ));
    }
    Ok(canonical)
}

fn valid_target(value: &str) -> bool {
    TARGETS.contains(&value)
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn valid_version(value: &str) -> bool {
    valid_segment(value) && value.contains('.')
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_service_token(value: &str) -> bool {
    valid_digest(value)
}

fn valid_operation_id(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .iter()
            .all(|index| value.as_bytes()[*index] == b'-')
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn valid_utc_timestamp(value: &str) -> bool {
    let shape_is_valid = value.len() == 20
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
        && value.as_bytes().get(19) == Some(&b'Z')
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| [4, 7, 10, 13, 16, 19].contains(&index) || byte.is_ascii_digit());
    if !shape_is_valid {
        return false;
    }
    let Ok(year) = value[0..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u32>() else {
        return false;
    };
    let Ok(hour) = value[11..13].parse::<u32>() else {
        return false;
    };
    let Ok(minute) = value[14..16].parse::<u32>() else {
        return false;
    };
    let Ok(second) = value[17..19].parse::<u32>() else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut result = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(result)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn digest_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn private_bytes(status: StatusCode, content_type: &'static str, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "build snapshot service is not ready\n",
    )
        .into_response()
}
fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "builder authorization required\n").into_response()
}
fn upgrade_required() -> Response {
    (
        StatusCode::UPGRADE_REQUIRED,
        "Vapor client or lock identity is stale\n",
    )
        .into_response()
}
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "current build snapshot not found\n").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_utc_and_malformed_timestamps() {
        assert!(valid_utc_timestamp("2026-11-02T10:30:00Z"));
        assert!(!valid_utc_timestamp("2026-11-02T10:30:00+01:00"));
        assert!(!valid_utc_timestamp("2026-99-72T10:30:00Z"));
    }

    #[test]
    fn operation_ids_are_canonical_uuid_strings() {
        assert!(valid_operation_id("00000000-0000-4000-8000-000000000001"));
        assert!(!valid_operation_id("../../etc/passwd"));
        assert!(!valid_operation_id("00000000-0000-4000-8000-00000000000g"));
    }

    #[test]
    fn protocol_digests_and_signatures_require_canonical_lowercase_hex() {
        assert!(valid_digest(&"a".repeat(64)));
        assert!(!valid_digest(&"A".repeat(64)));
        assert!(decode_hex::<2>("00ff").is_some());
        assert!(decode_hex::<2>("00FF").is_none());
    }

    #[tokio::test]
    async fn rejects_symlinked_cache_root_and_managed_directories() {
        let base =
            env::temp_dir().join(format!("vapor-build-cache-symlink-{}", std::process::id()));
        #[cfg(unix)]
        let root = base.join("root");
        let target = base.join("target");
        let _ = fs::remove_dir_all(&base).await;
        fs::create_dir_all(&target).await.unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &root).unwrap();
            assert!(ensure_managed_directories(&root).await.is_err());
            fs::remove_file(&root).await.unwrap();
            fs::create_dir(&root).await.unwrap();
            std::os::unix::fs::symlink(&target, root.join("staging")).unwrap();
            assert!(ensure_managed_directories(&root).await.is_err());
        }
        let _ = fs::remove_dir_all(&base).await;
    }
}
