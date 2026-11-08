use super::BuildCacheConfig;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_IDENTITY_AUTHZ_URL: &str =
    "http://127.0.0.1:7110/api/identity/v1/internal/authorization/check";

#[derive(Clone)]
pub(super) struct AuthorizationClient {
    endpoint: reqwest::Url,
    token: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct AuthorizationRequest<'a> {
    audience: &'static str,
    session_token: &'a str,
    policy: Policy,
}

#[derive(Serialize)]
struct Policy {
    mode: &'static str,
    requirements: [Requirement; 1],
}

#[derive(Serialize)]
struct Requirement {
    kind: &'static str,
    role: &'static str,
}

#[derive(Deserialize)]
struct Decision {
    allowed: bool,
    expires_at_unix: i64,
}

impl AuthorizationClient {
    pub(super) fn from_env() -> Option<Self> {
        let endpoint = std::env::var("VAPOR_BUILD_CACHE_IDENTITY_AUTHZ_URL")
            .unwrap_or_else(|_| DEFAULT_IDENTITY_AUTHZ_URL.to_owned());
        let endpoint = reqwest::Url::parse(&endpoint).ok()?;
        let token = std::env::var("VAPOR_BUILD_CACHE_IDENTITY_AUTHZ_TOKEN")
            .ok()
            .filter(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })?;
        if endpoint.scheme() != "http"
            || !endpoint
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback())
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return None;
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Self {
            endpoint,
            token,
            http,
        })
    }

    async fn allows_root(&self, session: &str) -> Result<bool, ()> {
        let request = AuthorizationRequest {
            audience: "vapor-build-cache-admin",
            session_token: session,
            policy: Policy {
                mode: "all",
                requirements: [Requirement {
                    kind: "role",
                    role: "root",
                }],
            },
        };
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(&self.token)
            .json(&request)
            .send()
            .await
            .map_err(|_| ())?;
        if response.status() != StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > 4096)
        {
            return Err(());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if bytes.len().saturating_add(chunk.len()) > 4096 {
                return Err(());
            }
            bytes.extend_from_slice(&chunk);
        }
        let decision: Decision = serde_json::from_slice(&bytes).map_err(|_| ())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs() as i64;
        Ok(decision.allowed && decision.expires_at_unix > now)
    }
}

pub(super) fn router(config: BuildCacheConfig) -> Router {
    Router::new()
        .route("/admin/build-cache", get(page))
        .with_state(config)
}

async fn page(State(config): State<BuildCacheConfig>, headers: HeaderMap) -> Response {
    let Some(session) = session_token(&headers) else {
        return private_response(
            StatusCode::UNAUTHORIZED,
            "Sign in to view Build Cache. <a href=\"/login\">Sign in</a>",
        );
    };
    let Some(auth) = config.admin_authorization.as_ref() else {
        return private_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Build Cache authorization is temporarily unavailable.",
        );
    };
    match auth.allows_root(&session).await {
        Ok(true) => {}
        Ok(false) => return private_response(StatusCode::FORBIDDEN, "Root access is required."),
        Err(()) => {
            return private_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Build Cache authorization is temporarily unavailable.",
            )
        }
    }
    let mut rows = String::new();
    for target in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-gnullvm"] {
        let configured = config.ready_for_target(target);
        let (state, version, digest, size, promotion, promoted_at) = if !configured {
            (
                "Unavailable: target lock/signing config missing",
                "—".to_owned(),
                "—".to_owned(),
                "—".to_owned(),
                "—".to_owned(),
                "—".to_owned(),
            )
        } else {
            match super::current_snapshot_state(&config, target)
                .await
                .ok()
                .flatten()
            {
                Some(super::CurrentSnapshotState::Current(snapshot)) => (
                    "Current",
                    snapshot.manifest.vapor_version,
                    snapshot.manifest.archive_sha256,
                    snapshot.manifest.archive_size.to_string(),
                    snapshot.promotion.operation_id,
                    snapshot.promotion.promoted_at_unix.to_string(),
                ),
                Some(super::CurrentSnapshotState::Stale {
                    manifest,
                    promotion,
                }) => (
                    "Stale (snapshot identity differs from current configuration)",
                    manifest.vapor_version,
                    manifest.archive_sha256,
                    manifest.archive_size.to_string(),
                    promotion.operation_id,
                    promotion.promoted_at_unix.to_string(),
                ),
                None => (
                    "No current snapshot",
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                ),
            }
        };
        let vapor_lock = config.vapor_lock_sha256.as_deref().unwrap_or("—");
        let toolchain_lock = config.toolchain_lock_sha256.as_deref().unwrap_or("—");
        rows.push_str(&format!("<tr><td><code>{}</code></td><td>{state}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>", escape_html(target), escape_html(&version), escape_html(vapor_lock), escape_html(toolchain_lock), escape_html(&digest), escape_html(&size), escape_html(&promotion), escape_html(&promoted_at)));
    }
    let html = format!("<p class=\"eyebrow\">Build Cache · Target snapshots</p><h1>Target snapshots</h1><p class=\"muted\">This service stores signed Cargo target snapshots for developer-workspace restore. It validates and promotes candidates; it does not run builds or provide a shared compiler cache. Native builder job orchestration is not implemented.</p><div class=\"card\"><div class=\"table-scroll\" role=\"region\" tabindex=\"0\" aria-label=\"Target snapshot table\"><table><thead><tr><th>Rust target</th><th>State</th><th>Vapor version</th><th>Vapor.lock SHA-256</th><th>Toolchain lock SHA-256</th><th>Archive SHA-256</th><th>Bytes</th><th>Last promotion</th><th>Promoted (Unix)</th></tr></thead><tbody>{rows}</tbody></table></div><p class=\"muted\">Only the exact current client and lock state is accepted. These archives are Cargo target-directory snapshots, not application releases or reusable per-compile cache entries.</p></div>");
    private_response(StatusCode::OK, &html)
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            (name == "vapor_identity_session"
                && (32..=256).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
            .then(|| value.to_owned())
        })
}

fn private_response(status: StatusCode, body: &str) -> Response {
    let mut response = (status, body.to_owned()).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.vapor.admin-page.v1+html; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::{router as admin_router, AuthorizationClient};
    use crate::BuildCacheConfig;
    use axum::routing::post;
    use axum::{Json, Router};
    use ring::signature::KeyPair;
    use serde_json::json;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    #[tokio::test]
    async fn build_cache_admin_shows_target_locks_and_latest_promotion_columns() {
        let auth_app = Router::new().route(
            "/",
            post(|| async {
                Json(json!({
                    "allowed": true,
                    "expires_at_unix": i64::MAX
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let auth_server = tokio::spawn(async move {
            axum::serve(listener, auth_app).await.unwrap();
        });

        let vapor_lock = "a".repeat(64);
        let toolchain_lock = "b".repeat(64);
        let mut config = BuildCacheConfig::new(
            std::env::temp_dir().join(format!("vapor-admin-test-{}", std::process::id())),
            "0.5.0".to_owned(),
            vapor_lock.clone(),
            toolchain_lock.clone(),
            "test-recipe".to_owned(),
            "test-key".to_owned(),
            [1_u8; 32],
            HashMap::from([
                ("x86_64-unknown-linux-gnu".to_owned(), "c".repeat(64)),
                ("x86_64-pc-windows-gnullvm".to_owned(), "d".repeat(64)),
            ]),
            "e".repeat(64),
        );
        config.admin_authorization = Some(AuthorizationClient {
            endpoint: reqwest::Url::parse(&endpoint).unwrap(),
            token: "f".repeat(64),
            http: reqwest::Client::new(),
        });

        let app = admin_router(config);
        let response = app
            .oneshot(
                axum::http::Request::get("/admin/build-cache")
                    .header(
                        "cookie",
                        "vapor_identity_session=abcdefghijklmnopqrstuvwxyz123456",
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        assert_eq!(
            response.headers()["content-type"],
            "application/vnd.vapor.admin-page.v1+html; charset=utf-8"
        );
        let html = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        assert!(!html.contains("<!doctype html>"));
        assert!(!html.contains("<body>"));
        assert!(html.starts_with("<p class=\"eyebrow\">Build Cache"));
        assert!(html.contains("x86_64-unknown-linux-gnu"));
        assert!(html.contains("x86_64-pc-windows-gnullvm"));
        assert!(html.contains(&vapor_lock));
        assert!(html.contains(&toolchain_lock));
        assert!(html.contains("Last promotion"));
        assert!(html.contains("Promoted (Unix)"));
        assert!(html.contains("aria-label=\"Target snapshot table\""));
        auth_server.abort();
    }

    #[tokio::test]
    async fn build_cache_admin_marks_snapshot_stale_when_vapor_lock_changes() {
        let auth_app = Router::new().route(
            "/",
            post(|| async {
                Json(json!({
                    "allowed": true,
                    "expires_at_unix": i64::MAX
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let auth_server = tokio::spawn(async move {
            axum::serve(listener, auth_app).await.unwrap();
        });

        let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).unwrap();
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(key.public_key().as_ref());
        let old_vapor_lock = "a".repeat(64);
        let toolchain_lock = "b".repeat(64);
        let root = std::env::temp_dir().join(format!(
            "vapor-stale-admin-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = BuildCacheConfig::new(
            root.clone(),
            "0.5.0".to_owned(),
            "c".repeat(64),
            toolchain_lock,
            "test-recipe".to_owned(),
            "test-key".to_owned(),
            public_key,
            HashMap::from([
                ("x86_64-unknown-linux-gnu".to_owned(), "d".repeat(64)),
                ("x86_64-pc-windows-gnullvm".to_owned(), "e".repeat(64)),
            ]),
            "f".repeat(64),
        );
        let archive = b"signed compiler snapshot";
        let manifest = crate::BuildSnapshotManifest {
            schema_version: 1,
            key_id: "test-key".to_owned(),
            vapor_version: "0.5.0".to_owned(),
            vapor_lock_sha256: old_vapor_lock.clone(),
            toolchain_lock_sha256: "b".repeat(64),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            build_recipe_id: "test-recipe".to_owned(),
            builder_environment_digest: "d".repeat(64),
            archive_sha256: crate::digest_hex(archive),
            archive_size: archive.len() as u64,
            created_at_utc: "2026-11-07T00:00:00Z".to_owned(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_id = crate::digest_hex(&manifest_bytes);
        let signature = crate::encode_hex(key.sign(&manifest_bytes).as_ref());
        let snapshot_dir = root
            .join("targets/x86_64-unknown-linux-gnu/snapshots")
            .join(&manifest_id);
        tokio::fs::create_dir_all(&snapshot_dir).await.unwrap();
        tokio::fs::write(snapshot_dir.join("manifest.json"), &manifest_bytes)
            .await
            .unwrap();
        tokio::fs::write(snapshot_dir.join("manifest.json.sig"), signature)
            .await
            .unwrap();
        tokio::fs::write(snapshot_dir.join("snapshot.tar.zst"), archive)
            .await
            .unwrap();
        let pointer = crate::CurrentPointer {
            schema_version: 1,
            manifest_id,
            operation_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            promoted_at_unix: 1_762_478_400,
        };
        tokio::fs::write(
            root.join("targets/x86_64-unknown-linux-gnu/current"),
            serde_json::to_vec(&pointer).unwrap(),
        )
        .await
        .unwrap();
        config.admin_authorization = Some(AuthorizationClient {
            endpoint: reqwest::Url::parse(&endpoint).unwrap(),
            token: "f".repeat(64),
            http: reqwest::Client::new(),
        });
        let client_config = config.clone();

        let response = admin_router(config)
            .oneshot(
                axum::http::Request::get("/admin/build-cache")
                    .header(
                        "cookie",
                        "vapor_identity_session=abcdefghijklmnopqrstuvwxyz123456",
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let html = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        assert!(html.contains("Stale (snapshot identity differs from current configuration)"));
        assert!(!html.contains("<td>Current</td>"));
        let response = crate::api_router(client_config.clone())
            .oneshot(
                axum::http::Request::get(
                    "/v1/targets/x86_64-unknown-linux-gnu/current/manifest.json",
                )
                .header("x-vapor-client-version", "0.5.0")
                .header("x-vapor-lock-sha256", "c".repeat(64))
                .header("x-vapor-toolchain-lock-sha256", "b".repeat(64))
                .body(axum::body::Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);

        let mut matching_config = client_config.clone();
        matching_config.vapor_lock_sha256 = Some(old_vapor_lock);
        let response = admin_router(matching_config)
            .oneshot(
                axum::http::Request::get("/admin/build-cache")
                    .header(
                        "cookie",
                        "vapor_identity_session=abcdefghijklmnopqrstuvwxyz123456",
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert!(String::from_utf8(html.to_vec())
            .unwrap()
            .contains("<td>Current</td>"));
        auth_server.abort();
        tokio::fs::remove_dir_all(root).await.ok();
    }

    #[tokio::test]
    async fn build_cache_admin_exposes_no_browser_mutation_route() {
        let config = BuildCacheConfig::new(
            std::env::temp_dir().join(format!("vapor-admin-method-test-{}", std::process::id())),
            "0.5.0".to_owned(),
            "a".repeat(64),
            "b".repeat(64),
            "test-recipe".to_owned(),
            "test-key".to_owned(),
            [1_u8; 32],
            HashMap::from([
                ("x86_64-unknown-linux-gnu".to_owned(), "c".repeat(64)),
                ("x86_64-pc-windows-gnullvm".to_owned(), "d".repeat(64)),
            ]),
            "e".repeat(64),
        );
        let response = admin_router(config)
            .oneshot(
                axum::http::Request::post("/admin/build-cache")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[tokio::test]
    async fn build_cache_auth_errors_use_the_shared_page_fragment_contract() {
        let config = BuildCacheConfig::new(
            std::env::temp_dir().join(format!("vapor-admin-unauth-test-{}", std::process::id())),
            "0.5.0".to_owned(),
            "a".repeat(64),
            "b".repeat(64),
            "test-recipe".to_owned(),
            "test-key".to_owned(),
            [1_u8; 32],
            HashMap::from([
                ("x86_64-unknown-linux-gnu".to_owned(), "c".repeat(64)),
                ("x86_64-pc-windows-gnullvm".to_owned(), "d".repeat(64)),
            ]),
            "e".repeat(64),
        );
        let response = admin_router(config)
            .oneshot(
                axum::http::Request::get("/admin/build-cache")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()["content-type"],
            "application/vnd.vapor.admin-page.v1+html; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.starts_with("Sign in to view Build Cache."));
        assert!(!body.contains("<html"));
    }
}
