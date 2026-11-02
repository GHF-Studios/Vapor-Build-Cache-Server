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
        let snapshot = super::current_snapshot(&config, target)
            .await
            .ok()
            .flatten();
        let configured = config.ready_for_target(target);
        let state = if !configured {
            "Unavailable: target lock/signing config missing"
        } else if snapshot.is_some() {
            "Current"
        } else {
            "No current snapshot"
        };
        let version = snapshot
            .as_ref()
            .map(|item| item.manifest.vapor_version.as_str())
            .unwrap_or("—");
        let digest = snapshot
            .as_ref()
            .map(|item| item.manifest.archive_sha256.as_str())
            .unwrap_or("—");
        let size = snapshot
            .as_ref()
            .map(|item| item.manifest.archive_size.to_string())
            .unwrap_or_else(|| "—".to_owned());
        let promotion = snapshot
            .as_ref()
            .map(|item| item.promotion.operation_id.as_str())
            .unwrap_or("—");
        let promoted_at = snapshot
            .as_ref()
            .map(|item| item.promotion.promoted_at_unix.to_string())
            .unwrap_or_else(|| "—".to_owned());
        let vapor_lock = config.vapor_lock_sha256.as_deref().unwrap_or("—");
        let toolchain_lock = config.toolchain_lock_sha256.as_deref().unwrap_or("—");
        rows.push_str(&format!("<tr><td><code>{}</code></td><td>{state}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{size}</td><td><code>{}</code></td><td>{promoted_at}</td></tr>", escape_html(target), escape_html(version), escape_html(vapor_lock), escape_html(toolchain_lock), escape_html(digest), escape_html(promotion)));
    }
    let html = format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Build Cache · Vapor Admin</title><link rel=\"stylesheet\" href=\"/admin/assets/admin.css\"><script defer src=\"/admin/assets/admin.js\"></script></head><body><main id=\"admin-content\"><p class=\"eyebrow\">Build Cache · Snapshot service</p><h1>Target snapshots</h1><p class=\"muted\">Read-only current snapshot state. Promotion is controlled by the VPS builder flow.</p><div class=\"card\"><table><thead><tr><th>Rust target</th><th>State</th><th>Vapor version</th><th>Vapor.lock SHA-256</th><th>Toolchain lock SHA-256</th><th>Archive SHA-256</th><th>Bytes</th><th>Last promotion</th><th>Promoted (Unix)</th></tr></thead><tbody>{rows}</tbody></table><p class=\"muted\">Only the exact current client and lock state is accepted. Snapshot bytes are compiler output only.</p></div></main></body></html>");
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
        HeaderValue::from_static("text/html; charset=utf-8"),
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
    use serde_json::json;
    use std::collections::HashMap;
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
        let html = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        assert!(html.contains("x86_64-unknown-linux-gnu"));
        assert!(html.contains("x86_64-pc-windows-gnullvm"));
        assert!(html.contains(&vapor_lock));
        assert!(html.contains(&toolchain_lock));
        assert!(html.contains("Last promotion"));
        assert!(html.contains("Promoted (Unix)"));
        auth_server.abort();
    }
}
