use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use vapor_build_cache_server::{router, BuildCacheConfig, BuildSnapshotManifest};

const ORCHESTRATOR_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn test_config() -> BuildCacheConfig {
    let root = unique_root();
    let signing_key = Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).unwrap();
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(signing_key.public_key().as_ref());
    BuildCacheConfig::new(
        root,
        "0.5.0".to_owned(),
        "a".repeat(64),
        "b".repeat(64),
        "vapor-dev-v1".to_owned(),
        "test-build-cache-key".to_owned(),
        public_key,
        HashMap::from([
            ("x86_64-unknown-linux-gnu".to_owned(), "c".repeat(64)),
            ("x86_64-pc-windows-gnullvm".to_owned(), "d".repeat(64)),
        ]),
        ORCHESTRATOR_TOKEN.to_owned(),
    )
}

fn unique_root() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "vapor-build-cache-test-{}-{stamp}",
        std::process::id()
    ))
}

#[tokio::test]
async fn current_snapshot_is_not_found_when_absent() {
    let config = test_config();
    let root = config.root.clone();
    let response = router(config)
        .oneshot(
            Request::get("/v1/targets/x86_64-unknown-linux-gnu/current/manifest.json")
                .header("x-vapor-client-version", "0.5.0")
                .header("x-vapor-lock-sha256", "a".repeat(64))
                .header("x-vapor-toolchain-lock-sha256", "b".repeat(64))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    tokio::fs::remove_dir_all(root).await.ok();
}

#[tokio::test]
async fn missing_version_headers_are_rejected() {
    let config = test_config();
    let root = config.root.clone();
    let response = router(config)
        .oneshot(
            Request::get("/v1/targets/x86_64-unknown-linux-gnu/current/manifest.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    tokio::fs::remove_dir_all(root).await.ok();
}

#[tokio::test]
async fn unsupported_target_is_not_found() {
    let config = test_config();
    let root = config.root.clone();
    let response = router(config)
        .oneshot(
            Request::get("/v1/targets/../../etc/current/manifest.json")
                .header("x-vapor-client-version", "0.5.0")
                .header("x-vapor-lock-sha256", "a".repeat(64))
                .header("x-vapor-toolchain-lock-sha256", "b".repeat(64))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    tokio::fs::remove_dir_all(root).await.ok();
}

#[tokio::test]
async fn admin_route_requires_identity_root_authorization() {
    let config = test_config();
    let root = config.root.clone();
    let response = router(config)
        .oneshot(
            Request::get("/admin/build-cache")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    tokio::fs::remove_dir_all(root).await.ok();
}

#[tokio::test]
async fn operation_issue_rejects_missing_or_wrong_orchestrator_credential() {
    let config = test_config();
    let root = config.root.clone();
    let response = router(config)
        .oneshot(
            Request::post("/v1/internal/operations")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "operation_id": "00000000-0000-4000-8000-000000000001",
                        "target_triple": "x86_64-unknown-linux-gnu",
                        "vapor_version": "0.5.0",
                        "vapor_lock_sha256": "a".repeat(64),
                        "toolchain_lock_sha256": "b".repeat(64)
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    tokio::fs::remove_dir_all(root).await.ok();
}

#[tokio::test]
async fn signed_candidate_promotes_and_serves_matching_snapshot() {
    let config = test_config();
    let root = config.root.clone();
    let app = router(config.clone());
    let operation = "00000000-0000-4000-8000-000000000001";
    let request = json!({
        "operation_id": operation,
        "target_triple": "x86_64-unknown-linux-gnu",
        "vapor_version": "0.5.0",
        "vapor_lock_sha256": "a".repeat(64),
        "toolchain_lock_sha256": "b".repeat(64)
    });
    let ticket_response = app
        .clone()
        .oneshot(
            Request::post("/v1/internal/operations")
                .header("authorization", format!("Bearer {ORCHESTRATOR_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ticket_response.status(), StatusCode::CREATED);
    let ticket_body = to_bytes(ticket_response.into_body(), 4096).await.unwrap();
    let ticket_json: Value = serde_json::from_slice(&ticket_body).unwrap();
    let ticket = ticket_json["credential"].as_str().unwrap();

    let archive = b"compressed target snapshot";
    let manifest = BuildSnapshotManifest {
        schema_version: 1,
        key_id: "test-build-cache-key".to_owned(),
        vapor_version: "0.5.0".to_owned(),
        vapor_lock_sha256: "a".repeat(64),
        toolchain_lock_sha256: "b".repeat(64),
        target_triple: "x86_64-unknown-linux-gnu".to_owned(),
        build_recipe_id: "vapor-dev-v1".to_owned(),
        builder_environment_digest: "c".repeat(64),
        archive_sha256: format!("{:x}", Sha256::digest(archive)),
        archive_size: archive.len() as u64,
        created_at_utc: "2026-11-02T10:30:00Z".to_owned(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let seed = [0x42; 32];
    let signing_key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let signature = signing_key.sign(&manifest_bytes);
    let signature_hex = signature
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let candidate_response = app
        .clone()
        .oneshot(
            Request::post("/v1/internal/targets/x86_64-unknown-linux-gnu/candidate")
                .header("x-vapor-builder-ticket", ticket)
                .header(
                    "x-vapor-candidate-manifest",
                    base64::engine::general_purpose::STANDARD.encode(manifest_bytes),
                )
                .header("x-vapor-candidate-signature", signature_hex)
                .body(Body::from(archive.as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(candidate_response.status(), StatusCode::CREATED);
    let current_pointer: Value = serde_json::from_slice(
        &tokio::fs::read(root.join("targets/x86_64-unknown-linux-gnu/current"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(current_pointer["schema_version"], 1);
    assert_eq!(current_pointer["operation_id"], operation);
    assert!(current_pointer["promoted_at_unix"].as_u64().unwrap() > 0);

    let manifest_response = app
        .clone()
        .oneshot(
            Request::get("/v1/targets/x86_64-unknown-linux-gnu/current/manifest.json")
                .header("x-vapor-client-version", "0.5.0")
                .header("x-vapor-lock-sha256", "a".repeat(64))
                .header("x-vapor-toolchain-lock-sha256", "b".repeat(64))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(manifest_response.status(), StatusCode::OK);
    assert_eq!(manifest_response.headers()["cache-control"], "no-store");

    let archive_response = app
        .oneshot(
            Request::get("/v1/targets/x86_64-unknown-linux-gnu/current/snapshot.tar.zst")
                .header("x-vapor-client-version", "0.5.0")
                .header("x-vapor-lock-sha256", "a".repeat(64))
                .header("x-vapor-toolchain-lock-sha256", "b".repeat(64))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(archive_response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(archive_response.into_body(), 4096).await.unwrap(),
        archive.as_slice()
    );
    tokio::fs::remove_dir_all(root).await.ok();
}

#[tokio::test]
async fn signed_candidate_rejects_mismatch_without_replacing_current() {
    let config = test_config();
    let root = config.root.clone();
    let current = config.root.join("targets/x86_64-unknown-linux-gnu/current");
    tokio::fs::create_dir_all(current.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&current, "old-snapshot\n").await.unwrap();
    let app = router(config.clone());
    let request = json!({
        "operation_id": "00000000-0000-4000-8000-000000000002",
        "target_triple": "x86_64-unknown-linux-gnu",
        "vapor_version": "0.5.0",
        "vapor_lock_sha256": "a".repeat(64),
        "toolchain_lock_sha256": "b".repeat(64)
    });
    let ticket_response = app
        .clone()
        .oneshot(
            Request::post("/v1/internal/operations")
                .header("authorization", format!("Bearer {ORCHESTRATOR_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let ticket_body = to_bytes(ticket_response.into_body(), 4096).await.unwrap();
    let ticket = serde_json::from_slice::<Value>(&ticket_body).unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_owned();
    let archive = b"candidate archive";
    let mut manifest = BuildSnapshotManifest {
        schema_version: 1,
        key_id: "test-build-cache-key".to_owned(),
        vapor_version: "0.5.0".to_owned(),
        vapor_lock_sha256: "a".repeat(64),
        toolchain_lock_sha256: "b".repeat(64),
        target_triple: "x86_64-unknown-linux-gnu".to_owned(),
        build_recipe_id: "vapor-dev-v1".to_owned(),
        builder_environment_digest: "c".repeat(64),
        archive_sha256: format!("{:x}", Sha256::digest(archive)),
        archive_size: archive.len() as u64,
        created_at_utc: "2026-11-02T10:30:00Z".to_owned(),
    };
    manifest.vapor_lock_sha256 = "d".repeat(64);
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let signing_key = Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).unwrap();
    let signature_hex = signing_key
        .sign(&manifest_bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let response = app
        .oneshot(
            Request::post("/v1/internal/targets/x86_64-unknown-linux-gnu/candidate")
                .header("x-vapor-builder-ticket", ticket)
                .header(
                    "x-vapor-candidate-manifest",
                    base64::engine::general_purpose::STANDARD.encode(manifest_bytes),
                )
                .header("x-vapor-candidate-signature", signature_hex)
                .body(Body::from(archive.as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        tokio::fs::read_to_string(&current).await.unwrap(),
        "old-snapshot\n"
    );
    tokio::fs::remove_dir_all(root).await.ok();
}
