use std::env;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("VAPOR_BUILD_CACHE_BIND").unwrap_or_else(|_| "127.0.0.1:7117".to_owned());
    let app = vapor_build_cache_server::app_router_from_env().await?;
    let listener = TcpListener::bind(&bind).await?;
    eprintln!("vapor-build-cache-server listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
