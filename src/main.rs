//! cipd — clean-room EtherNet/IP + CSPv4 + DF1 transport daemon with a unified CIP/PCCC router.
//!
//! Usage: cipd [config.json]   (default: /etc/cipd/config.json)

mod api;
mod cip;
mod config;
mod csp;
mod df1;
mod enip;
mod error;
mod pccc;
mod router;

use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cipd=info".into()),
        )
        .init();

    let cfg_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/cipd/config.json"));

    let cfg = config::Config::load(&cfg_path)
        .map_err(|e| anyhow::anyhow!("loading {}: {e}", cfg_path.display()))?;

    tracing::info!(
        devices = cfg.devices.len(),
        socket = %cfg.api_socket,
        "starting cipd"
    );

    let router = Arc::new(router::Router::new(cfg.devices));
    let socket = cfg.api_socket.clone();

    tokio::select! {
        r = api::serve(router, &socket) => {
            if let Err(e) = r { tracing::error!("api server exited: {e}"); }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received");
        }
    }

    let _ = std::fs::remove_file(&socket);
    Ok(())
}
