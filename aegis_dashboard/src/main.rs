use axum::Router;
use tokio::sync::broadcast;
use dashmap::DashMap;
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

mod data;
mod udp;
mod handlers;
mod handlers_ws_compat;

/// Re-export ws handler for mod.rs
mod handlers_ws_compat {
    pub use crate::handlers::ws::ws_handler;
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    fmt().with_env_filter(EnvFilter::from_default_env().add_directive("aegis_dashboard=info".parse().unwrap())).init();

    tracing::info!("🛡️ AEGIS NIDS Dashboard starting...");

    // Create broadcast channel for WebSocket
    let (tx, _) = broadcast::channel::<String>(100);

    // Shared state (DashMap for concurrent access)
    let stats = Arc::new(DashMap::new());
    let proto_stats = Arc::new(DashMap::new());
    let defcon = Arc::new(DashMap::new());
    let alerts = Arc::new(DashMap::new());

    // Initialize default DEFCON
    defcon.insert("level".into(), 5u8);
    defcon.insert("severity".into(), 0u8);
    stats.insert("total_events".into(), 0u64);

    // Build app state
    let state = handlers::AppState {
        tx: tx.clone(),
        stats: stats.clone(),
        proto_stats: proto_stats.clone(),
        defcon: defcon.clone(),
        alerts: alerts.clone(),
    };

    // Build router
    let app = handlers::build_router(state);

    // Spawn UDP listener in background
    let udp_tx = tx.clone();
    let udp_stats = stats.clone();
    let udp_proto = proto_stats.clone();
    let udp_defcon = defcon.clone();
    let udp_alerts = alerts.clone();
    tokio::spawn(async move {
        udp::run_udp_listener(udp_tx, udp_stats, udp_proto, udp_defcon, udp_alerts).await;
    });

    // Start HTTP server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("🛡️ Dashboard listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
