// ============================================================================
// AEGIS NIDS — Rust Dashboard (src/main.rs)
// ============================================================================

mod data;
mod handlers;
mod udp;

use axum::Router;
use dashmap::DashMap;
use data::*;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

/// Shared dashboard state
pub struct DashboardState {
    pub events: DashMap<String, ThreatEvent>,
    pub alerts: DashMap<String, Alert>,
    pub proto_stats: DashMap<String, ProtoStats>,
    pub src_ip_counts: DashMap<String, u32>,
    pub defcon_level: std::sync::atomic::AtomicU8,
    pub total_packets: std::sync::atomic::AtomicU64,
    pub total_threats: std::sync::atomic::AtomicU64,
    pub ws_clients: DashMap<String, tokio::sync::mpsc::Sender<String>>,
    pub start_time: std::time::Instant,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            events: DashMap::new(),
            alerts: DashMap::new(),
            proto_stats: DashMap::new(),
            src_ip_counts: DashMap::new(),
            defcon_level: std::sync::atomic::AtomicU8::new(5),
            total_packets: std::sync::atomic::AtomicU64::new(0),
            total_threats: std::sync::atomic::AtomicU64::new(0),
            ws_clients: DashMap::new(),
            start_time: std::time::Instant::now(),
        }
    }
}

/// WebSocket message types
pub mod ws {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", content = "data")]
    pub enum WsMessage {
        Threat(crate::data::ThreatEvent),
        Alert(crate::data::Alert),
        StatsUpdate(StatsSnapshot),
        DefconChange { level: u8 },
        PacketTick { total: u64, pps: u64 },
        Ping,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StatsSnapshot {
        pub total_packets: u64,
        pub total_threats: u64,
        pub defcon_level: u8,
        pub uptime_secs: u64,
        pub proto_stats: Vec<(String, crate::data::ProtoStats)>,
        pub top_sources: Vec<(String, u32)>,
    }
}

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("aegis_dashboard=info".parse().unwrap()),
        )
        .init();

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║   AEGIS NIDS — Rust Dashboard v0.1.0                 ║");
    info!("║   Real-time Threat Visualization                      ║");
    info!("╚══════════════════════════════════════════════════════╝");

    let state = Arc::new(DashboardState::new());

    // Spawn UDP listener
    let udp_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = udp::run_udp_listener(udp_state).await {
            warn!("UDP listener error: {}", e);
        }
    });

    // Spawn stats broadcaster
    let broadcast_state = state.clone();
    tokio::spawn(async move {
        handlers::ws::broadcast_stats_loop(broadcast_state).await;
    });

    let app = Router::new()
        .route("/", axum::routing::get(handlers::serve_dashboard))
        .route("/api/stats", axum::routing::get(handlers::api_stats))
        .route("/api/events", axum::routing::get(handlers::api_events))
        .route("/api/alerts", axum::routing::get(handlers::api_alerts))
        .route("/api/defcon", axum::routing::get(handlers::api_defcon))
        .route("/api/heatmap", axum::routing::get(handlers::api_heatmap))
        .route("/api/proto-dist", axum::routing::get(handlers::api_proto_dist))
        .route("/ws", axum::routing::get(handlers::ws::ws_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Dashboard listening on http://{}", addr);
    info!("WebSocket endpoint: ws://{}/ws", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
