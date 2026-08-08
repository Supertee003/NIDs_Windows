// ============================================================================
// AEGIS NIDS — WebSocket Handler (src/handlers/ws.rs)
// ============================================================================
// Uses tokio::select! instead of split() to avoid StreamExt import issues.

use crate::ws::WsMessage;
use crate::DashboardState;
use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};
use uuid::Uuid;

/// Handle WebSocket upgrade
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Process WebSocket connection using tokio::select!
async fn handle_socket(mut socket: WebSocket, state: Arc<DashboardState>) {
    let client_id = Uuid::new_v4().to_string();
    info!("WebSocket client connected: {}", client_id);

    // Channel for sending serialized JSON to this client
    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Register client
    state.ws_clients.insert(client_id.clone(), tx);

    // Main loop: receive from WS + send from channel concurrently
    loop {
        tokio::select! {
            // Receive from WebSocket client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Text(text))) => {
                        debug!("WS recv from {}: {}", client_id, text);
                    }
                    Some(Err(e)) => {
                        debug!("WS error from {}: {}", client_id, e);
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }
            // Send to WebSocket from channel
            json_msg = rx.recv() => {
                match json_msg {
                    Some(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // Cleanup
    state.ws_clients.remove(&client_id);
    info!("WebSocket client disconnected: {}", client_id);
}

/// Periodically broadcast stats to all WebSocket clients
pub async fn broadcast_stats_loop(state: Arc<DashboardState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        interval.tick().await;

        if state.ws_clients.is_empty() {
            continue;
        }

        let total_packets = state.total_packets.load(std::sync::atomic::Ordering::Relaxed);
        let total_threats = state.total_threats.load(std::sync::atomic::Ordering::Relaxed);
        let defcon = state.defcon_level.load(std::sync::atomic::Ordering::Relaxed);
        let uptime = state.start_time.elapsed().as_secs();

        let mut top_sources: Vec<(String, u32)> = state
            .src_ip_counts
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        top_sources.sort_by(|a, b| b.1.cmp(&a.1));
        top_sources.truncate(crate::data::MAX_TOP_SOURCES);

        let proto_stats: Vec<(String, crate::data::ProtoStats)> = state
            .proto_stats
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();

        let snapshot = crate::ws::StatsSnapshot {
            total_packets,
            total_threats,
            defcon_level: defcon,
            uptime_secs: uptime,
            proto_stats,
            top_sources,
        };

        let msg = WsMessage::StatsUpdate(snapshot);
        let msg_json = match serde_json::to_string(&msg) {
            Ok(j) => j,
            Err(_) => continue,
        };

        // Broadcast to all clients, remove dead ones
        let mut dead = Vec::new();
        for entry in state.ws_clients.iter() {
            if entry.value().try_send(msg_json.clone()).is_err() {
                dead.push(entry.key().clone());
            }
        }
        for id in dead {
            state.ws_clients.remove(&id);
        }
    }
}
