// ============================================================================
// AEGIS NIDS — UDP Listener (src/udp.rs)
// ============================================================================
// Receives threat events and stats from AEGIS Zig Core via UDP.
// The Zig Core sends msgpack-encoded data on port 9999 (configurable).

use crate::data::*;
use crate::DashboardState;
use chrono::Utc;
use std::net::UdpSocket;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Default UDP port for receiving data from AEGIS Core
const AEGIS_UDP_PORT: u16 = 9999;
const UDP_BUFFER_SIZE: usize = 65536;

/// Run the UDP listener loop. Blocks the current task.
pub async fn run_udp_listener(
    state: Arc<DashboardState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", AEGIS_UDP_PORT);
    let socket = UdpSocket::bind(&addr)?;
    socket.set_nonblocking(true)?;
    info!("UDP listener bound on {} — waiting for AEGIS Core data", addr);

    let mut buf = [0u8; UDP_BUFFER_SIZE];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                debug!("UDP recv {} bytes from {}", len, src);
                if let Ok(msg_str) = std::str::from_utf8(&buf[..len]) {
                    process_message(msg_str, &state);
                } else {
                    debug!(
                        "Non-UTF8 UDP payload ({} bytes), skipping msgpack decode",
                        len
                    );
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            Err(e) => {
                warn!("UDP recv error: {}", e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Process a decoded UDP message string and update dashboard state
fn process_message(msg_str: &str, state: &Arc<DashboardState>) {
    match serde_json::from_str::<AegisUdpMessage>(msg_str) {
        Ok(msg) => match msg {
            AegisUdpMessage::Threat {
                severity,
                category,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                rule_id,
                msg,
            } => {
                let event = ThreatEvent {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    severity: AegisUdpMessage::parse_severity(&severity),
                    category: category.clone(),
                    source_ip: src_ip.clone(),
                    dest_ip: dst_ip,
                    source_port: src_port,
                    dest_port: dst_port,
                    protocol: proto,
                    rule_id,
                    message: msg,
                    raw_payload: None,
                };

                state
                    .total_threats
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                state
                    .total_packets
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                state
                    .src_ip_counts
                    .entry(src_ip.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);

                state
                    .proto_stats
                    .entry(category.clone())
                    .and_modify(|s| {
                        s.packets += 1;
                        s.threats += 1;
                    })
                    .or_insert(ProtoStats {
                        packets: 1,
                        bytes: 0,
                        threats: 1,
                        avg_latency_us: 0.0,
                    });

                if state.events.len() >= MAX_EVENTS {
                    if let Some(k) = state.events.iter().next().map(|r| r.key().clone()) {
                        state.events.remove(&k);
                    }
                }
                state.events.insert(event.id.clone(), event.clone());

                // Serialize and broadcast
                let ws_msg = crate::ws::WsMessage::Threat(event);
                broadcast_ws_json(&state, &ws_msg);
            }

            AegisUdpMessage::Alert {
                severity,
                title,
                desc,
                src_ip,
                count,
                defcon,
            } => {
                let alert = Alert {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    severity: AegisUdpMessage::parse_severity(&severity),
                    title: title.clone(),
                    description: desc,
                    source_ip: src_ip,
                    event_count: count,
                    defcon_triggered: defcon,
                };

                if state.alerts.len() >= MAX_ALERTS {
                    if let Some(k) = state.alerts.iter().next().map(|r| r.key().clone()) {
                        state.alerts.remove(&k);
                    }
                }
                state.alerts.insert(alert.id.clone(), alert.clone());

                let ws_msg = crate::ws::WsMessage::Alert(alert);
                broadcast_ws_json(&state, &ws_msg);
            }

            AegisUdpMessage::Stats {
                proto,
                packets,
                bytes,
                threats,
            } => {
                state
                    .proto_stats
                    .entry(proto)
                    .and_modify(|s| {
                        s.packets += packets;
                        s.bytes += bytes;
                        s.threats += threats;
                    })
                    .or_insert(ProtoStats {
                        packets,
                        bytes,
                        threats,
                        avg_latency_us: 0.0,
                    });
            }

            AegisUdpMessage::Defcon { level } => {
                let clamped = level.clamp(1, 5);
                state
                    .defcon_level
                    .store(clamped, std::sync::atomic::Ordering::Relaxed);
                let ws_msg = crate::ws::WsMessage::DefconChange { level: clamped };
                broadcast_ws_json(&state, &ws_msg);
                info!("DEFCON level changed to {}", level);
            }

            AegisUdpMessage::PacketTick { total, pps } => {
                state
                    .total_packets
                    .store(total, std::sync::atomic::Ordering::Relaxed);
                let ws_msg = crate::ws::WsMessage::PacketTick { total, pps };
                broadcast_ws_json(&state, &ws_msg);
            }

            AegisUdpMessage::Ping => {
                debug!("Received ping from AEGIS Core");
            }
        },
        Err(e) => {
            let preview = &msg_str[..msg_str.len().min(80)];
            debug!("Unrecognized UDP message: {} (error: {})", preview, e);
        }
    }
}

/// Serialize a WsMessage to JSON and broadcast to all WebSocket clients
fn broadcast_ws_json(state: &DashboardState, msg: &crate::ws::WsMessage) {
    let msg_json = match serde_json::to_string(msg) {
        Ok(j) => j,
        Err(_) => return,
    };

    let mut dead_clients = Vec::new();
    for entry in state.ws_clients.iter() {
        // Channel carries String (serialized JSON)
        if entry.value().try_send(msg_json.clone()).is_err() {
            dead_clients.push(entry.key().clone());
        }
    }
    for id in dead_clients {
        state.ws_clients.remove(&id);
    }
}
