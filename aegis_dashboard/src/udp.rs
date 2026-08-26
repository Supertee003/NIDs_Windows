use std::net::UdpSocket;
use std::sync::Arc;
use tokio::sync::broadcast;
use crate::data::{AegisUdpMessage, ThreatEvent, DefconLevel, ProtoStats};
use dashmap::DashMap;
use chrono::Utc;
use uuid::Uuid;
use tracing::{info, warn, error};

pub async fn run_udp_listener(
    tx: broadcast::Sender<String>,
    stats: Arc<DashMap<String, u64>>,
    proto_stats: Arc<DashMap<String, u64>>,
    defcon: Arc<DashMap<String, u8>>,
    alerts: Arc<DashMap<String, String>>,
) {
    // UDP listener runs in blocking context
    // UX-02 FIX: Changed port from 10000 to 9999 (was mismatched with brain's port)
    // Note: If both brain (Python) and dashboard bind to 9999, only one will succeed.
    // Recommended: dashboard should use file-watch on logs/anomalous.json instead.
    // For now, use port 10001 as a secondary listener that the brain can forward to.
    const DASHBOARD_UDP_PORT: u16 = 10001;
    let result = std::thread::spawn(move || {
        let bind_addr = format!("127.0.0.1:{}", DASHBOARD_UDP_PORT);
        match UdpSocket::bind(&bind_addr) {
            Ok(sock) => {
                info!("[DASHBOARD UDP] Listening on {}", bind_addr);
                info!("[DASHBOARD UDP] NOTE: Configure brain to forward events to port {}", DASHBOARD_UDP_PORT);
                let mut buf = [0u8; 65535];
                loop {
                    match sock.recv_from(&mut buf) {
                        Ok((n, addr)) => {
                            let data = &buf[..n];
                            // Try JSON decode first
                            if let Ok(msg) = serde_json::from_slice::<AegisUdpMessage>(data) {
                                process_message(msg, &tx, &stats, &proto_stats, &defcon, &alerts);
                            } else {
                                // Try as plain text JSON
                                let text = String::from_utf8_lossy(data);
                                if let Ok(msg) = serde_json::from_str::<AegisUdpMessage>(&text) {
                                    process_message(msg, &tx, &stats, &proto_stats, &defcon, &alerts);
                                } else {
                                    warn!("[UDP] Failed to decode message from {} ({} bytes)", addr, n);
                                }
                            }
                        }
                        Err(e) => {
                            error!("[UDP] Recv error: {}", e);
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    }
                }
            }
            Err(e) => {
                error!("[UDP] Bind failed: {} — dashboard will run without UDP feed", e);
            }
        }
    });
    let _ = result;
}

fn process_message(
    msg: AegisUdpMessage,
    tx: &broadcast::Sender<String>,
    stats: &Arc<DashMap<String, u64>>,
    proto_stats: &Arc<DashMap<String, u64>>,
    defcon: &Arc<DashMap<String, u8>>,
    alerts: &Arc<DashMap<String, String>>,
) {
    // Build ThreatEvent from UDP message
    let event = ThreatEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: msg.timestamp.clone().unwrap_or_else(|| Utc::now().to_rfc3339()),
        attack_type: msg.attack_type.clone().unwrap_or_default(),
        policy: msg.policy.clone().unwrap_or_default(),
        reason: msg.reason.clone().unwrap_or_default(),
        source: msg.source.clone().unwrap_or_default(),
        source_ip: msg.source_ip.clone().unwrap_or_else(|| "0.0.0.0".into()),
        dest_ip: msg.dest_ip.clone().unwrap_or_else(|| "0.0.0.0".into()),
        source_port: msg.source_port.unwrap_or(0),
        dest_port: msg.dest_port.unwrap_or(0),
        protocol: msg.protocol.unwrap_or(0),
        severity: msg.severity.unwrap_or(1),
        rule_id: msg.rule_id.clone().unwrap_or_else(|| "UNKNOWN".into()),
    };

    // Update statistics
    stats.entry("total_events".into()).and_modify(|c| *c += 1).or_insert(1);
    
    // Update protocol stats
    let proto_key = match event.protocol {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "other",
    };
    proto_stats.entry(proto_key.into()).and_modify(|c| *c += 1).or_insert(1);

    // Update DEFCON based on severity
    let current_sev = defcon.get("severity").map(|v| *v.value()).unwrap_or(0);
    let new_sev = event.severity.max(current_sev);
    defcon.insert("severity".into(), new_sev);
    
    let defcon_level = if new_sev >= 3 { 1 } else if new_sev >= 2 { 3 } else { 5 };
    defcon.insert("level".into(), defcon_level);

    // Store alert (keep last 100)
    let alert_json = serde_json::to_string(&event).unwrap_or_default();
    alerts.insert(event.id.clone(), alert_json);
    if alerts.len() > 100 {
        // Remove oldest entries
        let keys: Vec<String> = alerts.iter().take(alerts.len() - 100).map(|e| e.key().clone()).collect();
        for k in keys { alerts.remove(&k); }
    }

    // Broadcast to WebSocket clients
    let ws_msg = serde_json::json!({
        "type": "threat",
        "data": event,
    }).to_string();
    let _ = tx.send(ws_msg);

    info!("[UDP] Processed: {} from {} (severity={})", 
        event.attack_type, event.source_ip, event.severity);
}
