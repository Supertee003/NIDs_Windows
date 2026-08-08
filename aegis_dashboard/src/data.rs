// ============================================================================
// AEGIS NIDS — Data Types (src/data.rs)
// ============================================================================
// Shared data structures for threat events, alerts, and statistics.
// These are serialized to JSON for both REST API and WebSocket responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum events to keep in memory (circular buffer behavior)
pub const MAX_EVENTS: usize = 1000;
pub const MAX_ALERTS: usize = 200;
pub const MAX_TOP_SOURCES: usize = 50;

// ─── Threat Severity ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_color(&self) -> &str {
        match self {
            Severity::Critical => "#ff0040",
            Severity::High => "#ff4040",
            Severity::Medium => "#ffaa00",
            Severity::Low => "#40c0ff",
            Severity::Info => "#80ff80",
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

// ─── Threat Event ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub rule_id: String,
    pub message: String,
    pub raw_payload: Option<String>,
}

// ─── Alert ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub source_ip: String,
    pub event_count: u32,
    pub defcon_triggered: Option<u8>,
}

// ─── Protocol Statistics ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtoStats {
    pub packets: u64,
    pub bytes: u64,
    pub threats: u64,
    pub avg_latency_us: f64,
}

// ─── DEFCON Levels ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DefconLevel {
    /// Normal operations
    Defcon5 = 5,
    /// Elevated — minor threats detected
    Defcon4 = 4,
    /// High — significant threat activity
    Defcon3 = 3,
    /// Severe — active attack detected
    Defcon2 = 2,
    /// Critical — system under sustained attack
    Defcon1 = 1,
}

impl DefconLevel {
    pub fn from_u8(level: u8) -> Self {
        match level {
            1 => DefconLevel::Defcon1,
            2 => DefconLevel::Defcon2,
            3 => DefconLevel::Defcon3,
            4 => DefconLevel::Defcon4,
            _ => DefconLevel::Defcon5,
        }
    }

    pub fn as_color(&self) -> &str {
        match self {
            DefconLevel::Defcon1 => "#ff0040",
            DefconLevel::Defcon2 => "#ff4040",
            DefconLevel::Defcon3 => "#ffaa00",
            DefconLevel::Defcon4 => "#40c0ff",
            DefconLevel::Defcon5 => "#80ff80",
        }
    }

    pub fn as_label(&self) -> &str {
        match self {
            DefconLevel::Defcon1 => "CRITICAL",
            DefconLevel::Defcon2 => "SEVERE",
            DefconLevel::Defcon3 => "HIGH",
            DefconLevel::Defcon4 => "ELEVATED",
            DefconLevel::Defcon5 => "NORMAL",
        }
    }
}

// ─── 5-Tuple Flow Key ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowKey {
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
}

// ─── UDP Message from AEGIS Core (msgpack-decoded JSON) ─────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AegisUdpMessage {
    #[serde(rename = "threat")]
    Threat {
        severity: String,
        category: String,
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        proto: String,
        rule_id: String,
        msg: String,
    },

    #[serde(rename = "alert")]
    Alert {
        severity: String,
        title: String,
        desc: String,
        src_ip: String,
        count: u32,
        defcon: Option<u8>,
    },

    #[serde(rename = "stats")]
    Stats {
        proto: String,
        packets: u64,
        bytes: u64,
        threats: u64,
    },

    #[serde(rename = "defcon")]
    Defcon { level: u8 },

    #[serde(rename = "packet_tick")]
    PacketTick { total: u64, pps: u64 },

    #[serde(rename = "ping")]
    Ping,
}

impl AegisUdpMessage {
    /// Parse severity string to enum
    pub fn parse_severity(s: &str) -> Severity {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}
