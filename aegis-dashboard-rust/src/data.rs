use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Threat event received from AEGIS Core via UDP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: String,
    pub attack_type: String,
    pub policy: String,
    pub reason: String,
    pub source: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub severity: u8,
    pub rule_id: String,
}

/// Alert for dashboard display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub time: String,
    pub threat: String,
    pub src: String,
    pub dst: String,
    pub action: String,
    pub severity: String,
}

impl From<&ThreatEvent> for Alert {
    fn from(ev: &ThreatEvent) -> Self {
        Alert {
            id: ev.id.clone(),
            time: ev.timestamp.clone(),
            threat: ev.attack_type.clone(),
            src: ev.source_ip.clone(),
            dst: ev.dest_ip.clone(),
            action: ev.policy.clone(),
            severity: match ev.severity {
                0 => "Low".into(),
                1 => "Medium".into(),
                2 => "High".into(),
                3 => "Critical".into(),
                _ => "Unknown".into(),
            },
        }
    }
}

/// Protocol statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoStats {
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub other: u64,
}

impl Default for ProtoStats {
    fn default() -> Self {
        Self { tcp: 0, udp: 0, icmp: 0, other: 0 }
    }
}

/// DEFCON level (1=MAXIMUM .. 5=SAFE)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DefconLevel {
    Maximum = 1,
    Severe = 2,
    High = 3,
    Elevated = 4,
    Safe = 5,
}

impl Default for DefconLevel {
    fn default() -> Self { Self::Safe }
}

impl DefconLevel {
    pub fn label(&self) -> &str {
        match self {
            Self::Maximum => "MAXIMUM",
            Self::Severe => "SEVERE",
            Self::High => "HIGH",
            Self::Elevated => "ELEVATED",
            Self::Safe => "SAFE",
        }
    }
    pub fn color(&self) -> &str {
        match self {
            Self::Maximum => "#ff0000",
            Self::Severe => "#ff6600",
            Self::High => "#ffcc00",
            Self::Elevated => "#3399ff",
            Self::Safe => "#00cc66",
        }
    }
}

/// Message from UDP listener
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisUdpMessage {
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub attack_type: Option<String>,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub dest_ip: Option<String>,
    #[serde(default)]
    pub source_port: Option<u16>,
    #[serde(default)]
    pub dest_port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<u8>,
    #[serde(default)]
    pub severity: Option<u8>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub raw_payload: Option<String>,
}
