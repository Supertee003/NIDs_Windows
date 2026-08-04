@@ -0,0 +1,297 @@
/**
 * aegis_dashboard/src/db.rs — SQLite database layer for AEGIS Dashboard
 *
 * Uses rusqlite (bundled SQLite) for local data persistence.
 * No external database server — fully standalone.
 */

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

// ====== Data Models ======

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub message: String,
    pub timestamp: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub layer: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIp {
    pub id: String,
    pub ip: String,
    pub reason: String,
    pub blocked_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStat {
    pub id: String,
    pub timestamp: String,
    pub total_packets: u64,
    pub alerts_count: u32,
    pub blocked_count: u32,
    pub avg_latency_ms: f64,
}

// ====== Database ======

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        let db = Database { conn };
        db.create_tables()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("Failed to open in-memory database: {}", e))?;
        let db = Database { conn };
        db.create_tables()?;
        Ok(db)
    }

    fn create_tables(&self) -> Result<(), String> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                dest_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                dest_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                layer TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                blocked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_stats (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                total_packets INTEGER NOT NULL DEFAULT 0,
                alerts_count INTEGER NOT NULL DEFAULT 0,
                blocked_count INTEGER NOT NULL DEFAULT 0,
                avg_latency_ms REAL NOT NULL DEFAULT 0.0
            );
        ").map_err(|e| format!("Failed to create tables: {}", e))?;
        Ok(())
    }

    // ====== Alerts ======

    pub fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, rule_id, severity, source_ip, dest_ip, source_port, dest_port,
                    protocol, message, timestamp, acknowledged
             FROM alerts ORDER BY timestamp DESC LIMIT ?1"
        ).map_err(|e| e.to_string())?;

        let alerts = stmt.query_map(params![limit as i64], |row| {
            Ok(Alert {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                severity: row.get(2)?,
                source_ip: row.get(3)?,
                dest_ip: row.get(4)?,
                source_port: row.get(5)?,
                dest_port: row.get(6)?,
                protocol: row.get(7)?,
                message: row.get(8)?,
                timestamp: row.get(9)?,
                acknowledged: row.get::<_, i32>(10)? != 0,
            })
        }).map_err(|e| e.to_string())?
          .filter_map(|a| a.ok())
          .collect();

        Ok(alerts)
    }

    pub fn insert_alert(&self, alert: &Alert) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR IGNORE INTO alerts
             (id, rule_id, severity, source_ip, dest_ip, source_port, dest_port,
              protocol, message, timestamp, acknowledged)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                alert.id, alert.rule_id, alert.severity,
                alert.source_ip, alert.dest_ip, alert.source_port,
                alert.dest_port, alert.protocol, alert.message,
                alert.timestamp, alert.acknowledged as i32
            ],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn acknowledge_alert(&self, id: &str) -> Result<(), String> {
        self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?1",
            params![id],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_unacknowledged_count(&self) -> Result<u32, String> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0",
            [],
            |row| row.get(0),
        ).map_err(|e| e.to_string())
    }

    // ====== Rules ======

    pub fn get_rules(&self) -> Result<Vec<Rule>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, severity, layer, enabled FROM rules ORDER BY id"
        ).map_err(|e| e.to_string())?;

        let rules = stmt.query_map([], |row| {
            Ok(Rule {
                id: row.get(0)?,
                name: row.get(1)?,
                severity: row.get(2)?,
                layer: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
            })
        }).map_err(|e| e.to_string())?
          .filter_map(|r| r.ok())
          .collect();

        Ok(rules)
    }

    pub fn insert_rule(&self, rule: &Rule) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR IGNORE INTO rules (id, name, severity, layer, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![rule.id, rule.name, rule.severity, rule.layer, rule.enabled as i32],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn toggle_rule(&self, id: &str) -> Result<(), String> {
        self.conn.execute(
            "UPDATE rules SET enabled = 1 - enabled WHERE id = ?1",
            params![id],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    // ====== Blocked IPs ======

    pub fn get_blocked_ips(&self) -> Result<Vec<BlockedIp>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC"
        ).map_err(|e| e.to_string())?;

        let ips = stmt.query_map([], |row| {
            Ok(BlockedIp {
                id: row.get(0)?,
                ip: row.get(1)?,
                reason: row.get(2)?,
                blocked_at: row.get(3)?,
            })
        }).map_err(|e| e.to_string())?
          .filter_map(|i| i.ok())
          .collect();

        Ok(ips)
    }

    pub fn block_ip(&self, ip: &str, reason: &str) -> Result<(), String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR IGNORE INTO blocked_ips (id, ip, reason, blocked_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, ip, reason, now],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn unblock_ip(&self, ip: &str) -> Result<(), String> {
        self.conn.execute(
            "DELETE FROM blocked_ips WHERE ip = ?1",
            params![ip],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    // ====== Traffic Stats ======

    pub fn get_stats(&self, limit: usize) -> Result<Vec<TrafficStat>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, total_packets, alerts_count, blocked_count, avg_latency_ms
             FROM traffic_stats ORDER BY timestamp DESC LIMIT ?1"
        ).map_err(|e| e.to_string())?;

        let stats = stmt.query_map(params![limit as i64], |row| {
            Ok(TrafficStat {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                total_packets: row.get(2)?,
                alerts_count: row.get(3)?,
                blocked_count: row.get(4)?,
                avg_latency_ms: row.get(5)?,
            })
        }).map_err(|e| e.to_string())?
          .filter_map(|s| s.ok())
          .collect();

        Ok(stats)
    }

    pub fn record_stat(&self, total_packets: u64, alerts: u32, blocked: u32, latency: f64) -> Result<(), String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO traffic_stats (id, timestamp, total_packets, alerts_count, blocked_count, avg_latency_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, now, total_packets as i64, alerts, blocked, latency],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }
}
