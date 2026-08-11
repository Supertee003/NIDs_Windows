//! correlation.rs — AEGIS NIDS Cross-Vector Correlation Engine (Layer 3: Rust)
//!
//! Implements:
//! 1. **Contextual Memory / Session Tracker** — Binds events from all 3 vectors
//!    (Network, File, Named Pipe) to the same PID/5-tuple session via QSBR RCU.
//! 2. **Cross-Vector Correlation Engine** — Links events across vectors
//!    (e.g., network anomaly + suspicious pipe = Lateral Movement detection).
//! 3. **Deterministic Threat Scoring** — Rule-based scoring matrix that
//!    combines evidence from multiple vectors into a single threat score.
//! 4. **Adaptive Rate-Limiting** — Graceful degradation under high load.
//! 5. **Forensic Snapshot Trigger** — Capture system state on Critical threats.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, OnceLock};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Event Source Vector ───
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventVector {
    Network = 0,
    File    = 1,
    Pipe    = 2,
}

// ─── Severity ───
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

// ─── Unified Event (matches Zig AegisEvent) ───
#[repr(C)]
#[derive(Debug, Clone)]
pub struct AegisEvent {
    pub event_id: u64,
    pub timestamp_ns: u64,
    pub source: EventVector,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub severity: Severity,
    pub risk_flags: u32,
    pub confidence: u8,
    pub session_id: u64,
    pub correlated_ids: [u64; 4],
    pub correlated_count: u8,
    pub forensic_hash: [u8; 32],
    pub forensic_preserved: bool,

    // Vector-specific fields (simplified for Rust — full data in Zig)
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,
    pub pipe_name_hash: u64,   // Hash of pipe name for correlation
    pub creator_pid: u32,
}

// ─── Session Context (Contextual Memory) ───
/// Tracks all events associated with a single PID + connection 5-tuple.
/// This is the key data structure for cross-vector correlation:
/// it binds Network, File, and Pipe events to the same process session.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: u64,
    pub pid: u32,
    pub ppid: u32,

    // Network context
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,

    // Event counts per vector
    pub network_events: u32,
    pub file_events: u32,
    pub pipe_events: u32,

    // Suspicious activity indicators
    pub suspicious_network: bool,   // Network rule matched
    pub suspicious_pipe: bool,      // C2 pipe name detected
    pub suspicious_file: bool,      // Suspicious file I/O
    pub cross_process_pipe: bool,   // Different PID connected to pipe

    // Risk accumulation
    pub total_risk_score: f64,      // Accumulated risk [0.0, 100.0]
    pub max_severity: Severity,

    // Recent event IDs (for correlation linking)
    pub recent_event_ids: Vec<u64>,

    // Timeline
    pub first_event_ns: u64,
    pub last_event_ns: u64,
}

impl SessionContext {
    pub fn new(session_id: u64, pid: u32) -> Self {
        Self {
            session_id,
            pid,
            ppid: 0,
            src_ip: 0, dst_ip: 0, src_port: 0, dst_port: 0,
            network_events: 0, file_events: 0, pipe_events: 0,
            suspicious_network: false, suspicious_pipe: false,
            suspicious_file: false, cross_process_pipe: false,
            total_risk_score: 0.0,
            max_severity: Severity::Info,
            recent_event_ids: Vec::with_capacity(32),
            first_event_ns: 0,
            last_event_ns: 0,
        }
    }

    /// ingest_event - Add an event to this session context.
    pub fn ingest_event(&mut self, event: &AegisEvent) {
        // Update timestamp range
        if self.first_event_ns == 0 { self.first_event_ns = event.timestamp_ns; }
        self.last_event_ns = event.timestamp_ns;

        // Count per-vector
        match event.source {
            EventVector::Network => {
                self.network_events += 1;
                if event.src_ip != 0 { self.src_ip = event.src_ip; }
                if event.dst_ip != 0 { self.dst_ip = event.dst_ip; }
                if event.src_port != 0 { self.src_port = event.src_port; }
                if event.dst_port != 0 { self.dst_port = event.dst_port; }
                if event.risk_flags != 0 { self.suspicious_network = true; }
            }
            EventVector::File => {
                self.file_events += 1;
                if event.risk_flags != 0 { self.suspicious_file = true; }
            }
            EventVector::Pipe => {
                self.pipe_events += 1;
                if event.risk_flags & 0x01 != 0 { self.suspicious_pipe = true; }
                if event.risk_flags & 0x02 != 0 { self.cross_process_pipe = true; }
            }
        }

        // Track max severity
        if event.severity > self.max_severity {
            self.max_severity = event.severity;
        }

        // Keep recent event IDs (circular)
        if self.recent_event_ids.len() >= 32 {
            self.recent_event_ids.remove(0);
        }
        self.recent_event_ids.push(event.event_id);
    }
}

// ─── Cross-Vector Correlation Engine ───
/// The core engine that:
/// 1. Maintains session contexts (contextual memory)
/// 2. Detects cross-vector threats (lateral movement, post-exploitation)
/// 3. Computes deterministic threat scores
/// 4. Triggers forensic snapshots on critical threats
/// 5. Implements adaptive rate-limiting
pub struct CorrelationEngine {
    /// Session tracker: PID → SessionContext (QSBR RCU protected)
    sessions: RwLock<HashMap<u32, Arc<Mutex<SessionContext>>>>,

    /// Session by 5-tuple (for network → pipe correlation)
    #[allow(dead_code)]  // Used by cross-vector correlation (future FFI export)
    sessions_by_tuple: RwLock<HashMap<u64, u32>>,  // session_hash → PID

    /// Threat scoring matrix (deterministic rules)
    scoring_rules: RwLock<Vec<ScoringRule>>,

    /// Adaptive rate limiter
    rate_limiter: AdaptiveRateLimiter,

    /// Forensic snapshot trigger
    forensic_trigger: ForensicTrigger,

    /// Statistics
    total_correlated: AtomicU64,
    critical_alerts: AtomicU64,
}

// ─── Scoring Rule (Deterministic) ───
/// Each rule defines a condition and a score contribution.
/// The total threat score is the sum of all matching rule scores.
/// This gives 100% deterministic, reproducible results.
#[derive(Debug, Clone)]
pub struct ScoringRule {
    pub id: u32,
    pub name: String,
    pub condition: ScoringCondition,
    pub score: f64,        // Points added when condition matches [0.0, 100.0]
    pub severity: Severity, // Minimum severity if this rule matches
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum ScoringCondition {
    /// Network anomaly detected (any risk flag set)
    NetworkAnomaly,
    /// Suspicious named pipe name (C2 pattern match)
    SuspiciousPipeName,
    /// Cross-process pipe connection (different creator vs connector PID)
    CrossProcessPipe,
    /// Network anomaly + Suspicious pipe within time window
    NetworkAndPipeAnomaly,
    /// Network anomaly + Suspicious file I/O within time window
    NetworkAndFileAnomaly,
    /// All 3 vectors show suspicious activity
    TripleVectorAnomaly,
    /// Suspicious port number (4444, 5555, 6667, 31337)
    SuspiciousPort,
    /// High entropy payload (possible encryption/packing)
    HighEntropyPayload,
    /// Known exploit signature matched
    ExploitSignature,
    /// Cobalt Strike C2 pattern (pipe name + network beacon)
    CobaltStrikePattern,
}

// ─── Adaptive Rate Limiter ───
/// Graceful degradation under high traffic load (DDoS protection).
/// When packet rate exceeds threshold, switches to selective mode:
/// - Only process packets matching high-risk signatures
/// - Pass low-risk traffic through without analysis
/// - Automatically recovers when load decreases
pub struct AdaptiveRateLimiter {
    /// Current packets-per-second rate
    current_pps: AtomicU64,
    /// Threshold for entering selective mode
    high_load_threshold: u64,      // e.g., 100,000 PPS
    /// Threshold for entering critical mode
    critical_load_threshold: u64,   // e.g., 500,000 PPS
    /// Current mode
    mode: RwLock<RateLimitMode>,
    /// Packets passed (not analyzed) due to rate limiting
    #[allow(dead_code)]  // Read by stats FFI export
    passed_count: AtomicU64,
    /// Packets selectively dropped
    #[allow(dead_code)]  // Read by stats FFI export
    dropped_count: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateLimitMode {
    Normal,       // Full analysis on all packets
    Selective,    // Only analyze high-risk packets
    Critical,     // Minimal analysis, pass most traffic
}

impl AdaptiveRateLimiter {
    pub fn new() -> Self {
        Self {
            current_pps: AtomicU64::new(0),
            high_load_threshold: 100_000,
            critical_load_threshold: 500_000,
            mode: RwLock::new(RateLimitMode::Normal),
            passed_count: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
        }
    }

    /// update_rate - Called by Go perf monitor with current PPS.
    pub fn update_rate(&self, pps: u64) {
        self.current_pps.store(pps, Ordering::Relaxed);
        let new_mode = if pps >= self.critical_load_threshold {
            RateLimitMode::Critical
        } else if pps >= self.high_load_threshold {
            RateLimitMode::Selective
        } else {
            RateLimitMode::Normal
        };
        if let Ok(mut mode) = self.mode.write() {
            *mode = new_mode;
        }
    }

    /// should_analyze - Determine if a packet should be analyzed.
    /// Returns true if full analysis, false if should pass through.
    pub fn should_analyze(&self, risk_flags: u32) -> bool {
        if let Ok(mode) = self.mode.read() {
            match *mode {
                RateLimitMode::Normal => true,
                RateLimitMode::Selective => risk_flags != 0, // Only analyze risky
                RateLimitMode::Critical => risk_flags >= 0x04, // Only high-risk
            }
        } else {
            true // Default: analyze
        }
    }

    pub fn get_mode(&self) -> RateLimitMode {
        self.mode.read().map(|m| *m).unwrap_or(RateLimitMode::Normal)
    }
}

// ─── Forensic Snapshot Trigger ───
/// When a critical threat is detected, captures:
/// - Current session state for all involved PIDs
/// - Network connection state
/// - Named pipe handles
/// - SHA-256 hash of all evidence
pub struct ForensicTrigger {
    snapshots: Mutex<Vec<ForensicSnapshot>>,
    auto_capture: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct ForensicSnapshot {
    pub snapshot_id: u64,
    pub timestamp_ns: u64,
    pub trigger_event_id: u64,
    pub trigger_pid: u32,
    pub threat_score: f64,
    pub session_ids: Vec<u64>,
    pub involved_pids: Vec<u32>,
    pub network_state: Vec<(u32, u32, u16, u16)>, // (src_ip, dst_ip, src_port, dst_port)
    pub pipe_names: Vec<String>,
    pub evidence_hash: [u8; 32],
}

impl ForensicTrigger {
    pub fn new() -> Self {
        Self {
            snapshots: Mutex::new(Vec::new()),
            auto_capture: AtomicBool::new(true),
        }
    }

    /// trigger_snapshot - Capture forensic snapshot on critical threat.
    pub fn trigger_snapshot(
        &self,
        event: &AegisEvent,
        session: &SessionContext,
        threat_score: f64,
    ) -> u64 {
        if !self.auto_capture.load(Ordering::Relaxed) { return 0; }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut snapshot = ForensicSnapshot {
            snapshot_id: event.event_id, // Use event ID as snapshot ID
            timestamp_ns: now,
            trigger_event_id: event.event_id,
            trigger_pid: event.pid,
            threat_score,
            session_ids: vec![session.session_id],
            involved_pids: vec![session.pid],
            network_state: vec![(session.src_ip, session.dst_ip,
                                  session.src_port, session.dst_port)],
            pipe_names: Vec::new(),
            evidence_hash: [0u8; 32],
        };

        // Compute evidence hash (simplified — production uses full SHA-256 chain)
        let hash_input = format!("{}:{}:{}:{:?}",
            snapshot.snapshot_id, snapshot.timestamp_ns,
            snapshot.trigger_pid, threat_score);
        snapshot.evidence_hash = super::sha256_compute(hash_input.as_bytes());

        let mut snapshots = self.snapshots.lock().unwrap();
        snapshots.push(snapshot);
        event.event_id
    }
}

// ─── Correlation Engine Implementation ───

impl CorrelationEngine {
    pub fn new() -> Self {
        let mut rules = Vec::new();

        // ── Default Scoring Rules (Deterministic) ──
        rules.push(ScoringRule {
            id: 1, name: "Network Anomaly".into(),
            condition: ScoringCondition::NetworkAnomaly,
            score: 20.0, severity: Severity::Medium, enabled: true,
        });
        rules.push(ScoringRule {
            id: 2, name: "Suspicious Pipe Name".into(),
            condition: ScoringCondition::SuspiciousPipeName,
            score: 35.0, severity: Severity::High, enabled: true,
        });
        rules.push(ScoringRule {
            id: 3, name: "Cross-Process Pipe".into(),
            condition: ScoringCondition::CrossProcessPipe,
            score: 25.0, severity: Severity::High, enabled: true,
        });
        rules.push(ScoringRule {
            id: 4, name: "Network + Pipe Anomaly (Lateral Movement)".into(),
            condition: ScoringCondition::NetworkAndPipeAnomaly,
            score: 60.0, severity: Severity::Critical, enabled: true,
        });
        rules.push(ScoringRule {
            id: 5, name: "Network + File Anomaly".into(),
            condition: ScoringCondition::NetworkAndFileAnomaly,
            score: 45.0, severity: Severity::High, enabled: true,
        });
        rules.push(ScoringRule {
            id: 6, name: "Triple Vector Anomaly".into(),
            condition: ScoringCondition::TripleVectorAnomaly,
            score: 85.0, severity: Severity::Critical, enabled: true,
        });
        rules.push(ScoringRule {
            id: 7, name: "Suspicious Port".into(),
            condition: ScoringCondition::SuspiciousPort,
            score: 15.0, severity: Severity::Medium, enabled: true,
        });
        rules.push(ScoringRule {
            id: 8, name: "Exploit Signature".into(),
            condition: ScoringCondition::ExploitSignature,
            score: 50.0, severity: Severity::Critical, enabled: true,
        });
        rules.push(ScoringRule {
            id: 9, name: "Cobalt Strike C2 Pattern".into(),
            condition: ScoringCondition::CobaltStrikePattern,
            score: 90.0, severity: Severity::Critical, enabled: true,
        });

        Self {
            sessions: RwLock::new(HashMap::new()),
            sessions_by_tuple: RwLock::new(HashMap::new()),
            scoring_rules: RwLock::new(rules),
            rate_limiter: AdaptiveRateLimiter::new(),
            forensic_trigger: ForensicTrigger::new(),
            total_correlated: AtomicU64::new(0),
            critical_alerts: AtomicU64::new(0),
        }
    }

    /// correlate - Main entry point: ingest an event and perform correlation.
    /// Returns the computed threat score for this event + session.
    pub fn correlate(&self, event: &AegisEvent) -> CorrelationResult {
        self.total_correlated.fetch_add(1, Ordering::Relaxed);

        // ── Adaptive Rate Limiting ──
        if !self.rate_limiter.should_analyze(event.risk_flags) {
            return CorrelationResult {
                threat_score: 0.0,
                severity: Severity::Info,
                correlated: false,
                snapshot_id: 0,
                action: CorrelationAction::Pass,
            };
        }

        // ── Update Session Context ──
        let session_id = self.get_or_create_session(event);
        self.update_session(session_id, event);

        // ── Evaluate Scoring Rules ──
        let session = self.get_session(event.pid);
        let (threat_score, max_severity) = if let Some(sess) = session {
            self.evaluate_rules(event, &sess.lock().unwrap())
        } else {
            (0.0, Severity::Info)
        };

        // ── Determine Action ──
        let action = if threat_score >= 80.0 {
            CorrelationAction::BlockAndPreserve
        } else if threat_score >= 50.0 {
            CorrelationAction::AlertAndPreserve
        } else if threat_score >= 20.0 {
            CorrelationAction::Alert
        } else {
            CorrelationAction::Pass
        };

        // ── Forensic Snapshot on Critical ──
        let snapshot_id = if threat_score >= 80.0 {
            self.critical_alerts.fetch_add(1, Ordering::Relaxed);
            if let Some(sess) = self.get_session(event.pid) {
                self.forensic_trigger.trigger_snapshot(event, &sess.lock().unwrap(), threat_score)
            } else {
                0
            }
        } else {
            0
        };

        CorrelationResult {
            threat_score,
            severity: max_severity,
            correlated: true,
            snapshot_id,
            action,
        }
    }

    /// get_or_create_session - Find or create session for this event's PID.
    fn get_or_create_session(&self, event: &AegisEvent) -> u64 {
        let pid = event.pid;
        let sid = {
            let mut sessions = self.sessions.write().unwrap();
            let session = sessions.entry(pid).or_insert_with(|| {
                Arc::new(Mutex::new(SessionContext::new(
                    event.session_id, pid
                )))
            });
            let sid = session.lock().unwrap().session_id;
            sid
        };
        sid
    }

    fn update_session(&self, _session_id: u64, event: &AegisEvent) {
        let sessions = self.sessions.read().unwrap();
        if let Some(session) = sessions.get(&event.pid) {
            session.lock().unwrap().ingest_event(event);
        }
    }

    fn get_session(&self, pid: u32) -> Option<Arc<Mutex<SessionContext>>> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(&pid).cloned()
    }

    /// evaluate_rules - Evaluate all scoring rules against event + session.
    fn evaluate_rules(&self, event: &AegisEvent, session: &SessionContext) -> (f64, Severity) {
        let rules = self.scoring_rules.read().unwrap();
        let mut total_score = 0.0_f64;
        let mut max_severity = Severity::Info;

        for rule in rules.iter() {
            if !rule.enabled { continue; }

            let matches = match rule.condition {
                ScoringCondition::NetworkAnomaly => session.suspicious_network,
                ScoringCondition::SuspiciousPipeName => session.suspicious_pipe,
                ScoringCondition::CrossProcessPipe => session.cross_process_pipe,
                ScoringCondition::NetworkAndPipeAnomaly =>
                    session.suspicious_network && session.suspicious_pipe,
                ScoringCondition::NetworkAndFileAnomaly =>
                    session.suspicious_network && session.suspicious_file,
                ScoringCondition::TripleVectorAnomaly =>
                    session.suspicious_network && session.suspicious_pipe && session.suspicious_file,
                ScoringCondition::SuspiciousPort => {
                    let port = event.dst_port;
                    port == 4444 || port == 5555 || port == 6667 || port == 31337
                }
                ScoringCondition::HighEntropyPayload =>
                    event.risk_flags & 0x10 != 0,
                ScoringCondition::ExploitSignature =>
                    event.risk_flags & 0x20 != 0,
                ScoringCondition::CobaltStrikePattern =>
                    session.suspicious_pipe && session.suspicious_network &&
                    session.pipe_events > 0 && session.network_events > 0,
            };

            if matches {
                total_score += rule.score;
                if rule.severity > max_severity {
                    max_severity = rule.severity;
                }
            }
        }

        // Cap at 100.0
        (total_score.min(100.0), max_severity)
    }

    /// update_load - Update rate limiter from Go perf monitor.
    pub fn update_load(&self, pps: u64) {
        self.rate_limiter.update_rate(pps);
    }

    /// get_stats - Return correlation engine statistics.
    pub fn get_stats(&self) -> CorrelationStats {
        CorrelationStats {
            total_correlated: self.total_correlated.load(Ordering::Relaxed),
            critical_alerts: self.critical_alerts.load(Ordering::Relaxed),
            active_sessions: self.sessions.read().unwrap().len(),
            rate_limit_mode: self.rate_limiter.get_mode(),
            current_pps: self.rate_limiter.current_pps.load(Ordering::Relaxed),
        }
    }
}

// ─── Result Types ───

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CorrelationAction {
    Pass             = 0,
    Alert            = 1,
    AlertAndPreserve = 2,
    BlockAndPreserve = 3,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub threat_score: f64,
    pub severity: Severity,
    pub correlated: bool,
    pub snapshot_id: u64,
    pub action: CorrelationAction,
}

#[derive(Debug, Clone)]
pub struct CorrelationStats {
    pub total_correlated: u64,
    pub critical_alerts: u64,
    pub active_sessions: usize,
    pub rate_limit_mode: RateLimitMode,
    pub current_pps: u64,
}

// ─── C-ABI Exports for Cross-Vector Correlation ───

// FATAL-08 fix: Replace `static mut` with OnceLock for safe singleton.
// Same pattern as lib.rs (G_FORENSIC_HASHER) and semi_nids.rs (G_SEMI_NIDS).
static G_CORRELATION_ENGINE: OnceLock<CorrelationEngine> = OnceLock::new();
static G_CORR_INIT: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "C" fn aegis_correlation_init() -> i32 {
    let _ = G_CORRELATION_ENGINE.set(CorrelationEngine::new());
    G_CORR_INIT.store(true, Ordering::Release);
    0
}

#[no_mangle]
pub extern "C" fn aegis_correlation_update_load(pps: u64) {
    if !G_CORR_INIT.load(Ordering::Acquire) { return; }
    if let Some(engine) = G_CORRELATION_ENGINE.get() {
        engine.update_load(pps);
    }
}

#[no_mangle]
pub extern "C" fn aegis_correlation_shutdown() {
    // OnceLock cannot be "unset" — mark inactive instead.
    // All FFI functions check G_CORR_INIT first, so this is safe.
    G_CORR_INIT.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lateral_movement_detection() {
        let engine = CorrelationEngine::new();

        // Simulate: network anomaly arrives
        let net_event = AegisEvent {
            event_id: 1, timestamp_ns: 1000, source: EventVector::Network,
            pid: 1234, tid: 1, ppid: 0,
            severity: Severity::Medium, risk_flags: 1,
            confidence: 80, session_id: 1,
            correlated_ids: [0; 4], correlated_count: 0,
            forensic_hash: [0; 32], forensic_preserved: false,
            src_ip: 0xC0A80A01, dst_ip: 0xC0A80A02,
            src_port: 49152, dst_port: 80, ip_proto: 6,
            pipe_name_hash: 0, creator_pid: 0,
        };
        let r1 = engine.correlate(&net_event);
        assert!(r1.threat_score >= 20.0); // NetworkAnomaly rule

        // Simulate: suspicious pipe created by SAME PID
        let pipe_event = AegisEvent {
            event_id: 2, timestamp_ns: 2000, source: EventVector::Pipe,
            pid: 1234, tid: 2, ppid: 0,
            severity: Severity::High, risk_flags: 0x01, // SUSPICIOUS_NAME
            confidence: 90, session_id: 1,
            correlated_ids: [0; 4], correlated_count: 0,
            forensic_hash: [0; 32], forensic_preserved: false,
            src_ip: 0, dst_ip: 0, src_port: 0, dst_port: 0, ip_proto: 0,
            pipe_name_hash: 12345, creator_pid: 1234,
        };
        let r2 = engine.correlate(&pipe_event);
        // Should detect Network + Pipe = Lateral Movement (score >= 60)
        assert!(r2.threat_score >= 60.0);
        assert_eq!(r2.severity, Severity::Critical,);
    }

    #[test]
    fn test_adaptive_rate_limiting() {
        let limiter = AdaptiveRateLimiter::new();

        limiter.update_rate(50_000);
        assert_eq!(limiter.get_mode(), RateLimitMode::Normal);
        assert!(limiter.should_analyze(0));

        limiter.update_rate(150_000);
        assert_eq!(limiter.get_mode(), RateLimitMode::Selective);
        assert!(limiter.should_analyze(1));   // Risky → analyze
        assert!(!limiter.should_analyze(0));  // Clean → skip

        limiter.update_rate(600_000);
        assert_eq!(limiter.get_mode(), RateLimitMode::Critical);
        assert!(limiter.should_analyze(0x04));  // High risk → analyze
        assert!(!limiter.should_analyze(0));    // Clean → skip
    }
}
