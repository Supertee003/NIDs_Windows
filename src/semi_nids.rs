//! semi_nids.rs — AEGIS Semi-NIDS Engine (Layer 3: Rust)
//!
//! Semi-NIDS = Semi-Autonomous Network Intrusion Detection & Response System
//!
//! Implements the 3 core properties:
//! 1. **Adaptive & Threshold-based Dropping** — Block only when confident
//! 2. **Graceful Degradation (Fail-Open)** — Never break legitimate traffic
//! 3. **Interactive Control Loop** — Human-in-the-loop decisions
//!
//! FFI Exports:
//!   aegis_semi_nids_init()            — Initialize engine
//!   aegis_semi_nids_evaluate()        — Evaluate threat → Drop/Alert/Pass
//!   aegis_semi_nids_set_policy()      — Human sets policy (Block/Whitelist/Ignore)
//!   aegis_semi_nids_get_pending()     — Get alerts pending human decision
//!   aegis_semi_nids_fail_open_status()— Query fail-open state
//!   aegis_semi_nids_update_load()     — Update from Go perf monitor
//!   aegis_semi_nids_block_ip()        — Immediate kernel-level block
//!   aegis_semi_nids_unblock_ip()      — Remove block (whitelist)
//!   aegis_semi_nids_get_stats()       — Get engine statistics
//!   aegis_semi_nids_shutdown()        — Shutdown engine

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::ForensicHasher;

// ═══════════════════════════════════════════════════════════════
// §1 — Adaptive & Threshold-based Dropping
// ═══════════════════════════════════════════════════════════════

/// Confidence level for adaptive dropping decisions.
/// The system only blocks when confidence is HIGH or CRITICAL.
/// At MEDIUM or below, it only alerts and logs.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Unknown  = 0,  // No signature match — always pass
    Low      = 1,  // Single indicator, could be FP
    Medium   = 2,  // Multiple indicators, likely real
    High     = 3,  // Strong evidence, very likely real
    Critical = 4,  // Certain — known exploit signature or cross-vector correlation
}

/// Decision returned by the Semi-NIDS engine for each packet/event.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemiNidsDecision {
    /// Pass through — no threat detected or confidence too low
    Pass          = 0,
    /// Log + alert to dashboard, but do NOT block
    AlertOnly     = 1,
    /// Temporarily rate-limit this source IP (soft block)
    RateLimit     = 2,
    /// Block this specific flow at kernel level (hard block)
    Block         = 3,
    /// Block IP entirely at kernel level + preserve forensic evidence
    BlockAndPreserve = 4,
    /// Pending human decision — alert shown, waiting for operator
    PendingHuman  = 5,
}

/// Thresholds that govern the adaptive dropping behavior.
/// These are the "knobs" that control how aggressive the system is.
#[derive(Debug, Clone)]
pub struct DropThresholds {
    /// Score threshold for AlertOnly (no blocking)
    pub alert_threshold: f64,         // Default: 20.0
    /// Score threshold for RateLimit (soft block)
    pub rate_limit_threshold: f64,    // Default: 40.0
    /// Score threshold for Block (hard block) — requires HIGH confidence
    pub block_threshold: f64,         // Default: 60.0
    /// Score threshold for BlockAndPreserve — requires CRITICAL confidence
    pub block_preserve_threshold: f64, // Default: 80.0
    /// Minimum confidence for any blocking action
    pub min_block_confidence: Confidence, // Default: High
    /// Duration (seconds) for temporary blocks before auto-expiry
    pub temp_block_duration_secs: u64,   // Default: 300 (5 min)
    /// Maximum concurrent temporary blocks
    pub max_temp_blocks: usize,          // Default: 1000
}

impl Default for DropThresholds {
    fn default() -> Self {
        Self {
            alert_threshold: 20.0,
            rate_limit_threshold: 40.0,
            block_threshold: 60.0,
            block_preserve_threshold: 80.0,
            min_block_confidence: Confidence::High,
            temp_block_duration_secs: 300,
            max_temp_blocks: 1000,
        }
    }
}

/// Computed threat assessment combining score + confidence.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    pub threat_score: f64,
    pub confidence: Confidence,
    pub decision: SemiNidsDecision,
    pub reason: u32,  // Bitfield: which rules triggered (for logging)
    pub session_id: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub timestamp_ns: u64,
}

// ═══════════════════════════════════════════════════════════════
// §2 — Graceful Degradation (Fail-Open)
// ═══════════════════════════════════════════════════════════════

/// Load state tracked from Go perf monitor.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Normal     = 0,  // CPU < 70%, analysis queue < 80%
    Elevated   = 1,  // CPU 70-85%, analysis queue 80-90%
    Overloaded = 2,  // CPU > 85% or analysis queue > 90%
    Critical   = 3,  // Analysis thread crashed or queue full
}

/// Fail-open controller. When the system is overloaded, it
/// transitions to pass-through mode to protect legitimate traffic.
pub struct FailOpenController {
    /// Current load state
    load_state: RwLock<LoadState>,
    /// Current CPU percentage (0-100) from Go perf monitor
    pub(crate) cpu_percent: AtomicU8,
    /// Current analysis queue fill percentage (0-100)
    pub(crate) queue_fill_percent: AtomicU8,
    /// Packets-per-second rate
    current_pps: AtomicU64,
    /// Threshold for Elevated state
    elevated_cpu_threshold: u8,    // Default: 70
    /// Threshold for Overloaded state
    overloaded_cpu_threshold: u8,  // Default: 85
    /// Threshold for Critical state (queue full)
    critical_queue_threshold: u8,  // Default: 95
    /// Whether fail-open is currently active (pass-through mode)
    fail_open_active: AtomicBool,
    /// Total packets passed through due to fail-open
    fail_open_passed: AtomicU64,
    /// Timestamp when fail-open was activated (for logging)
    fail_open_since_ns: AtomicU64,
}

impl FailOpenController {
    pub fn new() -> Self {
        Self {
            load_state: RwLock::new(LoadState::Normal),
            cpu_percent: AtomicU8::new(0),
            queue_fill_percent: AtomicU8::new(0),
            current_pps: AtomicU64::new(0),
            elevated_cpu_threshold: 70,
            overloaded_cpu_threshold: 85,
            critical_queue_threshold: 95,
            fail_open_active: AtomicBool::new(false),
            fail_open_passed: AtomicU64::new(0),
            fail_open_since_ns: AtomicU64::new(0),
        }
    }

    /// update_load — Called by Go perf monitor every 1 second.
    /// Updates CPU and queue metrics, recalculates load state.
    pub fn update_load(&self, cpu_pct: u8, queue_pct: u8, pps: u64) {
        self.cpu_percent.store(cpu_pct, Ordering::Relaxed);
        self.queue_fill_percent.store(queue_pct, Ordering::Relaxed);
        self.current_pps.store(pps, Ordering::Relaxed);

        let new_state = if cpu_pct >= self.overloaded_cpu_threshold
            || queue_pct >= self.critical_queue_threshold
        {
            LoadState::Overloaded
        } else if cpu_pct >= self.elevated_cpu_threshold
            || queue_pct >= 90
        {
            LoadState::Elevated
        } else {
            LoadState::Normal
        };

        let was_fail_open = self.fail_open_active.load(Ordering::Relaxed);

        let is_fail_open = match new_state {
            LoadState::Critical => true,
            LoadState::Overloaded => true,
            _ => false,
        };

        self.fail_open_active.store(is_fail_open, Ordering::Release);

        if !was_fail_open && is_fail_open {
            // Just entered fail-open — record timestamp
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            self.fail_open_since_ns.store(now, Ordering::Relaxed);
        }

        if let Ok(mut state) = self.load_state.write() {
            *state = new_state;
        }
    }

    /// should_pass_through — Returns true if packet should be passed
    /// without analysis due to fail-open or selective mode.
    ///
    /// FAIL-OPEN RULE (Critical Property #2):
    ///   If system is overloaded → pass ALL normal traffic through
    ///   Only continue analyzing packets that already have risk flags
    ///   (i.e., packets flagged by fast-path signature matching in kernel)
    pub fn should_pass_through(&self, risk_flags: u32) -> bool {
        let is_fail_open = self.fail_open_active.load(Ordering::Acquire);
        if !is_fail_open {
            return false; // Normal operation — analyze everything
        }

        // Fail-open is active: pass through UNLESS the packet already
        // has risk flags from kernel-level fast matching.
        // This means: drop known-bad traffic, pass everything else.
        if risk_flags != 0 {
            return false; // Has risk flags → still analyze even in fail-open
        }

        self.fail_open_passed.fetch_add(1, Ordering::Relaxed);
        true // No risk flags + overloaded → pass through (fail-open)
    }

    /// should_selective_analyze — Under elevated load, only analyze
    /// packets with risk flags. Clean traffic passes without full analysis.
    pub fn should_selective_analyze(&self, risk_flags: u32) -> bool {
        if let Ok(state) = self.load_state.read() {
            match *state {
                LoadState::Normal => true,           // Analyze all
                LoadState::Elevated => risk_flags != 0, // Only risky
                LoadState::Overloaded => risk_flags >= 0x04, // Only high-risk
                LoadState::Critical => false,         // Complete fail-open
            }
        } else {
            true
        }
    }

    pub fn get_load_state(&self) -> LoadState {
        self.load_state.read().map(|s| *s).unwrap_or(LoadState::Normal)
    }

    pub fn is_fail_open(&self) -> bool {
        self.fail_open_active.load(Ordering::Acquire)
    }

    pub fn get_fail_open_passed(&self) -> u64 {
        self.fail_open_passed.load(Ordering::Relaxed)
    }
}

// ═══════════════════════════════════════════════════════════════
// §3 — Interactive Control Loop (Human-in-the-loop)
// ═══════════════════════════════════════════════════════════════

/// Human policy decision for a pending alert.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanDecision {
    None      = 0,  // No decision yet — still pending
    Block     = 1,  // Operator chose to block IP permanently
    BlockTemp = 2,  // Operator chose temporary block (5 min)
    Whitelist = 3,  // Operator chose to whitelist (never alert again)
    Ignore    = 4,  // Operator chose to ignore this specific alert
    Escalate  = 5,  // Operator escalates to higher DEFCON level
}

/// A pending alert waiting for human decision.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PendingAlert {
    pub alert_id: u64,
    pub timestamp_ns: u64,
    pub threat_score: f64,
    pub confidence: Confidence,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub pid: u32,
    pub reason: u32,
    pub decision: HumanDecision,
    pub description: [u8; 256], // Fixed-size for C-ABI compatibility
    pub desc_len: u16,
}

/// Policy store — tracks human decisions (blocks, whitelists, etc.)
pub struct PolicyStore {
    /// Permanently blocked IPs (human decision)
    blocked_ips: RwLock<HashMap<u32, BlockedIpEntry>>,
    /// Temporarily blocked IPs with auto-expiry
    temp_blocked: RwLock<HashMap<u32, TempBlockEntry>>,
    /// Whitelisted IPs (never alert/block)
    whitelisted_ips: RwLock<HashMap<u32, WhitelistEntry>>,
    /// Pending alerts awaiting human decision
    pending_alerts: RwLock<Vec<PendingAlert>>,
    /// Maximum pending alerts before auto-dismiss oldest
    max_pending: usize,
    /// Next alert ID
    next_alert_id: AtomicU64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]  // Fields read by debug formatting and future FFI exports
struct BlockedIpEntry {
    ip: u32,
    blocked_at_ns: u64,
    blocked_by: HumanDecision,
    forensic_hash: [u8; 32],
    reason: u32,
}

#[allow(dead_code)]  // Fields used by expiry logic
struct TempBlockEntry {
    ip: u32,
    blocked_at_ns: u64,
    expires_at_ns: u64,
    remaining_pps: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]  // Fields read by debug formatting
struct WhitelistEntry {
    ip: u32,
    whitelisted_at_ns: u64,
    reason: u32,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            blocked_ips: RwLock::new(HashMap::new()),
            temp_blocked: RwLock::new(HashMap::new()),
            whitelisted_ips: RwLock::new(HashMap::new()),
            pending_alerts: RwLock::new(Vec::with_capacity(64)),
            max_pending: 256,
            next_alert_id: AtomicU64::new(1),
        }
    }

    /// is_blocked — Check if an IP is blocked (permanent or temporary).
    pub fn is_blocked(&self, ip: u32) -> bool {
        // Check permanent block
        if let Ok(map) = self.blocked_ips.read() {
            if map.contains_key(&ip) { return true; }
        }
        // Check temporary block
        if let Ok(map) = self.temp_blocked.read() {
            if let Some(entry) = map.get(&ip) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                return now < entry.expires_at_ns;
            }
        }
        false
    }

    /// is_whitelisted — Check if an IP is whitelisted.
    pub fn is_whitelisted(&self, ip: u32) -> bool {
        self.whitelisted_ips.read().map(|m| m.contains_key(&ip)).unwrap_or(false)
    }

    /// block_ip_permanent — Human decided to block IP permanently.
    pub fn block_ip_permanent(&self, ip: u32, reason: u32, forensic_hash: [u8; 32]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let entry = BlockedIpEntry {
            ip, blocked_at_ns: now,
            blocked_by: HumanDecision::Block,
            forensic_hash, reason,
        };

        if let Ok(mut map) = self.blocked_ips.write() {
            map.insert(ip, entry);
        }

        // Also remove from temp blocks if present
        if let Ok(mut map) = self.temp_blocked.write() {
            map.remove(&ip);
        }
    }

    /// block_ip_temporary — Auto or human temporary block (rate limit).
    pub fn block_ip_temporary(&self, ip: u32, duration_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let entry = TempBlockEntry {
            ip,
            blocked_at_ns: now,
            expires_at_ns: now + duration_secs * 1_000_000_000,
            remaining_pps: 0,
        };

        if let Ok(mut map) = self.temp_blocked.write() {
            // Limit number of temp blocks
            if map.len() >= 1000 {
                // Remove oldest
                if let Some(oldest_key) = map.iter()
                    .min_by_key(|(_, e)| e.blocked_at_ns)
                    .map(|(k, _)| *k)
                {
                    map.remove(&oldest_key);
                }
            }
            map.insert(ip, entry);
        }
    }

    /// whitelist_ip — Human decided to whitelist IP.
    pub fn whitelist_ip(&self, ip: u32, reason: u32) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let entry = WhitelistEntry { ip, whitelisted_at_ns: now, reason };

        // Remove from any blocks first
        if let Ok(mut map) = self.blocked_ips.write() { map.remove(&ip); }
        if let Ok(mut map) = self.temp_blocked.write() { map.remove(&ip); }

        if let Ok(mut map) = self.whitelisted_ips.write() {
            map.insert(ip, entry);
        }
    }

    /// unblock_ip — Remove all blocks for an IP.
    pub fn unblock_ip(&self, ip: u32) {
        if let Ok(mut map) = self.blocked_ips.write() { map.remove(&ip); }
        if let Ok(mut map) = self.temp_blocked.write() { map.remove(&ip); }
    }

    /// add_pending_alert — Add alert to queue for human review.
    pub fn add_pending_alert(&self, assessment: &ThreatAssessment, desc: &[u8]) -> u64 {
        let alert_id = self.next_alert_id.fetch_add(1, Ordering::Relaxed);

        let mut description = [0u8; 256];
        let copy_len = desc.len().min(255);
        description[..copy_len].copy_from_slice(&desc[..copy_len]);

        let alert = PendingAlert {
            alert_id,
            timestamp_ns: assessment.timestamp_ns,
            threat_score: assessment.threat_score,
            confidence: assessment.confidence,
            src_ip: assessment.src_ip,
            dst_ip: assessment.dst_ip,
            src_port: 0,
            dst_port: 0,
            pid: 0,
            reason: assessment.reason,
            decision: HumanDecision::None,
            description,
            desc_len: copy_len as u16,
        };

        if let Ok(mut alerts) = self.pending_alerts.write() {
            if alerts.len() >= self.max_pending {
                // Auto-dismiss oldest alert (take no action = effectively ignore)
                alerts.remove(0);
            }
            alerts.push(alert);
        }

        alert_id
    }

    /// resolve_alert — Human makes decision on a pending alert.
    pub fn resolve_alert(&self, alert_id: u64, decision: HumanDecision) -> i32 {
        if let Ok(mut alerts) = self.pending_alerts.write() {
            if let Some(alert) = alerts.iter_mut().find(|a| a.alert_id == alert_id) {
                alert.decision = decision;

                match decision {
                    HumanDecision::Block => {
                        self.block_ip_permanent(alert.src_ip, alert.reason, [0u8; 32]);
                    }
                    HumanDecision::BlockTemp => {
                        self.block_ip_temporary(alert.src_ip, 300); // 5 min default
                    }
                    HumanDecision::Whitelist => {
                        self.whitelist_ip(alert.src_ip, alert.reason);
                    }
                    HumanDecision::Ignore | HumanDecision::Escalate | HumanDecision::None => {
                        // No IP-level action
                    }
                }

                return 0;
            }
        }
        -1 // Alert not found
    }

    /// get_pending_alerts — Return copy of pending alerts for console/UI.
    pub fn get_pending_alerts(&self, max_count: usize) -> Vec<PendingAlert> {
        if let Ok(alerts) = self.pending_alerts.read() {
            alerts.iter().take(max_count).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// expire_temp_blocks — Remove expired temporary blocks.
    /// Should be called periodically (e.g., every 10 seconds).
    pub fn expire_temp_blocks(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut expired = 0u32;
        if let Ok(mut map) = self.temp_blocked.write() {
            let expired_keys: Vec<u32> = map.iter()
                .filter(|(_, e)| now >= e.expires_at_ns)
                .map(|(k, _)| *k)
                .collect();
            expired = expired_keys.len() as u32;
            for k in expired_keys {
                map.remove(&k);
            }
        }
        expired
    }

    /// get_blocked_count — Number of currently blocked IPs.
    pub fn get_blocked_count(&self) -> (usize, usize) {
        let perm = self.blocked_ips.read().map(|m| m.len()).unwrap_or(0);
        let temp = self.temp_blocked.read().map(|m| m.len()).unwrap_or(0);
        (perm, temp)
    }
}

// ═══════════════════════════════════════════════════════════════
// Semi-NIDS Engine — Main Controller
// ═══════════════════════════════════════════════════════════════

/// The central Semi-NIDS engine that orchestrates all three properties.
pub struct SemiNidsEngine {
    /// Adaptive dropping thresholds
    thresholds: RwLock<DropThresholds>,
    /// Fail-open controller
    fail_open: FailOpenController,
    /// Human policy store
    policy: PolicyStore,
    /// Forensic hasher for evidence preservation
    forensic: Mutex<ForensicHasher>,
    /// Statistics
    total_evaluated: AtomicU64,
    total_passed: AtomicU64,
    total_alerted: AtomicU64,
    total_blocked: AtomicU64,
    total_rate_limited: AtomicU64,
    total_fail_open_passes: AtomicU64,
    total_human_decisions: AtomicU64,
}

impl SemiNidsEngine {
    pub fn new() -> Self {
        Self {
            thresholds: RwLock::new(DropThresholds::default()),
            fail_open: FailOpenController::new(),
            policy: PolicyStore::new(),
            forensic: Mutex::new(ForensicHasher::new()),
            total_evaluated: AtomicU64::new(0),
            total_passed: AtomicU64::new(0),
            total_alerted: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_rate_limited: AtomicU64::new(0),
            total_fail_open_passes: AtomicU64::new(0),
            total_human_decisions: AtomicU64::new(0),
        }
    }

    /// evaluate — Main entry point for Semi-NIDS decision.
    ///
    /// This is called for every packet/event after basic parsing.
    /// It implements ALL 3 core properties:
    ///
    /// Property 1 (Adaptive Dropping):
    ///   - Computes threat_score + confidence from cross-vector correlation
    ///   - Only blocks when score >= threshold AND confidence >= min_confidence
    ///   - Low confidence threats are AlertOnly, never blocked
    ///
    /// Property 2 (Fail-Open):
    ///   - If system overloaded → pass clean traffic through
    ///   - Only continue analyzing traffic with risk flags
    ///
    /// Property 3 (Interactive Control Loop):
    ///   - For medium-confidence threats, queue alert for human review
    ///   - Human can [Block], [Whitelist], or [Ignore]
    ///   - Until human decides, only alert (don't block)
    ///
    pub fn evaluate(
        &self,
        src_ip: u32,
        dst_ip: u32,
        threat_score: f64,
        confidence: Confidence,
        risk_flags: u32,
        reason: u32,
        session_id: u64,
    ) -> ThreatAssessment {
        self.total_evaluated.fetch_add(1, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // ── Property 2: Fail-Open Check ──
        if self.fail_open.should_pass_through(risk_flags) {
            self.total_fail_open_passes.fetch_add(1, Ordering::Relaxed);
            return ThreatAssessment {
                threat_score, confidence,
                decision: SemiNidsDecision::Pass,
                reason, session_id, src_ip, dst_ip,
                timestamp_ns: now,
            };
        }

        // ── Check whitelisted IPs ──
        if self.policy.is_whitelisted(src_ip) {
            self.total_passed.fetch_add(1, Ordering::Relaxed);
            return ThreatAssessment {
                threat_score: 0.0, confidence: Confidence::Unknown,
                decision: SemiNidsDecision::Pass,
                reason: 0, session_id, src_ip, dst_ip,
                timestamp_ns: now,
            };
        }

        // ── Check already-blocked IPs ──
        if self.policy.is_blocked(src_ip) {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            return ThreatAssessment {
                threat_score, confidence,
                decision: SemiNidsDecision::Block,
                reason, session_id, src_ip, dst_ip,
                timestamp_ns: now,
            };
        }

        // ── Property 1: Adaptive & Threshold-based Dropping ──
        let thresholds = self.thresholds.read().unwrap().clone();

        let decision = if threat_score >= thresholds.block_preserve_threshold
            && confidence >= Confidence::Critical
        {
            // Certain threat at critical level → Block + preserve evidence
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            self.policy.block_ip_temporary(src_ip, thresholds.temp_block_duration_secs);

            // Forensic preservation
            if let Ok(mut hasher) = self.forensic.lock() {
                let evidence = format!("BLOCK:{}:{}:{}:{},score={}", src_ip, dst_ip, reason, session_id, threat_score);
                hasher.hash_evidence(now / 1_000_000, evidence.as_bytes());
            }

            SemiNidsDecision::BlockAndPreserve
        } else if threat_score >= thresholds.block_threshold
            && confidence >= thresholds.min_block_confidence
        {
            // High confidence threat → Block at kernel level
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            self.policy.block_ip_temporary(src_ip, thresholds.temp_block_duration_secs);
            SemiNidsDecision::Block
        } else if threat_score >= thresholds.rate_limit_threshold
            && confidence >= Confidence::Medium
        {
            // Medium confidence → Rate limit (soft block)
            self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
            self.policy.block_ip_temporary(src_ip, 60); // 1 min rate limit
            SemiNidsDecision::RateLimit
        } else if threat_score >= thresholds.alert_threshold {
            // Below blocking threshold → Alert only
            self.total_alerted.fetch_add(1, Ordering::Relaxed);

            // ── Property 3: Interactive Control Loop ──
            // For medium-confidence alerts, queue for human review
            if confidence >= Confidence::Medium && confidence < Confidence::High {
                // Add to pending alerts queue for human review
                let assessment = ThreatAssessment {
                    threat_score, confidence, decision: SemiNidsDecision::PendingHuman,
                    reason, session_id, src_ip, dst_ip, timestamp_ns: now,
                };
                self.policy.add_pending_alert(&assessment, b"auto-queued");
                SemiNidsDecision::PendingHuman
            } else {
                SemiNidsDecision::AlertOnly
            }
        } else {
            // Below alert threshold → Pass
            self.total_passed.fetch_add(1, Ordering::Relaxed);
            SemiNidsDecision::Pass
        };

        ThreatAssessment {
            threat_score, confidence, decision,
            reason, session_id, src_ip, dst_ip,
            timestamp_ns: now,
        }
    }

    /// set_policy — Human makes decision on a pending alert.
    pub fn set_policy(&self, alert_id: u64, decision: HumanDecision) -> i32 {
        self.total_human_decisions.fetch_add(1, Ordering::Relaxed);
        self.policy.resolve_alert(alert_id, decision)
    }

    /// update_load — From Go perf monitor (called every 1 second).
    pub fn update_load(&self, cpu_pct: u8, queue_pct: u8, pps: u64) {
        self.fail_open.update_load(cpu_pct, queue_pct, pps);
    }

    /// get_stats — Return engine statistics.
    pub fn get_stats(&self) -> SemiNidsStats {
        let (perm_blocks, temp_blocks) = self.policy.get_blocked_count();
        SemiNidsStats {
            total_evaluated: self.total_evaluated.load(Ordering::Relaxed),
            total_passed: self.total_passed.load(Ordering::Relaxed),
            total_alerted: self.total_alerted.load(Ordering::Relaxed),
            total_blocked: self.total_blocked.load(Ordering::Relaxed),
            total_rate_limited: self.total_rate_limited.load(Ordering::Relaxed),
            total_fail_open_passes: self.total_fail_open_passes.load(Ordering::Relaxed),
            total_human_decisions: self.total_human_decisions.load(Ordering::Relaxed),
            permanent_blocks: perm_blocks as u32,
            temporary_blocks: temp_blocks as u32,
            fail_open_active: self.fail_open.is_fail_open(),
            load_state: self.fail_open.get_load_state(),
            current_pps: self.fail_open.current_pps.load(Ordering::Relaxed),
        }
    }

    /// expire_temp_blocks — Periodic cleanup.
    pub fn expire_temp_blocks(&self) -> u32 {
        self.policy.expire_temp_blocks()
    }
}

// ─── Statistics ──

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SemiNidsStats {
    pub total_evaluated: u64,
    pub total_passed: u64,
    pub total_alerted: u64,
    pub total_blocked: u64,
    pub total_rate_limited: u64,
    pub total_fail_open_passes: u64,
    pub total_human_decisions: u64,
    pub permanent_blocks: u32,
    pub temporary_blocks: u32,
    pub fail_open_active: bool,
    pub load_state: LoadState,
    pub current_pps: u64,
}

// ═══════════════════════════════════════════════════════════════
// C-ABI FFI Exports
// ═══════════════════════════════════════════════════════════════

use std::sync::OnceLock;

static G_SEMI_NIDS: OnceLock<SemiNidsEngine> = OnceLock::new();
static G_SEMI_INIT: AtomicBool = AtomicBool::new(false);

/// Initialize the Semi-NIDS engine.
#[no_mangle]
pub extern "C" fn aegis_semi_nids_init() -> i32 {
    let _ = G_SEMI_NIDS.set(SemiNidsEngine::new());
    G_SEMI_INIT.store(true, Ordering::Release);
    0
}

/// Evaluate a threat and return decision.
/// Returns: SemiNidsDecision as u8 (0=Pass, 1=Alert, 2=RateLimit, 3=Block, 4=BlockPreserve, 5=PendingHuman)
///
/// Full 5-tuple is passed for port-based detection (e.g., suspicious ports 4444, 5555, 31337).
#[no_mangle]
pub extern "C" fn aegis_semi_nids_evaluate(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
    threat_score: f64,
    confidence: u8,    // 0-4 mapping to Confidence enum
    risk_flags: u32,
    process_id: u32,
) -> u8 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return 0; }

    let conf = match confidence {
        0 => Confidence::Unknown,
        1 => Confidence::Low,
        2 => Confidence::Medium,
        3 => Confidence::High,
        _ => Confidence::Critical,
    };

    // Check for suspicious ports (add to risk_flags)
    let effective_risk_flags = if dst_port == 4444 || dst_port == 5555
        || dst_port == 6667 || dst_port == 31337
        || dst_port == 4443 || dst_port == 8443
    {
        risk_flags | 0x01  // Flag as suspicious port
    } else {
        risk_flags
    };

    // Generate a session_id from the 5-tuple + PID for correlation
    let session_id = (src_ip as u64)
        .wrapping_shl(32) | (dst_ip as u64)
        ^ ((src_port as u64) << 16 | dst_port as u64)
        ^ (process_id as u64);

    if let Some(engine) = G_SEMI_NIDS.get() {
        let result = engine.evaluate(
            src_ip, dst_ip, threat_score, conf,
            effective_risk_flags, 1,  // reason=1 (from FFI)
            session_id,
        );

        // If PendingHuman, add to pending queue
        if result.decision == SemiNidsDecision::PendingHuman {
            let desc = format!(
                "Threat score={:.1}, confidence={:?}, src={}.{}.{}.{}:{} → {}.{}.{}.{}:{}, proto={}",
                threat_score, conf,
                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
                (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, dst_port,
                ip_proto,
            );
            engine.policy.add_pending_alert(&result, desc.as_bytes());
        }

        result.decision as u8
    } else {
        0
    }
}

/// Human sets policy on a pending alert.
/// decision: 1=Block, 2=BlockTemp, 3=Whitelist, 4=Ignore, 5=Escalate
#[no_mangle]
pub extern "C" fn aegis_semi_nids_set_policy(alert_id: u64, decision: u8) -> i32 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return -1; }

    let hd = match decision {
        1 => HumanDecision::Block,
        2 => HumanDecision::BlockTemp,
        3 => HumanDecision::Whitelist,
        4 => HumanDecision::Ignore,
        5 => HumanDecision::Escalate,
        _ => return -2,
    };

    if let Some(engine) = G_SEMI_NIDS.get() {
        engine.set_policy(alert_id, hd)
    } else {
        -1
    }
}

/// Get number of pending alerts (for console/UI polling).
#[no_mangle]
pub extern "C" fn aegis_semi_nids_get_pending_count() -> u32 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return 0; }
    if let Some(engine) = G_SEMI_NIDS.get() {
        engine.policy.get_pending_alerts(999).len() as u32
    } else {
        0
    }
}

/// Get pending alert details by index (for console polling).
/// Writes alert data to output buffer.
#[no_mangle]
pub extern "C" fn aegis_semi_nids_get_pending(
    index: u32,
    out_alert_id: *mut u64,
    out_src_ip: *mut u32,
    out_threat_score: *mut f64,
    out_confidence: *mut u8,
    out_decision: *mut u8,
) -> i32 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return -1; }
    if out_alert_id.is_null() || out_src_ip.is_null() { return -1; }

    if let Some(engine) = G_SEMI_NIDS.get() {
        let alerts = engine.policy.get_pending_alerts((index + 1) as usize);
        if let Some(alert) = alerts.get(index as usize) {
            unsafe {
                *out_alert_id = alert.alert_id;
                *out_src_ip = alert.src_ip;
                if !out_threat_score.is_null() { *out_threat_score = alert.threat_score; }
                if !out_confidence.is_null() { *out_confidence = alert.confidence as u8; }
                if !out_decision.is_null() { *out_decision = alert.decision as u8; }
            }
            return 0;
        }
    }
    -1
}

/// Query fail-open status with full detail.
/// Returns: 0=normal, 1=elevated, 2=overloaded, 3=critical
/// Also outputs: fail_open_active, cpu_pct, queue_pct via pointers.
#[no_mangle]
pub extern "C" fn aegis_semi_nids_fail_open_status(
    out_active: *mut bool,
    out_cpu_pct: *mut u8,
    out_queue_pct: *mut u8,
) -> u8 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return 0; }
    if let Some(engine) = G_SEMI_NIDS.get() {
        let state = engine.fail_open.get_load_state();
        let active = engine.fail_open.is_fail_open();
        let cpu = engine.fail_open.cpu_percent.load(Ordering::Relaxed);
        let queue = engine.fail_open.queue_fill_percent.load(Ordering::Relaxed);
        unsafe {
            if !out_active.is_null() { *out_active = active; }
            if !out_cpu_pct.is_null() { *out_cpu_pct = cpu; }
            if !out_queue_pct.is_null() { *out_queue_pct = queue; }
        }
        state as u8
    } else {
        0
    }
}

/// Update load from Go perf monitor (called every 1 second).
#[no_mangle]
pub extern "C" fn aegis_semi_nids_update_load(cpu_pct: u8, queue_pct: u8, pps: u64) {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return; }
    if let Some(engine) = G_SEMI_NIDS.get() {
        engine.update_load(cpu_pct, queue_pct, pps);
    }
}

/// Block an IP immediately (from console or UI button).
#[no_mangle]
pub extern "C" fn aegis_semi_nids_block_ip(ip: u32, reason: u32) -> i32 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return -1; }
    if let Some(engine) = G_SEMI_NIDS.get() {
        engine.policy.block_ip_permanent(ip, reason, [0u8; 32]);
        0
    } else {
        -1
    }
}

/// Unblock/whitelist an IP.
#[no_mangle]
pub extern "C" fn aegis_semi_nids_unblock_ip(ip: u32) -> i32 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return -1; }
    if let Some(engine) = G_SEMI_NIDS.get() {
        engine.policy.unblock_ip(ip);
        0
    } else {
        -1
    }
}

/// Get engine statistics.
#[no_mangle]
pub extern "C" fn aegis_semi_nids_get_stats(out_stats: *mut SemiNidsStats) -> i32 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return -1; }
    if out_stats.is_null() { return -1; }
    if let Some(engine) = G_SEMI_NIDS.get() {
        unsafe { *out_stats = engine.get_stats(); }
        return 0;
    }
    -1
}

/// Periodic maintenance — expire temp blocks, etc.
#[no_mangle]
pub extern "C" fn aegis_semi_nids_maintenance() -> u32 {
    if !G_SEMI_INIT.load(Ordering::Acquire) { return 0; }
    if let Some(engine) = G_SEMI_NIDS.get() {
        engine.expire_temp_blocks()
    } else {
        0
    }
}

/// Shutdown Semi-NIDS engine.
#[no_mangle]
pub extern "C" fn aegis_semi_nids_shutdown() {
    G_SEMI_INIT.store(false, Ordering::Release);
    // OnceLock cannot be "unset" — the engine remains but is marked inactive
    // This is safe: all FFI functions check G_SEMI_INIT first
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_dropping_high_confidence_blocks() {
        let engine = SemiNidsEngine::new();

        // Critical confidence + high score → BlockAndPreserve
        let result = engine.evaluate(
            0xC0A80A01, 0xC0A80A02,  // 192.168.10.1 → 192.168.10.2
            85.0,                      // threat_score
            Confidence::Critical,     // confidence
            0x01,                      // risk_flags
            1,                         // reason
            100,                       // session_id
        );
        assert_eq!(result.decision, SemiNidsDecision::BlockAndPreserve);
    }

    #[test]
    fn test_adaptive_dropping_low_confidence_alerts_only() {
        let engine = SemiNidsEngine::new();

        // Low confidence + high score → AlertOnly (NOT blocked!)
        let result = engine.evaluate(
            0xC0A80A01, 0xC0A80A02,
            65.0,                      // High score but...
            Confidence::Low,          // ...low confidence
            0x01, 1, 100,
        );
        assert_eq!(result.decision, SemiNidsDecision::AlertOnly);
    }

    #[test]
    fn test_adaptive_dropping_medium_confidence_pending_human() {
        let engine = SemiNidsEngine::new();

        // Medium confidence → PendingHuman (Property 3: Interactive Control)
        let result = engine.evaluate(
            0xC0A80A01, 0xC0A80A02,
            35.0,
            Confidence::Medium,
            0x01, 1, 100,
        );
        assert_eq!(result.decision, SemiNidsDecision::PendingHuman);
    }

    #[test]
    fn test_fail_open_passes_clean_traffic() {
        let engine = SemiNidsEngine::new();

        // Simulate overload
        engine.update_load(90, 96, 500_000);

        // Clean traffic (no risk flags) → Pass (fail-open)
        let result = engine.evaluate(
            0xC0A80A01, 0xC0A80A02,
            0.0,                       // No threat
            Confidence::Unknown,
            0,                          // NO risk flags → pass through
            0, 100,
        );
        assert_eq!(result.decision, SemiNidsDecision::Pass);
    }

    #[test]
    fn test_fail_open_still_analyzes_risky_traffic() {
        let engine = SemiNidsEngine::new();

        // Simulate overload
        engine.update_load(90, 96, 500_000);

        // Risky traffic (has risk flags) → Still evaluated even in fail-open
        let result = engine.evaluate(
            0xC0A80A01, 0xC0A80A02,
            85.0,
            Confidence::Critical,
            0x01,                       // HAS risk flags → still analyzed
            1, 100,
        );
        // Should be BlockAndPreserve, not Pass
        assert_eq!(result.decision, SemiNidsDecision::BlockAndPreserve);
    }

    #[test]
    fn test_whitelist_overrides_blocking() {
        let engine = SemiNidsEngine::new();
        let ip = 0xC0A80A01;

        // Whitelist the IP
        engine.policy.whitelist_ip(ip, 0);

        // Even critical threat → Pass (whitelisted)
        let result = engine.evaluate(
            ip, 0xC0A80A02,
            95.0,
            Confidence::Critical,
            0x01, 1, 100,
        );
        assert_eq!(result.decision, SemiNidsDecision::Pass);
    }

    #[test]
    fn test_human_decision_block() {
        let engine = SemiNidsEngine::new();

        // Create a PendingHuman alert
        let result = engine.evaluate(
            0xC0A80A01, 0xC0A80A02,
            35.0,
            Confidence::Medium,
            0x01, 1, 100,
        );
        assert_eq!(result.decision, SemiNidsDecision::PendingHuman);

        // Get pending alerts
        let alerts = engine.policy.get_pending_alerts(10);
        assert!(!alerts.is_empty());
        let alert_id = alerts[0].alert_id;

        // Human decides to block
        let rc = engine.set_policy(alert_id, HumanDecision::Block);
        assert_eq!(rc, 0);

        // Now the IP should be blocked
        assert!(engine.policy.is_blocked(0xC0A80A01));
    }

    #[test]
    fn test_temp_block_expiry() {
        let engine = SemiNidsEngine::new();
        let ip = 0xC0A80A01;

        // Temporary block for 0 seconds (immediate expiry)
        engine.policy.block_ip_temporary(ip, 0);

        // Wait a tiny bit for time to advance
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Expire should remove it
        let expired = engine.expire_temp_blocks();
        assert!(expired >= 1);
        assert!(!engine.policy.is_blocked(ip));
    }

    #[test]
    fn test_decision_threshold_ladder() {
        let engine = SemiNidsEngine::new();

        // Score 10 → Pass
        let r1 = engine.evaluate(1, 2, 10.0, Confidence::High, 0x01, 1, 1);
        assert_eq!(r1.decision, SemiNidsDecision::Pass);

        // Score 25 (alert threshold) → AlertOnly (High confidence, not Medium)
        let r2 = engine.evaluate(3, 4, 25.0, Confidence::High, 0x01, 1, 2);
        assert_eq!(r2.decision, SemiNidsDecision::AlertOnly);

        // Score 45 (rate limit threshold) + Medium confidence → RateLimit
        let r3 = engine.evaluate(5, 6, 45.0, Confidence::Medium, 0x01, 1, 3);
        assert_eq!(r3.decision, SemiNidsDecision::RateLimit);

        // Score 65 (block threshold) + High confidence → Block
        let r4 = engine.evaluate(7, 8, 65.0, Confidence::High, 0x01, 1, 4);
        assert_eq!(r4.decision, SemiNidsDecision::Block);

        // Score 85 (block+preserve threshold) + Critical confidence → BlockAndPreserve
        let r5 = engine.evaluate(9, 10, 85.0, Confidence::Critical, 0x01, 1, 5);
        assert_eq!(r5.decision, SemiNidsDecision::BlockAndPreserve);
    }
}
