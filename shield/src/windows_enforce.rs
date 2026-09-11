//! windows_enforce.rs - AEGIS Windows Enforcement Adapter (P4 / Phase K)
//!
//! Userspace half of the Windows enforcement path inside the Rust PEP
//! (shield). Bridges the decision plane to the WFP driver through
//! IOCTLs, with a netsh firewall fallback, and mirrors the driver's
//! blocklist/whitelist/fail-open semantics exactly.
//!
//! Contract sources (must stay in parity):
//!   - kernel/wfp/aegis_wfp.c   (IOCTL codes 0x800..0x807, thresholds)
//!   - core/wfp_production.zig  (Zig side of the same contract)
//!
//! Host-neutral core (decision engine, blocklist state, command
//! encoding, netsh builder) is pure std and fully tested on any OS.
//! The Win32 transport (CreateFile/DeviceIoControl FFI) is gated
//! behind #[cfg(windows)] and never executed by tests.
//!
//! Fail-closed rules:
//!   - whitelisted IPs can never be blocked
//!   - fail-open passes everything but never mutates block state
//!   - block table capacity is enforced (1024) like the driver

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

// ============================================================
// Driver contract constants (parity with aegis_wfp.c)
// ============================================================

pub const IOCTL_AEGIS_GET_RING_ADDR: u32 = 0x800;
pub const IOCTL_AEGIS_GET_STATS: u32 = 0x801;
pub const IOCTL_AEGIS_SEMI_BLOCK_IP: u32 = 0x802;
pub const IOCTL_AEGIS_SEMI_UNBLOCK_IP: u32 = 0x803;
pub const IOCTL_AEGIS_SEMI_SET_THRESHOLDS: u32 = 0x804;
pub const IOCTL_AEGIS_SEMI_GET_STATE: u32 = 0x805;
pub const IOCTL_AEGIS_SEMI_SET_FAILOPEN: u32 = 0x806;
pub const IOCTL_AEGIS_SEMI_WHITELIST_IP: u32 = 0x807;

/// Driver defaults: score is x10 fixed point (600 = 60.0).
pub const DEFAULT_BLOCK_THRESHOLD: i32 = 600;
pub const DEFAULT_RATELIMIT_THRESHOLD: i32 = 400;
pub const DEFAULT_ALERT_THRESHOLD: i32 = 200;

pub const MAX_BLOCKS: usize = 1024; // SEMI_NIDS_MAX_TEMP_BLOCKS
pub const BLOCK_DURATION_MS: u64 = 300_000; // 5 minutes
pub const FAIL_OPEN_CPU_THRESHOLD: u8 = 85;
pub const FAIL_OPEN_QUEUE_THRESHOLD: u8 = 95;

pub const DEVICE_PATH: &str = "\\\\.\\AegisWfp";

// ============================================================
// Decision plane (parity with wfp_production.enforcementDecision)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Confidence {
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Confidence {
    pub fn from_u8(v: u8) -> Confidence {
        match v {
            0 => Confidence::Unknown,
            1 => Confidence::Low,
            2 => Confidence::Medium,
            3 => Confidence::High,
            _ => Confidence::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Allow = 0,
    Alert = 1,
    RateLimit = 2,
    Block = 3,
}

/// Deterministic enforcement decision. Parity vectors are asserted
/// against the Zig implementation in tests.
pub fn decide(score_x10: i32, conf: Confidence, fail_open: bool) -> Action {
    if fail_open {
        return Action::Allow;
    }
    if score_x10 >= DEFAULT_BLOCK_THRESHOLD
        && (conf as u8) >= (Confidence::High as u8)
    {
        return Action::Block;
    }
    if score_x10 >= DEFAULT_RATELIMIT_THRESHOLD
        && (conf as u8) >= (Confidence::Medium as u8)
    {
        return Action::RateLimit;
    }
    if score_x10 >= DEFAULT_ALERT_THRESHOLD {
        return Action::Alert;
    }
    Action::Allow
}

/// Fail-open rule: Property 2 of the driver.
pub fn fail_open_active(cpu_pct: u8, queue_pct: u8) -> bool {
    cpu_pct >= FAIL_OPEN_CPU_THRESHOLD || queue_pct >= FAIL_OPEN_QUEUE_THRESHOLD
}

// ============================================================
// Blocklist state (mirror of SEMI_NIDS_STATE semantics)
// ============================================================

#[derive(Debug, Default)]
pub struct EnforceState {
    /// Permanent blocks (driver perm_blocks). Insertion-ordered cap.
    perm_blocks: HashSet<u32>,
    perm_order: Vec<u32>,
    /// Temporary blocks keyed by IP with expiry ms (0 = permanent).
    temp_blocks: HashMap<u32, u64>,
    /// Whitelisted IPs (driver whitelist).
    whitelist: HashSet<u32>,
    thresholds: (i32, i32, i32),
}

impl EnforceState {
    pub fn new() -> EnforceState {
        EnforceState {
            perm_blocks: HashSet::new(),
            perm_order: Vec::new(),
            temp_blocks: HashMap::new(),
            whitelist: HashSet::new(),
            thresholds: (
                DEFAULT_BLOCK_THRESHOLD,
                DEFAULT_RATELIMIT_THRESHOLD,
                DEFAULT_ALERT_THRESHOLD,
            ),
        }
    }

    pub fn set_thresholds(&mut self, block: i32, ratelimit: i32, alert: i32) {
        self.thresholds = (block, ratelimit, alert);
    }

    pub fn thresholds(&self) -> (i32, i32, i32) {
        self.thresholds
    }

    /// Permanent block. Whitelisted IPs are refused (fail-closed),
    /// duplicates are ignored, capacity is capped at MAX_BLOCKS.
    pub fn block_ip(&mut self, ip: u32) -> bool {
        if self.whitelist.contains(&ip) || self.perm_blocks.contains(&ip) {
            return false;
        }
        if self.perm_order.len() >= MAX_BLOCKS {
            return false;
        }
        if self.perm_blocks.insert(ip) {
            self.perm_order.push(ip);
            return true;
        }
        false
    }

    /// Unblock: removes from both tables and whitelists the IP,
    /// exactly like IOCTL_AEGIS_SEMI_UNBLOCK_IP in the driver.
    pub fn unblock_ip(&mut self, ip: u32) -> bool {
        let was = self.perm_blocks.remove(&ip) | self.temp_blocks.remove(&ip).is_some();
        if self.whitelist.insert(ip) {
            return true;
        }
        was
    }

    /// Temporary block with expiry (expires_at_ms == 0 -> permanent).
    pub fn temp_block_ip(&mut self, ip: u32, expires_at_ms: u64) -> bool {
        if self.whitelist.contains(&ip) {
            return false;
        }
        if self.temp_blocks.contains_key(&ip) {
            return false;
        }
        if self.perm_blocks.contains(&ip) {
            return false;
        }
        if self.temp_blocks.len() >= MAX_BLOCKS {
            return false;
        }
        self.temp_blocks.insert(ip, expires_at_ms);
        true
    }

    /// Whitelist only (IOCTL_AEGIS_SEMI_WHITELIST_IP semantics).
    pub fn whitelist_ip(&mut self, ip: u32) -> bool {
        self.whitelist.insert(ip)
    }

    /// Drop expired temporary blocks; returns how many were removed.
    pub fn expire_temp(&mut self, now_ms: u64) -> usize {
        let expired: Vec<u32> = self
            .temp_blocks
            .iter()
            .filter(|(_, &exp)| exp != 0 && exp <= now_ms)
            .map(|(&ip, _)| ip)
            .collect();
        for ip in &expired {
            self.temp_blocks.remove(ip);
        }
        expired.len()
    }

    /// Should this IP be dropped right now? Whitelist always passes;
    /// fail-open passes everything without touching state.
    pub fn should_drop(&self, ip: u32, now_ms: u64, fail_open: bool) -> bool {
        if fail_open {
            return false;
        }
        if self.whitelist.contains(&ip) {
            return false;
        }
        if self.perm_blocks.contains(&ip) {
            return true;
        }
        match self.temp_blocks.get(&ip) {
            Some(&0) => true,
            Some(&exp) => exp > now_ms,
            None => false,
        }
    }

    pub fn perm_block_count(&self) -> usize {
        self.perm_blocks.len()
    }

    pub fn temp_block_count(&self) -> usize {
        self.temp_blocks.len()
    }

    pub fn whitelist_count(&self) -> usize {
        self.whitelist.len()
    }
}

// ============================================================
// Command layer: IOCTL encoding + netsh fallback builder
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    BlockIp(u32),
    UnblockIp(u32),
    WhitelistIp(u32),
    /// (block, ratelimit, alert) x10 fixed point.
    SetThresholds(i32, i32, i32),
    SetFailOpen(bool),
}

impl Command {
    pub fn ioctl_code(&self) -> u32 {
        match self {
            Command::BlockIp(_) => IOCTL_AEGIS_SEMI_BLOCK_IP,
            Command::UnblockIp(_) => IOCTL_AEGIS_SEMI_UNBLOCK_IP,
            Command::WhitelistIp(_) => IOCTL_AEGIS_SEMI_WHITELIST_IP,
            Command::SetThresholds(_, _, _) => IOCTL_AEGIS_SEMI_SET_THRESHOLDS,
            Command::SetFailOpen(_) => IOCTL_AEGIS_SEMI_SET_FAILOPEN,
        }
    }

    /// Little-endian input payload, matching the driver's length
    /// checks (ULONG = 4 bytes, SEMI_NIDS_THRESHOLDS = 12 bytes,
    /// BOOLEAN = 1 byte).
    pub fn payload(&self) -> Vec<u8> {
        match self {
            Command::BlockIp(ip)
            | Command::UnblockIp(ip)
            | Command::WhitelistIp(ip) => ip.to_le_bytes().to_vec(),
            Command::SetThresholds(b, r, a) => {
                let mut v = Vec::with_capacity(12);
                v.extend_from_slice(&b.to_le_bytes());
                v.extend_from_slice(&r.to_le_bytes());
                v.extend_from_slice(&a.to_le_bytes());
                v
            }
            Command::SetFailOpen(flag) => vec![*flag as u8],
        }
    }

    /// netsh firewall fallback (used when the driver is absent).
        /// Real, runnable command text - kept as a pure builder so it
    /// is testable on every OS.
    pub fn netsh_fallback(&self) -> String {
        match self {
            Command::BlockIp(ip) => format!(
                "netsh advfirewall firewall add rule name=\"AEGIS block {}\" dir=out action=block remoteip={}",
                format_ipv4(*ip),
                format_ipv4(*ip)
            ),
            Command::UnblockIp(ip) => format!(
                "netsh advfirewall firewall delete rule name=\"AEGIS block {}\"",
                format_ipv4(*ip)
            ),
            Command::WhitelistIp(ip) => format!(
                "netsh advfirewall firewall set rule name=\"AEGIS block {}\" new action=allow",
                format_ipv4(*ip)
            ),
            Command::SetThresholds(_, _, _) => String::from(
                "aegisctl policy set-thresholds (no netsh equivalent; driver IOCTL only)",
            ),
            Command::SetFailOpen(flag) => format!(
                "aegisctl enforce fail-open {}",
                if *flag { "on" } else { "off" }
            ),
        }
    }
}

/// Format a driver-order IPv4 (u32, most significant byte = first
/// octet) as dotted quad. 0x7F000001 -> "127.0.0.1".
pub fn format_ipv4(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

// ============================================================
// Audit trail (provenance for every enforcement action)
// ============================================================

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub ts_ms: u64,
    pub text: String,
}

pub const AUDIT_CAP: usize = 256;

#[derive(Debug)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    dropped: u64,
}

impl AuditLog {
    fn new() -> AuditLog {
        AuditLog {
            entries: Vec::new(),
            dropped: 0,
        }
    }

    fn push(&mut self, ts_ms: u64, text: String) {
        if self.entries.len() >= AUDIT_CAP {
            self.entries.remove(0);
            self.dropped += 1;
        }
        self.entries.push(AuditEntry { ts_ms, text });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn last(&self) -> Option<&AuditEntry> {
        self.entries.last()
    }
}

// ============================================================
// Global state + extern "C" surface (shield cdylib pattern)
// ============================================================

static FAIL_OPEN: AtomicBool = AtomicBool::new(false);

fn state() -> &'static Mutex<EnforceState> {
    static CELL: std::sync::OnceLock<Mutex<EnforceState>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| Mutex::new(EnforceState::new()))
}

fn audit() -> &'static Mutex<AuditLog> {
    static CELL: std::sync::OnceLock<Mutex<AuditLog>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| Mutex::new(AuditLog::new()))
}

/// Apply a command to the in-process mirror state and the (optional)
/// kernel path. Returns true when the mirror state changed.
pub fn apply(cmd: &Command, ts_ms: u64) -> bool {
    let mut st = state().lock().unwrap();
    let changed = match cmd {
        Command::BlockIp(ip) => {
            let ok = st.block_ip(*ip);
            audit().lock().unwrap().push(
                ts_ms,
                format!("block_ip {} {}", format_ipv4(*ip), if ok { "ok" } else { "refused" }),
            );
            ok
        }
        Command::UnblockIp(ip) => {
            let ok = st.unblock_ip(*ip);
            audit().lock().unwrap().push(
                ts_ms,
                format!("unblock_ip {} {}", format_ipv4(*ip), if ok { "ok" } else { "noop" }),
            );
            ok
        }
        Command::WhitelistIp(ip) => {
            let ok = st.whitelist_ip(*ip);
            audit().lock().unwrap().push(
                ts_ms,
                format!("whitelist_ip {} {}", format_ipv4(*ip), if ok { "ok" } else { "noop" }),
            );
            ok
        }
        Command::SetThresholds(b, r, a) => {
            st.set_thresholds(*b, *r, *a);
            audit().lock().unwrap().push(
                ts_ms,
                format!("set_thresholds {} {} {}", b, r, a),
            );
            true
        }
        Command::SetFailOpen(flag) => {
            FAIL_OPEN.store(*flag, Ordering::SeqCst);
            audit().lock().unwrap().push(
                ts_ms,
                format!("set_fail_open {}", if *flag { "on" } else { "off" }),
            );
            true
        }
    };
    changed
}

pub fn set_fail_open(flag: bool) {
    FAIL_OPEN.store(flag, Ordering::SeqCst);
}

pub fn fail_open() -> bool {
    FAIL_OPEN.load(Ordering::SeqCst)
}

pub fn should_drop(ip: u32, now_ms: u64) -> bool {
    let st = state().lock().unwrap();
    st.should_drop(ip, now_ms, fail_open())
}

/// Decide + record for one evaluated flow. Returns the action code
/// (0 allow / 1 alert / 2 rate_limit / 3 block).
pub fn decide_and_record(score_x10: i32, confidence: u8, ts_ms: u64) -> u32 {
    let action = decide(score_x10, Confidence::from_u8(confidence), fail_open());
    audit().lock().unwrap().push(
        ts_ms,
        format!(
            "decide score={} conf={} -> {:?}",
            score_x10, confidence, action
        ),
    );
    action as u32
}

// ============================================================
// Win32 transport (compiled on Windows only, never run in tests)
// ============================================================

#[cfg(windows)]
mod win_transport {
    use super::{Command, DEVICE_PATH};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::RawHandle;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lpfilename: *const u16,
            dwdesiredaccess: u32,
            dwsharemode: u32,
            lpsecurityattributes: *const u8,
            dwcreationdisposition: u32,
            dwflagsandattributes: u32,
            htemplatefile: RawHandle,
        ) -> RawHandle;
        fn DeviceIoControl(
            hdevice: RawHandle,
            dwiocontrolcode: u32,
            lpinbuffer: *const u8,
            ninbuffersize: u32,
            lpoutbuffer: *mut u8,
            noutbuffersize: u32,
            lpbytesreturned: *mut u32,
            lpoverlapped: *const u8,
        ) -> i32;
        fn CloseHandle(hobject: RawHandle) -> i32;
    }

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: RawHandle = usize::MAX as RawHandle;

    /// Send one command to \\.\\AegisWfp via DeviceIoControl.
    pub fn send(cmd: &Command) -> Result<u32, String> {
        let wide: Vec<u16> = std::ffi::OsStr::new(DEVICE_PATH)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!("open {} failed (driver not loaded?)", DEVICE_PATH));
        }
        let payload = cmd.payload();
        let mut out = [0u8; 64];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                cmd.ioctl_code(),
                payload.as_ptr(),
                payload.len() as u32,
                out.as_mut_ptr(),
                out.len() as u32,
                &mut returned,
                std::ptr::null(),
            )
        };
        unsafe {
            CloseHandle(handle);
        }
        if ok == 0 {
            Err(format!("ioctl 0x{:X} failed", cmd.ioctl_code()))
        } else {
            Ok(returned)
        }
    }
}

/// Apply through the kernel when available, netsh fallback otherwise.
/// Host-neutral: on non-Windows this always returns the fallback text.
pub fn enforce(cmd: &Command, ts_ms: u64) -> Result<String, String> {
    let mirror_changed = apply(cmd, ts_ms);
    #[cfg(windows)]
    {
        match win_transport::send(cmd) {
            Ok(_) => return Ok(format!("kernel ok (mirror={})", mirror_changed)),
            Err(_) => {} // fall through to netsh
        }
    }
    Ok(format!("fallback: {}", cmd.netsh_fallback()))
}

// ============================================================
// extern "C" surface (same cdylib pattern as lib.rs)
// ============================================================

#[no_mangle]
pub extern "C" fn aegis_enforce_decide(score_x10: i32, confidence: u8, ts_ms: u64) -> u32 {
    decide_and_record(score_x10, confidence, ts_ms)
}

#[no_mangle]
pub extern "C" fn aegis_enforce_block_ip(ip: u32, ts_ms: u64) -> i32 {
    if apply(&Command::BlockIp(ip), ts_ms) {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn aegis_enforce_unblock_ip(ip: u32, ts_ms: u64) -> i32 {
    if apply(&Command::UnblockIp(ip), ts_ms) {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn aegis_enforce_whitelist_ip(ip: u32, ts_ms: u64) -> i32 {
    if apply(&Command::WhitelistIp(ip), ts_ms) {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn aegis_enforce_set_fail_open(flag: i32) -> i32 {
    set_fail_open(flag != 0);
    0
}

#[no_mangle]
pub extern "C" fn aegis_enforce_should_drop(ip: u32, now_ms: u64) -> i32 {
    if should_drop(ip, now_ms) {
        1
    } else {
        0
    }
}

// ============================================================
// Tests (cargo test - host-neutral, no Windows required)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_matrix_matches_zig_parity_vectors() {
        // Block: >= 600 AND confidence >= High.
        assert_eq!(decide(600, Confidence::High, false), Action::Block);
        assert_eq!(decide(950, Confidence::Critical, false), Action::Block);
        // High score, medium confidence -> rate limit only.
        assert_eq!(decide(900, Confidence::Medium, false), Action::RateLimit);
        // Rate limit: >= 400 AND >= Medium.
        assert_eq!(decide(400, Confidence::Medium, false), Action::RateLimit);
        assert_eq!(decide(400, Confidence::Low, false), Action::Alert);
        // Alert: >= 200, any confidence.
        assert_eq!(decide(200, Confidence::Unknown, false), Action::Alert);
        assert_eq!(decide(199, Confidence::Critical, false), Action::Allow);
        // Fail-open forces allow.
        assert_eq!(decide(990, Confidence::Critical, true), Action::Allow);
    }

    #[test]
    fn fail_open_triggers_at_driver_thresholds() {
        assert!(fail_open_active(85, 0));
        assert!(fail_open_active(10, 95));
        assert!(fail_open_active(100, 100));
        assert!(!fail_open_active(84, 94));
        assert!(!fail_open_active(0, 0));
    }

    #[test]
    fn ioctl_codes_and_payloads_match_driver() {
        let blk = Command::BlockIp(0x0100_000A);
        assert_eq!(blk.ioctl_code(), IOCTL_AEGIS_SEMI_BLOCK_IP);
        assert_eq!(blk.payload(), vec![0x0A, 0x00, 0x00, 0x01]);

        assert_eq!(
            Command::UnblockIp(1).ioctl_code(),
            IOCTL_AEGIS_SEMI_UNBLOCK_IP
        );
        assert_eq!(
            Command::WhitelistIp(1).ioctl_code(),
            IOCTL_AEGIS_SEMI_WHITELIST_IP
        );
        assert_eq!(
            Command::SetThresholds(600, 400, 200).ioctl_code(),
            IOCTL_AEGIS_SEMI_SET_THRESHOLDS
        );
        assert_eq!(
            Command::SetFailOpen(true).ioctl_code(),
            IOCTL_AEGIS_SEMI_SET_FAILOPEN
        );

        // Thresholds: 3 x i32 little-endian = 12 bytes.
        let th = Command::SetThresholds(600, 400, 200);
        assert_eq!(th.payload().len(), 12);
        assert_eq!(&th.payload()[0..4], &600i32.to_le_bytes());
        assert_eq!(&th.payload()[4..8], &400i32.to_le_bytes());
        assert_eq!(&th.payload()[8..12], &200i32.to_le_bytes());

        // Fail-open: 1 byte BOOLEAN.
        assert_eq!(Command::SetFailOpen(true).payload(), vec![1]);
        assert_eq!(Command::SetFailOpen(false).payload(), vec![0]);
    }

    #[test]
    fn netsh_fallback_builds_real_firewall_commands() {
        let blk = Command::BlockIp(0x7F00_0001); // 127.0.0.1
        let cmd = blk.netsh_fallback();
        assert!(cmd.starts_with("netsh advfirewall firewall add rule"));
        assert!(cmd.contains("action=block"));
        assert!(cmd.contains("127.0.0.1"));
        assert!(cmd.contains("AEGIS block 127.0.0.1"));

        let del = Command::UnblockIp(0x7F00_0001).netsh_fallback();
        assert!(del.starts_with("netsh advfirewall firewall delete rule"));
        assert!(del.contains("127.0.0.1"));
    }

    #[test]
    fn ipv4_format_uses_driver_byte_order() {
        assert_eq!(format_ipv4(0x7F00_0001), "127.0.0.1");
        assert_eq!(format_ipv4(0x0808_0808), "8.8.8.8");
        assert_eq!(format_ipv4(0xC0A8_0101), "192.168.1.1");
        assert_eq!(format_ipv4(0), "0.0.0.0");
    }

    #[test]
    fn block_unblock_whitelist_semantics_match_driver() {
        let mut st = EnforceState::new();
        // Block 10.0.0.1.
        assert!(st.block_ip(0x0A00_0001));
        assert!(!st.block_ip(0x0A00_0001)); // duplicate refused
        assert_eq!(st.perm_block_count(), 1);
        assert!(st.should_drop(0x0A00_0001, 1_000, false));

        // Unblock -> removed AND whitelisted (driver behavior).
        assert!(st.unblock_ip(0x0A00_0001));
        assert_eq!(st.perm_block_count(), 0);
        assert_eq!(st.whitelist_count(), 1);
        assert!(!st.should_drop(0x0A00_0001, 1_000, false));

        // Whitelisted IPs can never be blocked again (fail-closed).
        assert!(!st.block_ip(0x0A00_0001));
        assert_eq!(st.perm_block_count(), 0);
    }

    #[test]
    fn temp_blocks_expire_and_cap() {
        let mut st = EnforceState::new();
        assert!(st.temp_block_ip(0x0A00_0002, 5_000));
        assert!(st.should_drop(0x0A00_0002, 4_999, false));
        assert!(!st.should_drop(0x0A00_0002, 5_001, false));
        // Expired-but-present entry is swept by expire_temp.
        assert_eq!(st.expire_temp(6_000), 1);
        assert_eq!(st.temp_block_count(), 0);
        assert!(!st.should_drop(0x0A00_0002, 6_001, false));
        assert_eq!(st.expire_temp(6_002), 0); // nothing left to sweep

        // Permanent temp block (expires_at == 0).
        assert!(st.temp_block_ip(0x0A00_0003, 0));
        assert!(st.should_drop(0x0A00_0003, u64::MAX, false));

        // Capacity cap.
        let mut full = EnforceState::new();
        let mut i: u32 = 0;
        while i < MAX_BLOCKS as u32 {
            assert!(full.temp_block_ip(0x1000_0000 + i, 0));
            i += 1;
        }
        assert!(!full.temp_block_ip(0x2000_0000, 0));
        assert_eq!(full.temp_block_count(), MAX_BLOCKS);
    }

    #[test]
    fn blocklist_respects_driver_capacity() {
        let mut st = EnforceState::new();
        let mut i: u32 = 0;
        while i < MAX_BLOCKS as u32 {
            assert!(st.block_ip(0x3000_0000 + i));
            i += 1;
        }
        assert!(!st.block_ip(0x4000_0000));
        assert_eq!(st.perm_block_count(), MAX_BLOCKS);
    }

    #[test]
    fn fail_open_passes_everything_without_state_change() {
        let mut st = EnforceState::new();
        st.block_ip(0x0A00_0004);
        // Fail-open: even blocked IPs pass.
        assert!(!st.should_drop(0x0A00_0004, 0, true));
        // But state is untouched.
        assert_eq!(st.perm_block_count(), 1);
        assert!(st.should_drop(0x0A00_0004, 0, false));
    }

    #[test]
    fn apply_updates_mirror_and_audit() {
        // Fresh static state (test binary has its own process).
        assert!(apply(&Command::BlockIp(0x0A00_00F1), 100));
        assert!(should_drop(0x0A00_00F1, 100));
        // Duplicate is refused but still audited.
        assert!(!apply(&Command::BlockIp(0x0A00_00F1), 101));
        let log = audit().lock().unwrap();
        assert!(log.len() >= 2);
        let last = log.last().unwrap();
        assert!(last.text.contains("refused"));
        assert_eq!(last.ts_ms, 101);
    }

    #[test]
    fn decide_and_record_returns_action_codes() {
        set_fail_open(false);
        assert_eq!(decide_and_record(700, 3, 1), 3); // block
        assert_eq!(decide_and_record(450, 2, 2), 2); // rate limit
        assert_eq!(decide_and_record(250, 0, 3), 1); // alert
        assert_eq!(decide_and_record(100, 4, 4), 0); // allow
        set_fail_open(true);
        assert_eq!(decide_and_record(990, 4, 5), 0); // fail-open allow
        set_fail_open(false);
    }

    #[test]
    fn enforce_returns_fallback_text_off_windows() {
        // On Linux CI this exercises the fallback branch; on Windows
        // it will try the kernel first (driver absent -> fallback).
        let res = enforce(&Command::BlockIp(0x0808_0808), 42).unwrap();
        assert!(res.contains("8.8.8.8") || res.contains("kernel ok"));
    }

    #[test]
    fn audit_log_is_bounded() {
        let mut log = AuditLog::new();
        let mut i: u64 = 0;
        while i < (AUDIT_CAP as u64) + 50 {
            log.push(i, format!("entry {}", i));
            i += 1;
        }
        assert_eq!(log.len(), AUDIT_CAP);
        assert_eq!(log.dropped(), 50);
        assert!(log.last().unwrap().text.contains("entry 305"));
    }
}
