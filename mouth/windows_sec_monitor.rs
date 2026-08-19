// =====================================================================
// windows_sec_monitor.rs — AEGIS MOUTH (Rust) v3.0
// =====================================================================
//  DEFCON Security Enforcer — "ยามรักษาความปลอดภัย + กระบอกเสียง"
//  หน้าที่: ประกาศ DEFCON + บังคับใช้ + แจ้งเตือน + แสดง Mitigation
//
//  v3.0 redesign over v2.0:
//    1. DEFCON-aware border: สีขอบเปลี่ยนตามระดับภัยคุกคาม
//    2. Active Mitigations panel: แสดง IP ที่ถูกบล็อก/Process ที่ถูก Terminate
//    3. Enhanced Alert Feed: [Time] [Severity] [Source] → [Action Taken]
//    4. DEFCON เป็น focal point: แถบใหญ่ตรงกลาง + สีสะท้อนระดับ
//    5. ถอด System Metrics ออก (ย้ายไป NOSE แทน)
//
//  Compile:  rustc -O mouth/windows_sec_monitor.rs -o dist/windows_sec_monitor.exe
//  Run:      dist\windows_sec_monitor.exe --log logs\anomalous.json --refresh 1000
// =====================================================================

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::thread;

// =====================================================================
// CLI ARGS (best practice: --log + --refresh, matching NOSE)
// =====================================================================

struct Config {
    log_path: String,
    enforced_path: String,
    refresh_ms: u64,
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();
    let mut log_path = "logs/anomalous.json".to_string();
    let mut refresh_ms: u64 = 1000;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--log" => {
                if i + 1 < args.len() {
                    log_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--refresh" => {
                if i + 1 < args.len() {
                    refresh_ms = args[i + 1].parse().unwrap_or(1000);
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let enforced_path = log_path.replace("anomalous.json", "enforced.json");
    Config { log_path, enforced_path, refresh_ms }
}

// =====================================================================
// ANSI Colors + Cursor Control
// =====================================================================

const C_RESET: &str = "\x1b[0m";
const C_RED: &str = "\x1b[91;1m";
const C_ORANGE: &str = "\x1b[38;5;208m";
const C_YELLOW: &str = "\x1b[93m";
const C_GREEN: &str = "\x1b[92m";
const C_CYAN: &str = "\x1b[96;1m";
const C_MAGENTA: &str = "\x1b[95;1m";
const C_DIM: &str = "\x1b[2m";
const C_BOLD: &str = "\x1b[1m";
const C_BLUE: &str = "\x1b[94m";
const C_WHITE: &str = "\x1b[97m";

// v3.0: Cursor-based rendering (no flickering)
const CURSOR_HOME: &str = "\x1b[H";
const CLEAR_BELOW: &str = "\x1b[J";
const CLEAR_SCREEN: &str = "\x1b[2J";

fn move_cursor_home() {
    print!("{CURSOR_HOME}");
}

fn clear_screen_full() {
    print!("{CLEAR_SCREEN}{CURSOR_HOME}");
}

// =====================================================================
// DEFCON Configuration (5 levels)
// =====================================================================
// DEFCON 5 = SAFE      (0 alerts)
// DEFCON 4 = ELEVATED  (1-5 alerts)
// DEFCON 3 = HIGH      (5+ alerts or 1+ critical)
// DEFCON 2 = SEVERE    (5+ critical or 3+ blocks)
// DEFCON 1 = MAXIMUM   (10+ critical or 5+ blocks or kernel threats)

struct DefconInfo {
    level: u8,
    label: &'static str,
    color: &'static str,
    description: &'static str,
    border_color: &'static str,  // v3.0: border color for DEFCON level
}

fn calculate_defcon(total: usize, critical: usize, blocked: usize, kernel: usize) -> DefconInfo {
    if critical >= 10 || blocked >= 5 || kernel >= 3 {
        DefconInfo { level: 1, label: "MAXIMUM", color: C_MAGENTA,
            description: "10+ critical / 5+ blocks / kernel threats",
            border_color: "\x1b[95m" }  // magenta border
    } else if critical >= 5 || blocked >= 3 {
        DefconInfo { level: 2, label: "SEVERE", color: C_RED,
            description: "5+ critical or 3+ blocked IPs",
            border_color: "\x1b[91m" }  // red border
    } else if total >= 5 || critical >= 1 {
        DefconInfo { level: 3, label: "HIGH", color: C_ORANGE,
            description: "5+ alerts or 1+ critical",
            border_color: "\x1b[38;5;208m" }  // orange border
    } else if total >= 1 {
        DefconInfo { level: 4, label: "ELEVATED", color: C_YELLOW,
            description: "1-5 alerts detected",
            border_color: "\x1b[93m" }  // yellow border
    } else {
        DefconInfo { level: 5, label: "SAFE", color: C_GREEN,
            description: "0 alerts - Normal operations",
            border_color: "\x1b[92m" }  // green border
    }
}

// =====================================================================
// Alert Feed — Ring Buffer of recent alerts with detail
// v3.0: [Time] [Severity] [Source] → [Action Taken]
// =====================================================================

const ALERT_FEED_SIZE: usize = 8;

#[derive(Clone)]
struct AlertEntry {
    time: String,
    severity: String,
    source: String,
    action: String,
}

struct AlertFeed {
    entries: Vec<AlertEntry>,
}

impl AlertFeed {
    fn new() -> Self {
        AlertFeed { entries: Vec::with_capacity(ALERT_FEED_SIZE) }
    }

    fn push(&mut self, entry: AlertEntry) {
        if self.entries.len() >= ALERT_FEED_SIZE {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    fn push_from_log(&mut self, line: &str) {
        // Parse JSON line to extract alert info
        let time = extract_json_field(line, "timestamp").unwrap_or_else(|| "-".to_string());
        let severity = extract_json_field(line, "severity").unwrap_or_else(|| "Info".to_string());
        let source = extract_json_field(line, "source_ip")
            .or_else(|| extract_json_field(line, "src_ip"))
            .or_else(|| extract_json_field(line, "attack_type"))
            .unwrap_or_else(|| "unknown".to_string());

        // Determine action from policy field
        let policy = extract_json_field(line, "policy")
            .or_else(|| extract_json_field(line, "action"))
            .unwrap_or_else(|| "Log".to_string());
        let action = match policy.as_str() {
            "Drop" | "Block" | "BLOCK" => "BLOCKED".to_string(),
            "Alert" | "AlertOnly" => "ALERTED".to_string(),
            "Terminate" | "Kill" => "TERMINATED".to_string(),
            _ => format!("{}", policy),
        };

        self.push(AlertEntry { time, severity, source, action });
    }
}

fn extract_json_field(line: &str, field: &str) -> Option<String> {
    // Simple JSON string field extraction (no serde dependency for rustc compat)
    let search = format!("\"{}\":\"", field);
    if let Some(start) = line.find(&search) {
        let val_start = start + search.len();
        if let Some(end) = line[val_start..].find('"') {
            return Some(line[val_start..val_start + end].to_string());
        }
    }
    // Try numeric field
    let search_num = format!("\"{}\":", field);
    if let Some(start) = line.find(&search_num) {
        let val_start = start + search_num.len();
        let val_slice = line[val_start..].trim_start();
        if let Some(end) = val_slice.find(|c: char| !c.is_ascii_digit()) {
            if end > 0 {
                return Some(val_slice[..end].to_string());
            }
        }
    }
    None
}

// =====================================================================
// Active Mitigations — Ring Buffer of recent enforcement actions
// v3.0: แสดง IP ที่ถูกบล็อก + Process ที่ถูก Terminate
// =====================================================================

const MITIGATION_FEED_SIZE: usize = 6;

#[derive(Clone)]
struct MitigationEntry {
    time: String,
    action: String,    // "BLOCKED IP" or "TERMINATED PID"
    target: String,    // IP address or PID
    reason: String,    // Why it was blocked
}

struct MitigationFeed {
    entries: Vec<MitigationEntry>,
}

impl MitigationFeed {
    fn new() -> Self {
        MitigationFeed { entries: Vec::with_capacity(MITIGATION_FEED_SIZE) }
    }

    fn push(&mut self, entry: MitigationEntry) {
        if self.entries.len() >= MITIGATION_FEED_SIZE {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    fn add_from_log(&mut self, line: &str) {
        // Only add if the line represents a blocking/termination action
        let policy = extract_json_field(line, "policy")
            .or_else(|| extract_json_field(line, "action"))
            .unwrap_or_default();

        let is_block = policy == "Drop" || policy == "Block" || policy == "BLOCK";
        let is_terminate = policy == "Terminate" || policy == "Kill";

        if is_block || is_terminate {
            let time = extract_json_field(line, "timestamp")
                .unwrap_or_else(|| format!("{}", SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs()));
            let source_ip = extract_json_field(line, "source_ip")
                .or_else(|| extract_json_field(line, "src_ip"))
                .unwrap_or_else(|| "unknown".to_string());
            let attack = extract_json_field(line, "attack_type")
                .or_else(|| extract_json_field(line, "category"))
                .unwrap_or_else(|| "policy violation".to_string());

            if is_block {
                self.push(MitigationEntry {
                    time,
                    action: "BLOCKED IP".to_string(),
                    target: source_ip,
                    reason: attack,
                });
            } else {
                self.push(MitigationEntry {
                    time,
                    action: "TERMINATED".to_string(),
                    target: source_ip,
                    reason: attack,
                });
            }
        }
    }
}

// =====================================================================
// Tail-F Log Reader (seek-to-end + read new lines only)
// =====================================================================

struct TailReader {
    file: File,
    offset: u64,
    initialized: bool,
}

struct LogStats {
    total_alerts: usize,
    critical_count: usize,
    blocked_count: usize,
    kernel_count: usize,
    last_threat: String,
    new_entries: usize,
}

impl TailReader {
    fn new(path: &str) -> Option<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .ok()?;

        Some(TailReader {
            file,
            offset: 0,
            initialized: false,
        })
    }

    fn read_new_entries(&mut self) -> (LogStats, Vec<String>) {
        let mut stats = LogStats {
            total_alerts: 0,
            critical_count: 0,
            blocked_count: 0,
            kernel_count: 0,
            last_threat: String::from("None"),
            new_entries: 0,
        };
        let mut new_lines: Vec<String> = Vec::new();

        if !self.initialized {
            if let Ok(end_pos) = self.file.seek(SeekFrom::End(0)) {
                self.offset = end_pos;
            }
            self.initialized = true;
            return (stats, new_lines);
        }

        if self.file.seek(SeekFrom::Start(self.offset)).is_err() {
            return (stats, new_lines);
        }

        let reader = BufReader::new(&self.file);
        for line in reader.lines() {
            if let Ok(content) = line {
                if content.trim().is_empty() { continue; }
                stats.total_alerts += 1;
                stats.new_entries += 1;
                stats.last_threat = content.clone();
                new_lines.push(content.clone());

                if content.contains("\"Critical\"") { stats.critical_count += 1; }
                if content.contains("\"Drop\"") || content.contains("\"Block\"") || content.contains("\"BLOCK\"") {
                    stats.blocked_count += 1;
                }
                if content.contains("\"Tier-3\"") || content.contains("\"KERNEL_FILE\"") || content.contains("\"KERNEL_PROCESS\"") {
                    stats.kernel_count += 1;
                }
            }
        }

        if let Ok(new_pos) = self.file.seek(SeekFrom::End(0)) {
            self.offset = new_pos;
        }

        (stats, new_lines)
    }
}

// =====================================================================
// Cumulative Stats
// =====================================================================

struct CumulativeStats {
    total_alerts: usize,
    critical_count: usize,
    blocked_count: usize,
    kernel_count: usize,
    last_threat: String,
}

impl CumulativeStats {
    fn new() -> Self {
        CumulativeStats {
            total_alerts: 0,
            critical_count: 0,
            blocked_count: 0,
            kernel_count: 0,
            last_threat: String::from("None"),
        }
    }

    fn merge(&mut self, new: &LogStats) {
        self.total_alerts += new.total_alerts;
        self.critical_count += new.critical_count;
        self.blocked_count += new.blocked_count;
        self.kernel_count += new.kernel_count;
        if new.last_threat != "None" {
            self.last_threat = new.last_threat.clone();
        }
    }
}

// =====================================================================
// Enforcement Log (write when DEFCON changes)
// =====================================================================

fn write_enforcement_log(enforced_path: &str, level: u8, label: &str, prev_level: u8, stats: &CumulativeStats) {
    if let Some(parent) = std::path::Path::new(enforced_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    let action = if level < prev_level {
        "ESCALATE"
    } else if level > prev_level {
        "DE-ESCALATE"
    } else {
        "HOLD"
    };

    let entry = format!(
        r#"{{"timestamp":{ts},"component":"MOUTH","event":"defcon_change","defcon_level":{lvl},"defcon_label":"{lbl}","prev_level":{plvl},"action":"{act}","total_alerts":{total},"critical":{crit},"blocked":{blk},"kernel":{kern}}}"#,
        ts = timestamp,
        lvl = level,
        lbl = label,
        plvl = prev_level,
        act = action,
        total = stats.total_alerts,
        crit = stats.critical_count,
        blk = stats.blocked_count,
        kern = stats.kernel_count,
    );

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(enforced_path)
    {
        let _ = writeln!(file, "{}", entry);
    }

    eprintln!("{}", entry);
}

// =====================================================================
// ETW HOOK STUBS (future security monitoring)
// =====================================================================

fn etw_security_monitor_poll() -> u32 { 0 }
fn process_creation_monitor_poll() -> u32 { 0 }

// =====================================================================
// RENDER — v3.0: "ยามรักษาความปลอดภัย + กระบอกเสียง"
// Layout:
//   ┌─ DEFCON Border (color = threat level) ──────────────┐
//   │  ═══════════════════════════════════════════════════ │
//   │       AEGIS MOUTH v3.0 - DEFCON ENFORCER             │
//   │  ═══════════════════════════════════════════════════ │
//   │                                                       │
//   │  ██ DEFCON 3: HIGH ██     ← FOCAL POINT (large)     │
//   │  ▲ ESCALATED (was 4)      ← Change indicator        │
//   │  1  2  3  4  5            ← DEFCON bar              │
//   │  ─────────────────────────────────────────────────── │
//   │  [ ACTIVE MITIGATIONS ]    ← NEW in v3.0            │
//   │  BLOCKED IP  192.168.1.100  ← SYN Flood             │
//   │  BLOCKED IP  10.0.0.55      ← Port Scan             │
//   │  ─────────────────────────────────────────────────── │
//   │  [ ALERT FEED ]            ← Enhanced in v3.0       │
//   │  10:03:17 CRITICAL 192.168.1.100 → BLOCKED          │
//   │  10:03:15 HIGH     10.0.0.55     → ALERTED          │
//   │  ─────────────────────────────────────────────────── │
//   │  Stats: 12 alerts | 3 critical | 2 blocked          │
//   │  Enforced: logs/enforced.json                        │
//   └───────────────────────────────────────────────────────┘
// =====================================================================

fn render_border_top(bc: &str) {
    println!("{bc}╔════════════════════════════════════════════════════════════╗{C_RESET}");
}

fn render_border_bottom(bc: &str) {
    println!("{bc}╚════════════════════════════════════════════════════════════╝{C_RESET}");
}

fn render_border_side(bc: &str, content: &str) {
    println!("{bc}║{C_RESET} {content:<62} {bc}║{C_RESET}", content=content);
}

fn render_separator(bc: &str) {
    println!("{bc}╟──────────────────────────────────────────────────────────╢{C_RESET}");
}

fn render_dashboard(
    stats: &CumulativeStats,
    defcon: &DefconInfo,
    prev_level: u8,
    config: &Config,
    cycle: u64,
    new_entries: usize,
    alert_feed: &AlertFeed,
    mitigation_feed: &MitigationFeed,
) {
    let bc = defcon.border_color;  // DEFCON-aware border color

    if cycle == 0 {
        clear_screen_full();
    } else {
        move_cursor_home();
    }

    // ── Header ──
    render_border_top(bc);
    render_border_side(bc, &format!("{C_CYAN}{C_BOLD}   AEGIS MOUTH [Rust] v3.0 — DEFCON ENFORCER{C_RESET}"));
    render_border_side(bc, &format!("{C_DIM}   \"ยามรักษาความปลอดภัย + กระบอกเสียง\" — Alert + Mitigate + Enforce{C_RESET}"));
    render_separator(bc);

    // ── DEFCON Display — FOCAL POINT ──
    let defcon_block = format!("{color}{C_BOLD}  ██ DEFCON {level}: {label} ██{C_RESET}",
        color=defcon.color, level=defcon.level, label=defcon.label);
    render_border_side(bc, &defcon_block);
    render_border_side(bc, &format!("{C_DIM}  {desc}{C_RESET}", desc=defcon.description));

    // DEFCON change indicator
    if defcon.level != prev_level {
        let arrow = if defcon.level < prev_level { "▲ ESCALATED" } else { "▼ DE-ESCALATED" };
        let arrow_color = if defcon.level < prev_level { C_RED } else { C_GREEN };
        render_border_side(bc, &format!("  {arrow_color}{C_BOLD}{arrow}{C_RESET} (was DEFCON {prev_level})"));
    } else {
        render_border_side(bc, "");
    }

    // DEFCON Bar (visual bar with filled/empty blocks)
    let mut bar_str = String::from("  ");
    for i in 1..=5 {
        if i >= defcon.level {
            bar_str.push_str(&format!("{color}██{C_RESET} ", color=defcon.color));
        } else {
            bar_str.push_str(&format!("{C_DIM}──{C_RESET} "));
        }
    }
    bar_str.push_str("  1  2  3  4  5");
    render_border_side(bc, &bar_str);

    render_separator(bc);

    // ── Active Mitigations — NEW in v3.0 ──
    render_border_side(bc, &format!("{C_RED}{C_BOLD}[ ACTIVE MITIGATIONS ]{C_RESET}"));

    if mitigation_feed.entries.is_empty() {
        render_border_side(bc, &format!("  {C_DIM}No active mitigations — system is clean{C_RESET}"));
    } else {
        for entry in mitigation_feed.entries.iter().rev().take(5) {
            let action_color = if entry.action.starts_with("BLOCKED") { C_RED } else { C_ORANGE };
            // Truncate target for display
            let target_display = if entry.target.len() > 18 {
                format!("{}...", &entry.target[..15])
            } else {
                entry.target.clone()
            };
            // Truncate reason for display
            let reason_display = if entry.reason.len() > 22 {
                format!("{}...", &entry.reason[..19])
            } else {
                entry.reason.clone()
            };
            render_border_side(bc, &format!(
                "  {action_color}{action:<14}{C_RESET} {C_WHITE}{target:<18}{C_RESET} {C_DIM}{reason}{C_RESET}",
                action=entry.action, target=target_display, reason=reason_display
            ));
        }
    }

    render_separator(bc);

    // ── Alert Feed — Enhanced in v3.0 ──
    render_border_side(bc, &format!("{C_YELLOW}{C_BOLD}[ ALERT FEED ]{C_RESET}  {C_DIM}[Time] [Sev] [Source] -> [Action]{C_RESET}"));

    if alert_feed.entries.is_empty() {
        render_border_side(bc, &format!("  {C_DIM}>> Waiting for anomalous events...{C_RESET}"));
    } else {
        for entry in alert_feed.entries.iter().rev().take(6) {
            let sev_color = match entry.severity.as_str() {
                "Critical" => C_MAGENTA,
                "High" => C_RED,
                "Medium" | "Elevated" => C_ORANGE,
                "Low" | "Info" => C_YELLOW,
                _ => C_WHITE,
            };
            let act_color = match entry.action.as_str() {
                "BLOCKED" => C_RED,
                "TERMINATED" => C_MAGENTA,
                "ALERTED" => C_YELLOW,
                _ => C_DIM,
            };
            // Truncate source for display
            let src_display = if entry.source.len() > 16 {
                format!("{}...", &entry.source[..13])
            } else {
                entry.source.clone()
            };
            // Truncate time to just HH:MM:SS
            let time_short = if entry.time.len() > 8 {
                // Try to extract time portion from ISO timestamp
                if let Some(space_idx) = entry.time.find('T') {
                    let time_part = &entry.time[space_idx + 1..];
                    if time_part.len() >= 8 {
                        &time_part[..8]
                    } else {
                        &entry.time[..8]
                    }
                } else {
                    &entry.time[..8]
                }
            } else {
                &entry.time
            };
            render_border_side(bc, &format!(
                "  {C_DIM}{time:<8}{C_RESET} {sev_color}{sev:<8}{C_RESET} {C_WHITE}{src:<16}{C_RESET} {act_color}→ {act}{C_RESET}",
                time=time_short, sev=entry.severity, src=src_display, act=entry.action
            ));
        }
    }

    render_separator(bc);

    // ── Threat Statistics (compact) ──
    render_border_side(bc, &format!("{C_CYAN}[ THREAT STATS ]{C_RESET}"));
    render_border_side(bc, &format!(
        "  Alerts: {C_WHITE}{total}{C_RESET} │ Critical: {C_RED}{crit}{C_RESET} │ Blocked: {C_ORANGE}{blk}{C_RESET} │ Kernel: {C_YELLOW}{kern}{C_RESET} │ New: {C_CYAN}{new}{C_RESET}",
        total=stats.total_alerts, crit=stats.critical_count, blk=stats.blocked_count,
        kern=stats.kernel_count, new=new_entries
    ));

    // ── Footer ──
    render_separator(bc);
    let refresh_secs = config.refresh_ms as f64 / 1000.0;
    render_border_side(bc, &format!(
        "{C_GREEN}[ READY TO ENFORCE ]{C_RESET} │ {refresh_secs:.1}s │ Cycle {cycle} │ Enforced: {C_DIM}{path}{C_RESET}",
        path=config.enforced_path
    ));
    render_border_bottom(bc);

    // Clear any leftover content from previous render
    print!("{CLEAR_BELOW}");
}

// =====================================================================
// MAIN
// =====================================================================

fn main() {
    let config = parse_args();

    let mut cum_stats = CumulativeStats::new();
    let mut tail = TailReader::new(&config.log_path);
    let mut prev_defcon_level: u8 = 5;
    let mut cycle: u64 = 0;

    // v3.0: Alert feed + Mitigation feed
    let mut alert_feed = AlertFeed::new();
    let mut mitigation_feed = MitigationFeed::new();

    loop {
        let mut new_entries = 0;

        // Read new entries from log (tail-f pattern)
        if let Some(ref mut reader) = tail {
            let (new_stats, new_lines) = reader.read_new_entries();
            new_entries = new_stats.new_entries;
            cum_stats.merge(&new_stats);

            // v3.0: Feed new lines into alert_feed and mitigation_feed
            for line in &new_lines {
                alert_feed.push_from_log(line);
                mitigation_feed.add_from_log(line);
            }
        } else {
            tail = TailReader::new(&config.log_path);
        }

        // Calculate DEFCON from cumulative stats
        let defcon = calculate_defcon(
            cum_stats.total_alerts,
            cum_stats.critical_count,
            cum_stats.blocked_count,
            cum_stats.kernel_count,
        );

        // Render dashboard (v3.0: with alert + mitigation feeds)
        render_dashboard(&cum_stats, &defcon, prev_defcon_level, &config, cycle, new_entries, &alert_feed, &mitigation_feed);

        // Write enforcement log when DEFCON changes
        if defcon.level != prev_defcon_level {
            write_enforcement_log(
                &config.enforced_path,
                defcon.level,
                defcon.label,
                prev_defcon_level,
                &cum_stats,
            );

            // v3.0: Add DEFCON change to mitigation feed as well
            let action_label = if defcon.level < prev_defcon_level { "ESCALATED" } else { "DE-ESCALATED" };
            mitigation_feed.push(MitigationEntry {
                time: format!("{}", SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs()),
                action: format!("DEFCON {}", action_label),
                target: format!("Level {} → {}", prev_defcon_level, defcon.level),
                reason: "Threat level change".to_string(),
            });
        }

        // Update state
        prev_defcon_level = defcon.level;
        cycle += 1;

        let _ = std::io::stdout().flush();
        thread::sleep(Duration::from_millis(config.refresh_ms));
    }
}
