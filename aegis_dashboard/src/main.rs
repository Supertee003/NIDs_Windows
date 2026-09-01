//! AEGIS NIDS Dashboard — Rust egui Web UI Command Center
//! ============================================================
//! Reads logs/anomalous.json and displays:
//!   - DEFCON level bar
//!   - Threat counters
//!   - Latest alerts table
//!   - System status panel
//!
//! Build:   cargo build --release
//! Run:     aegis_dashboard.exe
//!          (or via run_aegis.bat / aegis_daemon.py start)

use eframe::egui;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

// =====================================================================
// DATA TYPES
// =====================================================================

// GAP-4: Updated AlertEntry to match aegis_core.ndjson schema (was anomalous.json)
#[derive(Debug, Deserialize, Default, Clone)]
struct AlertEntry {
    #[serde(default)]
    ts_ms: i64,
    #[serde(default)]
    mono_ns: i64,
    #[serde(default)]
    level: String,
    #[serde(default)]
    event: String,
    #[serde(default)]
    rule: String,
    #[serde(default)]
    src_ip: String,
    #[serde(default)]
    src_port: i64,
    #[serde(default)]
    session_id: i64,
    #[serde(default)]
    ruleset_version: i64,
    #[serde(default)]
    payload_len: i64,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct RuleEntry {
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    layer: String,
}

// =====================================================================
// APP STATE
// =====================================================================

struct AegisDashboard {
    alerts: Vec<AlertEntry>,
    rules: Vec<RuleEntry>,
    total_alerts: usize,
    total_blocked: usize,
    total_critical: usize,
    defcon_level: u8,
    last_refresh: Instant,
    log_path: PathBuf,
    rules_path: PathBuf,
    auto_refresh: bool,
    refresh_interval: f32, // seconds
    last_refresh_ago: f32,
}

impl AegisDashboard {
    fn new() -> Self {
        let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            alerts: Vec::new(),
            rules: Vec::new(),
            total_alerts: 0,
            total_blocked: 0,
            total_critical: 0,
            defcon_level: 5,
            last_refresh: Instant::now(),
            // GAP-4: Read aegis_core.ndjson (was anomalous.json - old Brain format)
            log_path: base.join("logs").join("aegis_core.ndjson"),
            rules_path: base.join("Rules.json"),
            auto_refresh: true,
            refresh_interval: 1.0,
            last_refresh_ago: 0.0,
        }
    }

    fn refresh_data(&mut self) {
        // Read alerts
        self.alerts.clear();
        self.total_alerts = 0;
        self.total_blocked = 0;
        self.total_critical = 0;

        if let Ok(content) = fs::read_to_string(&self.log_path) {
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<AlertEntry>(line) {
                    self.total_alerts += 1;
                    let event_type = entry.event.to_uppercase();
                    if event_type == "BLOCK" || event_type == "IP_BLOCKED" {
                        self.total_blocked += 1;
                    }
                    if entry.level == "critical" {
                        self.total_critical += 1;
                    }
                    self.alerts.push(entry);
                }
            }
        }

        // Keep last 50 alerts for display
        if self.alerts.len() > 50 {
            let start = self.alerts.len() - 50;
            self.alerts = self.alerts[start..].to_vec();
        }

        // Calculate DEFCON
        self.defcon_level = if self.total_critical >= 10 || self.total_blocked >= 5 {
            1
        } else if self.total_critical >= 5 || self.total_blocked >= 3 {
            2
        } else if self.total_alerts >= 5 || self.total_critical >= 1 {
            3
        } else if self.total_alerts >= 1 {
            4
        } else {
            5
        };

        // Read rules (count only)
        self.rules.clear();
        if let Ok(content) = fs::read_to_string(&self.rules_path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(arr) = data.get("nids_rules").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Ok(rule) = serde_json::from_value::<RuleEntry>(item.clone()) {
                            self.rules.push(rule);
                        }
                    }
                }
            }
        }

        self.last_refresh = Instant::now();
    }
}

// =====================================================================
// EGUI APP IMPLEMENTATION
// =====================================================================

impl eframe::App for AegisDashboard {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Auto-refresh
        self.last_refresh_ago = self.last_refresh.elapsed().as_secs_f32();
        if self.auto_refresh && self.last_refresh_ago >= self.refresh_interval {
            self.refresh_data();
        }

        // ====== TOP PANEL: DEFCON ======
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🛡️ AEGIS NIDS");
                ui.separator();

                // DEFCON indicator
                let (defcon_color, defcon_label) = match self.defcon_level {
                    1 => (egui::Color32::from_rgb(255, 0, 255), "MAXIMUM"),
                    2 => (egui::Color32::from_rgb(255, 50, 50), "SEVERE"),
                    3 => (egui::Color32::from_rgb(255, 165, 0), "HIGH"),
                    4 => (egui::Color32::from_rgb(255, 255, 0), "ELEVATED"),
                    _ => (egui::Color32::from_rgb(0, 255, 0), "SAFE"),
                };

                ui.colored_label(defcon_color,
                    format!("DEFCON {}: {}", self.defcon_level, defcon_label));

                ui.separator();

                // DEFCON bar
                for i in 1..=5u8 {
                    let active = i >= self.defcon_level;
                    let color = if active { defcon_color } else { egui::Color32::from_rgb(60, 60, 60) };
                    ui.colored_label(color, "██");
                }
                ui.label("1 2 3 4 5");

                ui.separator();

                // Counters
                ui.colored_label(egui::Color32::YELLOW, format!("Alerts: {}", self.total_alerts));
                ui.colored_label(egui::Color32::RED, format!("Critical: {}", self.total_critical));
                ui.colored_label(egui::Color32::from_rgb(255, 165, 0), format!("Blocked: {}", self.total_blocked));
            });
        });

        // ====== BOTTOM PANEL: Controls ======
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.auto_refresh, "Auto-refresh");
                ui.add(egui::Slider::new(&mut self.refresh_interval, 0.5..=5.0).text("Interval (s)"));

                if ui.button("Refresh Now").clicked() {
                    self.refresh_data();
                }

                ui.separator();
                ui.label(format!("Rules: {} loaded", self.rules.len()));
                ui.label(format!("Log: {}", self.log_path.display()));
                ui.label(format!("Refreshed {:.1}s ago", self.last_refresh_ago));
            });
        });

        // ====== SIDE PANEL: Rule Summary ======
        egui::SidePanel::left("rules_panel").min_width(180.0).show(ctx, |ui| {
            ui.heading("Detection Rules");
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for rule in &self.rules {
                    let is_block = rule.action.to_uppercase() == "BLOCK"
                        || rule.action.to_uppercase() == "DROP";
                    let color = if is_block {
                        egui::Color32::from_rgb(255, 100, 100)
                    } else {
                        egui::Color32::from_rgb(200, 200, 100)
                    };
                    ui.colored_label(color, format!("{} [{}]", rule.rule_id, rule.action));
                    ui.label(format!("  {}", rule.name));
                    ui.add_space(4.0);
                }
            });
        });

        // ====== CENTRAL PANEL: Alert Table ======
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Latest Alerts");
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                use egui_extras::Column;

                egui_extras::TableBuilder::new(ui)
                    .column(Column::exact(70.0))   // Time
                    .column(Column::exact(120.0))  // Source
                    .column(Column::remainder())   // Event
                    .column(Column::exact(80.0))   // Level
                    .column(Column::exact(70.0))   // Rule
                    .header(20.0, |mut header| {
                        header.col(|ui| { ui.strong("Time"); });
                        header.col(|ui| { ui.strong("Source"); });
                        header.col(|ui| { ui.strong("Event"); });
                        header.col(|ui| { ui.strong("Level"); });
                        header.col(|ui| { ui.strong("Rule"); });
                    })
                    .body(|mut body| {
                        // Show newest first
                        for entry in self.alerts.iter().rev() {
                            body.row(16.0, |mut row| {
                                // Timestamp (ts_ms is milliseconds since epoch)
                                row.col(|ui| {
                                    let ts = if entry.ts_ms > 0 {
                                        let secs = entry.ts_ms / 1000;
                                        let datetime = chrono::DateTime::from_timestamp(secs, 0)
                                            .unwrap_or_default();
                                        datetime.format("%H:%M:%S").to_string()
                                    } else {
                                        "-".to_string()
                                    };
                                    ui.label(ts);
                                });
                                // Source IP
                                row.col(|ui| {
                                    let src = if entry.src_ip.is_empty() {
                                        "-".to_string()
                                    } else {
                                        entry.src_ip.clone()
                                    };
                                    ui.label(src);
                                });
                                // Event
                                row.col(|ui| {
                                    let ev = if entry.event.is_empty() {
                                        "-".to_string()
                                    } else {
                                        entry.event.clone()
                                    };
                                    ui.label(ev);
                                });
                                // Level (was severity)
                                row.col(|ui| {
                                    let level = entry.level.clone();
                                    let color = if level == "Critical" || level == "critical" {
                                        egui::Color32::RED
                                    } else if level == "High" || level == "high" {
                                        egui::Color32::from_rgb(255, 165, 0)
                                    } else if level == "Medium" || level == "medium" {
                                        egui::Color32::YELLOW
                                    } else {
                                        egui::Color32::from_rgb(180, 180, 180)
                                    };
                                    ui.colored_label(color, &level);
                                });
                                // Rule (was policy)
                                row.col(|ui| {
                                    let rule = if entry.rule.is_empty() {
                                        "-".to_string()
                                    } else {
                                        entry.rule.clone()
                                    };
                                    ui.label(rule);
                                });
                            });
                        }
                    });
            });
        });

        // Request repaint for auto-refresh
        if self.auto_refresh {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

// =====================================================================
// MAIN
// =====================================================================

fn main() -> eframe::Result<()> {
    // G32 Gate-A: --version flag. Print SEMVER + exit 0 BEFORE eframe
    // initializes so the supervisor (and tests/runtime/test_version.py)
    // can verify the binary is present and reports a parseable version.
    // Without this, `aegis_dashboard --version` opens a GUI window and
    // never exits (G30 reported TIMEOUT).
    let args: Vec<String> = std::env::args().collect();
    for arg in args.iter().skip(1) {
        if arg == "--version" || arg == "-v" || arg == "-V" {
            println!("aegis-dashboard 0.1.0");
            std::process::exit(0);
        }
    }

    let mut app = AegisDashboard::new();
    app.refresh_data();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 700.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("AEGIS NIDS -- Dashboard (Rust egui)"),
        ..Default::default()
    };

    eframe::run_native("AEGIS Dashboard", options, Box::new(|_cc| Ok(Box::new(app))))
}
