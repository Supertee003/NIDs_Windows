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

#[derive(Debug, Deserialize, Default, Clone)]
struct AlertEntry {
    #[serde(default)]
    timestamp: f64,
    #[serde(default)]
    attack_type: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    policy: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    rule_id: String,
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
            log_path: base.join("logs").join("anomalous.json"),
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
                    let policy = entry.policy.to_uppercase();
                    if policy == "BLOCK" || policy == "DROP" {
                        self.total_blocked += 1;
                    }
                    if entry.severity == "Critical" {
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
                    .column(Column::remainder())   // Attack Type
                    .column(Column::exact(80.0))   // Severity
                    .column(Column::exact(70.0))   // Policy
                    .header(20.0, |mut header| {
                        header.col(|ui| { ui.strong("Time"); });
                        header.col(|ui| { ui.strong("Source"); });
                        header.col(|ui| { ui.strong("Attack Type"); });
                        header.col(|ui| { ui.strong("Severity"); });
                        header.col(|ui| { ui.strong("Policy"); });
                    })
                    .body(|mut body| {
                        // Show newest first
                        for entry in self.alerts.iter().rev() {
                            body.row(16.0, |mut row| {
                                // Timestamp
                                row.col(|ui| {
                                    let ts = if entry.timestamp > 0.0 {
                                        let secs = entry.timestamp as i64;
                                        let datetime = chrono::DateTime::from_timestamp(secs, 0)
                                            .unwrap_or_default();
                                        datetime.format("%H:%M:%S").to_string()
                                    } else {
                                        "-".to_string()
                                    };
                                    ui.label(ts);
                                });
                                // Source
                                row.col(|ui| { ui.label(&entry.source); });
                                // Attack type
                                row.col(|ui| { ui.label(&entry.attack_type); });
                                // Severity
                                row.col(|ui| {
                                    let color = if entry.severity == "Critical" {
                                        egui::Color32::RED
                                    } else if entry.severity == "High" {
                                        egui::Color32::from_rgb(255, 165, 0)
                                    } else {
                                        egui::Color32::YELLOW
                                    };
                                    ui.colored_label(color, &entry.severity);
                                });
                                // Policy
                                row.col(|ui| {
                                    let policy = entry.policy.to_uppercase();
                                    let color = if policy == "BLOCK" || policy == "DROP" {
                                        egui::Color32::RED
                                    } else {
                                        egui::Color32::YELLOW
                                    };
                                    ui.colored_label(color, &policy);
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
    let mut app = AegisDashboard::new();
    app.refresh_data();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 700.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("AEGIS NIDS — Dashboard (Rust egui)"),
        ..Default::default()
    };

    eframe::run_native("AEGIS Dashboard", options, Box::new(|_cc| Ok(Box::new(app))))
}
