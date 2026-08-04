/**
 * aegis_dashboard/src/main.rs — AEGIS NIDS Security Dashboard
 *
 * Pure Rust egui GUI — Zero HTTP, Zero API, Zero browser.
 * Connects to C++ Bridge via FFI (extern "C" ABI).
 * Falls back to SQLite + Rules.json when Bridge is offline.
 *
 * Architecture:
 *   egui Webview ←→ Rust Backend ←→ C++ Bridge FFI ←→ NIDS Engine
 *   (NO HTTP server, NO REST API, NO WebSocket server)
 */

mod bridge_ffi;
mod db;
mod rules;

use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ====== Application State ======

struct AegisDashboard {
    // Bridge state
    bridge_connected: bool,
    defcon_level: u8,
    defcon_label: String,
    event_count: u32,
    dropped_count: u32,

    // Data
    alerts: Vec<db::Alert>,
    blocked_ips: Vec<db::BlockedIp>,
    nids_rules: Vec<rules::NidsRule>,
    stats: Vec<db::TrafficStat>,

    // UI state
    active_tab: Tab,
    ip_input: String,
    status_message: String,
    refresh_timer: f32,

    // Database
    db: Arc<Mutex<db::Database>>,
}

#[derive(PartialEq, Copy, Clone)]
enum Tab {
    Overview,
    Alerts,
    Rules,
    BlockedIps,
    Bridge,
}

// ====== App Implementation ======

impl AegisDashboard {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Initialize Bridge FFI
        let bridge_connected = bridge_ffi::init();
        if bridge_connected {
            tracing::info!("C++ Bridge connected via FFI");
        } else {
            tracing::warn!("C++ Bridge not available — using fallback mode");
        }

        // Open database
        let db = match db::Database::open("aegis_dashboard.db") {
            Ok(db) => Arc::new(Mutex::new(db)),
            Err(e) => {
                tracing::error!("Database error: {} — using in-memory", e);
                Arc::new(Mutex::new(db::Database::open_in_memory().unwrap()))
            }
        };

        // Load rules
        let nids_rules = rules::load_rules_default();

        // Seed demo data if empty
        {
            let db_lock = db.lock().unwrap();
            if db_lock.get_alerts(1).unwrap_or_default().is_empty() {
                drop(db_lock);
                seed_demo_data(&db);
            }
        }

        let defcon_level = bridge_ffi::get_defcon_level();
        let defcon_label = bridge_ffi::get_defcon_label();

        // Load initial data
        let alerts = db.lock().unwrap().get_alerts(100).unwrap_or_default();
        let blocked_ips = db.lock().unwrap().get_blocked_ips().unwrap_or_default();
        let stats = db.lock().unwrap().get_stats(60).unwrap_or_default();

        Self {
            bridge_connected,
            defcon_level,
            defcon_label,
            event_count: bridge_ffi::get_event_count(),
            dropped_count: bridge_ffi::get_dropped_count(),
            alerts,
            blocked_ips,
            nids_rules,
            stats,
            active_tab: Tab::Overview,
            ip_input: String::new(),
            status_message: if bridge_connected {
                "Bridge connected — live data".to_string()
            } else {
                "Bridge offline — cached data".to_string()
            },
            refresh_timer: 0.0,
            db,
        }
    }

    /// Refresh data from Bridge + DB
    fn refresh_data(&mut self) {
        // Update Bridge state
        self.bridge_connected = bridge_ffi::is_available();
        self.defcon_level = bridge_ffi::get_defcon_level();
        self.defcon_label = bridge_ffi::get_defcon_label();
        self.event_count = bridge_ffi::get_event_count();
        self.dropped_count = bridge_ffi::get_dropped_count();

        // Pop new events from Bridge and insert into DB
        while let Some(event) = bridge_ffi::pop_event() {
            // Copy fields from packed struct to avoid alignment issues
            let evt_severity = event.severity;
            let evt_rule_id = event.rule_id;
            let evt_source_ip = event.source_ip;
            let evt_dest_ip = event.dest_ip;
            let evt_source_port = event.source_port;
            let evt_dest_port = event.dest_port;
            let evt_protocol = event.protocol;
            let evt_tier_result = event.tier_result;
            let evt_event_type = event.event_type;

            let alert = db::Alert {
                id: uuid::Uuid::new_v4().to_string(),
                rule_id: format!("R{:04}", evt_rule_id),
                severity: match evt_severity {
                    s if s >= 4 => "CRITICAL".to_string(),
                    s if s >= 3 => "HIGH".to_string(),
                    s if s >= 2 => "MEDIUM".to_string(),
                    _ => "LOW".to_string(),
                },
                source_ip: bridge_ffi::ip_to_string(evt_source_ip),
                dest_ip: bridge_ffi::ip_to_string(evt_dest_ip),
                source_port: evt_source_port as u16,
                dest_port: evt_dest_port as u16,
                protocol: bridge_ffi::protocol_name(evt_protocol as u32).to_string(),
                message: format!("Tier-{} match on {} layer",
                    evt_tier_result, bridge_ffi::event_type_name(evt_event_type as u32)),
                timestamp: chrono::Utc::now().to_rfc3339(),
                acknowledged: false,
            };

            if let Ok(db) = self.db.lock() {
                let _ = db.insert_alert(&alert);
            }
        }

        // Refresh from DB
        let db_lock = self.db.lock().unwrap();
        self.alerts = db_lock.get_alerts(100).unwrap_or_default();
        self.blocked_ips = db_lock.get_blocked_ips().unwrap_or_default();
        self.stats = db_lock.get_stats(60).unwrap_or_default();
    }
}

// ====== egui App Trait ======

impl eframe::App for AegisDashboard {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Auto-refresh every 1 second
        self.refresh_timer += ctx.input(|i| i.stable_dt);
        if self.refresh_timer >= 1.0 {
            self.refresh_timer = 0.0;
            self.refresh_data();
        }
        // Request repaint for live updates
        ctx.request_repaint_after(Duration::from_millis(500));

        // ====== Top Panel (DEFCON + Status) ======
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🛡 AEGIS NIDS");
                ui.separator();

                // DEFCON indicator
                let defcon_color = bridge_ffi::defcon_color(self.defcon_level);
                ui.label(egui::RichText::new(format!("DEFCON {}", self.defcon_level))
                    .color(defcon_color).size(18.0).strong());
                ui.label(&self.defcon_label);

                ui.separator();

                // Bridge status
                if self.bridge_connected {
                    ui.colored_label(egui::Color32::GREEN, "● Bridge Online");
                } else {
                    ui.colored_label(egui::Color32::RED, "● Bridge Offline");
                }

                ui.separator();

                // Stats
                ui.label(format!("Events: {}", self.event_count));
                ui.label(format!("Alerts: {}", self.alerts.len()));
                ui.label(format!("Blocked: {}", self.blocked_ips.len()));
            });
        });

        // ====== Bottom Panel (Status Bar) ======
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&self.status_message).small());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("100% Standalone — Zero API").small().color(egui::Color32::GREEN));
                });
            });
        });

        // ====== Side Panel (Tabs) ======
        egui::SidePanel::left("side_panel").min_width(120.0).show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::Overview, "📋 Overview");
                ui.selectable_value(&mut self.active_tab, Tab::Alerts, "🚨 Alerts");
                ui.selectable_value(&mut self.active_tab, Tab::Rules, "📜 Rules");
                ui.selectable_value(&mut self.active_tab, Tab::BlockedIps, "🚫 Blocked IPs");
                ui.selectable_value(&mut self.active_tab, Tab::Bridge, "🔌 Bridge");
            });
        });

        // ====== Main Content ======
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::Overview => self.render_overview(ui),
                Tab::Alerts => self.render_alerts(ui),
                Tab::Rules => self.render_rules(ui),
                Tab::BlockedIps => self.render_blocked_ips(ui),
                Tab::Bridge => self.render_bridge(ui),
            }
        });
    }
}

// ====== Tab Renderers ======

impl AegisDashboard {
    fn render_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Dashboard Overview");
        ui.add_space(8.0);

        // DEFCON gauge
        let defcon_color = bridge_ffi::defcon_color(self.defcon_level);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("DEFCON Level").size(16.0));
                ui.add_space(16.0);
                ui.label(egui::RichText::new(format!("{}", self.defcon_level))
                    .color(defcon_color).size(32.0).strong());
                ui.label(egui::RichText::new(&self.defcon_label).size(16.0).color(defcon_color));
            });
        });

        ui.add_space(8.0);

        // Stats grid
        egui::Grid::new("stats_grid").num_columns(4).show(ui, |ui| {
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.label("Total Events");
                    ui.label(egui::RichText::new(format!("{}", self.event_count)).size(20.0).strong());
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.label("Active Alerts");
                    let unack = self.alerts.iter().filter(|a| !a.acknowledged).count();
                    ui.label(egui::RichText::new(format!("{}", unack))
                        .size(20.0).strong()
                        .color(if unack > 0 { egui::Color32::from_rgb(220, 38, 38) } else { egui::Color32::GREEN }));
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.label("Blocked IPs");
                    ui.label(egui::RichText::new(format!("{}", self.blocked_ips.len())).size(20.0).strong());
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.label("Active Rules");
                    let enabled = self.nids_rules.iter().filter(|r| r.enabled).count();
                    ui.label(egui::RichText::new(format!("{}/{}", enabled, self.nids_rules.len())).size(20.0).strong());
                });
            });
            ui.end_row();
        });

        ui.add_space(12.0);

        // Recent alerts table
        ui.heading("Recent Alerts");
        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            egui::Grid::new("recent_alerts").show(ui, |ui| {
                ui.label(egui::RichText::new("Time").strong());
                ui.label(egui::RichText::new("Rule").strong());
                ui.label(egui::RichText::new("Severity").strong());
                ui.label(egui::RichText::new("Source").strong());
                ui.label(egui::RichText::new("Dest").strong());
                ui.label(egui::RichText::new("Protocol").strong());
                ui.end_row();

                for alert in self.alerts.iter().take(20) {
                    ui.label(&alert.timestamp[..19.min(alert.timestamp.len())]);
                    ui.label(&alert.rule_id);
                    ui.colored_label(rules::severity_color(&alert.severity), &alert.severity);
                    ui.label(&alert.source_ip);
                    ui.label(&alert.dest_ip);
                    ui.label(&alert.protocol);
                    ui.end_row();
                }
            });
        });
    }

    fn render_alerts(&mut self, ui: &mut egui::Ui) {
        ui.heading("Alerts");
        ui.add_space(4.0);

        let unack = self.alerts.iter().filter(|a| !a.acknowledged).count();
        ui.label(format!("Total: {} | Unacknowledged: {}", self.alerts.len(), unack));
        ui.add_space(4.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("alerts_table").show(ui, |ui| {
                ui.label(egui::RichText::new("Time").strong());
                ui.label(egui::RichText::new("Rule ID").strong());
                ui.label(egui::RichText::new("Severity").strong());
                ui.label(egui::RichText::new("Source IP").strong());
                ui.label(egui::RichText::new("Dest IP").strong());
                ui.label(egui::RichText::new("Port").strong());
                ui.label(egui::RichText::new("Proto").strong());
                ui.label(egui::RichText::new("Message").strong());
                ui.label(egui::RichText::new("Status").strong());
                ui.end_row();

                for alert in &self.alerts {
                    ui.label(&alert.timestamp[..19.min(alert.timestamp.len())]);
                    ui.label(&alert.rule_id);
                    ui.colored_label(rules::severity_color(&alert.severity), &alert.severity);
                    ui.label(&alert.source_ip);
                    ui.label(&alert.dest_ip);
                    ui.label(format!("{}→{}", alert.source_port, alert.dest_port));
                    ui.label(&alert.protocol);
                    ui.label(&alert.message);
                    if alert.acknowledged {
                        ui.colored_label(egui::Color32::GREEN, "ACK");
                    } else {
                        ui.colored_label(egui::Color32::YELLOW, "NEW");
                    }
                    ui.end_row();
                }
            });
        });
    }

    fn render_rules(&mut self, ui: &mut egui::Ui) {
        ui.heading("NIDS Rules");
        ui.add_space(4.0);
        ui.label(format!("Total: {} rules", self.nids_rules.len()));
        ui.add_space(4.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("rules_table").show(ui, |ui| {
                ui.label(egui::RichText::new("Rule ID").strong());
                ui.label(egui::RichText::new("Name").strong());
                ui.label(egui::RichText::new("Layer").strong());
                ui.label(egui::RichText::new("Severity").strong());
                ui.label(egui::RichText::new("Action").strong());
                ui.label(egui::RichText::new("Ports").strong());
                ui.label(egui::RichText::new("Status").strong());
                ui.end_row();

                for rule in &self.nids_rules {
                    ui.label(&rule.rule_id);
                    ui.label(&rule.name);
                    ui.colored_label(rules::layer_color(&rule.layer), &rule.layer);
                    ui.colored_label(rules::severity_color(&rule.severity), &rule.severity);
                    ui.label(&rule.action);

                    if let Some(ports) = &rule.target_ports {
                        let port_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                        ui.label(port_str.join(","));
                    } else {
                        ui.label("any");
                    }

                    if rule.enabled {
                        ui.colored_label(egui::Color32::GREEN, "ON");
                    } else {
                        ui.colored_label(egui::Color32::RED, "OFF");
                    }
                    ui.end_row();
                }
            });
        });
    }

    fn render_blocked_ips(&mut self, ui: &mut egui::Ui) {
        ui.heading("Blocked IPs");
        ui.add_space(4.0);

        // Block IP input
        ui.horizontal(|ui| {
            ui.label("Block IP:");
            let _response = ui.text_edit_singleline(&mut self.ip_input);
            if ui.button("Block").clicked() && !self.ip_input.is_empty() {
                if let Some(ip_u32) = bridge_ffi::string_to_ip(&self.ip_input) {
                    // Block via Bridge FFI
                    let bridge_ok = bridge_ffi::block_ip(ip_u32);
                    // Also record in DB
                    if let Ok(db) = self.db.lock() {
                        let _ = db.block_ip(&self.ip_input, "Manual block from dashboard");
                    }
                    self.status_message = format!("Blocked {} (Bridge: {})", self.ip_input, bridge_ok);
                    self.ip_input.clear();
                } else {
                    self.status_message = format!("Invalid IP: {}", self.ip_input);
                }
            }
        });

        ui.add_space(8.0);

        // Blocked IPs table
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("blocked_table").show(ui, |ui| {
                ui.label(egui::RichText::new("IP Address").strong());
                ui.label(egui::RichText::new("Reason").strong());
                ui.label(egui::RichText::new("Blocked At").strong());
                ui.label(egui::RichText::new("Action").strong());
                ui.end_row();

                let mut to_unblock = None;
                for blocked in &self.blocked_ips {
                    ui.label(&blocked.ip);
                    ui.label(&blocked.reason);
                    ui.label(&blocked.blocked_at);
                    if ui.button("Unblock").clicked() {
                        to_unblock = Some(blocked.ip.clone());
                    }
                    ui.end_row();
                }

                if let Some(ip) = to_unblock {
                    if let Some(ip_u32) = bridge_ffi::string_to_ip(&ip) {
                        bridge_ffi::unblock_ip(ip_u32);
                    }
                    if let Ok(db) = self.db.lock() {
                        let _ = db.unblock_ip(&ip);
                    }
                    self.status_message = format!("Unblocked {}", ip);
                }
            });
        });
    }

    fn render_bridge(&mut self, ui: &mut egui::Ui) {
        ui.heading("Bridge Status");
        ui.add_space(8.0);

        egui::Grid::new("bridge_grid").show(ui, |ui| {
            ui.label("Connection:");
            if self.bridge_connected {
                ui.colored_label(egui::Color32::GREEN, "Connected via FFI");
            } else {
                ui.colored_label(egui::Color32::RED, "Disconnected (fallback mode)");
            }
            ui.end_row();

            ui.label("IPC Method:");
            ui.label("extern \"C\" ABI (zero-copy FFI)");
            ui.end_row();

            ui.label("DEFCON Level:");
            ui.colored_label(bridge_ffi::defcon_color(self.defcon_level),
                format!("{} — {}", self.defcon_level, self.defcon_label));
            ui.end_row();

            ui.label("Event Count:");
            ui.label(format!("{}", self.event_count));
            ui.end_row();

            ui.label("Dropped:");
            ui.label(format!("{}", self.dropped_count));
            ui.end_row();

            ui.label("Architecture:");
            ui.label("egui → Rust → FFI → C++ Bridge → NIDS Engine");
            ui.end_row();

            ui.label("Network Attack Surface:");
            ui.colored_label(egui::Color32::GREEN, "ZERO (no HTTP, no API, no ports)");
            ui.end_row();
        });

        ui.add_space(12.0);

        if ui.button("🔄 Reconnect Bridge").clicked() {
            self.bridge_connected = bridge_ffi::init();
            self.status_message = if self.bridge_connected {
                "Bridge reconnected".to_string()
            } else {
                "Bridge still unavailable".to_string()
            };
        }

        if ui.button("🧪 Bridge Self-Test").clicked() && self.bridge_connected {
            let event_count = bridge_ffi::get_event_count();
            let defcon = bridge_ffi::get_defcon_level();
            self.status_message = format!("Self-test: events={}, defcon={}", event_count, defcon);
        }
    }
}

// ====== Demo Data ======

fn seed_demo_data(db: &Arc<Mutex<db::Database>>) {
    let db_lock = db.lock().unwrap();

    // Seed alerts
    let demo_alerts = [
        ("R9064", "HIGH", "10.0.0.45", "192.168.1.1", 80, 443, "TCP", "SQL Injection attempt detected"),
        ("R9065", "CRITICAL", "10.0.0.99", "192.168.1.10", 22, 22, "TCP", "Brute force SSH attempt"),
        ("R9066", "MEDIUM", "172.16.0.5", "192.168.1.1", 53, 53, "UDP", "DNS tunneling pattern detected"),
        ("R9067", "HIGH", "10.0.0.100", "192.168.1.1", 445, 445, "TCP", "SMB exploit attempt"),
        ("R9068", "LOW", "192.168.1.50", "192.168.1.1", 8080, 8080, "TCP", "Unusual port scan detected"),
    ];

    for (i, (rule, sev, src, dst, sp, dp, proto, msg)) in demo_alerts.iter().enumerate() {
        let alert = db::Alert {
            id: format!("alert-{:04}", i + 1),
            rule_id: rule.to_string(),
            severity: sev.to_string(),
            source_ip: src.to_string(),
            dest_ip: dst.to_string(),
            source_port: *sp,
            dest_port: *dp,
            protocol: proto.to_string(),
            message: msg.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            acknowledged: *sev != "CRITICAL",
        };
        let _ = db_lock.insert_alert(&alert);
    }

    // Seed blocked IPs
    let _ = db_lock.block_ip("10.0.0.99", "SSH brute force");
    let _ = db_lock.block_ip("10.0.0.100", "SMB exploit");

    tracing::info!("Demo data seeded");
}

// ====== Main ======

fn main() -> eframe::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    tracing::info!("AEGIS NIDS Dashboard starting...");
    tracing::info!("Architecture: egui → Rust → FFI → C++ Bridge");
    tracing::info!("Zero HTTP, Zero API, Zero browser — 100% standalone");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("AEGIS NIDS — Security Dashboard"),
        ..Default::default()
    };

    eframe::run_native(
        "AEGIS NIDS Dashboard",
        options,
        Box::new(|cc| Ok(Box::new(AegisDashboard::new(cc)))),
    )
}
