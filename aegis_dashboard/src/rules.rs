@@ -0,0 +1,91 @@
/**
 * aegis_dashboard/src/rules.rs — NIDS Rules loader from Rules.json
 */

use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct NidsRule {
    pub rule_id: String,
    pub name: String,
    pub layer: String,
    pub severity: String,
    pub action: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub fast_pattern: Option<String>,
    #[serde(default)]
    pub regex_pattern: Option<String>,
    #[serde(default)]
    pub target_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub target_protocols: Option<Vec<String>>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RulesFile {
    pub nids_rules: Vec<NidsRule>,
}

/// Load rules from Rules.json file
pub fn load_rules(path: &str) -> Result<Vec<NidsRule>, String> {
    if !Path::new(path).exists() {
        return Err(format!("Rules file not found: {}", path));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules: {}", e))?;

    let rules: RulesFile = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse rules JSON: {}", e))?;

    Ok(rules.nids_rules)
}

/// Load rules with fallback to default path
pub fn load_rules_default() -> Vec<NidsRule> {
    let paths = [
        "Rules.json",
        "../Rules.json",
        "../../NIDs_Windows/Rules.json",
    ];

    for path in &paths {
        if let Ok(rules) = load_rules(path) {
            tracing::info!("Loaded {} rules from {}", rules.len(), path);
            return rules;
        }
    }

    tracing::warn!("No Rules.json found — using empty rule set");
    Vec::new()
}

/// Get layer color for egui
pub fn layer_color(layer: &str) -> egui::Color32 {
    match layer {
        "NETWORK_L7" => egui::Color32::from_rgb(59, 130, 246),   // Blue
        "NETWORK_L4" => egui::Color32::from_rgb(139, 92, 246),   // Purple
        "KERNEL_FILE" => egui::Color32::from_rgb(249, 115, 22),  // Orange
        "KERNEL_PROCESS" => egui::Color32::from_rgb(234, 179, 8), // Yellow
        "PIPE_MONITOR" => egui::Color32::from_rgb(34, 197, 94),  // Green
        _ => egui::Color32::GRAY,
    }
}

/// Get severity color
pub fn severity_color(severity: &str) -> egui::Color32 {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => egui::Color32::from_rgb(220, 38, 38),
        "HIGH" => egui::Color32::from_rgb(249, 115, 22),
        "MEDIUM" => egui::Color32::from_rgb(234, 179, 8),
        "LOW" => egui::Color32::from_rgb(59, 130, 246),
        "INFO" => egui::Color32::from_rgb(34, 197, 94),
        _ => egui::Color32::GRAY,
    }
}
