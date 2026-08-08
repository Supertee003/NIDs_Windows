pub mod ws;

use axum::{
    extract::State,
    response::{Html, Json, IntoResponse},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::broadcast;
use dashmap::DashMap;

/// Shared application state
pub struct AppState {
    pub tx: broadcast::Sender<String>,
    pub stats: Arc<DashMap<String, u64>>,
    pub proto_stats: Arc<DashMap<String, u64>>,
    pub defcon: Arc<DashMap<String, u8>>,
    pub alerts: Arc<DashMap<String, String>>,
}

/// Build the router with all routes
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard_page))
        .route("/api/stats", get(get_stats))
        .route("/api/defcon", get(get_defcon))
        .route("/api/alerts", get(get_alerts))
        .route("/api/proto", get(get_proto_stats))
        .route("/ws", get(crate::handlers::ws::ws_handler))
        .with_state(state)
}

/// Serve embedded HTML dashboard
async fn dashboard_page() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

/// GET /api/stats — total event counts
async fn get_stats(State(state): State<AppState>) -> Json<Value> {
    let total = state.stats.get("total_events").map(|v| *v.value()).unwrap_or(0);
    Json(json!({
        "total_events": total,
        "uptime_secs": chrono::Utc::now().timestamp(),
    }))
}

/// GET /api/defcon — current DEFCON level
async fn get_defcon(State(state): State<AppState>) -> Json<Value> {
    let level = state.defcon.get("level").map(|v| *v.value()).unwrap_or(5);
    let label = match level {
        1 => "MAXIMUM",
        2 => "SEVERE",
        3 => "HIGH",
        4 => "ELEVATED",
        _ => "SAFE",
    };
    let color = match level {
        1 => "#ff0000",
        2 => "#ff6600",
        3 => "#ffcc00",
        4 => "#3399ff",
        _ => "#00cc66",
    };
    Json(json!({
        "level": level,
        "label": label,
        "color": color,
    }))
}

/// GET /api/alerts — recent alerts
async fn get_alerts(State(state): State<AppState>) -> Json<Value> {
    let alert_list: Vec<Value> = state.alerts.iter()
        .map(|entry| {
            serde_json::from_str::<Value>(entry.value()).unwrap_or(json!({}))
        })
        .collect();
    Json(json!({ "alerts": alert_list }))
}

/// GET /api/proto — protocol distribution
async fn get_proto_stats(State(state): State<AppState>) -> Json<Value> {
    let tcp = state.proto_stats.get("tcp").map(|v| *v.value()).unwrap_or(0);
    let udp = state.proto_stats.get("udp").map(|v| *v.value()).unwrap_or(0);
    let icmp = state.proto_stats.get("icmp").map(|v| *v.value()).unwrap_or(0);
    let other = state.proto_stats.get("other").map(|v| *v.value()).unwrap_or(0);
    Json(json!({
        "tcp": tcp,
        "udp": udp,
        "icmp": icmp,
        "other": other,
    }))
}

/// Embedded HTML dashboard (Chart.js + WebSocket real-time updates)
static DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS NIDS Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e17;color:#e0e0e0;overflow-x:hidden}
.header{background:linear-gradient(135deg,#0d1b2a,#1b263b);padding:20px;border-bottom:2px solid #00cc66;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:24px;color:#00cc66;text-shadow:0 0 10px rgba(0,204,102,0.5)}
.header .defcon{padding:8px 20px;border-radius:8px;font-weight:bold;font-size:18px;text-transform:uppercase}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(400px,1fr));gap:16px;padding:16px}
.card{background:#111827;border-radius:12px;padding:20px;border:1px solid #1f2937;box-shadow:0 4px 6px rgba(0,0,0,0.3)}
.card h2{color:#60a5fa;margin-bottom:12px;font-size:16px;text-transform:uppercase;letter-spacing:1px}
.stat-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #1f2937}
.stat-label{color:#9ca3af}.stat-value{font-weight:bold;font-size:18px}
#alert-log{max-height:400px;overflow-y:auto;font-family:monospace;font-size:13px}
.alert-item{padding:6px 8px;margin:4px 0;border-radius:4px;border-left:3px solid}
.alert-critical{background:#1a0000;border-color:#ff0000;color:#ff6b6b}
.alert-high{background:#1a0e00;border-color:#ff6600;color:#ffaa6b}
.alert-medium{background:#1a1a00;border-color:#ffcc00;color:#ffdd6b}
.alert-low{background:#001a1a;border-color:#3399ff;color:#6bd4ff}
.status-dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:8px}
.status-ok{background:#00cc66;box-shadow:0 0 6px #00cc66}
.status-warn{background:#ffcc00;box-shadow:0 0 6px #ffcc00}
.status-err{background:#ff0000;box-shadow:0 0 6px #ff0000}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ AEGIS NIDS Dashboard</h1>
  <div class="defcon" id="defcon-badge" style="background:#00cc66;color:#000">DEFCON 5: SAFE</div>
</div>
<div class="grid">
  <div class="card"><h2>📊 Threat Statistics</h2>
    <div class="stat-row"><span class="stat-label">Total Events</span><span class="stat-value" id="total-events">0</span></div>
    <div class="stat-row"><span class="stat-label">TCP Packets</span><span class="stat-value" id="tcp-count">0</span></div>
    <div class="stat-row"><span class="stat-label">UDP Packets</span><span class="stat-value" id="udp-count">0</span></div>
    <div class="stat-row"><span class="stat-label">ICMP Packets</span><span class="stat-value" id="icmp-count">0</span></div>
    <div class="stat-row"><span class="stat-label">Other</span><span class="stat-value" id="other-count">0</span></div>
    <div style="margin-top:12px"><canvas id="proto-chart" height="180"></canvas></div>
  </div>
  <div class="card"><h2>🚨 Recent Alerts</h2><div id="alert-log"></div></div>
  <div class="card"><h2>📡 System Status</h2>
    <div class="stat-row"><span><span class="status-dot status-ok"></span>Zig Core (Tier-1)</span><span class="stat-value" style="color:#00cc66">ONLINE</span></div>
    <div class="stat-row"><span><span class="status-dot status-ok"></span>Python Brain (Tier-2)</span><span class="stat-value" style="color:#00cc66">ONLINE</span></div>
    <div class="stat-row"><span><span class="status-dot status-ok"></span>Rust Shield (Tier-3)</span><span class="stat-value" style="color:#00cc66">ONLINE</span></div>
    <div class="stat-row"><span><span class="status-dot status-ok"></span>C++ IPC Bridge</span><span class="stat-value" style="color:#00cc66">ONLINE</span></div>
    <div class="stat-row"><span><span class="status-dot status-ok"></span>WFP Driver</span><span class="stat-value" style="color:#00cc66">LOADED</span></div>
  </div>
  <div class="card"><h2>📈 Threat Timeline</h2><canvas id="timeline-chart" height="180"></canvas></div>
</div>
<script>
let protoChart=null,timelineChart=null,timelineData=[];
async function fetchAPI(path){try{const r=await fetch(path);return await r.json()}catch(e){return null}}
async function updateStats(){
  const s=await fetchAPI('/api/stats');if(s)document.getElementById('total-events').textContent=s.total_events;
  const p=await fetchAPI('/api/proto');if(p){document.getElementById('tcp-count').textContent=p.tcp;document.getElementById('udp-count').textContent=p.udp;document.getElementById('icmp-count').textContent=p.icmp;document.getElementById('other-count').textContent=p.other;updateProtoChart(p)}
  const d=await fetchAPI('/api/defcon');if(d){const b=document.getElementById('defcon-badge');b.textContent='DEFCON '+d.level+': '+d.label;b.style.background=d.color;b.style.color=d.level<=2?'#fff':'#000'}
  const a=await fetchAPI('/api/alerts');if(a&&a.alerts){const log=document.getElementById('alert-log');a.alerts.slice(-20).reverse().forEach(al=>{const div=document.createElement('div');const sev=al.severity||1;div.className='alert-item alert-'+(sev>=3?'critical':sev>=2?'high':sev>=1?'medium':'low');div.textContent=new Date(al.timestamp).toLocaleTimeString()+' | '+al.attack_type+' | '+al.source_ip+' | '+al.policy;log.prepend(div)});while(log.children.length>50)log.removeChild(log.lastChild))}
}
function updateProtoChart(p){if(!protoChart){protoChart=new Chart(document.getElementById('proto-chart'),{type:'doughnut',data:{labels:['TCP','UDP','ICMP','Other'],datasets:[{data:[p.tcp,p.udp,p.icmp,p.other],backgroundColor:['#60a5fa','#f472b6','#fbbf24','#9ca3af']}]},options:{plugins:{legend:{labels:{color:'#e0e0e0'}}}}})}else{protoChart.data.datasets[0].data=[p.tcp,p.udp,p.icmp,p.other];protoChart.update()}}
setInterval(updateStats,2000);updateStats();
// WebSocket
const ws=new WebSocket('ws://'+location.host+'/ws');
ws.onmessage=function(e){try{const msg=JSON.parse(e.data);if(msg.type==='threat'){const d=msg.data;const now=new Date();timelineData.push({t:now,y:1});if(timelineData.length>60)timelineData.shift();updateTimeline()}}catch(ex){}};
function updateTimeline(){if(!timelineChart){timelineChart=new Chart(document.getElementById('timeline-chart'),{type:'line',data:{labels:timelineData.map(d=>d.t.toLocaleTimeString()),datasets:[{label:'Threats',data:timelineData.map(d=>d.y),borderColor:'#ff6b6b',backgroundColor:'rgba(255,107,107,0.1)',fill:true,tension:0.4}]},options:{scales:{x:{ticks:{color:'#9ca3af'}},y:{ticks:{color:'#9ca3af'}}},plugins:{legend:{labels:{color:'#e0e0e0'}}}}})}else{timelineChart.data.labels=timelineData.map(d=>d.t.toLocaleTimeString());timelineChart.data.datasets[0].data=timelineData.map(d=>d.y);timelineChart.update()}}
</script>
</body>
</html>"##;
