// ============================================================================
// AEGIS NIDS — HTTP Handlers (src/handlers/mod.rs)
// ============================================================================

pub mod ws;

use crate::data::*;
use crate::DashboardState;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
};
use serde_json::json;
use std::sync::Arc;

/// Serve the embedded dashboard HTML
pub async fn serve_dashboard() -> impl IntoResponse {
    Html(DASHBOARD_HTML.to_string())
}

/// REST API: Stats
pub async fn api_stats(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let total_packets = state.total_packets.load(std::sync::atomic::Ordering::Relaxed);
    let total_threats = state.total_threats.load(std::sync::atomic::Ordering::Relaxed);
    let defcon = state.defcon_level.load(std::sync::atomic::Ordering::Relaxed);
    let uptime = state.start_time.elapsed().as_secs();

    let mut top_sources: Vec<(String, u32)> = state
        .src_ip_counts
        .iter()
        .map(|r| (r.key().clone(), *r.value()))
        .collect();
    top_sources.sort_by(|a, b| b.1.cmp(&a.1));
    top_sources.truncate(MAX_TOP_SOURCES);

    let proto_stats: Vec<(String, ProtoStats)> = state
        .proto_stats
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();

    Json(json!({
        "total_packets": total_packets,
        "total_threats": total_threats,
        "defcon_level": defcon,
        "uptime_secs": uptime,
        "events_count": state.events.len(),
        "alerts_count": state.alerts.len(),
        "ws_clients": state.ws_clients.len(),
        "top_sources": top_sources,
        "proto_stats": proto_stats,
    }))
}

/// REST API: Events
pub async fn api_events(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let events: Vec<ThreatEvent> = state.events.iter().map(|r| r.value().clone()).collect();
    Json(events)
}

/// REST API: Alerts
pub async fn api_alerts(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let alerts: Vec<Alert> = state.alerts.iter().map(|r| r.value().clone()).collect();
    Json(alerts)
}

/// REST API: DEFCON
pub async fn api_defcon(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let level = state.defcon_level.load(std::sync::atomic::Ordering::Relaxed);
    let defcon = DefconLevel::from_u8(level);
    Json(json!({
        "level": level,
        "label": defcon.as_label(),
        "color": defcon.as_color(),
    }))
}

/// REST API: Heatmap
pub async fn api_heatmap(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let mut sources: Vec<(String, u32)> = state
        .src_ip_counts
        .iter()
        .map(|r| (r.key().clone(), *r.value()))
        .collect();
    sources.sort_by(|a, b| b.1.cmp(&a.1));
    sources.truncate(MAX_TOP_SOURCES);
    Json(sources)
}

/// REST API: Protocol Distribution
pub async fn api_proto_dist(State(state): State<Arc<DashboardState>>) -> impl IntoResponse {
    let dist: Vec<(String, ProtoStats)> = state
        .proto_stats
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    Json(dist)
}

// ─── Embedded Dashboard HTML ────────────────────────────────────────────────

static DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS NIDS Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a1a;color:#e0e0e0}
        .header{background:linear-gradient(135deg,#0a0a2a,#1a0a2a);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid #2a0a3a}
        .header h1{font-size:24px;color:#ff4080}
        .header .status{display:flex;gap:16px;align-items:center}
        .defcon-badge{padding:6px 16px;border-radius:8px;font-weight:700;font-size:14px}
        .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:16px 24px}
        .card{background:#12122a;border-radius:12px;padding:16px;border:1px solid #2a1a3a}
        .card h3{font-size:13px;color:#8080a0;text-transform:uppercase;margin-bottom:8px}
        .card .value{font-size:32px;font-weight:700}
        .card.critical .value{color:#ff0040}
        .card.high .value{color:#ff4040}
        .card.medium .value{color:#ffaa00}
        .card.info .value{color:#40c0ff}
        .charts{display:grid;grid-template-columns:2fr 1fr;gap:16px;padding:0 24px 16px}
        .chart-card{background:#12122a;border-radius:12px;padding:16px;border:1px solid #2a1a3a}
        .chart-card h3{font-size:14px;color:#8080a0;margin-bottom:12px}
        .events-panel{padding:0 24px 24px}
        .events-panel h3{font-size:14px;color:#8080a0;margin-bottom:8px;text-transform:uppercase}
        .event-row{display:grid;grid-template-columns:80px 80px 120px 100px 1fr;gap:8px;padding:6px 12px;background:#0a0a1a;border-radius:4px;margin-bottom:2px;font-size:12px}
        .event-row .sev{font-weight:700}
        .sev-critical{color:#ff0040}.sev-high{color:#ff4040}.sev-medium{color:#ffaa00}.sev-low{color:#40c0ff}.sev-info{color:#80ff80}
        #ws-status{width:10px;height:10px;border-radius:50%;display:inline-block}
        #ws-status.connected{background:#40ff80}#ws-status.disconnected{background:#ff4040}
    </style>
</head>
<body>
    <div class="header">
        <h1>AEGIS NIDS Dashboard</h1>
        <div class="status">
            <span><span id="ws-status" class="disconnected"></span> WS</span>
            <span id="defcon-badge" class="defcon-badge" style="background:#40c0ff20;color:#40c0ff">DEFCON 5</span>
            <span id="uptime" style="color:#8080a0">00:00:00</span>
        </div>
    </div>
    <div class="grid">
        <div class="card critical"><h3>Total Packets</h3><div class="value" id="stat-packets">0</div></div>
        <div class="card high"><h3>Threats Detected</h3><div class="value" id="stat-threats">0</div></div>
        <div class="card medium"><h3>Active Events</h3><div class="value" id="stat-events">0</div></div>
        <div class="card info"><h3>WS Clients</h3><div class="value" id="stat-ws">0</div></div>
    </div>
    <div class="charts">
        <div class="chart-card"><h3>Threat Timeline (last 60s)</h3><canvas id="chart-timeline"></canvas></div>
        <div class="chart-card"><h3>Protocol Distribution</h3><canvas id="chart-proto"></canvas></div>
    </div>
    <div class="events-panel">
        <h3>Recent Events</h3>
        <div id="events-list"></div>
    </div>
    <script>
        let ws;
        function connectWs(){
            ws=new WebSocket(`ws://${location.host}/ws`);
            ws.onopen=()=>{document.getElementById('ws-status').className='connected'};
            ws.onclose=()=>{document.getElementById('ws-status').className='disconnected';setTimeout(connectWs,2000)};
            ws.onmessage=(e)=>{handleWsMessage(JSON.parse(e.data))};
        }
        connectWs();
        const timelineCtx=document.getElementById('chart-timeline').getContext('2d');
        const protoCtx=document.getElementById('chart-proto').getContext('2d');
        const timelineData=new Array(60).fill(0);
        const timelineChart=new Chart(timelineCtx,{type:'line',data:{labels:new Array(60).fill(''),datasets:[{label:'Threats/s',data:timelineData,borderColor:'#ff4080',backgroundColor:'#ff408020',fill:true,tension:0.4}]},options:{responsive:true,scales:{y:{beginAtZero:true,grid:{color:'#1a1a3a'}},x:{display:false}},plugins:{legend:{display:false}}}});
        const protoChart=new Chart(protoCtx,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#ff4080','#ff8040','#ffaa00','#40c0ff','#80ff80','#c040ff']}]},options:{responsive:true,plugins:{legend:{position:'right',labels:{color:'#e0e0e0'}}}}});
        let threatsThisSecond=0;
        function handleWsMessage(msg){
            if(msg.type==='Threat'){threatsThisSecond++;addEventRow(msg.data);document.getElementById('stat-threats').textContent=parseInt(document.getElementById('stat-threats').textContent)+1}
            else if(msg.type==='StatsUpdate'){const d=msg.data;document.getElementById('stat-packets').textContent=d.total_packets.toLocaleString();document.getElementById('stat-threats').textContent=d.total_threats.toLocaleString();document.getElementById('stat-events').textContent=d.events_count;document.getElementById('stat-ws').textContent=d.ws_clients;if(d.proto_stats&&d.proto_stats.length>0){protoChart.data.labels=d.proto_stats.map(p=>p[0]);protoChart.data.datasets[0].data=d.proto_stats.map(p=>p[1].packets);protoChart.update()}}
            else if(msg.type==='DefconChange'){updateDefcon(msg.data.level)}
            else if(msg.type==='PacketTick'){document.getElementById('stat-packets').textContent=msg.data.total.toLocaleString()}
        }
        function updateDefcon(level){const colors={1:'#ff0040',2:'#ff4040',3:'#ffaa00',4:'#40c0ff',5:'#80ff80'};const badge=document.getElementById('defcon-badge');badge.textContent='DEFCON '+level;badge.style.color=colors[level];badge.style.background=colors[level]+'20'}
        function addEventRow(evt){const list=document.getElementById('events-list');const row=document.createElement('div');row.className='event-row';const sevClass='sev-'+evt.severity.toLowerCase();row.innerHTML=`<span class="sev ${sevClass}">${evt.severity}</span><span>${evt.category}</span><span>${evt.source_ip}</span><span>${evt.protocol}</span><span style="color:#a0a0c0">${evt.message}</span>`;list.prepend(row);if(list.children.length>50)list.removeChild(list.lastChild)}
        setInterval(()=>{timelineData.shift();timelineData.push(threatsThisSecond);threatsThisSecond=0;timelineChart.data.datasets[0].data=[...timelineData];timelineChart.update('none')},1000);
        let uptimeSecs=0;
        setInterval(()=>{uptimeSecs++;const h=Math.floor(uptimeSecs/3600).toString().padStart(2,'0');const m=Math.floor((uptimeSecs%3600)/60).toString().padStart(2,'0');const s=(uptimeSecs%60).toString().padStart(2,'0');document.getElementById('uptime').textContent=`${h}:${m}:${s}`},1000);
        fetch('/api/stats').then(r=>r.json()).then(d=>{document.getElementById('stat-packets').textContent=d.total_packets.toLocaleString();document.getElementById('stat-threats').textContent=d.total_threats.toLocaleString();document.getElementById('stat-events').textContent=d.events_count;document.getElementById('stat-ws').textContent=d.ws_clients;updateDefcon(d.defcon_level)});
    </script>
</body>
</html>
"#;
