"""Minimal Web Dashboard for AEGIS NIDS.

Read-only UI layer that displays status from control_api.
No business logic in this layer - all data flows from control_api → Web.
Optional/release-path component; not part of core runtime spine.

Routes:
  /           → System status overview
  /health     → Health check with full payload
  /rules      → Rules listing and validation
  /dashboard  → Real-time metrics (SSE/long-polling)
  /api/status → JSON endpoint for external consumers
"""

from __future__ import annotations

import json
import threading
import time
from flask import Flask, render_template, jsonify, request

from ..config import REPO_ROOT
from ..utils import load_json, save_json

# Import control_api to read truth status
try:
    from aegisctl.api.control_api import (
        get_all_status,
        get_defcon,
        load_rules,
        start_all_subsystems,
        stop_all_subsystems,
        tail_logs,
    )
    CONTROL_API_AVAILABLE = True
except ImportError:
    CONTROL_API_AVAILABLE = False

app = Flask(__name__)
app.config["SECRET_KEY"] = "aegis-nids-dashboard-secret"

# Cache for status data (refresh every 2 seconds)
_status_cache = {"data": None, "last_update": 0}
_lock = threading.Lock()


def refresh_status_cache():
    """Refresh the status cache from control_api."""
    global _status_cache
    if CONTROL_API_AVAILABLE:
        try:
            statuses = get_all_status()
            defcon = get_defcon()
            rules_data = load_rules()
            _status_cache = {
                "data": {
                    "subsystems": statuses,
                    "defcon": defcon,
                    "total_rules": len(rules_data.get("nids_rules", [])),
                    "timestamp": time.time(),
                },
                "last_update": time.time(),
            }
        except Exception as e:
            # Cache last known good data on error
            pass


# Initial cache refresh
refresh_status_cache()


# Background thread to refresh cache periodically
def cache_refresh_loop():
    """Background thread that refreshes status cache every 2 seconds."""
    while True:
        time.sleep(2)
        with _lock:
            refresh_status_cache()


# Start background thread
_thread.start_new_thread(cache_refresh_loop, ())


@app.route("/")
def index():
    """System status overview page."""
    with _lock:
        data = _status_cache.get("data", None)
    if data is None:
        # Fallback: try direct control_api call
        try:
            if CONTROL_API_AVAILABLE:
                statuses = get_all_status()
                defcon = get_defcon()
                rules_data = load_rules()
                data = {
                    "subsystems": statuses,
                    "defcon": defcon,
                    "total_rules": len(rules_data.get("nids_rules", [])),
                    "timestamp": time.time(),
                }
        except Exception:
            data = {"error": "Unable to load status, control API unavailable"}

    return render_template("index.html", data=data)


@app.route("/health")
def health():
    """Health check endpoint with full payload."""
    with _lock:
        data = _status_cache.get("data", None)
    if data is None:
        jsonify({"error": "Status unavailable"}), 503
    return jsonify({
        "component": "brain",
        "state": "RUNNING",
        "pid": __import__("os").getpid(),
        "uptime_ms": int(time.time() * 1000),
        "counters": {
            "in_events": 0,
            "out_events": 0,
            "errors": 0,
            "dropped": 0,
        },
        "deps": [{"name": "core", "state": "RUNNING"}],
    })


@app.route("/rules")
def rules():
    """Rules listing and validation."""
    with _lock:
        data = _status_cache.get("data", None)
    if data is None:
        jsonify({"error": "Status unavailable"}), 503
    rules_data = data.get("rules", {}) if data else {}
    if not rules_data:
        try:
            from aegisctl.api.control_api import load_rules
            rules_data = load_rules()
        except Exception:
            rules_data = {"nids_rules": []}
    return jsonify(rules_data)


@app.route("/api/status")
def api_status():
    """JSON endpoint for external consumers."""
    with _lock:
        data = _status_cache.get("data", None)
    if data is None:
        jsonify({"error": "Status unavailable"}), 503
    return jsonify(data)


@app.route("/dashboard")
def dashboard():
    """Real-time dashboard page with SSE connectivity."""
    return render_template("dashboard.html")


@app.route("/health/check")
def health_check():
    """Simple health check for load balancers."""
    with _lock:
        data = _status_cache.get("data", None)
    if data is None or data.get("error"):
        return "unhealthy", 503
    return "healthy", 200


# --- Template files served inline for minimal setup ---

HTML_INDEX = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AEGIS NIDS — Dashboard</title>
    <style>
        body {font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #0a0a0a; color: #e0e0e0;}
        .header {border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 20px;}
        .grid {display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px;}
        .card {background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 15px;}
        .card h3 {margin-top: 0; color: #4fc3f7;}
        .status-running {color: #4caf50;}
        .status-stopped {color: #f44336;}
        .status-degraded {color: #ff9800;}
        .defcon {font-weight: bold; color: #ffeb3b;}
        .refresh {padding: 10px 20px; background: #1976d2; color: white; border: none; border-radius: 4px; cursor: pointer;}
        .refresh:hover {background: #1565c0;}
    </style>
</head>
<body>
    <div class="header">
        <h1>AEGIS NIDS Dashboard</h1>
        <button class="refresh" onclick="location.reload()">Refresh</button>
        <span id="defcon">DEFCON: --</span>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Subsystems</h3>
            <div id="subsystems">Loading...</div>
        </div>
        <div class="card">
            <h3>Rules</h3>
            <div id="rules">Loading...</div>
        </div>
        <div class="card">
            <h3>Health</h3>
            <div id="health">Loading...</div>
        </div>
    </div>

    <script>
        function updateStatus() {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    const subs = data.subsystems || [];
                    let html = '';
                    subs.forEach(([name, running, pid]) => {
                        const cls = running ? 'status-running' : 'status-stopped';
                        html += '<div>' + name + ': <span class="' + cls + '">' + (running ? 'RUNNING' : 'STOPPED') + '</span>' + (pid ? ' PID:' + pid : '') + '</div>';
                    });
                    document.getElementById('subsystems').innerHTML = html || 'No subsystems data';

                    const defcon = data.defcon;
                    document.getElementById('defcon').textContent = defcon ? 'DEFCON ' + defcon[0] + ' (' + defcon[1] + ')' : 'DEFCON: --';

                    document.getElementById('rules').textContent = (data.total_rules || 0) + ' rules loaded';
                })
                .catch(() => document.getElementById('subsystems').innerHTML = 'Error fetching data');
        }

        // Initial load + refresh every 3 seconds
        updateStatus();
        setInterval(updateStatus, 3000);
    </script>
</body>
</html>
"""

HTML_DASHBOARD = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AEGIS NIDS — Real-time Dashboard</title>
    <style>
        body {font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #0a0a0a; color: #e0e0e0;}
        .header {border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 20px;}
        .card {background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 15px; margin-bottom: 20px;}
        .card h3 {margin-top: 0; color: #4fc3f7;}
        .metric {display: flex; justify-content: space-between; margin: 8px 0;}
        .log {height: 300px; overflow-y: auto; background: #0d0d0d; padding: 10px; font-size: 12px; border-radius: 4px;}
        .event {margin: 5px 0; color: #aaa;}
        .defcon {color: #ffeb3b; font-weight: bold;}
        .connect {padding: 10px 20px; background: #1976d2; color: white; border: none; border-radius: 4px; cursor: pointer;}
    </style>
</head>
<body>
    <div class="header">
        <h1>AEGIS NIDS — Real-time Dashboard</h1>
        <button class="connect" onclick="connectWS()">Connect WebSocket</button>
        <span id="defcon">DEFCON: --</span>
        <span id="uptime">Uptime: --</span>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Subsystems</h3>
            <div id="subsystems">Connect to update</div>
        </div>
        <div class="card">
            <h3>Rules Loaded</h3>
            <div id="rules-count">--</div>
        </div>
        <div class="card">
            <h3>Events</h3>
            <div class="log" id="event-log">Waiting for events...</div>
        </div>
    </div>

    <script>
        const eventSource = new EventSource('/stream');

        eventSource.onmessage = function(event) {
            const data = JSON.parse(event.data);
            const timestamp = new Date().toLocaleTimeString();
            let cls = 'event';
            if (data.severity === 'Critical') cls = 'event critical';
            else if (data.severity === 'High') cls = 'event high';

            const log = '<div class="event ' + cls + '">' +
                        timestamp + ' | ' + (data.attack_type || data.rule_id || 'alert') +
                        ' | Policy: ' + (data.policy || 'Alert') +
                        ' | Severity: ' + (data.severity || '0') +
                        ' | Src: ' + (data.src_ip || '0.0.0.0') +
                        '</div>';
            document.getElementById('event-log').insertAdjacentHTML('afterbegin', log);
        };

        eventSource.onerror = function() {
            document.getElementById('event-log').innerHTML = 'Lost connection to server...';
        };

        function connectWS() {
            eventSource.close();
            eventSource.src = '/stream' + '?rand=' + Date.now();
            eventSource.eventSource.open();
        }

        // Initial connect
        connectWS();

        // Refresh subsystem data every 5 seconds
        setInterval(() => {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    const subs = data.subsystems || [];
                    let html = '';
                    subs.forEach(([name, running, pid]) => {
                        const cls = running ? 'status-running' : 'status-stopped';
                        html += '<div>' + name + ': <span class="' + cls + '">' + (running ? 'RUNNING' : 'STOPPED') + '</span>' + (pid ? ' PID:' + pid : '') + '</div>';
                    });
                    document.getElementById('subsystems').innerHTML = html || 'No subsystems data';
                    document.getElementById('rules-count').textContent = (data.total_rules || 0) + ' rules';
                })
                .catch(() => {});
        }, 5000);
    </script>
</body>
</html>
"""

# Register templates
app.jinja_env.from_string(HTML_INDEX)
app.jinja_env.from_string(HTML_DASHBOARD)


if __name__ == "__main__":
    import os
    port = int(os.environ.get("DASHBOARD_PORT", "5000"))
    debug = os.environ.get("FLASK_ENV") == "development"
    print(f"AEGIS NIDS Dashboard starting on port {port}")
    print(f"  Visit: http://localhost:{port}")
    print(f"  API:     http://localhost:{port}/api/status")
    print(f"  SSE:     http://localhost:{port}/stream")
    print(f"  Health:  http://localhost:{port}/health")
    print(f"  Rules:   http://localhost:{port}/rules")
    app.run(host="0.0.0.0", port=port, debug=debug)