"""Read-only AEGIS operator dashboard.

The web layer is deliberately thin. It queries the Zig control plane through
``control_api`` and never infers a host block from a log line or policy action.
Confirmed blocking is displayed only when an EnforcementReceipt validates.
"""
from __future__ import annotations

import json
import time
from typing import Any, Iterator

from flask import Flask, Response, jsonify, render_template_string

from ..api.control_api import get_health_payload, load_rules, query_control
from ..contracts import incident_from_record, project_operator_state

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def _read(command: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    result = query_control(command, payload or {})
    return result if isinstance(result, dict) else {}


def snapshot() -> dict[str, Any]:
    """Return one consistent read-only snapshot for all web views."""
    health = get_health_payload()
    enforcement = _read("enforcement.status")
    metrics = _read("metrics.snapshot")
    incidents_response = _read("incidents.list", {"severity_min": 0})
    raw_incidents = incidents_response.get("incidents", [])
    incidents = [incident_from_record(x) for x in raw_incidents if isinstance(x, dict)]
    rules = load_rules()
    return {
        "schema": "aegis.operator.snapshot.v1",
        "timestamp_ms": int(time.time() * 1000),
        "health": health,
        "enforcement": enforcement,
        "operator": project_operator_state(health, enforcement),
        "metrics": metrics,
        "incidents": incidents,
        "rules": rules.get("nids_rules", []) if isinstance(rules, dict) else [],
    }


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS NIDS — Operator Console</title>
<style>
body{font-family:system-ui,sans-serif;background:#0a0f14;color:#e8eef2;margin:0;padding:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.card{background:#121b22;border:1px solid #29404c;border-radius:8px;padding:16px}.ok{color:#60d394}.warn{color:#ffc857}.bad{color:#ff6b6b}.muted{color:#9db0ba}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #29404c;text-align:left}.pill{font-weight:700}
</style></head><body>
<h1>AEGIS NIDS Operator Console</h1><p class="muted">Read-only view. Host blocking requires a valid EnforcementReceipt.</p>
<div id="summary" class="grid"><div class="card">Loading authoritative snapshot…</div></div>
<div class="card"><h2>Incidents</h2><table><thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Source</th><th>Status</th><th>Evidence</th></tr></thead><tbody id="incidents"></tbody></table></div>
<script>
function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function render(s){const h=s.health||{},o=s.operator||{},e=s.enforcement||{},m=s.metrics||{};
document.getElementById('summary').innerHTML=[
 ['Runtime',h.state||'UNKNOWN',h.degraded?'warn':'ok'],['Mode',o.enforcement_label||'UNKNOWN',o.prevention_gate==='closed'?'warn':'ok'],
 ['Host effect',e.host_effect_capable?'CAPABLE':'NOT CAPABLE',e.host_effect_capable?'warn':'ok'],['Events',m.events_processed??h.counters?.out_events??0,'ok'],
 ['Forensics',h.forensic?.integrity||'see health','ok'],['Rules',s.rules?.length??0,'ok']].map(x=>`<div class="card"><div class="muted">${esc(x[0])}</div><div class="pill ${x[2]}">${esc(x[1])}</div></div>`).join('');
document.getElementById('incidents').innerHTML=(s.incidents||[]).map(i=>`<tr><td>${esc(i.timestamp_ms)}</td><td>${esc(i.rule_id)}</td><td>${esc(i.severity)}</td><td>${esc(i.src_ip||'-')}</td><td class="pill ${i.status==='BLOCKED_CONFIRMED'?'bad':'warn'}">${esc(i.status)}</td><td>${esc(i.evidence)}</td></tr>`).join('')||'<tr><td colspan="6" class="muted">No incidents returned by control plane</td></tr>'}
function refresh(){fetch('/api/snapshot').then(r=>r.json()).then(render).catch(()=>{})} refresh(); setInterval(refresh,3000);
</script></body></html>"""


@app.get("/")
def index() -> str:
    return render_template_string(INDEX_HTML)


@app.get("/api/snapshot")
def api_snapshot():
    return jsonify(snapshot())


@app.get("/api/status")
def api_status():
    # Compatibility endpoint; it intentionally exposes the same snapshot.
    return jsonify(snapshot())


@app.get("/api/incidents")
def api_incidents():
    return jsonify({"schema": "aegis.incidents.v1", "incidents": snapshot()["incidents"]})


@app.get("/api/receipt")
def api_receipt():
    return jsonify({"available": False, "reason": "receipts are returned by enforcement.verify only"}), 404


@app.get("/health")
def health():
    data = snapshot()["health"]
    return jsonify(data), (200 if data.get("state") in {"RUNNING", "READY"} else 503)


@app.get("/rules")
def rules():
    return jsonify({"nids_rules": snapshot()["rules"]})


@app.get("/stream")
def stream():
    def events() -> Iterator[str]:
        # SSE is read-only and bounded by the client disconnect; every message
        # is a complete authoritative snapshot, not a locally invented event.
        while True:
            yield f"data: {json.dumps(snapshot(), separators=(',', ':'))}\n\n"
            time.sleep(3)
    return Response(events(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/health/check")
def health_check():
    data = snapshot()["health"]
    healthy = data.get("state") in {"RUNNING", "READY"} and not data.get("degraded", True)
    return ("healthy", 200) if healthy else ("degraded", 503)


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("DASHBOARD_PORT", "5000")), debug=False)
