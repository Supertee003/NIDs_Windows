"""Read-only AEGIS operator dashboard.

The web layer is deliberately thin. It queries the Zig control plane through
``control_api`` and never infers a host block from a log line or policy action.
Confirmed blocking is displayed only when an EnforcementReceipt validates.

Data sources (all read-only):
  * control plane  - health / enforcement / metrics / forensics / incident counters
  * evidence log   - logs/aegis_core.ndjson (canonical event records, same
                     data path as the desktop dashboard)
  * rule config    - configs/Rules.json

This module never mutates host state. Privileged actions stay in the control
plane behind the Rust PEP; the UI only projects what the backend attests.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterator

from flask import Flask, Response, jsonify, render_template_string

from ..api.control_api import get_health_payload, load_rules, query_control
from ..contracts import incident_from_record, project_operator_state

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_LOG = REPO_ROOT / "logs" / "aegis_core.ndjson"
FEED_LIMIT = 50
FEED_SCAN_BYTES = 262_144
# Statuses that may only be shown when a receipt validates; anything else
# from a log line is a decision label, not a confirmed host effect.
ENFORCEMENT_CLAIM_STATUSES = {"ENFORCED", "BLOCKED", "BLOCKED_CONFIRMED"}


def _read(command: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    result = query_control(command, payload or {})
    return result if isinstance(result, dict) else {}


def _record_to_incident(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize one evidence-log record without inventing enforcement.

    A record whose enforcement_status says 'enforced' but whose receipt
    fields do not validate is downgraded to PEP_UNVERIFIED: the UI must
    never render ENFORCED from an action label or log line alone.
    """
    receipt: dict[str, Any] | None = None
    if str(raw.get("enforcement_status", "")).lower() == "enforced":
        receipt = {key: raw.get(key) for key in ("filter_id", "request_id", "event_id", "trace_id", "audit_id") if raw.get(key)}
        receipt["status"] = "enforced"
        receipt["host_effect_confirmed"] = bool(raw.get("host_effect_confirmed", False))
    record: dict[str, Any] = {
        "incident_id": raw.get("session_id") or raw.get("event_id", 0),
        "event_id": raw.get("event_id", 0),
        "rule_id": raw.get("rule") or raw.get("rule_id", ""),
        "severity": raw.get("level") or raw.get("severity", "UNKNOWN"),
        "source": raw.get("source", "evidence_log"),
        "src_ip": raw.get("src_ip"),
        "dst_ip": raw.get("dst_ip"),
        "timestamp_ms": raw.get("ts_ms", 0),
        "status": raw.get("enforcement_status") or "observed",
        "evidence": raw.get("event", ""),
    }
    if receipt is not None:
        record["enforcement_receipt"] = receipt
    incident = incident_from_record(record)
    if not incident["receipt_valid"] and incident["status"] in ENFORCEMENT_CLAIM_STATUSES:
        incident["status"] = "PEP_UNVERIFIED"
    incident["detail"] = {
        "src_port": raw.get("src_port", 0),
        "payload_len": raw.get("payload_len", 0),
        "ruleset_version": raw.get("ruleset_version", 0),
        "session_id": raw.get("session_id", 0),
    }
    return incident


def _read_detection_feed() -> dict[str, Any]:
    """Tail the canonical evidence log (read-only).

    The control plane remains authoritative for counters and enforcement
    state; this feed shows the operator the same records the desktop
    dashboard renders.
    """
    if not EVIDENCE_LOG.is_file():
        return {"available": False, "path": str(EVIDENCE_LOG), "records": [], "total_scanned": 0}
    try:
        size = EVIDENCE_LOG.stat().st_size
        with EVIDENCE_LOG.open("rb") as handle:
            handle.seek(max(0, size - FEED_SCAN_BYTES))
            tail = handle.read()
    except OSError:
        return {"available": False, "path": str(EVIDENCE_LOG), "records": [], "total_scanned": 0}
    records: list[dict[str, Any]] = []
    total_scanned = 0
    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        total_scanned += 1
        records.append(_record_to_incident(raw))
    records.sort(key=lambda item: item.get("timestamp_ms") or 0)
    return {
        "available": True,
        "path": str(EVIDENCE_LOG),
        "records": records[-FEED_LIMIT:][::-1],
        "total_scanned": total_scanned,
    }


def _severity_order(value: Any) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(value).lower(), 5)


def _threat_posture(records: list[dict[str, Any]], health: dict[str, Any] | None = None) -> dict[str, Any]:
    """Presentation-only threat posture (FE-DEF-095a: daemon is the authority).

    When daemon health carries defcon_level/defcon_label (control/defcon.zig
    over daemon-owned counters), those win — even with zero evidence-log
    records, so a missing log file can never display SAFE over live
    incidents. Otherwise the legacy evidence-log ladder applies and the
    basis says so explicitly. This is NOT an enforcement claim either way.
    """
    if isinstance(health, dict):
        level = health.get("defcon_level")
        label = health.get("defcon_label")
        if isinstance(level, int) and 1 <= level <= 5 and isinstance(label, str) and label:
            confirmed = sum(1 for r in records if r.get("receipt_valid"))
            return {
                "defcon": level,
                "label": label,
                "critical": sum(1 for r in records if _severity_order(r.get("severity")) == 0),
                "high": sum(1 for r in records if _severity_order(r.get("severity")) == 1),
                "confirmed_blocks": confirmed,
                "records": len(records),
                "basis": "daemon authority (control plane), not an enforcement claim",
            }
    critical = sum(1 for r in records if _severity_order(r.get("severity")) == 0)
    high = sum(1 for r in records if _severity_order(r.get("severity")) == 1)
    confirmed = sum(1 for r in records if r.get("receipt_valid"))
    total = len(records)
    if critical >= 10 or confirmed >= 5:
        defcon = 1
    elif critical >= 5 or confirmed >= 3:
        defcon = 2
    elif total >= 5 or critical >= 1:
        defcon = 3
    elif total >= 1:
        defcon = 4
    else:
        defcon = 5
    labels = {1: "MAXIMUM", 2: "SEVERE", 3: "HIGH", 4: "ELEVATED", 5: "SAFE"}
    return {
        "defcon": defcon,
        "label": labels[defcon],
        "critical": critical,
        "high": high,
        "confirmed_blocks": confirmed,
        "records": total,
        "basis": "derived from evidence log, not an enforcement claim",
    }


def snapshot() -> dict[str, Any]:
    """Return one consistent read-only snapshot for all web views."""
    health = get_health_payload()
    enforcement = _read("enforcement.status")
    metrics = _read("metrics.snapshot")
    incident_counters = _read("incidents.list")
    forensic = _read("forensics.verify")
    feed = _read_detection_feed()
    incidents = [incident_from_record(x) for x in feed["records"]]
    rules = load_rules()
    return {
        "schema": "aegis.operator.snapshot.v1",
        "timestamp_ms": int(time.time() * 1000),
        "control": {
            "available": bool(health.get("runtime_available", True)),
            "source": health.get("source", "control_plane"),
            "diagnostic": not bool(health.get("runtime_available", True)),
        },
        "health": health,
        "enforcement": enforcement,
        "operator": project_operator_state(health, enforcement),
        "metrics": metrics,
        "incident_counters": incident_counters,
        "forensic": forensic,
        "feed": {"available": feed["available"], "path": feed["path"], "total_scanned": feed["total_scanned"]},
        "incidents": incidents,
        "threat": _threat_posture(incidents, health),
        "rules_runtime": {
            "active": int(health.get("rules_loaded", 0) or 0),
            "policies_active": int(health.get("policies_loaded", 0) or 0),
            "catalog": len(rules.get("nids_rules", [])) if isinstance(rules, dict) else 0,
            "source": "control_daemon_health",
        },
        "rules": rules.get("nids_rules", []) if isinstance(rules, dict) else [],
    }


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS NIDS — Operator Console</title>
<style>
:root{--bg:#0a0f14;--panel:#121b22;--line:#29404c;--text:#e8eef2;--muted:#9db0ba;--ok:#60d394;--warn:#ffc857;--bad:#ff6b6b;--crit:#ff5555;--high:#ffa64d;--med:#ffd93d;--low:#8fa3ad;--info:#6ea8fe}
*{box-sizing:border-box}
body{font-family:system-ui,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);margin:0;padding:0}
header{position:sticky;top:0;z-index:10;background:rgba(10,15,20,.97);border-bottom:1px solid var(--line);padding:10px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header h1{font-size:16px;margin:0;letter-spacing:.5px}
header .sub{color:var(--muted);font-size:12px}
nav{margin-left:auto;display:flex;gap:4px}
nav a{color:var(--muted);text-decoration:none;font-size:12.5px;padding:5px 10px;border-radius:6px}
nav a:hover{background:#1b2831;color:var(--text)}
.wrap{max-width:1400px;margin:0 auto;padding:16px 20px 60px}
.banner{display:none;border:1px solid var(--warn);background:rgba(255,200,87,.08);color:var(--warn);border-radius:8px;padding:10px 14px;margin:12px 0;font-size:13px}
.banner.off{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.card .v{font-size:20px;font-weight:700;margin-top:4px}
.card .s{color:var(--muted);font-size:11px;margin-top:3px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.crit{color:var(--crit)}
.muted{color:var(--muted)}.small{font-size:12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:14px 0}
.panel h2{font-size:13px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);margin:0 0 10px}
.grid2{display:grid;grid-template-columns:minmax(0,1.9fr) minmax(280px,1fr);gap:14px}
@media(max-width:980px){.grid2{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:7px 9px;border-bottom:1px solid #1d2c36;text-align:left;vertical-align:top}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:700;letter-spacing:.3px}
.pill.ok{background:rgba(96,211,148,.14)}.pill.warn{background:rgba(255,200,87,.14)}.pill.bad{background:rgba(255,107,107,.16)}.pill.crit{background:rgba(255,85,85,.18)}.pill.info{background:rgba(110,168,254,.14)}.pill.mut{background:#1c2a34;color:var(--muted)}
.chip{display:inline-block;min-width:64px;text-align:center;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:700}
.sev-critical{background:rgba(255,85,85,.18);color:var(--crit)}
.sev-high{background:rgba(255,166,77,.16);color:var(--high)}
.sev-medium{background:rgba(255,217,61,.13);color:var(--med)}
.sev-low,.sev-info,.sev-unknown{background:#1c2a34;color:var(--low)}
.st-PEP_UNVERIFIED{background:rgba(255,200,87,.15);color:var(--warn)}
.st-BLOCKED_CONFIRMED{background:rgba(96,211,148,.18);color:var(--ok)}
.st-ENFORCED,.st-DETECTED,.st-OBSERVED,.st-ALERTED{background:#1c2a34;color:var(--text)}
.controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.controls input[type=search]{flex:1;min-width:180px;background:#0d151c;border:1px solid var(--line);border-radius:7px;color:var(--text);padding:7px 10px;font-size:13px}
.controls select{background:#0d151c;border:1px solid var(--line);border-radius:7px;color:var(--text);padding:6px 8px;font-size:12.5px}
.controls label{font-size:12px;color:var(--muted);display:flex;gap:6px;align-items:center}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:1px}
.dot.on{background:var(--ok)}.dot.retry{background:var(--warn);animation:blink 1s infinite}.dot.off{background:var(--bad)}
@keyframes blink{50%{opacity:.35}}
.defcon-strip{display:flex;gap:4px;margin-top:8px}
.defcon-strip div{flex:1;height:6px;border-radius:3px;background:#1c2a34}
.receipt-note{font-size:11.5px;color:var(--muted);margin-top:8px}
.subrow{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid #1d2c36;font-size:13px}
.subrow:last-child{border-bottom:none}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:6px 18px;font-size:13px}
.kv div span:first-child{color:var(--muted)}
.feed-empty{color:var(--muted);font-size:13px;padding:14px 4px}
details summary{cursor:pointer;color:var(--muted);font-size:12px;margin-top:6px}
footer{color:var(--muted);font-size:11.5px;text-align:center;margin-top:26px}
</style></head><body>
<header>
  <h1>AEGIS NIDS</h1><span class="sub">Operator Console — read-only</span>
  <span id="hdrState" class="pill mut">connecting…</span>
  <span id="hdrMode" class="pill mut">—</span>
  <span class="sub" id="hdrUpdated"></span>
  <nav>
    <a href="#overview">Overview</a><a href="#detection">Detection</a>
    <a href="#rules">Rules</a><a href="#enforcement">Enforcement</a><a href="#system">System</a>
  </nav>
</header>
<div class="wrap">
  <div id="banner" class="banner"></div>

  <div id="overview"></div>

  <div id="detection" class="panel">
    <h2>Detection Feed <span class="muted small" id="feedMeta"></span></h2>
    <div class="controls">
      <input type="search" id="q" placeholder="Filter by rule, IP, event text…">
      <select id="sevFilter">
        <option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option>
      </select>
      <select id="stFilter">
        <option value="">All statuses</option><option>DETECTED</option><option>OBSERVED</option><option>ALERTED</option>
        <option>PEP_UNVERIFIED</option><option>BLOCKED_CONFIRMED</option>
      </select>
      <label><input type="checkbox" id="confirmedOnly"> confirmed only</label>
      <span class="small muted" id="feedCount"></span>
    </div>
    <div id="feedTable"></div>
  </div>

  <div class="grid2">
    <div class="panel" id="rules">
      <h2>Detection Rules <span class="muted small" id="ruleCount"></span></h2>
      <div class="controls"><input type="search" id="ruleQ" placeholder="Filter rules…"></div>
      <div id="ruleTable"></div>
    </div>
    <div>
      <div class="panel" id="enforcement">
        <h2>Enforcement</h2>
        <div id="enfBody" class="kv"></div>
        <div class="receipt-note">Confirmed blocks require a validated EnforcementReceipt (status ENFORCED + host-effect proof + provider read-back). Log lines and policy labels alone never count.</div>
      </div>
      <div class="panel" id="system">
        <h2>Runtime &amp; Subsystems</h2>
        <div id="sysBody"></div>
        <h2 style="margin-top:14px">Workers &amp; Data Plane</h2>
        <div id="workerBody" class="kv"></div>
        <h2 style="margin-top:14px">Forensic Integrity</h2>
        <div id="forensicBody" class="kv"></div>
      </div>
    </div>
  </div>
  <footer>AEGIS operator console — thin read-only client of the AEGIS control plane. Privileged actions stay behind the Rust PEP.</footer>
</div>
<script>
const $=id=>document.getElementById(id);
function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function num(x){const n=Number(x??0);return Number.isFinite(n)?n.toLocaleString():'0'}
function fmtTime(ms){if(!ms)return '—';const d=new Date(ms);const p=n=>String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds())}
function relTime(ms){if(!ms)return '—';const s=Math.max(0,(Date.now()-ms)/1000);
  if(s<60)return Math.floor(s)+'s ago';if(s<3600)return Math.floor(s/60)+'m '+Math.floor(s%60)+'s ago';
  if(s<86400)return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m ago';return Math.floor(s/86400)+'d ago'}
function uptime(ms){ms=Number(ms??0);if(!ms)return '—';const s=Math.floor(ms/1000);
  if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m '+(s%60)+'s';return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m'}
function sevClass(s){return 'sev-'+String(s??'').toLowerCase()}
function sevLabel(s){return String(s??'UNKNOWN').toUpperCase()}

let snap=null,lastOk=0,fails=0,mode='connecting';
const REFRESH_MS=3000;

function statePill(state,degraded){
  const cls=(state==='RUNNING'||state==='READY')&&!degraded?'ok':(state==='FAILED'?'bad':'warn');
  return `<span class="pill ${cls}">${esc(state||'UNKNOWN')}</span>`}

function renderHeader(){
  const o=snap.operator||{},h=snap.health||{},c=snap.control||{};
  $('hdrState').innerHTML=statePill(h.state,h.degraded);
  $('hdrState').title='runtime state: '+(h.state||'unknown')+(c.diagnostic?' (diagnostic, daemon unavailable)':'');
  const gate=o.prevention_gate==='open'?'open':'closed';
  $('hdrMode').className='pill '+(o.enforcement_label==='OBSERVE_ONLY'?'mut':(o.host_effect_capable?'ok':'warn'));
  $('hdrMode').textContent=o.enforcement_label||'—';
  $('hdrMode').title='prevention gate: '+gate+'; host-effect capable: '+(o.host_effect_capable?'yes':'no');
  $('hdrUpdated').textContent=lastOk?'updated '+relTime(lastOk):(fails?'fetch failing':'');
}

function renderBanner(){
  const b=$('banner');let msg='';
  const c=snap.control||{};
  if(!c.available)msg='Control plane unavailable — subsystem data below is diagnostic only (PID/process inspection). Start the AEGIS runtime for authoritative state.';
  else if(snap.forensic&&snap.forensic.integrity==='failed')msg='Forensic integrity check FAILED — hash chain verification failed. Treat forensic records as suspect.';
  else if(snap.feed&&snap.feed.available===false)msg='No evidence log yet (logs/aegis_core.ndjson absent). Detection feed will populate once the runtime writes canonical events.';
  b.textContent=msg;b.classList.toggle('off',!!msg);
}

function kpi(label,value,cls,sub){return `<div class="card"><div class="k">${esc(label)}</div><div class="v ${cls||''}">${value}</div>${sub?`<div class="s">${sub}</div>`:''}</div>`}

function renderOverview(){
  const h=snap.health||{},m=snap.metrics||{},ic=snap.incident_counters||{},f=snap.forensic||{},t=snap.threat||{},o=snap.operator||{};
  const events=Number(m.events_processed??h.counters?.out_events??0);
  const errors=Number(m.errors??h.counters?.errors??0);
  const det=Number(m.detections??ic.detections??0);
  const open=Number(ic.incidents_open??m.incidents_open??0);
  const fState=f.integrity==='ok'?'ok':(f.integrity==='failed'?'bad':(f.integrity?'bad':'warn'));
  const fText=f.integrity?f.integrity.toUpperCase():(f.verified===false?'UNAVAILABLE':'NO DATA');
  let out='<div class="cards">';
  out+=kpi('Runtime',statePill(h.state,h.degraded),'','uptime '+uptime(h.uptime_ms)+', v'+esc(h.version||'?'));
  out+=kpi('Threat Posture',`DEFCON ${t.defcon||5} · ${esc(t.label||'—')}`,t.defcon<=2?'crit':(t.defcon===3?'warn':'ok'),
    `${num(t.records)} records · ${num(t.critical)} critical · ${num(t.confirmed_blocks)} confirmed`);
  out+=kpi('Enforcement Mode',esc(o.enforcement_label||'—'),o.enforcement_label==='ENFORCEMENT_READY'?'ok':(o.enforcement_label==='OBSERVE_ONLY'?'warn':'bad'),
    'gate '+(o.prevention_gate||'closed')+(o.host_effect_capable?' · host-effect capable':' · no host effect'));
  out+=kpi('Events',num(events),'ok',errors?`${num(errors)} errors`:'no errors');
  out+=kpi('Detections',num(det),det?'warn':'',open?`${num(open)} open`:'');
  out+=kpi('Rules',num(snap.rules?.length??0),'ok','from configs/Rules.json');
  out+=kpi('Forensic Integrity',esc(fText),fState,`records ${num(f.records)}`);
  out+=kpi('Control Plane',snap.control?.available?'LIVE':'DIAGNOSTIC',snap.control?.available?'ok':'warn',
    snap.control?.available?'authoritative daemon data':'subsystem data is diagnostic only');
  out+='</div>';
  const strip=Array.from({length:5},(_,i)=>{const lvl=i+1;const active=lvl>=(t.defcon||5);
    const col=[ '','var(--crit)','var(--high)','var(--med)','var(--low)','var(--ok)'][t.defcon||5];
    return `<div style="${active&&col?`background:${col}`:''}"></div>`}).join('');
  out+=`<div class="defcon-strip" title="DEFCON ${t.defcon||5} — derived from evidence, not an enforcement claim">${strip}</div>
  <div class="small muted" style="margin-top:4px">DEFCON ${t.defcon||5} is derived from local evidence records (${t.basis?esc(t.basis):''}).</div>`;
  $('overview').innerHTML=out;
}

function feedRows(){
  const q=$('q').value.trim().toLowerCase();
  const sev=$('sevFilter').value;const st=$('stFilter').value;const confOnly=$('confirmedOnly').checked;
  return (snap.incidents||[]).filter(i=>{
    if(confOnly&&!i.receipt_valid)return false;
    if(sev&&String(i.severity??'').toLowerCase()!==sev)return false;
    if(st&&i.status!==st)return false;
    if(q){const hay=[i.rule_id,i.src_ip,i.dst_ip,i.status,i.evidence,i.incident_id].join(' ').toLowerCase();if(!hay.includes(q))return false}
    return true});
}

function renderFeed(){
  const rows=feedRows();
  $('feedCount').textContent=`${rows.length} shown`;
  const f=snap.feed||{};
  $('feedMeta').textContent=f.available?`· source ${f.path} · ${f.total_scanned} records scanned`:'';
  if(!rows.length){$('feedTable').innerHTML=`<div class="feed-empty">${(snap.incidents||[]).length?'No records match the current filters.':'No detection records yet — the feed fills from logs/aegis_core.ndjson as the runtime processes events.'}</div>`;return}
  let html='<table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source → Dest</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
  for(const i of rows){
    const dst=i.dst_ip?esc(i.dst_ip):(i.detail&&i.detail.src_port?'port '+(i.detail.src_port??''):'—');
    const detail=[i.evidence?esc(i.evidence):null,i.receipt_valid?null:(i.receipt_errors&&i.receipt_errors.length?'receipt: '+esc(i.receipt_errors.join(', ')):null),
      i.detail&&i.detail.payload_len?'payload '+i.detail.payload_len+'B':null].filter(Boolean).join(' · ');
    html+=`<tr>
      <td class="small" title="${fmtTime(i.timestamp_ms)}">${fmtTime(i.timestamp_ms)}<div class="muted">${relTime(i.timestamp_ms)}</div></td>
      <td><span class="chip ${sevClass(i.severity)}">${sevLabel(i.severity)}</span></td>
      <td>${esc(i.rule_id||'—')}</td>
      <td class="small">${esc(i.src_ip||'—')} → ${dst}</td>
      <td><span class="pill st-${esc(i.status)} ${i.receipt_valid?'ok':''}">${esc(i.status)}</span>${i.receipt_valid?'':(i.status==='PEP_UNVERIFIED'?' <span class="muted small">unverified</span>':'')}</td>
      <td class="small muted">${detail||'—'}</td></tr>`;
  }
  html+='</tbody></table>';$('feedTable').innerHTML=html;
}

function renderRules(){
  const q=$('ruleQ').value.trim().toLowerCase();
  const rows=(snap.rules||[]).filter(r=>!q||[r.rule_id,r.name,r.category,r.severity,r.action].join(' ').toLowerCase().includes(q));
  $('ruleCount').textContent=`· ${rows.length} of ${(snap.rules||[]).length}`;
  if(!rows.length){$('ruleTable').innerHTML='<div class="feed-empty">No rules loaded from configs/Rules.json.</div>';return}
  let html='<table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Action</th><th>Layer</th></tr></thead><tbody>';
  for(const r of rows){
    html+=`<tr><td>${esc(r.rule_id||'—')}</td><td>${esc(r.name||'—')}</td><td class="small muted">${esc(r.category||'—')}</td>
    <td><span class="chip ${sevClass(r.severity)}">${sevLabel(r.severity)}</span></td>
    <td class="small">${esc((r.action||'').toUpperCase())}</td><td class="small muted">${esc(r.layer||'—')}</td></tr>`;
  }
  html+='</tbody></table>';$('ruleTable').innerHTML=html;
}

function kv(pairs){return pairs.map(([k,v,cls])=>`<div><span>${esc(k)}</span> <span class="${cls||''}">${v}</span></div>`).join('')}

function renderEnforcement(){
  const e=snap.enforcement||{},o=snap.operator||{},t=snap.threat||{};
  const cap=e.host_effect_capable;
  $('enfBody').innerHTML=kv([
    ['Prevention gate',`<span class="pill ${e.prevention_gate==='open'?'ok':'mut'}">${esc(e.prevention_gate||'closed').toUpperCase()}</span>`],
    ['Host effect capable',cap?'<span class="pill ok">YES</span>':'<span class="pill warn">NO</span>'],
    ['PEP available',e.pep_available?'<span class="pill ok">YES</span>':'<span class="pill warn">NO</span>'],
    ['WFP provider ready',e.provider_ready?'<span class="pill ok">READY</span>':'<span class="pill warn">UNAVAILABLE</span>'],
    ['Tier-3',esc(e.tier3||'—')+(e.tier3_enforcing?' <span class="pill ok">ENFORCING</span>':'')],
    ['Enforcement mode',esc(e.enforcement_mode||'detection-only')],
    ['Confirmed blocks (window)',num(t.confirmed_blocks),t.confirmed_blocks?'ok':''],
    ['Receipt required',snap?esc(String(e.receipt_required)): 'yes'],
  ]);
}

function renderSystem(){
  const h=snap.health||{};
  const subs=h.subsystems||{};const names=Object.keys(subs);
  let html='<div>';
  for(const n of names.sort()){const s=subs[n];
    const run=s.state==='RUNNING'||s.state==='READY';
    html+=`<div class="subrow"><span>${esc(n)}</span><span>${statePill(s.state,false)} <span class="muted small">${s.pid?('pid '+s.pid):''}</span></span></div>`}
  if(!names.length)html+='<div class="feed-empty">No subsystem data (control plane unavailable).</div>';
  html+='</div>';
  $('sysBody').innerHTML=html;
  const w=h.workers||{};const req=['pipeline_ready','sensor_ready','nose_ready','etw_ready','fim_ready','registry_ready'];
  const ready=req.filter(k=>w[k]).length;
  const reasons=(w.failure_reasons||[]).join(', ');
  const dp=h.data_plane||{};
  const eo=h.exactly_once||{};
  const pep=h.rust_pep||h.rust_shield||{};
  $('workerBody').innerHTML=kv([
    ['Worker readiness',`${ready}/6 ${ready<6?'<span class="pill warn">PARTIAL</span>':'<span class="pill ok">READY</span>'}`],
    ['Failure reasons',esc(reasons||'none')||'none',reasons?'warn':''],
    ['Nose frames',`read ${num(dp.nose_frames_read)} · submitted ${num(dp.nose_frames_submitted)} · dropped ${num(dp.nose_frames_dropped)}`],
    ['Exact-once',`last id ${num(eo.last_event_id)} · dup ${num(eo.duplicate_event_ids)} · non-monotonic ${num(eo.non_monotonic_event_ids)}`,
      (eo.duplicate_event_ids>0||eo.non_monotonic_event_ids>0)?'warn':''],
    ['Rust PEP / WFP',`${esc(pep.state||'UNKNOWN')} · provider ${pep.provider_ready?'READY':'UNAVAILABLE'} · host-effect ${pep.host_effect_capable?'CAPABLE':'NOT CAPABLE'}`],
    ['Counters',`in ${num(h.counters?.in_events)} · out ${num(h.counters?.out_events)} · err ${num(h.counters?.errors)} · dropped ${num(h.counters?.dropped)}`],
  ]);
  const f=snap.forensic||{};
  const ok=f.integrity==='ok';
  $('forensicBody').innerHTML=kv([
    ['Chain integrity',f.integrity?`<span class="pill ${ok?'ok':'bad'}">${esc(f.integrity.toUpperCase())}</span>`:'<span class="pill warn">NO DATA</span>'],
    ['Records',num(f.records)],
    ['Verified',f.verified===true?'<span class="pill ok">YES</span>':(f.verified===false?'<span class="pill bad">NO</span>':'<span class="pill mut">—</span>')],
  ]);
}

function render(){
  if(!snap)return;
  mode='online';
  renderHeader();renderBanner();renderOverview();renderFeed();renderRules();renderEnforcement();renderSystem();
}

async function refresh(){
  try{
    const r=await fetch('/api/snapshot',{cache:'no-store'});
    if(!r.ok)throw new Error('http '+r.status);
    snap=await r.json();lastOk=Date.now();fails=0;render();
  }catch(e){
    fails++;mode=fails>=3?'offline':'retrying';
    if(!snap)return;
    renderHeader();renderBanner();
    const b=$('banner');
    if(!b.classList.contains('off')){b.textContent='Connection lost — showing last received data ('+relTime(lastOk)+'). Retrying…';b.classList.add('off')}
  }
}

setInterval(refresh,REFRESH_MS);
['q','sevFilter','stFilter','confirmedOnly','ruleQ'].forEach(id=>$(id).addEventListener('input',()=>{if(snap){renderFeed();if(id==='ruleQ')renderRules()}}));
refresh();
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
    data = snapshot()
    return jsonify({"schema": "aegis.incidents.v1", "incidents": data["incidents"]})


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
    return Response(
        _sse_events(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


SSE_RETRY_MS = 3000
SSE_TICK_S = 3


def _sse_events(interval_s: float = SSE_TICK_S) -> Iterator[str]:
    """Yield one authoritative snapshot per tick (FE-SSE-090).

    Two failure modes closed here, both previously silent:

    * Client disconnect: the generator previously had no explicit
      handling, so a dead socket kept rendering full snapshots on
      every tick until garbage collection. GeneratorExit now ends
      the stream immediately (it must never yield after that).
    * Snapshot failure: one failed control query previously killed
      the whole stream (the exception propagated and the EventSource
      reconnected into another failure). A failed tick now emits an
      error event and the stream continues on the next tick.

    The stream stays read-only and bounded per message: every message
    is a complete snapshot, never a locally invented event.
    """
    yield f": connected\nretry: {SSE_RETRY_MS}\n\n"
    try:
        while True:
            try:
                payload = json.dumps(snapshot(), separators=(",", ":"))
            except Exception as exc:  # one bad tick must not kill the stream
                payload = json.dumps(
                    {
                        "schema": "aegis.operator.snapshot.v1",
                        "error": "snapshot_failed",
                        "detail": str(exc)[:200],
                    }
                )
            yield f"data: {payload}\n\n"
            time.sleep(interval_s)
    except GeneratorExit:
        return


@app.get("/health/check")
def health_check():
    data = snapshot()["health"]
    healthy = data.get("state") in {"RUNNING", "READY"} and not data.get("degraded", True)
    return ("healthy", 200) if healthy else ("degraded", 503)


if __name__ == "__main__":
    import os
    # T1-NET-019: loopback only. This console exposes detection logic
    # (Rules.json) and log contents; it must never listen on LAN interfaces.
    app.run(host="127.0.0.1", port=int(os.environ.get("DASHBOARD_PORT", "5000")), debug=False)
