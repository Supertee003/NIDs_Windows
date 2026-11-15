"""Bracket a lab attack with before/after runtime facts, not recollection.

RB-021 attributes a Kali run by hand: `events count --src-ip`, `events tail`,
`forensic search`, `alerts`, each typed after the fact and each reading the
whole log. That leaves three holes a hand-typed run cannot close:

  1. Nothing proves the sensor was looking at the interface the attack used.
     The daemon's canonical ingress is Go Nose, which auto-selects the first
     physical adapter with an address (`nose/capture.go:firstUpDevice`). On a
     host whose only live link is Wi-Fi that is the Wi-Fi NIC, so a Kali VM on
     a host-only VMnet can attack all day and stay invisible. The operator
     then reads "0 detections" as a detector failure.
  2. Nothing scopes the evidence to the attack interval. A pre-existing row
     from the same source is indistinguishable from a new firing.
  3. Nothing records the cost. A lab run that burns queue headroom or sheds
     frames must not look like a clean pass.

So this tool does one thing: it takes a byte offset into the durable evidence
log, plus runtime counters, waits while the operator attacks, then re-reads
both and reports only what changed. Everything it prints is a measurement.

Usage:
    # 1. Prove the capture path and learn the real target IP (writes nothing)
    python tools/lab_attack_window.py --preflight

    # 2. Bracket the attack (start this, then fire from Kali)
    python tools/lab_attack_window.py --label wifi-bridged-20261116 \
        --seconds 240 --expect-src 192.168.1.50

    # 3. Machine-readable
    python tools/lab_attack_window.py --label ... --json out.json

Exit codes:
    0  PASS      wire ingress advanced AND at least one row attributed to --expect-src
    2  NO_ATTRIBUTION  wire advanced, no row from the attacker (miss, not silence)
    3  BLIND     wire ingress did not advance: the sensor is not on that segment
    4  unavailable  control pipe unreachable
    5  INVARIANT detection-only contract violated (a host effect was recorded)

The tool is read-only: no service control, no rules, no policy, no writes
outside the --out-root artifact. It never restarts a component, so it cannot
invalidate a soak window that is already running.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
NOSE_EXE = REPO / "nose" / "aegis-nose.exe"
RULES_FILE = REPO / "configs" / "Rules.json"
DEFAULT_OUT_ROOT = REPO / "admin-evidence"

# Mirrors nose/capture.go:firstUpDevice(). The Go selector skips adapters with
# no address and any adapter whose name/description carries one of these
# markers, so an operator-facing "the sensor watches X" claim must use the
# same list -- a tool that guessed differently would bless the wrong target.
SKIP_MARKERS = (
    "wan miniport",
    "hyper-v",
    "vmware",
    "bluetooth",
    "wi-fi direct",
    "teamviewer",
    "loopback",
    "npcap loopback",
)

# Detection-only contract: a lab row may be observed, never enforced.
ALLOWED_ENFORCEMENT = {"observed", ""}
INVARIANT_FIELDS = ("host_effect_confirmed",)

MAX_DELTA_BYTES = 128 * 1024 * 1024


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _stamp(moment: dt.datetime) -> str:
    return moment.strftime("%Y%m%dT%H%M%SZ")


def fnv1a32(text: str) -> int:
    """FNV-1a 32-bit over UTF-8. The same derivation the Zig rule loader uses
    to turn a rule id string into the numeric id the evidence log stores."""
    h = 0x811C9DC5
    for byte in text.encode("utf-8"):
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def rule_names(rules_file: Path = RULES_FILE) -> dict[int, dict]:
    """Numeric rule id -> {rule_id, name, layer}. Absent file is not an error:
    an unknown numeric must stay visible, never be dropped."""
    try:
        doc = json.loads(rules_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    rows = doc.get("nids_rules")
    if not isinstance(rows, list):
        return {}
    out: dict[int, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        rid = row.get("rule_id")
        if not isinstance(rid, str):
            continue
        out[fnv1a32(rid)] = {
            "rule_id": rid,
            "name": row.get("name", ""),
            "layer": row.get("layer", ""),
        }
    return out


def describe_rule(numeric: str | int) -> str:
    try:
        key = int(numeric)
    except (TypeError, ValueError):
        return f"rule={numeric}"
    hit = rule_names().get(key)
    if hit is None:
        return f"rule={key} UNKNOWN"
    return f"{hit['rule_id']} {hit['name']}"


# --------------------------------------------------------------------------
# evidence log
# --------------------------------------------------------------------------


def event_log_path() -> Path:
    """Same resolution order as `aegisctl.py events`.

    The service writes relative to ITS cwd (System32); an interactive run
    writes under the repo. Newest existing candidate wins, because reading the
    stale one has already produced false quiet results (F2). An explicit
    AEGIS_EVENT_LOG is authoritative even when the file is missing.
    """
    override = os.environ.get("AEGIS_EVENT_LOG")
    if override:
        return Path(override)
    candidates = [
        Path(r"C:\Windows\System32\logs\aegis_core.ndjson"),
        REPO / "logs" / "aegis_core.ndjson",
    ]
    best: Path | None = None
    best_mtime = -1.0
    for path in candidates:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime > best_mtime:
            best, best_mtime = path, mtime
    return best if best is not None else candidates[-1]


def log_offset(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def read_rows_since(path: Path, offset: int) -> tuple[list[dict], int, int]:
    """Rows appended after `offset`, plus (bytes_read, next_offset).

    A trailing partial line is left for the next read: the writer may be
    mid-append, and half a JSON object must never be counted as evidence.
    """
    if not path.exists():
        return [], 0, offset
    try:
        size = path.stat().st_size
    except OSError:
        return [], 0, offset
    if size <= offset:
        return [], 0, offset
    if size - offset > MAX_DELTA_BYTES:
        offset = size - MAX_DELTA_BYTES
    with path.open("rb") as handle:
        handle.seek(offset)
        blob = handle.read()
    consumed = blob.rfind(b"\n") + 1
    rows: list[dict] = []
    for line in blob[:consumed].splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    # Advance only past the last complete line: a trailing partial object is
    # re-read next time instead of being skipped forever.
    return rows, consumed, offset + consumed


def attribute(rows: list[dict], src_ip: str | None) -> list[dict]:
    if not src_ip:
        return []
    return [row for row in rows if row.get("src_ip") == src_ip]


# --------------------------------------------------------------------------
# capture-path discovery (mirrors the Go selector, read-only)
# --------------------------------------------------------------------------


def parse_list_devices(text: str) -> list[dict]:
    """Parse `aegis-nose.exe --list-devices` stderr into device records."""
    devices: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        line = line.strip()
        match = re.match(
            r'\[NOSE DEVICES\] #(\d+) name=(\S+) description="(.*)" addresses=(\d+)',
            line,
        )
        if match:
            current = {
                "index": int(match.group(1)),
                "name": match.group(2),
                "description": match.group(3),
                "addresses": [],
                "_declared": int(match.group(4)),
            }
            devices.append(current)
            continue
        match = re.match(r"\[NOSE DEVICES\] #(\d+) address=(\S+) netmask=(\S+)", line)
        if match and current is not None:
            current["addresses"].append({"ip": match.group(2), "netmask": match.group(3)})
    return devices


def select_capture_device(devices: list[dict]) -> dict | None:
    """The adapter Go Nose auto-selects: first with an address whose
    name+description carries no skip marker, else the first with an address."""
    real = [d for d in devices if d.get("addresses")]
    for device in real:
        label = (device["name"] + " " + device.get("description", "")).lower()
        if not any(marker in label for marker in SKIP_MARKERS):
            return device
    return real[0] if real else None


def usable_ipv4(device: dict | None) -> list[str]:
    if not device:
        return []
    out = []
    for entry in device.get("addresses", []):
        ip = entry.get("ip", "")
        if ":" in ip:
            continue
        if ip.startswith("169.254.") or ip.startswith("127."):
            continue
        out.append(ip)
    return out


def discover_capture() -> dict:
    """Run the shipped selector and report what it would watch."""
    info: dict = {"nose_exe": str(NOSE_EXE), "available": False, "devices": []}
    if not NOSE_EXE.is_file():
        info["error"] = "aegis-nose.exe not found"
        return info
    try:
        proc = subprocess.run(
            [str(NOSE_EXE), "--list-devices"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(NOSE_EXE.parent),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
        return info
    devices = parse_list_devices(proc.stdout + "\n" + proc.stderr)
    info["devices"] = devices
    info["available"] = bool(devices)
    chosen = select_capture_device(devices)
    if chosen is not None:
        info["selected_name"] = chosen["name"]
        info["selected_description"] = chosen.get("description", "")
        info["selected_ipv4"] = usable_ipv4(chosen)
    return info


# --------------------------------------------------------------------------
# control-plane snapshots
# --------------------------------------------------------------------------


def _payload(response: dict | None) -> dict:
    if not isinstance(response, dict):
        return {}
    data = response.get("data", response)
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return {}
    return data if isinstance(data, dict) else {}


class Control:
    def __init__(self) -> None:
        if str(TOOLS) not in sys.path:
            sys.path.insert(0, str(TOOLS))
        from aegisctl.client import AegisClient  # local import: keeps --help offline

        self._client = AegisClient()

    def ask(self, command: str) -> dict:
        try:
            return _payload(self._client.send(command))
        except Exception:  # noqa: BLE001 - any transport fault means "no facts"
            return {}


def snapshot(control: Control) -> dict:
    status = control.ask("status")
    queue = control.ask("queue.stats")
    incidents = control.ask("incidents.list")
    return {
        "taken_at": _utc_now().isoformat().replace("+00:00", "Z"),
        "packets_captured": status.get("packets_captured"),
        "uptime_ms": status.get("uptime_ms"),
        "pid": status.get("pid"),
        "flows_active": status.get("flows_active"),
        "dropped_total": queue.get("dropped_total"),
        "shed_overload": queue.get("shed_overload"),
        "source_quota_shed": queue.get("source_quota_shed"),
        "depth": queue.get("depth"),
        "by_source": queue.get("by_source") or [],
        "detections": incidents.get("detections"),
        "incidents_open": incidents.get("incidents_open"),
        "available": bool(status) or bool(queue),
    }


def _delta(before, after) -> int | None:
    if isinstance(before, int) and isinstance(after, int):
        return after - before
    return None


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------


def preflight(control: Control, sample_seconds: float) -> dict:
    discover = discover_capture()
    first = snapshot(control)
    if not first["available"]:
        return {"ok": False, "reason": "control pipe unavailable", "capture": discover}
    time.sleep(max(1.0, sample_seconds))
    second = snapshot(control)
    gained = _delta(first["packets_captured"], second["packets_captured"])
    return {
        "ok": gained is not None and gained > 0,
        "reason": "wire ingress advancing" if (gained or 0) > 0 else "no frames advanced",
        "sample_seconds": sample_seconds,
        "frames_gained": gained,
        "capture": discover,
        "before": first,
        "after": second,
    }


# --------------------------------------------------------------------------
# window evaluation
# --------------------------------------------------------------------------


def evaluate(
    before: dict,
    after: dict,
    rows: list[dict],
    expect_src: str | None,
) -> dict:
    """Turn the two snapshots plus the new rows into a verdict.

    PASS needs two independent facts: the ingress counter moved (the sensor is
    on that segment) AND a row exists that names the attacker (the pipeline
    attributed it). Either alone is not a detection proof.
    """
    gained = _delta(before.get("packets_captured"), after.get("packets_captured"))
    attributed = attribute(rows, expect_src)

    per_rule: dict[str, int] = {}
    for row in attributed:
        per_rule[str(row.get("rule", "0"))] = per_rule.get(str(row.get("rule", "0")), 0) + 1

    violations = []
    for row in rows:
        status = row.get("enforcement_status")
        if isinstance(status, str) and status not in ALLOWED_ENFORCEMENT:
            violations.append({"event": row.get("event"), "enforcement_status": status})
        for field in INVARIANT_FIELDS:
            if row.get(field) is True:
                violations.append({"event": row.get("event"), field: True})

    if violations:
        verdict, code = "INVARIANT", 5
    elif not scored(gained):
        verdict, code = "BLIND", 3
    elif expect_src and not attributed:
        verdict, code = "NO_ATTRIBUTION", 2
    else:
        verdict, code = "PASS", 0

    return {
        "verdict": verdict,
        "exit_code": code,
        "frames_gained": gained,
        "rows_total": len(rows),
        "rows_attributed": len(attributed),
        "expect_src": expect_src,
        "per_rule": per_rule,
        "per_rule_named": {key: describe_rule(key) for key in per_rule},
        "detections_delta": _delta(before.get("detections"), after.get("detections")),
        "dropped_delta": _delta(before.get("dropped_total"), after.get("dropped_total")),
        "shed_delta": _delta(before.get("shed_overload"), after.get("shed_overload")),
        "quota_shed_delta": _delta(
            before.get("source_quota_shed"), after.get("source_quota_shed")
        ),
        "violations": violations[:20],
        "violations_total": len(violations),
    }


def scored(gained: int | None) -> bool:
    """A counter that is missing or went backwards is not evidence of ingress."""
    return gained is not None and gained > 0


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def render_text(doc: dict) -> list[str]:
    lines = []
    pre = doc.get("preflight") or {}
    capture = pre.get("capture") or {}
    if capture.get("selected_name"):
        lines.append(f"capture device : {capture['selected_name']}")
        lines.append(f"  description  : {capture.get('selected_description', '')}")
        ips = capture.get("selected_ipv4") or []
        lines.append(f"  target IPv4  : {', '.join(ips) if ips else 'none'}")
    elif capture:
        lines.append(f"capture device : unknown ({capture.get('error', 'no devices')})")
    if pre.get("frames_gained") is not None:
        lines.append(f"preflight      : {pre['reason']} ({pre['frames_gained']:+d} frames)")

    result = doc.get("result") or {}
    if not result:
        return lines
    lines.append("")
    lines.append(f"frames gained  : {result.get('frames_gained')}")
    lines.append(f"new rows       : {result.get('rows_total')}")
    lines.append(f"attributed rows: {result.get('rows_attributed')} (src {result.get('expect_src') or 'n/a'})")
    lines.append(
        "deltas         : detections {0:+d}  dropped {1:+d}  shed {2:+d}  quota_shed {3:+d}".format(
            result.get("detections_delta") or 0,
            result.get("dropped_delta") or 0,
            result.get("shed_delta") or 0,
            result.get("quota_shed_delta") or 0,
        )
    )
    named = result.get("per_rule_named") or {}
    if named:
        lines.append("per rule       :")
        for key, name in sorted(named.items(), key=lambda kv: -result["per_rule"][kv[0]]):
            lines.append(f"  {result['per_rule'][key]:>5}  {name}")
    if result.get("violations_total"):
        lines.append(f"VIOLATIONS     : {result['violations_total']}")
    lines.append("")
    lines.append(f"VERDICT        : {result.get('verdict')} (exit {result.get('exit_code')})")
    return lines


def render_markdown(doc: dict) -> str:
    pre = doc.get("preflight") or {}
    capture = pre.get("capture") or {}
    result = doc.get("result") or {}
    out = [
        f"# Lab attack window: {doc.get('label', 'unlabelled')}",
        "",
        f"- started: `{doc.get('started_at')}`",
        f"- finished: `{doc.get('finished_at')}`",
        f"- window: {doc.get('seconds')} s",
        f"- repo HEAD: `{doc.get('head_sha')}`",
        f"- evidence log: `{doc.get('event_log')}`",
        "",
        "## Capture path",
        "",
        f"- selected device: `{capture.get('selected_name', 'unknown')}`",
        f"- description: {capture.get('selected_description', '')}",
        f"- target IPv4: {', '.join(capture.get('selected_ipv4') or []) or 'none'}",
        f"- preflight: {pre.get('reason', 'not run')} "
        f"({pre.get('frames_gained')} frames over {pre.get('sample_seconds')} s)",
        "",
        "## Measurement",
        "",
        "| fact | before | after | delta |",
        "|---|---:|---:|---:|",
    ]
    before = doc.get("before") or {}
    after = doc.get("after") or {}
    for key in ("packets_captured", "detections", "dropped_total", "shed_overload",
                "source_quota_shed", "flows_active"):
        out.append(
            f"| {key} | {before.get(key)} | {after.get(key)} | {_delta(before.get(key), after.get(key))} |"
        )
    out += [
        "",
        f"- new evidence rows: {result.get('rows_total')}",
        f"- rows attributed to `{result.get('expect_src') or 'n/a'}`: {result.get('rows_attributed')}",
    ]
    named = result.get("per_rule_named") or {}
    if named:
        out += ["", "| rows | rule |", "|---:|---|"]
        for key, name in sorted(named.items(), key=lambda kv: -result["per_rule"][kv[0]]):
            out.append(f"| {result['per_rule'][key]} | {name} |")
    if result.get("violations_total"):
        out += ["", f"**Detection-only violations: {result['violations_total']}**", ""]
        for item in result.get("violations") or []:
            out.append(f"- `{json.dumps(item, sort_keys=True)}`")
    out += ["", "## Verdict", "", f"`{result.get('verdict')}` (exit {result.get('exit_code')})", ""]
    return "\n".join(out)


def head_sha() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(REPO),
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return proc.stdout.strip() or "unknown"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def run_window(args, control: Control) -> tuple[dict, int]:
    log = event_log_path()
    offset = log_offset(log)
    started = _utc_now()

    pre = preflight(control, args.preflight_seconds) if not args.skip_preflight else {}
    before = pre.get("before") if pre else snapshot(control)
    if before is None:
        before = snapshot(control)

    if args.seconds > 0:
        print(f"window open: {args.seconds}s -- fire the attack now", flush=True)
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            remaining = int(deadline - time.monotonic())
            if remaining and remaining % 10 == 0:
                print(f"  {remaining:>4}s remaining", flush=True)
            time.sleep(1)
    after = snapshot(control)
    rows, _, _ = read_rows_since(log, offset)
    result = evaluate(before, after, rows, args.expect_src)
    doc = {
        "label": args.label,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": _utc_now().isoformat().replace("+00:00", "Z"),
        "seconds": args.seconds,
        "head_sha": head_sha(),
        "event_log": str(log),
        "log_offset": offset,
        "preflight": pre,
        "before": before,
        "after": after,
        "result": result,
    }
    return doc, result["exit_code"]


def write_artifacts(doc: dict, out_root: Path) -> tuple[Path, Path]:
    folder = out_root / f"lab-{doc['label']}"
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"attack-window-{_stamp(_utc_now())}"
    json_path = folder / f"{stem}.json"
    md_path = folder / f"{stem}.md"
    json_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(doc), encoding="utf-8")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bracket a lab attack with before/after runtime facts.",
    )
    parser.add_argument("--label", default="", help="artifact label, e.g. wifi-bridged-20261116")
    parser.add_argument("--seconds", type=int, default=180, help="attack window length (0 = instant)")
    parser.add_argument("--expect-src", default=None, help="attacker IPv4 to attribute")
    parser.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT), help="artifact root")
    parser.add_argument("--preflight", action="store_true", help="only prove the capture path")
    parser.add_argument("--skip-preflight", action="store_true", help="skip the 5 s ingress sample")
    parser.add_argument("--preflight-seconds", type=float, default=5.0)
    parser.add_argument("--json", default=None, help="also write the doc to this path")
    args = parser.parse_args(argv)

    if not args.label:
        args.label = "unlabelled-" + _stamp(_utc_now())

    control = Control()

    if args.preflight:
        pre = preflight(control, args.preflight_seconds)
        if pre.get("capture"):
            for line in render_text({"preflight": pre}):
                print(line)
        if not pre.get("ok"):
            print(f"PREFLIGHT FAILED: {pre.get('reason')}", file=sys.stderr)
            if pre.get("reason") == "control pipe unavailable":
                return 4
            return 3
        print("PREFLIGHT OK: the sensor is receiving frames on this device")
        return 0

    doc, code = run_window(args, control)
    for line in render_text(doc):
        print(line)
    json_path, md_path = write_artifacts(doc, Path(args.out_root))
    print(f"artifact: {json_path}")
    print(f"report  : {md_path}")
    if args.json:
        Path(args.json).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
