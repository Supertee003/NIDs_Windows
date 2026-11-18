"""Select which segment the sensor watches, and prove it is the one you meant.

Why this tool exists
--------------------
Two capture readers can exist on this host:

  * Go Nose -- the canonical network ingress. It takes an explicit ``--iface``
    selector (``$AEGIS_NOSE_IFACE``) or auto-selects the first physical adapter
    with an address (``nose/capture.go:firstUpDevice``, which skips WAN
    Miniport, Hyper-V, VMware, Bluetooth, Wi-Fi Direct, TeamViewer, loopback).
  * The daemon's optional direct Npcap reader -- pinned by
    ``$AEGIS_DAEMON_IFACE`` and allowed to run only when its selector is
    disjoint from the nose selector (EVT-200: overlapping readers duplicate
    events, and a duplicate is not a second detection).

Both knobs are machine-scope environment variables read at process start.
Hand-editing them is how a lab ends up watching a segment nobody attacks --
a host-only Kali VM against a sensor auto-selected onto Wi-Fi -- real packets,
zero detections, and an operator who blames the detector. This tool turns that
decision into one validated command:

  * it enumerates the devices Npcap actually exposes (``--list-devices``),
  * it resolves a selector the way the runtime does (exact canonical name,
    else a unique case-insensitive description substring) and refuses
    ambiguity instead of guessing,
  * it enforces the disjointness rule before anything is written,
  * it prints the exact machine-scope command, and mutates only with --apply,
  * it never restarts a service unless asked: a restart ends a soak window.

Usage
-----
    python tools/capture_select.py --list              # devices Npcap exposes
    python tools/capture_select.py --show              # pins + verdict
    python tools/capture_select.py --plan --nose VMnet1
    python tools/capture_select.py --apply --nose VMnet1          # admin
    python tools/capture_select.py --apply --nose "<npf>" --daemon "<npf>"
    python tools/capture_select.py --clear --role daemon --apply
    python tools/capture_select.py --verify            # ingress advancing?

Read-only modes (--list/--show/--plan/--verify) never write, never restart,
and never touch rules, policy, or WFP state. --apply writes the two
machine-scope variables and nothing else; the caller restarts the service.

Exit codes
----------
    0  OK / plan rendered / nothing to change
    2  blocked: invalid or ambiguous selector, overlapping roles, needs admin
    3  verification failed: ingress did not advance on the selected device
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = Path(__file__).resolve().parent
NOSE_EXE = REPO / "nose" / "aegis-nose.exe"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

# Reuse the one parser/selector that already mirrors the Go runtime, so this
# tool cannot drift into blessing a device the sensor would not open.
from lab_attack_window import parse_list_devices, select_capture_device, usable_ipv4  # noqa: E402

NOSE_ENV = "AEGIS_NOSE_IFACE"
DAEMON_ENV = "AEGIS_DAEMON_IFACE"
ENV_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

_UNSET = object()


# --------------------------------------------------------------------------
# pure helpers (unit-pinned; no system touch)
# --------------------------------------------------------------------------


def resolve_selector(devices: list[dict], selector: str) -> tuple[dict | None, str]:
    """Resolve a selector to exactly one Npcap device, or explain why not.

    Precedence matches the runtime: exact canonical name first (so a GUID is
    never reinterpreted as a substring), then a case-insensitive description
    substring. Two matches is an error, never a coin flip.
    """
    text = (selector or "").strip()
    if not text:
        return None, "empty selector"
    if text.startswith("#"):
        try:
            index = int(text[1:])
        except ValueError:
            return None, "index selector must look like #3 (see --list)"
        for device in devices:
            if device.get("index") == index:
                return device, ""
        return None, f"no device at index {index}"
    lowered = text.lower()
    for device in devices:
        if (device.get("name") or "").lower() == lowered:
            return device, ""
    for device in devices:
        if (device.get("description") or "").strip().lower() == lowered:
            return device, ""
    matches = [d for d in devices if lowered in (d.get("description") or "").lower()]
    if not matches:
        return None, "matches no Npcap device"
    if len(matches) > 1:
        labels = "; ".join(
            f"#{d.get('index', '?')} {d.get('name')} ({(d.get('description') or '?')[:40]})"
            for d in matches[:4]
        )
        return None, f"ambiguous: {len(matches)} devices match -> {labels}"
    return matches[0], ""


def overlaps(first: str, second: str) -> bool:
    """True when two selectors can name the same device (EVT-200 rule)."""
    a = (first or "").strip().lower()
    b = (second or "").strip().lower()
    if not a or not b:
        return False
    return a == b or a in b or b in a


def direct_capture_state(nose_device: str, daemon_device: str) -> tuple[str, str]:
    """The daemon guard's verdict, reproduced from the pinned contract.

    Inputs are *resolved canonical device names*, never raw selectors: a GUID
    and a description substring can name one adapter, and the guard must judge
    identity (see ``selectorsResolveDisjoint`` in src/capture/npcap_adapter.zig).
    Enabled only when both are present and different.
    """
    if not daemon_device:
        return "disabled", "AEGIS_DAEMON_IFACE unset"
    if not nose_device:
        return "disabled", "AEGIS_NOSE_IFACE unset or unresolved: device identity unprovable"
    if overlaps(nose_device, daemon_device):
        return "disabled", "both selectors resolve to one device"
    return "enabled", "selectors resolve to two devices"


def evaluate(devices: list[dict], env: dict) -> dict:
    """Everything an operator needs before trusting a capture topology."""
    nose_pin = (env.get(NOSE_ENV) or "").strip()
    daemon_pin = (env.get(DAEMON_ENV) or "").strip()
    auto = select_capture_device(devices)
    problems: list[str] = []

    def role(selector: str, label: str) -> dict:
        if not selector:
            return {"pinned": False, "selector": "", "device": None,
                    "target_ipv4": [], "error": ""}
        device, error = resolve_selector(devices, selector)
        if error:
            problems.append(f"{label}: {selector!r} {error}")
        return {
            "pinned": True,
            "selector": selector,
            "device": (device or {}).get("name"),
            "description": (device or {}).get("description"),
            "target_ipv4": usable_ipv4(device),
            "error": error,
        }

    nose = role(nose_pin, "nose pin")
    daemon = role(daemon_pin, "daemon pin")
    state, reason = direct_capture_state(nose.get("device") or "", daemon.get("device") or "")
    if daemon_pin and not nose_pin:
        problems.append(
            "daemon pin set without a nose pin: direct capture stays disabled "
            "(overlap with the auto-selected nose reader is unprovable)"
        )
    if state == "enabled" and daemon.get("error"):
        problems.append("daemon pin does not resolve to a real device")

    effective = nose["device"] if nose["device"] else (auto or {}).get("name")
    return {
        "tool": "capture_select",
        "devices_seen": len(devices),
        "auto_select": {
            "name": (auto or {}).get("name"),
            "description": (auto or {}).get("description"),
            "target_ipv4": usable_ipv4(auto),
        },
        "nose": nose,
        "daemon": daemon,
        "effective_nose_device": effective,
        "effective_nose_source": "pin" if nose["device"] else "auto-select",
        "direct_capture": {"state": state, "reason": reason},
        "problems": problems,
        "verdict": "CAPTURE_SELECT_BLOCKED" if problems else "CAPTURE_SELECT_OK",
    }


def build_plan(
    devices: list[dict],
    *,
    nose: object = _UNSET,
    daemon: object = _UNSET,
    clear_role: str = "",
) -> dict:
    """Validate a requested change and render the exact commands it needs."""
    commands: list[list[str]] = []
    errors: list[str] = []
    resolved: dict[str, str] = {}

    def pin(value: object, name: str, label: str) -> None:
        if value is _UNSET:
            return
        text = str(value).strip()
        if not text:
            errors.append(f"{label}: empty selector (use --clear --role)")
            return
        device, error = resolve_selector(devices, text)
        if error:
            errors.append(f"{label}: {text!r} {error}")
            return
        resolved[label] = device["name"]
        commands.append(["setx", "/M", name, device["name"]])

    if clear_role in ("nose", "both"):
        resolved["nose"] = ""
        commands.append(["reg", "delete", ENV_KEY, "/V", NOSE_ENV, "/F"])
    else:
        pin(nose, NOSE_ENV, "nose")

    if clear_role in ("daemon", "both"):
        resolved["daemon"] = ""
        commands.append(["reg", "delete", ENV_KEY, "/V", DAEMON_ENV, "/F"])
    else:
        pin(daemon, DAEMON_ENV, "daemon")

    if "nose" in resolved and "daemon" in resolved:
        if overlaps(resolved["nose"], resolved["daemon"]):
            errors.append(
                "nose and daemon resolve to the same/overlapping device: "
                "the direct reader would duplicate canonical events"
            )

    return {
        "tool": "capture_select",
        "mode": "plan",
        "resolved": resolved,
        "commands": commands,
        "errors": errors,
        "restart_required": bool(commands) and not errors,
        "verdict": "CAPTURE_SELECT_BLOCKED" if errors else "CAPTURE_SELECT_PLAN_OK",
    }


def render_devices(devices: list[dict], state: dict) -> str:
    """Human table: index, selector, description, IPv4, role tags."""
    nose_pin = state["nose"].get("selector", "")
    daemon_pin = state["daemon"].get("selector", "")
    lines = [f"{len(devices)} Npcap device(s)"]
    for device in devices:
        name = device.get("name") or "?"
        tags = []
        if state.auto_select.get("name") == name:
            tags.append("AUTO")
        if nose_pin and resolve_selector(devices, nose_pin)[0] is device:
            tags.append("NOSE")
        if daemon_pin and resolve_selector(devices, daemon_pin)[0] is device:
            tags.append("DAEMON")
        ips = ", ".join(usable_ipv4(device)) or "-"
        desc = (device.get("description") or "")[:56]
        tag_text = ("  <" + ",".join(tags) + ">") if tags else ""
        lines.append(f"  #{device.get('index', '?'):>2} {name}{tag_text}")
        lines.append(f"      {desc}  [{ips}]")
    return "\n".join(lines)


def render_state(state: dict) -> str:
    nose = state["nose"]
    daemon = state["daemon"]
    lines = [
        "CAPTURE SELECTION",
        f"  devices seen      : {state['devices_seen']}",
        f"  nose pin          : {nose.get('selector') or '(unset: auto-select)'}",
        f"  nose watches      : {state['effective_nose_device'] or '?'} "
        f"({state['effective_nose_source']})",
        f"  attack target IP  : {', '.join(nose.get('target_ipv4') or state['auto_select'].get('target_ipv4') or []) or '?'}",
        f"  daemon pin        : {daemon.get('selector') or '(unset)'}",
        f"  direct capture    : {state['direct_capture']['state']} ({state['direct_capture']['reason']})",
    ]
    if nose.get("error"):
        lines.append(f"  nose error        : {nose['error']}")
    if daemon.get("error"):
        lines.append(f"  daemon error      : {daemon['error']}")
    for problem in state["problems"]:
        lines.append(f"  PROBLEM           : {problem}")
    lines.append(f"  verdict           : {state['verdict']}")
    return "\n".join(lines)


def render_plan(plan: dict) -> str:
    lines = ["CAPTURE SELECTION PLAN (nothing written yet)"]
    if plan["errors"]:
        for error in plan["errors"]:
            lines.append(f"  ERROR : {error}")
    for resolved, name in plan["resolved"].items():
        lines.append(f"  {resolved:<6}: {name or '(cleared -> auto-select)'}")
    for command in plan["commands"]:
        lines.append("  $ " + " ".join(command))
    if plan["restart_required"]:
        lines.append("  restart required: the service reads these at process start")
        lines.append("  $ Restart-Service AegisNids   # ends a running soak window")
    lines.append(f"  verdict: {plan['verdict']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# host seams (kept thin so tests never touch the host)
# --------------------------------------------------------------------------


def load_devices() -> list[dict]:
    """Ask the shipped Go binary what Npcap exposes (read-only)."""
    proc = subprocess.run(
        [str(NOSE_EXE), "--list-devices"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(NOSE_EXE.parent),
    )
    return parse_list_devices(proc.stdout + "\n" + proc.stderr)


def read_machine_env(names: tuple[str, ...]) -> dict:
    """Machine-scope values; falls back to the process env when unreadable."""
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ENV_KEY, 0, winreg.KEY_READ) as key:
            out = {}
            for name in names:
                try:
                    out[name] = str(winreg.QueryValueEx(key, name)[0])
                except FileNotFoundError:
                    out[name] = ""
            return out
    except OSError:
        return {name: os.environ.get(name, "") for name in names}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def apply_commands(commands: list[list[str]]) -> list[dict]:
    """Run the machine-scope writes. Caller has already checked elevation."""
    results = []
    for command in commands:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=60)
        results.append({
            "command": " ".join(command),
            "rc": proc.returncode,
            "stderr": (proc.stderr or "").strip()[:200],
        })
    return results


def verify_ingress(seconds: int = 5) -> int:
    """Delegate to the proven preflight: does wire ingress advance at all?"""
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "lab_attack_window.py"), "--preflight",
         "--seconds", str(seconds)],
        capture_output=True, text=True, timeout=300, cwd=str(REPO),
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validated capture-segment selection")
    parser.add_argument("--list", action="store_true", help="list Npcap devices")
    parser.add_argument("--show", action="store_true", help="show pins and verdict")
    parser.add_argument("--plan", action="store_true", help="validate and print commands")
    parser.add_argument("--apply", action="store_true", help="write machine-scope pins (admin)")
    parser.add_argument("--nose", default=_UNSET, help="selector for AEGIS_NOSE_IFACE")
    parser.add_argument("--daemon", default=_UNSET, help="selector for AEGIS_DAEMON_IFACE")
    parser.add_argument("--clear", action="store_true", help="remove a pin (with --role)")
    parser.add_argument("--role", choices=("nose", "daemon", "both"), default="",
                        help="which pin --clear removes")
    parser.add_argument("--verify", action="store_true", help="prove ingress advances")
    parser.add_argument("--seconds", type=int, default=5, help="verify sample window")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.clear and not args.role:
        parser.error("--clear needs --role nose|daemon|both")

    wants_change = args.plan or args.apply
    if not any((args.list, args.show, wants_change, args.verify)):
        args.show = True

    devices = load_devices() if (args.list or args.show or wants_change) else []
    state = evaluate(devices, read_machine_env((NOSE_ENV, DAEMON_ENV))) if devices else {}

    if args.list:
        print(json.dumps({"devices": devices, "auto_select": state.get("auto_select")},
                         indent=2) if args.json else render_devices(devices, state))
        return 0

    if wants_change:
        plan = build_plan(
            devices,
            nose=args.nose,
            daemon=args.daemon,
            clear_role=args.role if args.clear else "",
        )
        if args.json:
            print(json.dumps(plan, indent=2))
        else:
            print(render_plan(plan))
        if plan["errors"]:
            return 2
        if not args.apply:
            return 0
        if not is_admin():
            print("BLOCKED: machine-scope writes need an elevated shell", file=sys.stderr)
            for command in plan["commands"]:
                print("  " + " ".join(command), file=sys.stderr)
            return 2
        results = apply_commands(plan["commands"])
        for result in results:
            print(f"  rc={result['rc']} {result['command']} {result['stderr']}")
        failed = [r for r in results if r["rc"] != 0]
        if failed:
            print("CAPTURE_SELECT_BLOCKED: a write failed", file=sys.stderr)
            return 2
        print("APPLIED. Restart AegisNids for the running processes to inherit the pins.")
        return 0

    if args.verify:
        return 3 if verify_ingress(args.seconds) not in (0,) else 0

    print(json.dumps(state, indent=2) if args.json else render_state(state))
    return 0 if state["verdict"] == "CAPTURE_SELECT_OK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
