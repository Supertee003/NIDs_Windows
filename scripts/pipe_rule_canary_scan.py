#!/usr/bin/env python3
"""Observe-only synthetic named-pipe canary for R3001-R3005."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "configs" / "Rules.json"
CASES = {
    "R3001": ("MSSE-1234", "eventpipe-1234"),
    "R3002": ("psexec-svc", "spoolss"),
    "R3003": ("anonymous-channel", "sqlquery"),
    "R3004": ("meterpreter-ctrl", "diagnostic-channel"),
    "R3005": ("atsvc-job-1", "schedule-notify"),
}
PREFIXES = {
    "R3001": ("msse-", "postex_", "status_"),
    "R3002": ("psexec", "paexec"),
    "R3003": ("anonymous",),
    "R3004": ("meterpreter",),
    "R3005": ("atsvc",),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    rules = {r["rule_id"]: r for r in json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]}
    errors: list[str] = []
    rows: list[tuple[str, str, bool, bool, bool, bool]] = []
    for rule_id, (positive, negative) in CASES.items():
        rule = rules.get(rule_id)
        if not rule:
            errors.append(f"missing rule {rule_id}")
            continue
        pattern = re.compile(rule["regex_pattern"], re.IGNORECASE)
        prefixes = PREFIXES[rule_id]
        sensor_positive = any(positive.lower().startswith(p) for p in prefixes)
        sensor_negative = any(negative.lower().startswith(p) for p in prefixes)
        regex_positive = bool(pattern.search(positive))
        regex_negative = bool(pattern.search(negative))
        rows.append((rule_id, positive, sensor_positive, sensor_negative, regex_positive, regex_negative))
        if not sensor_positive or not regex_positive:
            errors.append(f"{rule_id}: positive pipe did not match sensor and/or rule regex")
        if sensor_negative or regex_negative:
            errors.append(f"{rule_id}: benign pipe matched sensor and/or rule regex")

    status = "PASS" if not errors else "FAIL"
    lines = [
        "# L2_PIPE Synthetic Rule Canary",
        "",
        f"**Status:** `{status}`",
        "",
        "This scan checks in-memory pipe-name fixtures against the native prefix matcher and configured rule regexes. It does not create a named pipe, perform remote execution, or invoke enforcement.",
        "",
        "| Rule | Positive | Sensor+ | Sensor- | Regex+ | Regex- |",
        "|---|---|---:|---:|---:|---:|",
    ]
    lines.extend(f"| `{rid}` | `{name}` | `{sp}` | `{sn}` | `{rp}` | `{rn}` |" for rid, name, sp, sn, rp, rn in rows)
    lines += ["", "## Findings", ""]
    lines.extend(f"- **ERROR:** {item}" for item in errors) if errors else lines.append("- All five pipe rules matched their positive fixture and rejected their benign fixture in both matching layers.")
    lines += ["", "## Sensor boundary note", "", "The canary proves name matching only. Full pipe-sensor qualification still requires a captured native enumeration event, canonical event, forensic record, and observe-only host-effect proof; prevention remains closed.", ""]
    report = "\n".join(lines)
    print(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
