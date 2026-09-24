#!/usr/bin/env python3
"""Observe-only synthetic path canary for the five KERNEL_FILE rules."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "configs" / "Rules.json"
TARGETS = ("R1001", "R1002", "R1003", "R1004", "R1005")
CASES = {
    "R1001": (r"C:\Windows\System32\drivers\aegis-proof.sys", r"C:\Users\Public\aegis-proof.txt"),
    "R1002": (r"C:\Temp\document.locked", r"C:\Temp\document.txt"),
    "R1003": (r"C:\Users\Proof\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\aegis.lnk", r"C:\Users\Proof\Documents\aegis.txt"),
    "R1004": (r"C:\Windows\System32\aegis-proof.dll", r"C:\Windows\System32\aegis-proof.txt"),
    "R1005": (r"C:\Windows\System32\drivers\etc\hosts", r"C:\Windows\System32\drivers\etc\hosts.bak"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    rules = {r["rule_id"]: r for r in json.loads(RULES.read_text(encoding="utf-8"))["nids_rules"]}
    errors: list[str] = []
    rows: list[tuple[str, str, bool, bool]] = []
    for rule_id in TARGETS:
        rule = rules.get(rule_id)
        if not rule:
            errors.append(f"missing rule {rule_id}")
            continue
        try:
            pattern = re.compile(rule["regex_pattern"], re.IGNORECASE)
        except re.error as exc:
            errors.append(f"{rule_id}: invalid regex: {exc}")
            continue
        positive, negative = CASES[rule_id]
        positive_match = bool(pattern.search(positive))
        negative_match = bool(pattern.search(negative))
        rows.append((rule_id, positive, positive_match, negative_match))
        if not positive_match:
            errors.append(f"{rule_id}: positive path did not match")
        if negative_match:
            errors.append(f"{rule_id}: negative path matched (false positive)")

    status = "PASS" if not errors else "FAIL"
    lines = [
        "# KERNEL_FILE Synthetic Rule Canary",
        "",
        f"**Status:** `{status}`",
        "",
        "This scan compiles the configured R1001-R1005 regexes against in-memory Windows path fixtures only. It performs no file I/O against the fixture paths and does not invoke enforcement.",
        "",
        "| Rule | Positive path | Positive match | Negative match |",
        "|---|---|---:|---:|",
    ]
    lines.extend(f"| `{rid}` | `{path}` | `{pos}` | `{neg}` |" for rid, path, pos, neg in rows)
    lines += ["", "## Findings", ""]
    lines.extend(f"- **ERROR:** {item}" for item in errors) if errors else lines.append("- All five configured regexes matched their positive fixture and rejected their negative fixture.")
    lines += ["", "## Sensor boundary note", "", "The canary proves rule-pattern behavior only. The FIM adapter now carries the active watch-root identity into the canonical file event; full E2E qualification still requires a Windows host run with evidence capture and no enforcement request.", ""]
    report = "\n".join(lines)
    print(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
