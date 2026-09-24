from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "aegisctl.py"
LAUNCHER = ROOT / "scripts" / "aegis.ps1"
MANUAL = ROOT / "docs" / "AEGIS_Operator_Usage_Manual.md"

ast.parse(CLI.read_text(encoding="utf-8"))
text = LAUNCHER.read_text(encoding="utf-8")
manual = MANUAL.read_text(encoding="utf-8")
checks = {
    "launcher_start": '"start" { Invoke-Cli @("start", "--all") }' in text,
    "forensic_verify_route": 'Invoke-Cli @("forensics", "verify")' in text,
    "manual_start": '.\\scripts\\aegis.ps1 start' in manual,
    "manual_snapshot": 'python tools\\aegisctl.py snapshot' in manual,
}
for name, passed in checks.items():
    print(f"{name}: {'PASS' if passed else 'FAIL'}")
if not all(checks.values()):
    raise SystemExit(1)
print("operator-cli-validation: PASS")
