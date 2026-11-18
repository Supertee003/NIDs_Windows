"""E2 pins for the installer's service-existence guards (SERVICE-EXISTS-001).

`scripts/install_aegis.ps1` guarded service creation with the *output* of
`sc.exe query`:

    $driverSvc = sc.exe query AegisWfp 2>$null
    if (-not $driverSvc) { sc.exe create AegisWfp ... }

    if (-not (sc.exe query AegisNids 2>$null)) { sc.exe create AegisNids ... }

`sc.exe` writes its failure text to STDOUT, so on a host without the service the
output is non-empty ("[SC] EnumQueryServicesStatus:OpenService FAILED 1060: …").
`-not` of a non-empty string is false, so **neither service was ever created on a
clean host** — the exact machine the clean-host E5 gate runs on. The NSIS
installer issues `sc create` unconditionally and was not affected.

These pins are three layers, because the bug was invisible to a passing test:

1. behavioural — the premise that `sc.exe query` prints to stdout on failure is
   asserted against a real `sc.exe`, so the rule can never become folklore,
2. structural — no truthiness test on `sc.exe query` may exist in the file, and
   every `sc.exe query`/`sc.exe create` must be followed by a `$LASTEXITCODE`
   check,
3. consequence — a failed create must abort the install instead of being piped
   to `Out-Null`.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "scripts" / "install_aegis.ps1"
REPLACEMENT = ROOT / "scripts" / "wfp_service.ps1"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code_lines(path: Path = INSTALL) -> list[str]:
    """Source lines with comments removed: prose about the bug is not the bug."""
    return [
        line for line in _read(path).splitlines()
        if not line.lstrip().startswith("#")
    ]


@pytest.mark.skipif(sys.platform != "win32", reason="sc.exe is Windows-only")
def test_sc_query_writes_its_failure_to_stdout() -> None:
    """The premise: output truthiness cannot answer "does this service exist?"."""
    proc = subprocess.run(
        ["sc.exe", "query", f"AegisNoSuchSvc{uuid.uuid4().hex[:8]}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode != 0, "querying an absent service must not exit 0"
    assert proc.stdout.strip(), (
        "sc.exe wrote nothing to stdout; if that ever changes, re-derive the rule "
        "instead of keeping a stale comment"
    )
    assert "1060" in proc.stdout or "FAILED" in proc.stdout


def test_no_guard_tests_the_output_of_sc_query() -> None:
    text = "\n".join(_code_lines())
    offenders = re.findall(
        r"if\s*\(\s*(?:-not\s*)?\(?\s*sc\.exe\s+(?:query|qc)\b[^)]*\)?\s*\)",
        text,
    )
    assert offenders == [], (
        "service existence must be tested with $LASTEXITCODE, not with sc.exe "
        f"output truthiness: {offenders}"
    )


def test_every_sc_query_is_followed_by_an_exit_code_test() -> None:
    lines = _code_lines()
    queries = [i for i, line in enumerate(lines) if "sc.exe query" in line]
    assert queries, "install_aegis.ps1 must still query before creating"
    for index in queries:
        window = "\n".join(lines[index : index + 4])
        assert "$LASTEXITCODE" in window, (
            f"line {index + 1} queries the SCM but does not check $LASTEXITCODE:\n"
            f"{lines[index]}"
        )


def test_a_failed_create_aborts_the_install() -> None:
    lines = _code_lines()
    creates = [i for i, line in enumerate(lines) if "sc.exe create" in line]
    assert creates, "install_aegis.ps1 must create the services somewhere"
    for index in creates:
        window = "\n".join(lines[index : index + 4])
        assert "$LASTEXITCODE -ne 0" in window and "throw" in window, (
            f"line {index + 1} creates a service without failing closed:\n"
            f"{lines[index]}"
        )
        assert "| Out-Null" not in lines[index], (
            "piping a create to Out-Null hides the failure that leaves a host "
            "without its service"
        )


def test_the_rpc_driver_helper_keeps_its_exit_code_check() -> None:
    """`wfp_service.ps1` was already correct; the fix must not regress it."""
    text = _read(REPLACEMENT)
    assert re.search(r"sc\.exe query \$svcName[^\n]*\n\s*if \(\$LASTEXITCODE", text), (
        "wfp_service.ps1 must keep testing $LASTEXITCODE after its query"
    )
    assert shutil.which("sc.exe") or sys.platform != "win32"
