"""EVT-179: aggregator console/service split pins.

go/aggregator/main.go was split into a build-tag-neutral runtime
(server_runtime.go: runAggregator/requestShutdown), a console entrypoint
(console_main.go, tag `!service`) and a Windows service wrapper
(service_main.go, tag `service`), with generateUUID shared via
uuid_util.go. Pinned statically (no heavy build in the suite) plus
`go vet` on both tag variants and a live `--version` probe when the
console binary is present:

  S1. console_main.go carries `//go:build !service` and calls both
      runAggregator() and requestShutdown().
  S2. service_main.go carries `//go:build service` and drives
      runAggregator() without os.Exit/log.Fatalf on the run path.
  S3. server_runtime.go defines runAggregator + requestShutdown and
      never log.Fatalf (the service variant must report Stopped to the
      SCM instead of dying mid-startup).
  S4. main.go no longer defines func main nor generateUUID (the split
      is real, not a copy); uuid_util.go owns generateUUID.
  S5. `go vet ./...` green under both the default and `service` tags.
  S6. console binary `--version` still prints aegis-aggregator (live
      only when the exe is present; skipped otherwise, never failed).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
AGG = REPO / "go" / "aggregator"


def _read(name: str) -> str:
    return (AGG / name).read_text(encoding="utf-8")


def test_console_entrypoint_tag_and_calls():
    text = _read("console_main.go")
    assert "//go:build !service" in text
    assert "runAggregator()" in text
    assert "requestShutdown()" in text
    assert "aegis-aggregator 0.1.0" in text


def test_service_wrapper_tag_and_run_path():
    text = _read("service_main.go")
    assert "//go:build service" in text
    assert "runAggregator()" in text
    # The SCM run path (Execute) reports Stopped to the SCM instead of
    # dying: no os.Exit / log.Fatalf there. os.Exit lives only in the
    # pre-service main() guard (refusing console runs before serving),
    # which is the honest shape for a service binary.
    execute = text.split("func (m *aegisService) Execute", 1)[1]
    execute = execute.split("\nfunc main()", 1)[0]
    assert "os.Exit" not in execute
    assert "log.Fatalf" not in execute
    guard = text.split("\nfunc main()", 1)[1]
    assert "IsWindowsService" in guard
    assert "os.Exit" in guard


def test_shared_runtime_never_fatalf():
    text = _read("server_runtime.go")
    assert "func runAggregator()" in text
    assert "func requestShutdown()" in text
    # Strip // comments first: the docstring names log.Fatalf only to
    # forbid it. The code itself must not call it (the service variant
    # reports Stopped to the SCM instead of dying mid-startup).
    code = "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith("//"))
    assert "log.Fatalf" not in code
    assert "os.Exit" not in code


def test_split_is_real_not_a_copy():
    main_text = _read("main.go")
    assert "\nfunc main()" not in main_text
    assert "func generateUUID" not in main_text
    uuid_text = _read("uuid_util.go")
    assert "func generateUUID" in uuid_text


def test_go_vet_both_tag_variants():
    try:
        default = subprocess.run(
            ["go", "vet", "./..."], capture_output=True, text=True,
            timeout=300, cwd=str(AGG))
    except (OSError, FileNotFoundError):
        pytest.skip("go toolchain unavailable")
        return
    assert default.returncode == 0, default.stderr[-2000:]
    service = subprocess.run(
        ["go", "vet", "-tags", "service", "./..."], capture_output=True,
        text=True, timeout=300, cwd=str(AGG))
    assert service.returncode == 0, service.stderr[-2000:]


def test_console_version_flag_live():
    exe = AGG / "aegis-aggregator.exe"
    if not exe.is_file():
        pytest.skip("console binary not built")
        return
    proc = subprocess.run(
        [str(exe), "--version"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-1000:]
    assert "aegis-aggregator" in proc.stdout
