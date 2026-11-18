"""NOSE-TOOLCHAIN-001: the Go half of the product had no gate that ran the Go tools.

`nose/` is 24 tracked `.go` files — packet acquisition, collectors, the pipe
writer, the canonical-event encoder — and until now nothing in the test suite
invoked `go vet`, `go build` or a test compile. A broken file there would have
been found by a human running `go test` by hand, not by the suite.

Two properties are pinned, and one fact is recorded as a limitation:

* `go vet ./...`, `go build` and a compile-only `go test -run <no match>` all pass
  for the module;
* every `.go` file is either compiled by the Windows build or excluded by an
  explicit build constraint, and a platform-excluded file stays a stub (a large
  one would mean logic hiding behind a tag nothing compiles).

The limitation: `traffic_sys_other.go` carries `//go:build !windows`, so it is
not compiled on this host, and `GOOS=linux go build` fails inside
`github.com/google/gopacket/pcap` (cgo + libpcap) before our code is reached.
Its syntax is checked with `gofmt -e`; its *behaviour* on another platform is
not verified anywhere, and this test says so instead of implying otherwise.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOSE = ROOT / "nose"

GO = shutil.which("go")
GOFMT = shutil.which("gofmt")
needs_go = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")

# A `//go:build !windows` file is a fallback stub. Growing past this means
# real logic lives where no build in this repository compiles it.
STUB_LINE_LIMIT = 60


def _go_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "nose"], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout
    return sorted(p for p in out.splitlines() if p.endswith(".go"))


def _run(args: list[str], cwd: Path = NOSE) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, cwd=cwd, timeout=600)


def _build_constraint(path: Path) -> str:
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()[:5]:
        if line.startswith("//go:build"):
            return line.split("//go:build", 1)[1].strip()
    return ""


@needs_go
def test_go_vet_passes() -> None:
    proc = _run([GO, "vet", "./..."])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not proc.stderr.strip(), proc.stderr


@needs_go
def test_the_module_builds(tmp_path: Path) -> None:
    target = tmp_path / ("aegis-nose.exe" if shutil.os.name == "nt" else "aegis-nose")
    proc = _run([GO, "build", "-o", str(target), "."])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert target.exists() and target.stat().st_size > 0


@needs_go
def test_every_test_file_compiles() -> None:
    """Compile the test binary without running a capture test on a live adapter."""
    proc = _run([GO, "test", "-run", "XXXNO_SUCH_TEST", "-count=1", "."])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "no tests to run" in (proc.stdout + proc.stderr)


def test_every_go_file_is_built_or_constrained() -> None:
    files = _go_files()
    assert files, "no Go files tracked under nose/"
    constrained: list[str] = []
    for rel in files:
        constraint = _build_constraint(ROOT / rel)
        if constraint:
            constrained.append(f"{rel} [{constraint}]")
    # Whatever is not Windows-built must say why; the census is written down so a
    # new platform-excluded file has to be looked at.
    assert constrained == [
        "nose/capture_pipe_test.go [windows]",
        "nose/traffic_sys_other.go [!windows]",
        "nose/traffic_sys_windows.go [windows]",
    ], f"the build-constrained set changed: {constrained}"


def test_a_platform_excluded_file_stays_a_stub() -> None:
    stub = NOSE / "traffic_sys_other.go"
    if not stub.exists():
        pytest.skip("the non-Windows fallback was removed")
    lines = [l for l in stub.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) <= STUB_LINE_LIMIT, (
        f"traffic_sys_other.go grew to {len(lines)} non-blank lines; no build in "
        "this repository compiles a !windows file (GOOS=linux fails inside "
        "gopacket/pcap), so logic there is unverified - move it behind a testable "
        "seam instead of growing the stub"
    )


@needs_go
def test_the_uncompilable_fallback_still_parses() -> None:
    """`gofmt -e` reports syntax errors without needing the dependency graph.

    Formatting itself is not pinned: `gofmt -l` lists 24 of the 24 tracked files
    for alignment-only reasons (`colorBlue    = ...    // comment`), and
    reformatting `nose/` mid-soak would change the source commit under a running
    soak sample for whitespace. The syntax check is what catches a real break in
    the file the Windows build never sees.
    """
    if GOFMT is None:
        pytest.skip("gofmt not installed")
    stub = NOSE / "traffic_sys_other.go"
    if not stub.exists():
        pytest.skip("the non-Windows fallback was removed")
    proc = subprocess.run([GOFMT, "-e", str(stub)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), f"traffic_sys_other.go does not parse: {proc.stderr}"
