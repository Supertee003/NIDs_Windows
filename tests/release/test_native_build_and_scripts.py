"""NATIVE-BUILD-001 / OPS-PORTABLE-001: the native adapters and the operator scripts.

Three things were wrong and none of them was covered by a check:

1. **The bridge could not be built from a clean checkout.** `bridge/CMakeLists.txt`
   points every target at `<repo>/dist`, a gitignored directory that a clean tree
   does not have. Configure succeeded, then the link failed with
   `LNK1104: cannot open file 'D:\\NIDs_Windows\\dist\\aegis_ipc.dll'` because the
   MSVC linker does not create output directories. Configure now makes it.
2. **The operator batch files pinned one machine.** `nose/run_nose.bat` and
   `nose/cleanup_nose_mouth.bat` hardcoded `D:\\NIds_Windows\\...` (and in a
   different case than the real path). Both now derive their directory from
   `%~dp0`.
3. **A tracked script deletes tracked files.** `nose/cleanup_nose_mouth.bat` is a
   one-time v4→v5 migration that deletes `run_nose.bat`, `nose/README.md`,
   `mouth/Cargo.toml`, `mouth/Cargo.lock`, `mouth/.gitignore` and `mouth/src`.
   Run on a current checkout it damages the repository with no prompt. It now
   refuses to run without `--run-cleanup`.

The build pins are real MSVC builds through the Visual Studio generator, which
finds the compiler without a `vcvars` shell. They skip where cmake or that
generator is absent; the script pins always run.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CMAKE = shutil.which("cmake")

DRIVE_PATH = re.compile(r"[A-Za-z]:\\\\[A-Za-z]")
SCRIPT_FILES = ["nose/run_nose.bat", "nose/cleanup_nose_mouth.bat", "mouth/build_mouth.bat"]

ROOT_DLLS = ["aegis_wfp_user", "aegis_etw_helper", "aegis_fim_helper"]


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=ROOT, timeout=1800,
    )


def _cmake_vs(build_dir: Path, source: Path) -> subprocess.CompletedProcess:
    return _run([
        CMAKE, "-S", str(source), "-B", str(build_dir),
        "-G", "Visual Studio 17 2022", "-A", "x64",
    ])


needs_msvc = pytest.mark.skipif(CMAKE is None, reason="cmake not installed")


@needs_msvc
def test_root_native_adapters_build(tmp_path: Path) -> None:
    build = tmp_path / "build"
    configured = _cmake_vs(build, ROOT)
    if configured.returncode != 0 and "could not find any instance" in (
        configured.stdout + configured.stderr
    ).lower():
        pytest.skip("no Visual Studio instance available for the VS generator")
    assert configured.returncode == 0, (configured.stdout + configured.stderr)[-3000:]

    built = _run([CMAKE, "--build", str(build), "--config", "Release"])
    assert built.returncode == 0, (built.stdout + built.stderr)[-3000:]
    for name in ROOT_DLLS:
        dll = build / "Release" / f"{name}.dll"
        assert dll.exists() and dll.stat().st_size > 4096, f"{dll} was not produced"


@needs_msvc
def test_bridge_builds_into_dist(tmp_path: Path) -> None:
    build = tmp_path / "bridge"
    configured = _cmake_vs(build, ROOT / "bridge")
    if configured.returncode != 0 and "could not find any instance" in (
        configured.stdout + configured.stderr
    ).lower():
        pytest.skip("no Visual Studio instance available for the VS generator")
    assert configured.returncode == 0, (configured.stdout + configured.stderr)[-3000:]

    built = _run([CMAKE, "--build", str(build), "--config", "Release"])
    assert built.returncode == 0, (built.stdout + built.stderr)[-3000:]
    # dist/ is gitignored; the build writes there by design.
    dll = ROOT / "dist" / "aegis_ipc.dll"
    assert dll.exists(), "the bridge did not produce dist/aegis_ipc.dll"


def test_bridge_creates_its_output_directory() -> None:
    """Without this line a clean tree cannot link, whatever the generator."""
    text = (ROOT / "bridge" / "CMakeLists.txt").read_text(encoding="utf-8-sig")
    assert "file(MAKE_DIRECTORY" in text, (
        "bridge/CMakeLists.txt must create its dist output directory at "
        "configure time; the MSVC linker fails with LNK1104 otherwise"
    )
    assert text.find("file(MAKE_DIRECTORY") < text.find("add_library("), (
        "the directory must be created before the first target is declared"
    )


@pytest.mark.parametrize("rel", SCRIPT_FILES)
def test_batch_scripts_do_not_hardcode_a_drive(rel: str) -> None:
    text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    offenders = [
        line for line in text.splitlines()
        if DRIVE_PATH.search(line) and not line.strip().upper().startswith("REM")
    ]
    assert not offenders, f"{rel} hardcodes an absolute drive path: {offenders}"


def test_the_destructive_cleanup_script_stays_gated() -> None:
    text = (ROOT / "nose" / "cleanup_nose_mouth.bat").read_text(encoding="utf-8", errors="replace")
    gate = text.find("--run-cleanup")
    first_delete = re.search(r"^\s*(del|rmdir)\s", text, re.MULTILINE)
    assert gate > 0, "cleanup_nose_mouth.bat lost its confirmation gate"
    assert first_delete, "the script no longer deletes anything; delete the pin with it"
    assert gate < first_delete.start(), (
        "the confirmation gate must appear before the first delete"
    )
    assert "exit /b 2" in text, "the gate must abort, not warn and continue"


def test_the_c_stubs_are_not_part_of_the_product_build() -> None:
    """`src/tests/stubs/*.c` are linked by nothing.

    `etw_helper_stub.c` and `fim_helper_stub.c` are referenced only by manifests
    and audit reports, not by `CMakeLists.txt` or `build.zig`. That is the fact
    this pin records: they must not silently become part of the shipped DLLs.
    If someone starts building them, this fails and the decision gets a record.
    """
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8-sig")
    zig = (ROOT / "build.zig").read_text(encoding="utf-8-sig")
    for stub in ["etw_helper_stub.c", "fim_helper_stub.c"]:
        assert stub not in cmake, f"{stub} is now compiled into a native target"
        assert stub not in zig, f"{stub} is now compiled by build.zig"


def test_the_native_adapters_are_wired_into_the_root_build() -> None:
    """The two `src/windows` C files must stay referenced by the root build."""
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8-sig")
    for source in ["src/windows/aegis_wfp.c", "src/windows/fim_native.c"]:
        assert source in cmake, f"{source} is no longer part of the native build"


def test_the_install_stage_waits_for_the_installer_exit_code() -> None:
    """E5-EXITCODE-001.

    The NSIS installer is a Windows-subsystem executable: `& $Exe` does not wait
    for it and leaves `$LASTEXITCODE` as `$null`, so the install stage printed
    `installer exited ` with no number and aborted after a successful install.
    Only `Start-Process -Wait -PassThru` returns the code, and a reboot-required
    code (3010/1641) must not count as failure in a stage that reboots anyway.
    """
    text = (ROOT / "scripts" / "e5-clean-host.ps1").read_text(encoding="utf-8-sig")
    invoke = text.split("function Invoke-External", 1)[1].split("function ", 1)[0]
    assert "Start-Process" in invoke and "-PassThru" in invoke and "-Wait" in invoke, (
        "Invoke-External must obtain the exit code through Start-Process -Wait -PassThru"
    )
    assert "& $Exe @Arguments" not in invoke, (
        "calling a Windows-subsystem installer with & leaves $LASTEXITCODE null"
    )
    assert "3010" in text and "1641" in text, (
        "the install stage must accept reboot-required exit codes"
    )
