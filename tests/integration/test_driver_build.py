"""DRIVER-BUILD-001: build both kernel drivers with the real WDK toolchain.

`drivers/` was covered by a syntax-only `cl -Zs` parse for the minifilter sources
(DRIVER-SYNTAX-001) precisely because nothing built the kernels. It turns out the
WDK is installed on this host and both canonical build scripts work, so the
stronger claim is available: the two `.sys` binaries compile and link.

What this gate runs, and nothing more:

* `scripts/wdk_build_production.ps1`    → `build/x64/wfp/aegis_wfp.sys`
* `scripts/wdk_build_minifilter.ps1`    → `build/x64/minifilter/aegis_minifilter.sys`

Each is asserted to report `BUILD OK`, to produce a binary above a size floor,
and to print a SHA-256 that matches the file actually on disk.

**Not run, deliberately:** signing (`wfp_sign.ps1`, `minifilter_sign.ps1`),
service install/start (`*_service.ps1`), and any unload. Those change the host's
kernel state — the machine is running production drivers right now, and swapping
them would both break the live system and invalidate the running soak window.
Kernel behaviour (does the filter block? does unload clean up?) therefore stays
unproven, and no test here may claim otherwise.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which("powershell")

BUILDS = [
    ("scripts/wdk_build_production.ps1", "build/x64/wfp/aegis_wfp.sys", 16384),
    ("scripts/wdk_build_minifilter.ps1", "build/x64/minifilter/aegis_minifilter.sys", 4096),
]

pytestmark = pytest.mark.host_live


def _wdk_ready() -> bool:
    kits = Path("C:/Program Files (x86)/Windows Kits/10/Include")
    return POWERSHELL is not None and kits.is_dir()


needs_wdk = pytest.mark.skipif(not _wdk_ready(), reason="PowerShell or the WDK headers are absent")


@pytest.mark.parametrize("script,binary,size_floor", BUILDS)
@needs_wdk
def test_the_driver_builds(script: str, binary: str, size_floor: int) -> None:
    proc = subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / script)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=ROOT, timeout=900,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output[-3000:]
    assert "BUILD OK" in output, output[-3000:]
    assert "FAIL:" not in output, output[-3000:]

    artifact = ROOT / binary
    assert artifact.is_file(), f"{script} reported success but {binary} is missing"
    assert artifact.stat().st_size > size_floor, f"{binary} is only {artifact.stat().st_size} bytes"

    printed = re.search(r"SHA-256:\s*([0-9A-Fa-f]{64})", output)
    assert printed, f"{script} printed no SHA-256:\n{output[-1500:]}"
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest().upper()
    assert printed.group(1).upper() == actual, (
        f"{binary} hashes to {actual} but the build reported {printed.group(1)}"
    )


@needs_wdk
def test_no_test_touches_kernel_state() -> None:
    """The gate must never sign, install, swap or unload a driver.

    Asserted over this package: if a future test starts calling the signing or
    service scripts, this fails and the decision has to be argued for.
    """
    forbidden = ("wfp_sign.ps1", "minifilter_sign.ps1", "wfp_service.ps1",
                 "minifilter_service.ps1", "e5_driver_swap.ps1")
    # Naming the script in an assertion about the installer template is fine;
    # *executing* it is not. Flag only lines that invoke something.
    invocation = ("subprocess", "Popen", "powershell", "check_output", "call(", "run(")
    offenders = []
    for path in (ROOT / "tests").rglob("*.py"):
        if path.name == Path(__file__).name:
            continue
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if any(name in line for name in forbidden) and any(tok in line for tok in invocation):
                offenders.append(f"{path.relative_to(ROOT).as_posix()}:{lineno}")
    assert not offenders, (
        "a test references a driver signing/installing script; those change host "
        f"kernel state and are not allowed in the suite: {offenders}"
    )
