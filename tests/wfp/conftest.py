"""Enable the genuine Windows PEP host tests when their real artifacts exist.

`test_t11_windows_host.py` gates three host-verification tests behind
`AEGIS_RUN_WFP_HOST_TESTS=1`. The gate exists so hosted CI (and bare dev hosts)
never try to drive a PEP that is not installed. On a provisioned AEGIS host the
artifacts are unambiguous, so enable the gate here instead of asking every
operator to remember an export:

- `target/release/aegis_pep.dll` — the Rust PEP under test, and
- `%SystemRoot%\\System32\\drivers\\aegis_wfp.sys` — the installed signed driver.

Both must be real files. Nothing is synthesized and no assertion is weakened:
the tests still load the actual DLL and prove DETECTION-ONLY (ESCALATE reason 8,
filter_id == 0). Hash pinning stays operator-controlled via
`AEGIS_EXPECTED_PEP_SHA256` / `AEGIS_EXPECTED_DRIVER_SHA256`; when unset, the
tests print the hashes they actually used so the evidence records can pin them.

CI is unaffected: on non-Windows the tests already skip on `os.name`, and CI has
no PEP DLL in `target/release/`.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PEP_DLL = REPO_ROOT / "target" / "release" / "aegis_pep.dll"
DRIVER_SYS = (
    Path(os.environ.get("SystemRoot", r"C:\Windows"))
    / "System32"
    / "drivers"
    / "aegis_wfp.sys"
)

if os.name == "nt" and PEP_DLL.is_file() and DRIVER_SYS.is_file():
    os.environ.setdefault("AEGIS_RUN_WFP_HOST_TESTS", "1")
