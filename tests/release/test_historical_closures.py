"""CLOSURE-RECHECK-001: re-check old closure claims against the current tree.

`EVIDENCE_INDEX.known_gaps` carries 223 entries marked
`CLOSED_AT_RECORDED_HEAD`: their own `result` recorded a pass at the head they
name, and nobody has looked at them since. Treating that as a closure is how a
repo ends up shipping on a 2026-09-10 assertion.

These four were picked because their claim is mechanical: two paths must agree,
no IOCTL in the bridge may be writable, the crypto must be real, and the PEP must
be the only importer. Each is re-checked **at the current tree**, which is the
only thing that turns a historical record into a current one.

Scope discipline: passing here promotes exactly those four entries to `CLOSED`
with this file named as the basis. Nothing else in the ledger changes.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def test_evt_023_the_control_pipe_name_still_agrees() -> None:
    """EVT-023: 'named pipe path matches between Zig runtime and Python CLI'."""
    zig = re.search(r'control_pipe_name\s*=\s*"([^"]+)"', _read("src/platform/win32_pipe.zig"))
    assert zig, "control_pipe_name not found in src/platform/win32_pipe.zig"
    py = re.search(r'CONTROL_PIPE\s*=\s*r?"([^"]+)"', _read("tools/aegisctl/api/control_api.py"))
    assert py, "CONTROL_PIPE not found in tools/aegisctl/api/control_api.py"

    # Both literals describe the same Win32 path; unescape each side's spelling
    # to a fixed point (the Zig literal escapes every backslash twice, the
    # Python one is a raw string, so the two need different depths).
    def normalise(value: str) -> str:
        while "\\\\" in value:
            value = value.replace("\\\\", "\\")
        return value

    assert normalise(zig.group(1)) == normalise(py.group(1)), (zig.group(1), py.group(1))


def test_evt_039_the_bridge_still_defines_no_writable_ioctl() -> None:
    """EVT-039 / GAP-011: 'wfp_ioctl.zig defines zero write IOCTLs'."""
    source = _read("src/policy/wfp_ioctl.zig")
    ctl_codes = re.findall(r"CTL_CODE\([^)]*\)", source)
    assert ctl_codes, "no CTL_CODE definitions found; the bridge may have been rewritten"
    writable = [code for code in ctl_codes if "FILE_WRITE_DATA" in code or "FILE_WRITE_EA" in code]
    assert not writable, f"the bridge defines writable IOCTLs: {writable}"


def test_evt_039_the_device_is_opened_read_only() -> None:
    """GAP-011: 'GENERIC_WRITE removed from device open'."""
    source = _read("src/policy/wfp_ioctl.zig")
    opens = re.findall(r"openDevice|CreateFileW|GENERIC_\w+", source)
    assert opens, "no device-open call found in wfp_ioctl.zig"
    # Every access mask passed where the mask is chosen must be GENERIC_READ.
    chosen = re.findall(r"desired_access[^\n]*", source) + re.findall(r"GENERIC_READ,\s*//[^\n]*", source)
    assert any("GENERIC_READ" in line for line in chosen), "device access mask not found"
    assert "GENERIC_WRITE," not in source.replace(" ", ""), (
        "a GENERIC_WRITE mask is still passed to the device open"
    )


def test_evt_024_the_rust_pep_verifies_with_real_crypto() -> None:
    """EVT-024: 'Ed25519 production verification implemented with ring crate'."""
    source = _read("rust-src/lib.rs")
    assert "ring::signature" in source, "rust-src/lib.rs no longer uses ring::signature"
    assert "verify_policy_signature_verifies_real_ed25519" in source, (
        "the Ed25519 verification test the entry named is gone"
    )
    # A stub would compare hashes instead of verifying a signature; fail if the
    # only verification present is a SHA-256 comparison.
    assert "UnparsedPublicKey" in source or "signature::verify" in source, (
        "no signature verification call found; the crypto looks stubbed again"
    )


def test_the_pep_is_still_the_only_importer_of_the_bridge() -> None:
    """EVT-039: 'only rust_pep.zig imports wfp_ioctl (read-only functions only)'.

    CLOSURE-RECHECK-002 (2026-11-20, RULE-COVERAGE-001).  The WFP capture layer
    now reads the kernel-observed TCP flags from the same 48-byte header, so
    `src/capture/wfp_telemetry.zig` imports `wfp_ioctl.zig`.  That import is
    confined to the pure wire-format helpers (`WfpEventHeader`, `wfpTcpFlags`,
    `WFP_TCP_FLAGS_PRESENT`); `wfp_ioctl.zig` remains read-only by construction
    (the two EVT-039 pins above: zero writable IOCTLs, GENERIC_READ-only open).
    The security-relevant invariant is device ownership, so this re-check now
    asserts the import allow-list *and* that only the PEP touches the device.
    """
    allowed = {"src/core/rust_pep.zig", "src/capture/wfp_telemetry.zig"}
    importers = []
    for path in (ROOT / "src").rglob("*.zig"):
        if path.name in {"all_tests.zig", "wfp_ioctl.zig"}:
            continue  # test aggregator and the module itself
        if re.search(r'@import\("[^"]*wfp_ioctl\.zig"\)', path.read_text(encoding="utf-8", errors="replace")):
            importers.append(path.relative_to(ROOT).as_posix())
    assert set(importers) == allowed, f"unexpected importers of wfp_ioctl: {importers}"

    # The transport (device open/read/stats) stays PEP-only: no other module
    # may reference the device functions, not even one that imports the module
    # for its pure helpers.
    device_calls = (
        "wfp_ioctl.init", "wfp_ioctl.shutdown", "wfp_ioctl.isConnected",
        "wfp_ioctl.read_events", "wfp_ioctl.get_stats",
    )
    foreign = []
    for path in (ROOT / "src").rglob("*.zig"):
        rel = path.relative_to(ROOT).as_posix()
        if rel in {"src/core/rust_pep.zig", "src/policy/wfp_ioctl.zig"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for call in device_calls:
            if call in text:
                foreign.append(f"{rel}:{call}")
    assert not foreign, f"non-PEP device transport use: {foreign}"
