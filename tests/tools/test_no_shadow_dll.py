"""EVT-182: no shadow DLL may sit in the repo root.

The Rust PEP resolves its WFP bridge as bare `aegis_wfp_user.dll` first,
and CWD is on the Windows DLL search order -- so a stale copy in the repo
root SHADOWS the real one. A 9/20 root copy missing a single export
(`aegis_wfp_ioctl_query_filter`) failed the whole adapter load with no
fallback, and T11 skipped for weeks while every direct probe passed.
Pinned here, all without elevation and without touching the host:

  S1. No bridge DLL in the repo root (the build script no longer drops
      one there; consumers use build/Release and zig-out/bin).
  S2. build_wfp_user_bridge.ps1 has no repo-root destination.
  S3. The fallback candidate (build/Release) exports all five bridge
      symbols (load + GetProcAddress only -- the device is never opened).
"""
from __future__ import annotations

import ctypes
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

BRIDGE_EXPORTS = (
    "aegis_wfp_ioctl_open",
    "aegis_wfp_ioctl_block_flow",
    "aegis_wfp_ioctl_unblock_filter",
    "aegis_wfp_ioctl_query_filter",
    "aegis_wfp_ioctl_query_filter_dir",
)


def test_no_bridge_dll_in_repo_root():
    for name in ("aegis_wfp_user.dll", "aegis_ipc.dll"):
        assert not (REPO / name).is_file(), (
            f"{name} in repo root shadows the loader's bare-name candidate; "
            "see EVT-182")


def test_build_script_has_no_root_destination():
    text = (REPO / "scripts" / "build_wfp_user_bridge.ps1").read_text(
        encoding="utf-8")
    assert "(Join-Path $Repo 'aegis_wfp_user.dll')" not in text
    assert '(Join-Path $Repo "aegis_wfp_user.dll")' not in text


def test_fallback_candidate_exports_all_bridge_symbols():
    dll_path = REPO / "build" / "Release" / "aegis_wfp_user.dll"
    assert dll_path.is_file(), "fallback candidate missing"
    lib = ctypes.WinDLL(str(dll_path))
    try:
        get = lib._handle  # noqa: SLF001 (handle probe only, no calls)
        k32 = ctypes.windll.kernel32
        getaddr = k32.GetProcAddress
        getaddr.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        getaddr.restype = ctypes.c_void_p
        freelib = k32.FreeLibrary
        freelib.argtypes = [ctypes.c_void_p]
        freelib.restype = ctypes.c_int
        for sym in BRIDGE_EXPORTS:
            assert getaddr(get, sym.encode()), f"missing export: {sym}"
    finally:
        freelib(get)
