"""GAP-008 hybrid settlement: artifact-set selection rule pins (EVT-093).

The committed 539-entry manifest grandfathers ~244 non-reproducible
entries (232 bridge/build/, ~10 brain cython byproducts, 2 loose
go/aggregator .exe); the NEXT --manifest regeneration must apply the rule
below. These pins execute without any build: a pure predicate plus source
facts, no tree writes.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "release_engineering", REPO / "tools" / "release_engineering.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_canonical_sources_are_walked():
    text = (REPO / "tools" / "release_engineering.py").read_text(encoding="utf-8")
    start = text.index("include_dirs = [")
    walked = text[start:text.index("]", start)]
    for d in ("src", "configs", "rust-src", "nose"):
        assert f'"{d}"' in walked, d


def test_build_trees_are_excluded():
    mod = _load()
    for p in (
        "bridge/build/CMakeCache.txt",
        "bridge/build/aegis_adapter.dir/Debug/aegis_adapter.obj",
        "bridge/build/CMakeFiles/4.4.2/CMakeDetermineCompilerABI_CXX.bin",
        "brain/cython/build/temp.win-amd64-cpython-314/Release/aegis_hotspot.obj",
        "brain/aegis_brain_cython/build/lib.win-amd64-cpython-314/"
        "aegis_brain_cython/fast_scan.cp314-win_amd64.pyd",
    ):
        assert mod._is_excluded(p), p


def test_byproduct_suffixes_are_excluded():
    mod = _load()
    for p in (
        "brain/aegis_brain_cython/fast_scan.cp314-win_amd64.pyd",
        "brain/cython/aegis_hotspot.cp314-win_amd64.pyd",
        "go/aggregator/aegis-aggregator.exe",
        "go/aggregator/aggregator.exe",
        "bridge/CMakeFiles/probe.obj",
    ):
        assert mod._is_excluded(p), p


def test_legit_sources_are_kept():
    mod = _load()
    for p in (
        "bridge/aegis_adapter.cpp",
        "bridge/aegis_adapter.hpp",
        "bridge/CMakeLists.txt",
        "src/main.zig",
        "src/windows/etw_native.c",
        "rust-src/lib.rs",
        "nose/main.go",
        "configs/test/etw_realtime_config.json",
        "config/Rules.json",
        "tools/release_engineering.py",
        "scripts/check_summary.py",
        "brain/windows_brain.py",
    ):
        assert not mod._is_excluded(p), p


def test_releasable_predicate_needs_git_visibility():
    mod = _load()
    visible = {"src/main.zig", "scripts/kali_attack_nids.py"}
    assert mod._is_releasable("src/main.zig", visible)
    # Untracked AND ignored (attack sims, caches, backups, generated C)
    # must never gain provenance entries, even when present on disk.
    assert not mod._is_releasable("scripts/kali_attacks/R2001_mimikatz.py", visible)
    assert not mod._is_releasable("nose/.pytest_cache/CACHEDIR.TAG", visible)
    # None (git unavailable) preserves the old accept-all behavior.
    assert mod._is_releasable("anything/at/all.py", None)


def test_git_visible_files_returns_usable_set_or_none():
    mod = _load()
    visible = mod.git_visible_files()
    if visible is None:
        pytest.skip("git unavailable in this environment")
    assert "src/main.zig" in visible
    assert isinstance(visible, set)
