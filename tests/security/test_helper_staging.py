"""E2 regression for the native-helper staging gate (#30 / S1-01).

The FIM helper crash (exception 0x80000003 at aegis_fim_helper!aegis_fim_stop)
survived a committed fix because the packaging input zig-out/bin still held a
2026-10-16 build: CMake writes build/Release and no step copied it forward.
These tests pin the rule the gate enforces, using a throwaway tree.
"""
from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "stage_helpers", ROOT / "tools" / "stage_helpers.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_tree(tmp_path: Path, *, source_newer: bool = False) -> Path:
    """Create <root>/src + <root>/build/Release with controlled mtimes."""
    tool = load_tool()
    base = time.time() - 10_000
    src_time = base + 9_000 if source_newer else base
    for rel in {s for sources in tool.HELPERS.values() for s in sources}:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"/* source */\n")
        os.utime(p, (src_time, src_time))
    for dll in tool.HELPERS:
        built = tmp_path / "build" / "Release" / dll
        built.parent.mkdir(parents=True, exist_ok=True)
        built.write_bytes(b"MZ built " + dll.encode())
        # built 5_000s after the baseline; stale only when the source is newer
        os.utime(built, (base + 5_000, base + 5_000))
    return tmp_path


def test_stage_copies_release_build_into_packaging_dir(tmp_path: Path) -> None:
    tool = load_tool()
    root = make_tree(tmp_path)

    assert tool.stage(root) == 0
    for dll in tool.HELPERS:
        staged = root / "zig-out" / "bin" / dll
        assert staged.is_file(), dll
        assert staged.read_bytes() == (root / "build" / "Release" / dll).read_bytes()
    assert tool.check(root) == []


def test_check_fails_when_staged_copy_is_stale(tmp_path: Path) -> None:
    """The exact #30 shape: a valid build exists, the packaged copy is older."""
    tool = load_tool()
    root = make_tree(tmp_path)
    staged = root / "zig-out" / "bin"
    staged.mkdir(parents=True)
    for dll in tool.HELPERS:
        stale = staged / dll
        stale.write_bytes(b"MZ old " + dll.encode())
        os.utime(stale, (time.time() - 50_000, time.time() - 50_000))

    problems = tool.check(root)
    assert problems, "a stale staged helper must fail the packaging gate"
    assert any("predates its source" in p or "differs from" in p for p in problems)


def test_stage_refuses_a_build_older_than_its_source(tmp_path: Path) -> None:
    tool = load_tool()
    root = make_tree(tmp_path, source_newer=True)

    assert tool.stage(root) == 1
    assert not (root / "zig-out" / "bin").exists()


def test_missing_build_is_reported_not_ignored(tmp_path: Path) -> None:
    tool = load_tool()
    root = make_tree(tmp_path)
    (root / "build" / "Release" / "aegis_fim_helper.dll").unlink()

    assert tool.stage(root) == 1
    problems = tool.check(root)
    assert any("not built" in p for p in problems)
