"""PACKAGING-CACHE-001: a release tree carries runtime files, not test residue.

The first `f5cc38e` candidate copied `brain/aegis_brain_cython/.pytest_cache/`
into the signed tree. Its `nodeids` file changes on every test run, so the
signed bytes were not reproducible, and a shipped artifact ended up documenting
which local tests had run.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import release_candidate  # noqa: E402  (tools/ is not a package)


def test_cache_and_residue_names_are_excluded():
    for name in ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"):
        assert name in release_candidate.COPY_IGNORE, (
            f"{name} must not reach a signed release tree"
        )


def test_copytree_keeps_runtime_files_and_drops_caches(tmp_path):
    src = tmp_path / "brain"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (src / "pkg" / "__pycache__").mkdir()
    (src / "pkg" / "__pycache__" / "module.cpython-314.pyc").write_bytes(b"junk")
    (src / ".pytest_cache" / "v" / "cache").mkdir(parents=True)
    (src / ".pytest_cache" / "v" / "cache" / "nodeids").write_text("[]\n",
                                                                  encoding="utf-8")

    out = tmp_path / "out" / "brain"
    shutil.copytree(src, out,
                    ignore=shutil.ignore_patterns(*release_candidate.COPY_IGNORE))

    copied = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert copied == ["pkg/module.py"]
