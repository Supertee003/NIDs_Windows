"""EVT-223: `--refresh-digests --adopt-missing` is the bounded, reviewed
artifact-set growth path.

Pins:
  * without the flag, refresh NEVER changes the recorded artifact set
    (digests/sizes only) — the original "stable set" guarantee;
  * with it, exactly the releasable files `collect_artifacts()` walks and
    the set lacks are added (printed, ordered, digest-recorded) and nothing
    is dropped or duplicated.

All writes target tmp_path (test hygiene: no tracked-tree state; the module
ROOT/MANIFEST_PATH globals are monkeypatched to the tmp tree).
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load_mod():
    spec = importlib.util.spec_from_file_location(
        "release_engineering_under_test", REPO / "tools" / "release_engineering.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _bootstrap(tmp_path, monkeypatch):
    """Tmp tree with two releasable sources, only one recorded."""
    mod = _load_mod()
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "MANIFEST_PATH", tmp_path / "build_manifest.json")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "old.zig").write_text("pub const a = 1;\n", encoding="utf-8")
    (tmp_path / "src" / "new.zig").write_text("pub const b = 2;\n", encoding="utf-8")
    manifest = {
        "version": "9.9.9",
        "source_commit": "deadbee",
        "artifacts": [{
            "path": "src/old.zig",
            "size": mod.file_size(tmp_path / "src" / "old.zig"),
            "sha256": mod.file_sha256(tmp_path / "src" / "old.zig"),
            "language": "zig",
        }],
    }
    (tmp_path / "build_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    return mod


def _doc(mod):
    return json.loads(mod.MANIFEST_PATH.read_text(encoding="utf-8"))


def test_refresh_without_flag_never_changes_the_set(tmp_path, monkeypatch):
    mod = _bootstrap(tmp_path, monkeypatch)
    rc = mod.refresh_digests("cafe123")
    assert rc == 0
    doc = _doc(mod)
    assert [a["path"] for a in doc["artifacts"]] == ["src/old.zig"]
    assert doc["source_commit"] == "cafe123"


def test_adopt_missing_adds_exactly_the_releasable_unrecorded_files(tmp_path, monkeypatch, capsys):
    mod = _bootstrap(tmp_path, monkeypatch)
    rc = mod.refresh_digests("cafe123", adopt_missing=True)
    assert rc == 0
    doc = _doc(mod)
    assert [a["path"] for a in doc["artifacts"]] == ["src/new.zig", "src/old.zig"]
    adopted = [a for a in doc["artifacts"] if a["path"] == "src/new.zig"][0]
    assert adopted["language"] == "zig"
    assert adopted["sha256"] == mod.file_sha256(tmp_path / "src" / "new.zig")
    assert adopted["size"] == mod.file_size(tmp_path / "src" / "new.zig")
    out = capsys.readouterr().out
    assert "adopted: 1" in out
    assert "adopted: src/new.zig" in out


def test_adopt_missing_is_idempotent(tmp_path, monkeypatch):
    mod = _bootstrap(tmp_path, monkeypatch)
    assert mod.refresh_digests("cafe123", adopt_missing=True) == 0
    first = _doc(mod)
    assert mod.refresh_digests("cafe123", adopt_missing=True) == 0
    second = _doc(mod)
    assert [a["path"] for a in second["artifacts"]] == [a["path"] for a in first["artifacts"]]
