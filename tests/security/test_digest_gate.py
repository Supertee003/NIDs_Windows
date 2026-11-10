"""E2 regression for the release digest gate (S1-02).

--refresh-digests used to hash the working tree and then verify that same
tree, so any modified artifact became "verified" by the act of refreshing it.
It must now refuse while a tracked artifact is uncommitted; hashing committed
state is the only thing that proves anything.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "release_engineering", ROOT / "tools" / "release_engineering.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )


def make_repo(tmp_path: Path, mod) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "test")
    (repo / "tracked.py").write_text("print('one')\n", encoding="utf-8")
    git(repo, "add", "tracked.py")
    git(repo, "commit", "-qm", "first")

    digest = mod.file_sha256(repo / "tracked.py")
    manifest = {
        "source_commit": "deadbeef",
        "artifacts": [
            {"path": "tracked.py", "sha256": digest, "size": 13},
        ],
    }
    (repo / "build_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    git(repo, "add", "build_manifest.json")
    git(repo, "commit", "-qm", "manifest")

    mod.ROOT = repo
    mod.MANIFEST_PATH = repo / "build_manifest.json"
    return repo


def test_refresh_refuses_uncommitted_artifact(tmp_path: Path) -> None:
    mod = load_tool()
    repo = make_repo(tmp_path, mod)
    (repo / "tracked.py").write_text("print('tampered')\n", encoding="utf-8")

    assert mod.refresh_digests("deadbeef") == 1
    recorded = json.loads((repo / "build_manifest.json").read_text(encoding="utf-8"))
    assert recorded["artifacts"][0]["sha256"] != mod.file_sha256(repo / "tracked.py")


def test_refresh_records_a_clean_tree(tmp_path: Path) -> None:
    mod = load_tool()
    repo = make_repo(tmp_path, mod)
    # committed change: digest recorded against committed state
    (repo / "tracked.py").write_text("print('two')\n", encoding="utf-8")
    git(repo, "add", "tracked.py")
    git(repo, "commit", "-qm", "second")

    assert mod.refresh_digests("cafebabe") == 0
    recorded = json.loads((repo / "build_manifest.json").read_text(encoding="utf-8"))
    assert recorded["artifacts"][0]["sha256"] == mod.file_sha256(repo / "tracked.py")
    assert recorded["source_commit"] == "cafebabe"
