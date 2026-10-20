"""TRUTH-SOURCE-COMMIT: source-commit semantics for the truth gate.

ADR-0008. A truth map records the last commit that touched the source/build
tree, not the commit that merely records evidence. The verifier must accept a
source commit that is an ancestor of HEAD, reject a records-only commit used as
the source, reject a source older than the actual last source change, and
reject a recorded source that is not the real source commit.

Each test builds a disposable git repo under tmp_path and runs a copy of
tools/truth.py; no tracked tree state is written.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

TRUTH = Path(__file__).resolve().parents[2] / "tools" / "truth.py"

JSON_HEADS = (
    "SYSTEM_MAP.json",
    "FLOW_MAP.json",
    "AUTHORITY_MAP.json",
    "CONTRACT_MAP.json",
    "EVIDENCE_INDEX.json",
    "build_truth.json",
    "runtime_manifest.json",
)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _new_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "checkout", "-q", "-b", "main")
    _git(repo, "config", "user.email", "truth-test@example.com")
    _git(repo, "config", "user.name", "truth-test")
    _git(repo, "config", "core.autocrlf", "false")
    return repo


def _commit(repo: Path, rel: str, content: str, message: str) -> str:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", rel)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _write_artifacts(repo: Path, full_sha: str, short_sha: str) -> None:
    for name in JSON_HEADS:
        (repo / name).write_text(
            json.dumps({"head_sha": full_sha}) + "\n", encoding="utf-8"
        )
    (repo / "build_manifest.json").write_text(
        json.dumps({"source_commit": short_sha}) + "\n", encoding="utf-8"
    )
    (repo / "AI_CONTEXT.md").write_text(
        f"# AI_CONTEXT\n\n**HEAD:** `{full_sha}`\n", encoding="utf-8"
    )
    (repo / "inventory.json").write_text("{}\n", encoding="utf-8")
    (repo / "reference_map.json").write_text("{}\n", encoding="utf-8")
    tools = repo / "tools"
    tools.mkdir(exist_ok=True)
    shutil.copy(TRUTH, tools / "truth.py")


def _run(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(repo / "tools" / "truth.py"), "verify"],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def test_accepts_source_ancestor(tmp_path: Path) -> None:
    repo = _new_repo(tmp_path)
    source = _commit(repo, "src/main.zig", "v1\n", "source")
    _commit(repo, "docs/notes.md", "records\n", "records")
    _write_artifacts(repo, source, source[:7])

    result = _run(repo)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "TRUTH_VALID" in result.stdout


def test_rejects_docs_commit_as_source(tmp_path: Path) -> None:
    repo = _new_repo(tmp_path)
    _commit(repo, "src/main.zig", "v1\n", "source")
    docs = _commit(repo, "docs/notes.md", "records\n", "records")
    _write_artifacts(repo, docs, docs[:7])

    result = _run(repo)

    assert result.returncode != 0, result.stdout


def test_rejects_source_changed_after_recorded(tmp_path: Path) -> None:
    repo = _new_repo(tmp_path)
    source = _commit(repo, "src/main.zig", "v1\n", "source")
    _commit(repo, "docs/notes.md", "records\n", "records")
    _write_artifacts(repo, source, source[:7])
    _commit(repo, "src/main.zig", "v2\n", "source change")

    result = _run(repo)

    assert result.returncode != 0, result.stdout


def test_rejects_non_ancestor_source(tmp_path: Path) -> None:
    repo = _new_repo(tmp_path)
    _commit(repo, "src/main.zig", "v1\n", "source")
    _commit(repo, "docs/notes.md", "records\n", "records")
    _git(repo, "checkout", "-q", "--orphan", "orphan")
    _git(repo, "rm", "-rfq", ".")
    orphan = _commit(repo, "orphan.txt", "orphan\n", "orphan")
    _git(repo, "checkout", "-q", "main")
    _write_artifacts(repo, orphan, orphan[:7])

    result = _run(repo)

    assert result.returncode != 0, result.stdout
