"""LEGACY-INERT-001: `tools/legacy/` is history, not a way to mutate the tree.

The directory held 28 runnable Python files. Several of them are *patchers*:
`patch_graph_daemon.py` rewrites `scripts/aegis_graph.py`, `update_auth.py`
rewrites `AUTHORITY_MAP.json`, `fix_console.py` rewrites
`tools/aegisctl/commands/console.py`. They were kept for history but stayed
runnable, so a stray `python tools/legacy/<name>.py` — or a glob over `tools/`,
or a repository-wide `compileall` gate — could either mutate tracked files or
fail on a file that does not even parse (`fix_console.py:95` had an unterminated
f-string, which is why a repo-wide compile gate could never be clean).

The directory now says what it means: every `.py` refuses to run, the whole
directory compiles, nothing product-side imports it, and the orphan Rust crate
is not part of any build. The census test makes an unclassified new file a
failure rather than a silent addition.
"""
from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LEGACY = "tools/legacy"

# Non-Python files that legitimately live here: a pre-refactor snapshot with a
# non-.py suffix (never executed, kept for diffing) and an orphan Rust crate
# whose directory name states that it is quarantined.
NON_EXECUTABLE = {
    f"{LEGACY}/Dashboard.py.before-unified-snapshot",
    f"{LEGACY}/rust_shield_orphan_quarantined/Cargo.toml",
    f"{LEGACY}/rust_shield_orphan_quarantined/src/lib.rs",
    f"{LEGACY}/rust_shield_orphan_quarantined/src/main.rs",
    f"{LEGACY}/rust_shield_orphan_quarantined/src/pep.rs",
}

PRODUCT_DIRS = [
    "src",
    "tools",
    "nose",
    "brain",
    "scripts",
    "installer",
    "shared",
    "contracts",
    "ts_policy",
    "drivers",
]


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", LEGACY], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout
    return [p for p in out.splitlines() if p]


def _python_files() -> list[str]:
    return [p for p in _tracked() if p.endswith(".py")]


def _top_level_statements(text: str) -> list[ast.stmt]:
    return ast.parse(text).body


def _without_docstring_and_future(body: list[ast.stmt]) -> list[ast.stmt]:
    rest = body
    while rest:
        node = rest[0]
        is_doc = (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
        is_future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
        if is_doc or is_future:
            rest = rest[1:]
            continue
        break
    return rest


def test_the_legacy_tree_is_classified() -> None:
    """Every tracked file is either guardable Python or an allowlisted artifact."""
    files = _tracked()
    assert files, "tools/legacy is empty; the census would pass vacuously"
    python_files = set(_python_files())
    others = set(files) - python_files
    unclassified = sorted(others - NON_EXECUTABLE)
    assert not unclassified, (
        "a new non-Python file under tools/legacy has to be classified here "
        f"before it can be trusted to be inert: {unclassified}"
    )
    stale = sorted(NON_EXECUTABLE - others)
    assert not stale, f"the allowlist names files that no longer exist: {stale}"


@pytest.mark.parametrize("rel", _python_files())
def test_every_legacy_python_file_parses(rel: str) -> None:
    source = (ROOT / rel).read_text(encoding="utf-8")
    ast.parse(source)  # SyntaxError names the file: fix_console.py:95 used to fail here


@pytest.mark.parametrize("rel", _python_files())
def test_every_legacy_python_file_refuses_to_run(rel: str) -> None:
    body = _without_docstring_and_future(_top_level_statements((ROOT / rel).read_text(encoding="utf-8")))
    assert body, f"{rel} has no statements after its docstring"
    first = body[0]
    assert isinstance(first, ast.Raise) and isinstance(first.exc, ast.Call), (
        f"{rel} must start with the quarantine guard, not with its old body"
    )
    assert getattr(first.exc.func, "id", "") == "SystemExit", rel
    message = first.exc.args[0].value if first.exc.args else ""
    assert "QUARANTINED" in message, f"{rel} guard does not say it is quarantined"
    assert rel in message, (
        f"{rel} guard must name its own path so the message points at the file"
    )


def test_running_a_legacy_patcher_writes_nothing() -> None:
    """The behavioural half: the file that rewrites AUTHORITY_MAP.json is inert."""
    target = ROOT / "AUTHORITY_MAP.json"
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    proc = subprocess.run(
        [sys.executable, str(ROOT / LEGACY / "update_auth.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    after = hashlib.sha256(target.read_bytes()).hexdigest()
    assert proc.returncode != 0, "the quarantined patcher ran to completion"
    assert "QUARANTINED" in (proc.stderr + proc.stdout)
    assert before == after, "the quarantined patcher mutated AUTHORITY_MAP.json"


def test_the_whole_legacy_tree_compiles() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", str(ROOT / LEGACY)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_no_product_module_reaches_into_the_legacy_tree() -> None:
    pattern = r"tools\.legacy|tools\\\\legacy|from +legacy[ .]|import +legacy\b"
    hits: list[str] = []
    for rel in _tracked():
        if rel.startswith(LEGACY + "/"):
            continue
        path = ROOT / rel
        if path.suffix not in {".py", ".ps1", ".zig", ".go", ".rs", ".ts", ".c", ".h", ".nsi"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "tools/legacy" in text or "tools\\legacy" in text:
            hits.append(rel)
    assert not hits, (
        "product code must not reach into the quarantine; move what is needed "
        f"into a live module instead: {hits}"
    )


def test_the_orphan_rust_crate_is_not_part_of_a_build() -> None:
    crate = ROOT / LEGACY / "rust_shield_orphan_quarantined"
    assert crate.name.endswith("_quarantined"), "the directory name must state its status"
    root_cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    assert "[workspace]" not in root_cargo, (
        "a workspace would compile the orphan crate as a second PEP"
    )
    for build_file in ("build.zig", "CMakeLists.txt", "mouth/Cargo.toml"):
        path = ROOT / build_file
        if path.exists():
            assert "rust_shield_orphan_quarantined" not in path.read_text(
                encoding="utf-8", errors="ignore"
            ), f"{build_file} builds the quarantined crate"
