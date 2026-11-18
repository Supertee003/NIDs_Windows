"""TOOLS-IMPORT-001: importing a module under `tools/` must not touch the host.

AGENTS.md TEST HYGIENE rule 1: "Product modules (brain, CLI, tools) must be
importable with no socket bind, no serve loop, no banner on stdout, and no
`sys.exit` under a test runner's argv." Two files under `tools/` broke it, and
the breakage was invisible because nothing imported them:

* `tools/update_health_cmd.py` was a patcher whose body sat at module level. On
  **import** it read `tools/aegisctl.py`, replaced `cmd_health`, and wrote the
  file back. Any tool that walks `tools/` — an inventory builder, a doc
  generator, `python -m doctest`, this very probe — would have rewritten the
  main CLI and printed "Done". (It is moved to `tools/legacy/` with the
  quarantine guard, because the patch it applies was never in `aegisctl.py`:
  `getRuntimeHealth` does not appear there.)
* `tools/probe_control_pipe.py` dialled `\\\\.\\pipe\\aegis_control` and printed
  JSON at import, i.e. importing it opened the live daemon's control pipe. It is
  now a `main()` behind `__main__`.

`tools/legacy/` is excluded on purpose: those files raise `SystemExit` at import
by design (LEGACY-INERT-001), which is the opposite of a host effect.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
LEGACY = TOOLS / "legacy"

PROBE = """
import importlib, importlib.util, pathlib, sys
target = pathlib.Path(sys.argv[1]).resolve()
tools_dir = target.parents[len(target.relative_to(pathlib.Path(sys.argv[2])).parts) - 1]
sys.path.insert(0, sys.argv[2])
# Package module (any parent holds __init__.py): import it by dotted name so
# relative imports resolve the way the CLI resolves them.
parts = target.relative_to(pathlib.Path(sys.argv[2])).with_suffix("").parts
if len(parts) > 1 and (pathlib.Path(sys.argv[2]) / parts[0] / "__init__.py").exists():
    importlib.import_module(".".join(parts))
else:
    spec = importlib.util.spec_from_file_location("probe_" + target.stem, target)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
"""


def _tracked_tools() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "tools"], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout
    return [p for p in out.splitlines() if p]


def _importable_modules() -> list[str]:
    return [
        p
        for p in _tracked_tools()
        if p.endswith(".py") and not p.startswith("tools/legacy/")
    ]


@pytest.mark.parametrize("rel", _importable_modules())
def test_importing_a_tool_module_has_no_host_effect(rel: str) -> None:
    proc = subprocess.run(
        [sys.executable, "-c", PROBE, str(ROOT / rel), str(TOOLS)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )
    assert proc.returncode == 0, f"{rel} failed to import:\n{proc.stdout}\n{proc.stderr}"
    assert not proc.stdout.strip(), (
        f"{rel} printed on import; a module must not speak until it is asked: "
        f"{proc.stdout[:400]!r}"
    )
    assert not proc.stderr.strip(), f"{rel} warned on import: {proc.stderr[:400]!r}"


def _module_level_side_effects(tree: ast.Module) -> list[str]:
    """Writes and exits reachable from module scope (not from a function)."""
    hits: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.If):
            test = ast.dump(node.test)
            if "__name__" in test:  # the __main__ guard is not an import effect
                continue
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            name = getattr(sub.func, "attr", None) or getattr(sub.func, "id", None)
            if name in {"write_text", "write_bytes"}:
                hits.append(f"line {sub.lineno}: {name}()")
            elif name == "open":
                mode = sub.args[1] if len(sub.args) > 1 else None
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and (
                    "w" in mode.value or "a" in mode.value or "+" in mode.value
                ):
                    hits.append(f"line {sub.lineno}: open({mode.value!r})")
            elif name in {"dump", "dumps"} and getattr(sub.func, "attr", None) == "dump":
                hits.append(f"line {sub.lineno}: json.dump()")
    return hits


@pytest.mark.parametrize("rel", _importable_modules())
def test_no_module_writes_to_the_tree_at_import(rel: str) -> None:
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
    hits = _module_level_side_effects(tree)
    assert not hits, (
        f"{rel} writes at module scope, so importing it mutates the tree: {hits}. "
        "Put the body behind `if __name__ == '__main__':` or into a function."
    )


def test_the_census_would_notice_a_new_tool_file() -> None:
    """Every tracked file under tools/ with a .py suffix is probed above."""
    listed = {p for p in _tracked_tools() if p.endswith(".py") and not p.startswith("tools/legacy/")}
    assert listed == set(_importable_modules())
    assert len(listed) >= 15, "the probe set collapsed; it should cover the whole tree"


def test_the_two_offenders_stay_fixed() -> None:
    probe = (TOOLS / "probe_control_pipe.py").read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in probe, "the pipe probe must not dial at import"
    assert not (TOOLS / "update_health_cmd.py").exists(), (
        "the tree-mutating patcher belongs in tools/legacy/ behind the quarantine guard"
    )
    moved = (LEGACY / "update_health_cmd.py").read_text(encoding="utf-8")
    assert "QUARANTINED" in moved
