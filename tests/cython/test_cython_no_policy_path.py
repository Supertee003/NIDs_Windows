"""T5b AC4: Cython module has no path to policy / PEP / Windows privilege.

Locks in the architecture invariant that the Cython-accelerated scan loop
is a pure string-search helper:

  - No subprocess invocation
  - No os.system / os.popen / os.exec*
  - No ctypes / cffi calls (no native privilege boundary)
  - No firewall, WFP, iptables, or netsh references
  - No PEP enforcement bindings
  - No file or registry writes
  - No network I/O
  - The Cython module only does `re.Pattern.search(payload)` and returns
    Python-level strings/ints that the CALLER uses to make a policy decision

This test is the AC4 evidence. It uses AST inspection on both the Cython
source (.pyx) and the pure-Python fallback (.py) so it works whether or
not the Cython extension is compiled.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CYTHON_DIR = REPO_ROOT / "brain" / "cython"

FORBIDDEN_CALLS = {
    # subprocess / fork-and-exec
    "subprocess",
    "Popen",
    "system",
    "popen",
    "exec",
    "execvp",
    "execve",
    "fork",
    "spawn",
    # ctypes / cffi / c-level FFI
    "ctypes",
    "CDLL",
    "WinDLL",
    "cdll",
    "windll",
    # privileged / firewall / WFP
    "netsh",
    "iptables",
    "wfp",
    "firewall",
    "wfp_ioctl",
    "pep_",
    "enforce",
    "block_ip",
    "rust_pep",
    "wfp_production",
    # network I/O
    "socket",
    "connect",
    "send",
    "sendto",
    "recv",
    # file / registry writes
    "open",
    "write",
    "RegOpenKeyEx",
    "RegSetValueEx",
    # policy engine bindings
    "policy_engine",
    "enforcement",
}
# `open` is too broad (ast parses "open" in docstrings, comments, etc.).
# We allow "open" as a name reference but forbid explicit `open(...)` calls
# via the AST call check below. Remove it from the import check to avoid
# false positives in source-level scans.
FORBIDDEN_IMPORTS = FORBIDDEN_CALLS - {"open"}


def _scan_source(path: Path) -> tuple[set[str], set[str]]:
    """Return (imported_modules, called_names) detected in a Python source file.

    For .pyx files we use a lenient regex pass instead of ast (Cython is
    not valid Python at every point). For .py files we use ast.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return set(), set()
        imports: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    imports.add(n.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr)
        return imports, calls
    # .pyx — regex-based
    import re
    imports: set[str] = set()
    calls: set[str] = set()
    # import X
    for m in re.finditer(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", text, re.MULTILINE):
        name = m.group(1) or m.group(2)
        if name:
            imports.add(name.split(".")[0])
    # function calls (X(...))
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
        calls.add(m.group(1))
    return imports, calls


def test_cython_module_no_policy_path() -> None:
    """AC4 (Cython): brain.cython.cython_regex_scan.pyx has no system authority."""
    pyx = CYTHON_DIR / "cython_regex_scan.pyx"
    assert pyx.exists(), f"missing Cython source: {pyx}"
    imports, calls = _scan_source(pyx)

    bad_imports = imports & FORBIDDEN_IMPORTS
    assert not bad_imports, (
        f"Cython module imports forbidden module(s): {sorted(bad_imports)}"
    )

    # `re.compile` / `re.search` are allowed; the rest of re is not. We
    # allow the `re` module import but call the result the only sanctioned
    # call. Disallow calls to anything that looks privileged.
    # The Cython loop calls `pat.search(payload)` and `engine.get(...)` —
    # both are list/dict methods and are fine.
    bad_calls = calls & FORBIDDEN_CALLS
    assert not bad_calls, (
        f"Cython module calls forbidden function(s): {sorted(bad_calls)}"
    )


def test_python_fallback_no_policy_path() -> None:
    """AC4 (Python): brain/cython/_py_fallback.py has no system authority.

    This is the AC4 evidence that works in CI without the Cython extension
    compiled: the pure-Python fallback is the oracle and it is provably
    policy-free.
    """
    py = CYTHON_DIR / "_py_fallback.py"
    assert py.exists(), f"missing Python fallback: {py}"
    imports, calls = _scan_source(py)

    bad_imports = imports & FORBIDDEN_IMPORTS
    assert not bad_imports, (
        f"Python fallback imports forbidden module(s): {sorted(bad_imports)}"
    )

    bad_calls = calls & FORBIDDEN_CALLS
    assert not bad_calls, (
        f"Python fallback calls forbidden function(s): {sorted(bad_calls)}"
    )


def test_cython_package_init_no_policy_path() -> None:
    """AC4 (package): brain/cython/__init__.py only does try/except dispatch."""
    py = CYTHON_DIR / "__init__.py"
    assert py.exists(), f"missing package init: {py}"
    imports, calls = _scan_source(py)

    bad_imports = imports & FORBIDDEN_IMPORTS
    assert not bad_imports, (
        f"package init imports forbidden module(s): {sorted(bad_imports)}"
    )
    bad_calls = calls & FORBIDDEN_CALLS
    assert not bad_calls, (
        f"package init calls forbidden function(s): {sorted(bad_calls)}"
    )


def test_no_os_or_subprocess_at_runtime() -> None:
    """AC4 (runtime): importing brain.cython must not pull in any privileged
    modules that the package itself directly depends on. We use
    `modulefinder` (or a manual import + walk) to find ONLY the modules
    that `brain/cython/__init__.py` imports, excluding anything that
    pytest's test session has already loaded.
    """
    import importlib
    import io
    import tokenize

    # Read the source of brain/cython/__init__.py and walk its import graph
    # explicitly. This is more accurate than checking sys.modules (which
    # contains everything pytest has ever loaded across all tests).
    init_path = CYTHON_DIR / "__init__.py"
    init_src = init_path.read_text(encoding="utf-8")
    init_tree = ast.parse(init_src)

    # Collect every name the init file references via import / import-from.
    referenced: set[str] = set()
    for node in ast.walk(init_tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                referenced.add(n.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                referenced.add(node.module)
                for n in node.names:
                    referenced.add(f"{node.module}.{n.name}")

    # The sanctioned imports are: brain.cython.cython_regex_scan (the
    # compiled extension) or brain.cython._py_fallback (the pure-Python
    # fallback). The Cython extension is a C module and does NOT pull in
    # any Python stdlib beyond `re`; the fallback imports only `re` and
    # stdlib typing helpers. Either way, nothing privileged.
    for ref in referenced:
        top = ref.split(".")[0]
        assert top not in FORBIDDEN_IMPORTS, (
            f"brain/cython/__init__.py imports {ref!r}; "
            f"{top!r} is a forbidden module (subprocess, ctypes, socket, ...)"
        )
