"""SRC-CLOSURE-001: every Zig file is either built or explicitly quarantined.

Five modules under `src/` open with a header saying they are quarantined and
"must never be wired into the daemon" (`policy/dispatcher.zig`,
`policy/dispatcher_phase_b.zig`, `reliability/lifecycle.zig`,
`reliability/reliability.zig`, `federation/federation.zig` — the last one says
SUPERSEDED). Nothing enforced those sentences: no test checked that the daemon
does not reach them, and no test noticed a module that nothing imports at all.
An unreferenced file is not harmless here — it is a second implementation of a
plane whose header claims it is the only one, and the next reader cannot tell
which one runs.

This module turns the comments into a check:

* the import closure is computed from every `.zig` path `build.zig` names, so a
  new target joins the check automatically;
* nothing in the `src/main.zig` closure may reach a quarantined file — that is
  the "must never be wired into the daemon" claim, tested;
* every tracked `.zig` must be reachable from some build root or be in the
  classified list below, with the reason written in the file's own header, so a
  new orphan fails instead of accumulating.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build.zig"
MAIN = "src/main.zig"

IMPORT = re.compile(r'@import\("([^"]+)"\)')
BUILD_ZIG_PATH = re.compile(r'"((?:src|tests)/[^"]*\.zig)"')

# Files outside every build root, and the word each one must use in its own
# header to say so. The list is the census, not a wish: a file here that becomes
# reachable fails `test_the_classification_is_not_stale`, and a file that is
# neither reachable nor here fails `test_every_zig_file_is_built_or_classified`.
UNBUILT = {
    "src/policy/dispatcher.zig": ("QUARANTINED", "quarantined"),
    "src/policy/dispatcher_phase_b.zig": ("QUARANTINED", "quarantined"),
    "src/reliability/lifecycle.zig": ("QUARANTINED", "quarantined"),
    # REL-SPEC-050: the G20-G33 design specimen; its live homes are
    # watchdog/fault_injection/security_check/latency_histogram in daemon.zig.
    "src/reliability/reliability.zig": ("SPECIMEN", "specimen"),
    "src/federation/federation.zig": ("SUPERSEDED", "superseded"),
    "src/capture/npcap_test_live.zig": ("TOOL_ONLY", "verification tool"),
}


def _tracked_zig() -> list[str]:
    import subprocess

    out = subprocess.run(
        ["git", "ls-files", "src"], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout
    return sorted(p for p in out.splitlines() if p.endswith(".zig"))


def _build_roots() -> list[str]:
    roots = sorted(set(BUILD_ZIG_PATH.findall(BUILD.read_text(encoding="utf-8"))))
    assert roots, "build.zig names no .zig root; the closure would be empty"
    return roots


def _closure(roots: list[str]) -> set[str]:
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        rel = stack.pop()
        if rel in seen:
            continue
        path = ROOT / rel
        if not path.exists() or path.suffix != ".zig":
            continue
        seen.add(rel)
        for spec in IMPORT.findall(path.read_text(encoding="utf-8", errors="ignore")):
            if spec in {"std", "builtin"} or spec.startswith("@"):
                continue
            target = (path.parent / spec).resolve()
            try:
                stack.append(target.relative_to(ROOT).as_posix())
            except ValueError:
                continue
    return seen


def test_every_build_root_exists_and_is_tracked() -> None:
    tracked = set(_tracked_zig())
    for rel in _build_roots():
        assert (ROOT / rel).exists(), f"build.zig names a missing root: {rel}"
        assert rel in tracked, f"build.zig names an untracked root: {rel} - a clean clone cannot build"


def test_the_daemon_cannot_reach_a_quarantined_module() -> None:
    """`must never be wired into the daemon` is a claim about the import graph."""
    production = _closure([MAIN])
    assert MAIN in production
    reached = sorted(production & set(UNBUILT))
    assert not reached, (
        "src/main.zig reaches a module that is classified as unbuilt/quarantined "
        "here (the edge itself is pinned by tests/security/test_forbidden_edges.py; "
        f"this is the whole-closure view): {reached}"
    )


def test_every_zig_file_is_built_or_classified() -> None:
    reachable = _closure(_build_roots())
    orphans = sorted(p for p in _tracked_zig() if p not in reachable and p not in UNBUILT)
    assert not orphans, (
        "these modules are in no build root's import closure and are not classified "
        f"in tests/security/test_src_import_closure.py: {orphans}"
    )


def test_the_classification_is_not_stale() -> None:
    reachable = _closure(_build_roots())
    stale = sorted(p for p in UNBUILT if p in reachable)
    assert not stale, f"these are now built, so the exemption is stale: {stale}"
    gone = sorted(p for p in UNBUILT if not (ROOT / p).exists())
    assert not gone, f"the census names files that no longer exist: {gone}"


@pytest.mark.parametrize("rel,entry", sorted(UNBUILT.items()))
def test_each_classified_file_says_why_in_its_own_header(rel: str, entry: tuple[str, str]) -> None:
    reason, marker = entry
    header = "\n".join(
        (ROOT / rel).read_text(encoding="utf-8", errors="ignore").splitlines()[:24]
    ).lower()
    assert marker in header, (
        f"{rel} is classified {reason} but its own header does not say {marker!r}; "
        "the next reader would have to trust this test file instead of the module: "
        f"{header[:200]!r}"
    )


def test_the_closure_actually_covers_the_tree() -> None:
    """A closure that silently returns almost nothing would pass every pin above."""
    reachable = _closure(_build_roots())
    tracked = set(_tracked_zig())
    missing = len(tracked - reachable - set(UNBUILT))
    assert missing == 0
    assert len(reachable & tracked) >= 250, (
        f"only {len(reachable & tracked)} of {len(tracked)} modules are reachable; "
        "the @import parser is probably missing a form"
    )
