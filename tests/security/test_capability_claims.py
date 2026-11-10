"""S2-03: the runtime must not advertise a detection it never executes.

Two shapes of the same defect, both observed in this tree:

1. a detector constructed in `src/daemon.zig` and never fed (it appeared in the
   process, consumed memory, and proved nothing);
2. a capability flag hard-coded `true` in `src/contract/runtime_manifest.zig`
   for a module that no production path calls, so every consumer that negotiates
   on the manifest believed T1055 injection detection was live.

These tests pin the rule rather than today's numbers: a claimed capability must
have an execution site, and a construction must have an ingestion site.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DAEMON = ROOT / "src" / "daemon.zig"
MANIFEST = ROOT / "src" / "contract" / "runtime_manifest.zig"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def test_injection_capability_is_not_claimed() -> None:
    """The detector has no producer, so the manifest flag must stay false."""
    body = _text(MANIFEST)
    claimed = re.search(r"c\.has_injection_detector\s*=\s*true\s*;", body)
    assert claimed is None, (
        "runtime_manifest claims has_injection_detector = true, but no production "
        "path builds an InjectionEvent or calls ingest(); wire a producer first, "
        "then turn this into a probe of that producer"
    )


def test_a_constructed_detector_has_an_ingestion_site() -> None:
    """Constructing a detector without a call site is the production-mock shape."""
    body = _text(DAEMON)
    constructed = re.findall(r"InjectionDetector\.init\s*\(", body)
    if not constructed:
        return
    fed = re.search(r"\.ingest\s*\(", body)
    assert fed is not None, (
        "src/daemon.zig constructs an InjectionDetector but never calls ingest(); "
        "either wire it to a telemetry producer or delete the construction"
    )


def test_daemon_has_no_dead_imports() -> None:
    """An import whose identifier is never used again is dead weight at best."""
    body = _text(DAEMON)
    dead: list[str] = []
    for match in re.finditer(r'^const\s+(\w+)\s*=\s*@import\("([^"]+)"\);', body, re.MULTILINE):
        name, module = match.group(1), match.group(2)
        uses = len(re.findall(rf"\b{re.escape(name)}\b", body))
        if uses <= 1:
            dead.append(f"{name} = @import(\"{module}\")")
    assert not dead, (
        "src/daemon.zig imports modules it never uses (a capability that exists "
        "only as a declaration):\n  " + "\n  ".join(dead)
    )


def test_architecture_doc_does_not_call_the_detector_realtime() -> None:
    """The claim in docs/ARCHITECTURE.md must match the code, not the module."""
    doc = _text(ROOT / "docs" / "ARCHITECTURE.md")
    row = next(
        (line for line in doc.splitlines() if "T1055" in line),
        "",
    )
    assert row, "docs/ARCHITECTURE.md no longer documents the T1055 detector"
    assert "NOT WIRED" in row, (
        "the T1055 row must state that it is not wired until a producer exists: "
        f"{row.strip()}"
    )
    assert "REAL-time ETW path" not in doc, (
        "docs/ARCHITECTURE.md still claims a real-time ETW path for the injection "
        "detector, which the daemon never runs"
    )
