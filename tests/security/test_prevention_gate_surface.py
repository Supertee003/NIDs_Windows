"""SLICE-C-LAB: prevention gate surface pins (source-level).

The prevention gate (runtime_state.g_prevention_gate_open) is the single
master switch for host-mutating enforcement. These pins make sure no future
patch can open it by accident:

  1. g_prevention_gate_open has exactly one writer module
     (src/pipeline/runtime_state.zig), holding the dedicated lab opener.
  2. openPreventionGateLab is referenced only by its owner module and by
     the daemon call site, which is itself behind the lab build option.
  3. The lab build flag (lab + -prevention-gate) never appears in release /
     CI / tooling surfaces: default builds have no way to pass it, and the
     build option defaults to false.
  4. The single S1 pipeline call site threads the gate into
     pep_bindings.enforce, so the pipeline is gate-controlled.

Historical context: G1 in docs/SLICE_C_LAB_GATE_DESIGN.md (NIC-001 lab).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
RUNTIME_STATE = "src/pipeline/runtime_state.zig"
DAEMON = "src/daemon.zig"

_ASSIGN = re.compile(r"\bg_prevention_gate_open\s*=(?!=)")

SKIP_DIRS = {
    "node_modules", ".venv", "venv", "target", ".git", ".zig-cache",
    "__pycache__", "dist", "build", "zig-out", ".pytest_cache",
}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".exe", ".dll",
                 ".lib", ".pdb", ".bin", ".zip", ".webp"}


def _zig_sources():
    return sorted(SRC.rglob("*.zig"))


def test_gate_flag_has_single_writer_module():
    writers = []
    for path in _zig_sources():
        rel = path.relative_to(REPO).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            if _ASSIGN.search(line):
                writers.append((rel, lineno))
    assert writers, "no store to g_prevention_gate_open exists"
    owners = {rel for rel, _ in writers}
    assert owners == {RUNTIME_STATE}, (
        f"gate stores outside the owner module: {sorted(owners - {RUNTIME_STATE})}"
    )


def test_lab_opener_referenced_only_by_owner_and_daemon():
    opener = "openPreventionGateLab"
    assert opener in (REPO / RUNTIME_STATE).read_text(encoding="utf-8")
    assert opener in (REPO / DAEMON).read_text(encoding="utf-8")
    offenders = []
    for path in _zig_sources():
        rel = path.relative_to(REPO).as_posix()
        if rel in {RUNTIME_STATE, DAEMON}:
            continue
        if opener in path.read_text(encoding="utf-8"):
            offenders.append(rel)
    assert offenders == [], f"unexpected opener references: {offenders}"


def test_daemon_open_call_is_behind_the_lab_build_option():
    text = (REPO / DAEMON).read_text(encoding="utf-8")
    idx = text.index("openPreventionGateLab")
    window = text[max(0, idx - 700): idx]
    assert "if (build_options.lab_prevention_gate)" in window, (
        "the daemon gate-open call must sit behind the lab build option"
    )


def test_lab_build_flag_absent_from_release_surfaces():
    # Assembled so this file itself never carries the literal.
    flag = "lab" + "-prevention-gate"
    build_zig = (REPO / "build.zig").read_text(encoding="utf-8")
    idx = build_zig.find(flag)
    assert idx != -1, "build.zig must declare the lab gate option"
    assert "orelse false" in build_zig[idx: idx + 260], (
        "the lab gate build option must default to false"
    )
    scanned = ("scripts", "tools", "configs", ".github", "drivers", "nose",
               "brain", "mouth", "shield", "ts_policy", "installer", "packaging")
    offenders = []
    for name in scanned:
        root = REPO / name
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                path = Path(dirpath) / fn
                if path.suffix.lower() in SKIP_SUFFIXES:
                    continue
                try:
                    if path.stat().st_size > 2_000_000:
                        continue
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                if flag in text:
                    offenders.append(path.relative_to(REPO).as_posix())
    assert offenders == [], f"lab gate flag leaked into release surfaces: {offenders}"


def test_pipeline_enforce_call_passes_the_gate():
    text = (REPO / "src" / "pipeline" / "event_processor.zig").read_text(encoding="utf-8")
    assert text.count("pep_enf.enforce(") == 1, "expected exactly one S1 enforce call site"
    idx = text.index("pep_enf.enforce(")
    window = text[idx: idx + 500]
    assert "g_prevention_gate_open" in window, (
        "the S1 enforcement call must pass the prevention gate"
    )
