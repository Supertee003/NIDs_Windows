"""FORENSIC-SOURCE-001: one canonical source space for forensic records.

The forensic ring used to store the *legacy* pipeline ordinal in
`reserved[6]` (`capture_npcap=1`, `system=99`) while every other operator
surface speaks the *canonical* `canonical_event.EventSource` space
(`npcap_sensor=9`, `zig_core=0`). `forensics.list --source N` therefore named a
different sensor than `--source N` anywhere else, and legacy ordinals such as
99 were indistinguishable from a canonical value.

Contract pinned here:
  AC1. The canonical Zig enum and the Python canonical map agree exactly.
  AC2. Every canonical ordinal has a stable name, and the daemon owns it.
  AC3. New records are written in the canonical space, marked by the
       `reserved[5]` source-space version byte.
  AC4. Records written before the change are canonicalized on read, and the
       `--source` filter compares one space only.
  AC5. Operator surfaces render the daemon-provided source name.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CANONICAL_ZIG = REPO_ROOT / "src" / "contract" / "canonical_event.zig"
BRAIN_CANONICAL = REPO_ROOT / "brain" / "canonical_event.py"
FORENSIC_ZIG = REPO_ROOT / "src" / "forensic" / "forensic_pipeline.zig"
HANDLER = REPO_ROOT / "src" / "control" / "handler_registry.zig"
GRAPH = REPO_ROOT / "scripts" / "aegis_graph.py"


def _zig_canonical_sources() -> dict[str, int]:
    source = CANONICAL_ZIG.read_text(encoding="utf-8")
    block = re.search(r"pub const EventSource = enum\(u8\) \{(.*?)\n\};", source, re.S)
    assert block is not None, "canonical_event.zig must declare EventSource"
    return {name: int(value) for name, value in re.findall(r"(\w+) = (\d+),", block.group(1))}


def _zig_source_names() -> dict[str, str]:
    source = CANONICAL_ZIG.read_text(encoding="utf-8")
    block = re.search(r"pub fn sourceName\(source: EventSource\) \[\]const u8 \{(.*?)\n\}", source, re.S)
    assert block is not None, "canonical_event.zig must declare sourceName"
    return {name: text for name, text in re.findall(r"\.(\w+) => \"([a-z_]+)\"", block.group(1))}


def _brain_canonical_sources() -> dict[str, int]:
    spec = importlib.util.spec_from_file_location("brain_canonical_event_under_test", BRAIN_CANONICAL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules, so register the
    # module under test before executing it.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module.SOURCE


# ── AC1/AC2: one canonical space across tiers ──────────────────────────────

def test_zig_canonical_enum_matches_the_python_canonical_map():
    zig = _zig_canonical_sources()
    brain = _brain_canonical_sources()
    assert zig, "no canonical sources parsed from the Zig enum"
    assert zig == brain, (
        "the canonical source ordinals disagree between "
        "src/contract/canonical_event.zig and brain/canonical_event.py"
    )


def test_every_canonical_ordinal_has_a_stable_name():
    zig = _zig_canonical_sources()
    names = _zig_source_names()
    assert names == {name: name for name in zig}, (
        "sourceName must name every canonical ordinal with its own stable name"
    )


# ── AC3: the writer speaks the canonical space ─────────────────────────────

def test_new_records_are_written_in_the_canonical_space():
    source = FORENSIC_ZIG.read_text(encoding="utf-8")
    assert "pub const SOURCE_SPACE_CANONICAL: u8 = 1;" in source
    assert ".reserved = [_]u8{" in source
    assert "SOURCE_SPACE_CANONICAL," in source
    assert "@intFromEnum(canonicalSourceOf(ev.source))" in source
    assert "@intFromEnum(ev.source)" not in source, (
        "the raw legacy ordinal must never be written into a forensic record"
    )
    assert "canonicalSourceFromRecord" in source


# ── AC4: legacy records are canonicalized on read ──────────────────────────

def test_handler_reads_one_space_for_the_whole_ring():
    source = HANDLER.read_text(encoding="utf-8")
    assert "forensicRecordOrigin" in source
    assert "canonicalSourceFromRecord" in source
    assert "canonical_event.sourceName(canonical)" in source
    assert '\\"source_name\\"' in source
    assert '\\"source_space\\"' in source
    # The filter must compare the canonicalized ordinal, not the stored byte.
    assert "origin.ordinal != @as(u8, @intCast(source))" in source
    assert "header.reserved[6] != @as(u8, @intCast(source))" not in source
    # Both read paths (list + show) expose the same attribution.
    assert source.count("forensicRecordOrigin(header.reserved[6], header.reserved[5])") == 2


def test_legacy_ordinals_are_mapped_not_reinterpreted():
    source = FORENSIC_ZIG.read_text(encoding="utf-8")
    assert "std.meta.intToEnum(event.EventSource, raw) catch return .external" in source, (
        "an unknown legacy ordinal must become `external`, never a named sensor"
    )
    assert "std.meta.intToEnum(canonical_event.EventSource, raw) catch .external" in source
    for legacy, canonical in (
        (".capture_npcap", ".npcap_sensor"),
        (".capture_etw", ".host_telemetry"),
        (".capture_fim", ".file_sensor"),
        (".capture_registry", ".registry_sensor"),
        (".system", ".zig_core"),
        (".federation", ".cluster_federation"),
    ):
        assert f"{legacy} => {canonical}" in source, f"{legacy} must map to {canonical}"


# ── AC5: operator surfaces render the daemon's name ────────────────────────

def test_graph_renders_the_daemon_source_name(monkeypatch):
    pytest.importorskip("networkx", reason="graph stack (networkx) not installed")
    sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location("aegis_graph_source_space", GRAPH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    document = {
        "available": True,
        "records": [{
            "record_seq": 5, "event_id": 6, "rule_id": 7,
            "source": 9, "source_name": "npcap_sensor", "source_space": "canonical",
            "payload_len": 12, "verified": True,
        }],
        "records_returned": 1, "truncated": False, "next_after": None,
        "integrity": "ok", "verified": True,
    }

    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(document), "")

    # monkeypatch (not module.subprocess.run = ...) so the patched global
    # subprocess.run is restored for every later test in this interpreter.
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "graph.html"
            module.generate_forensic_graph(output, 10)
            html = output.read_text(encoding="utf-8", errors="replace")
    finally:
        sys.path.remove(str(REPO_ROOT))
    assert "Source npcap_sensor" in html, (
        "the evidence graph must render the canonical source name, not a bare ordinal"
    )
