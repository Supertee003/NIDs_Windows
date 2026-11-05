"""Unit tests for the read-only STIX 2.1 export of xdr.list incidents.

Scope: mapping correctness, deterministic observable ids, structural
validation of the produced bundle, and the CLI file mode. Tests write only
to tmp_path (no tracked-tree state). This is an advisory export surface; it
proves the mapping at E2 and nothing about runtime host behavior.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS_DIR))

from stix_export import (  # noqa: E402
    STIX_NAMESPACE,
    ExportError,
    build_bundle,
    parse_entity,
    stix_timestamp,
    validate_bundle,
)

GENERATED = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

# Mirrors the live xdr.list shape (control_api query_control("xdr.list")).
VIEW = {
    "xdr_scope": "advisory_read_only",
    "started": True,
    "evidence_total": 7,
    "advisories_total": 0,
    "receipts_recorded": 0,
    "incidents": [
        {"id": 1, "entity": "v4:185.199.109.133", "severity": 0, "confidence": 0,
         "source_categories_used": 0, "decision_made_ms": 0, "distinct_sources": 1,
         "evidence": 2},
        {"id": 2, "entity": "v6:260647004408000000000000ac409bd1", "severity": 1,
         "confidence": 40, "source_categories_used": 1, "decision_made_ms": 0,
         "distinct_sources": 1, "evidence": 1},
        {"id": 3, "entity": "v4:192.168.1.39", "severity": 0, "confidence": 0,
         "source_categories_used": 0, "decision_made_ms": 0, "distinct_sources": 1,
         "evidence": 1},
    ],
}


def _objects_by_type(bundle):
    obs = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    scos = [o for o in bundle["objects"] if o["type"] in ("ipv4-addr", "ipv6-addr")]
    return obs, scos


# ---------------------------------------------------------------------------
# Entity parsing
# ---------------------------------------------------------------------------

def test_parse_entity_v4_roundtrip():
    assert parse_entity("v4:185.199.109.133") == ("v4", "185.199.109.133")


def test_parse_entity_rejects_leading_zero_octets():
    # "001" is octal-ambiguous; a validating parser must reject, not normalize.
    assert parse_entity("v4:192.168.001.039") is None


@pytest.mark.parametrize("bad", ["v4:999.1.2.3", "v4:xyz", "v4:", "v4:1.2.3"])
def test_parse_entity_v4_rejects_malformed(bad):
    assert parse_entity(bad) is None


def test_parse_entity_v6_unpacks_and_compresses():
    # Packed form of 2606:4700:4408::ac40:9bd1
    kind, value = parse_entity("v6:260647004408000000000000ac409bd1")
    assert (kind, value) == ("v6", "2606:4700:4408::ac40:9bd1")


@pytest.mark.parametrize("bad", [
    "v6:260647004408000000000000ac409bd",    # 31 hex digits
    "v6:260647004408000000000000ac409bd12",  # 33 hex digits
    "v6:zz0647004408000000000000ac409bd1",   # non-hex
    "v6:",
    "mac:001122334455",                       # unknown kind is skipped, never guessed
    "", "noseparator",
])
def test_parse_entity_rejects_unknown_and_malformed(bad):
    assert parse_entity(bad) is None


def test_parse_entity_rejects_non_string():
    assert parse_entity(None) is None
    assert parse_entity(12345) is None


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def test_stix_timestamp_format_has_millisecond_z():
    ts = stix_timestamp(GENERATED)
    assert ts == "2026-11-05T12:00:00.000Z"


def test_epoch_ms_zero_maps_to_fallback_not_1970():
    from stix_export import timestamp_from_epoch_ms
    dt = timestamp_from_epoch_ms(0, GENERATED)
    assert dt == GENERATED
    dt = timestamp_from_epoch_ms(1500000000000, GENERATED)
    assert dt.year == 2017


# ---------------------------------------------------------------------------
# Bundle construction
# ---------------------------------------------------------------------------

def test_build_bundle_maps_every_incident():
    bundle = build_bundle(VIEW, now=GENERATED)
    obs, scos = _objects_by_type(bundle)
    assert len(obs) == 3
    assert len(scos) == 3
    assert validate_bundle(bundle) == []


def test_build_bundle_sco_ids_deterministic_across_runs():
    a = build_bundle(VIEW, now=GENERATED)
    b = build_bundle({**VIEW, "incidents": VIEW["incidents"][:2]}, now=GENERATED)
    by_value_a = {o["value"]: o["id"] for o in a["objects"] if o["type"] in ("ipv4-addr", "ipv6-addr")}
    by_value_b = {o["value"]: o["id"] for o in b["objects"] if o["type"] in ("ipv4-addr", "ipv6-addr")}
    assert set(by_value_b) == set(by_value_a) - {"192.168.1.39"}  # subset view -> subset ids
    assert all(by_value_b[v] == by_value_a[v] for v in by_value_b)  # same row -> same id


def test_build_bundle_observed_data_fields():
    bundle = build_bundle(VIEW, now=GENERATED)
    obs, scos = _objects_by_type(bundle)
    first = next(o for o in obs if o["x_aegis_entity"] == "v4:185.199.109.133")
    assert first["type"] == "observed-data"
    assert first["spec_version"] == "2.1"
    assert first["created"] == first["modified"] == "2026-11-05T12:00:00.000Z"
    assert first["first_observed"] == first["last_observed"] == "2026-11-05T12:00:00.000Z"
    assert first["number_observed"] == 2
    assert first["object_refs"] == [scos[0]["id"]]
    # AEGIS facts ride on x_aegis_* custom properties.
    assert first["x_aegis_incident_id"] == 1
    assert first["x_aegis_distinct_sources"] == 1
    assert first["x_aegis_export_schema_version"] == "1"


def test_build_bundle_no_zero_evidence_number_observed():
    view = {**VIEW, "incidents": [{**VIEW["incidents"][0], "evidence": 0}]}
    bundle = build_bundle(view, now=GENERATED)
    obs, _ = _objects_by_type(bundle)
    assert obs[0]["number_observed"] == 1  # STIX requires >= 1
    assert validate_bundle(bundle) == []


def test_build_bundle_decision_made_ms_used_when_set():
    view = {**VIEW, "incidents": [{**VIEW["incidents"][0], "decision_made_ms": 1762329600000}]}
    bundle = build_bundle(view, now=GENERATED)
    obs, _ = _objects_by_type(bundle)
    assert obs[0]["first_observed"].startswith("2025-11-05T")


def test_build_bundle_skips_unknown_entities_and_counts_them():
    view = {**VIEW, "incidents": [*VIEW["incidents"], {"id": 9, "entity": "mac:00-11-22"}]}
    bundle = build_bundle(view, now=GENERATED)
    obs, _ = _objects_by_type(bundle)
    assert len(obs) == 3
    assert bundle["x_aegis_export_skipped_entities"] == [{"id": 9, "entity": "mac:00-11-22"}]
    assert bundle["x_aegis_incident_count"] == 4
    assert validate_bundle(bundle) == []


@pytest.mark.parametrize("bad_view", [None, [], {"no_incidents": 1}, {"incidents": 7},
                                      {"incidents": ["carrot"]}])
def test_build_bundle_static_input_validation(bad_view):
    with pytest.raises(ExportError):
        build_bundle(bad_view, now=GENERATED)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_validate_bundle_detects_missing_and_broken_fields():
    base = build_bundle(VIEW, now=GENERATED)
    stripped = json.loads(json.dumps(base))
    first = stripped["objects"][0]
    for key in ("spec_version", "id"):
        first.pop(key)
    first["id"] = "ipv4-addr--not-a-uuid"
    second = [o for o in stripped["objects"] if o["type"] == "observed-data"][0]
    second["number_observed"] = 0
    second["first_observed"] = "2026-11-05 12:00:00"
    errors = validate_bundle(stripped)
    assert any("missing required key 'spec_version'" in e for e in errors)
    assert any("bad id format" in e for e in errors)
    assert any("number_observed" in e for e in errors)
    assert any("bad first_observed" in e for e in errors)
    assert validate_bundle(base) == []


def test_sco_namespace_is_fixed_constant():
    assert STIX_NAMESPACE == uuid.UUID("f1e3b2d4-7ac6-4b8f-9d2e-0a1c3b5d7f91")


# ---------------------------------------------------------------------------
# CLI (file mode; writes only to tmp_path)
# ---------------------------------------------------------------------------

def test_cli_file_mode_writes_valid_bundle(tmp_path, monkeypatch):
    src = tmp_path / "xdr.json"
    src.write_text(json.dumps(VIEW), encoding="utf-8")
    out = tmp_path / "out.stix.json"
    result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "stix_export.py"),
         "--file", str(src), "--out", str(out)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
    assert out.suffix == ".json"
    assert f"WROTE {out} objects=6 incidents=3 skipped=0" in result.stdout
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    assert validate_bundle(bundle) == []


def test_cli_rejects_non_json_output_suffix(tmp_path):
    src = tmp_path / "xdr.json"
    src.write_text(json.dumps(VIEW), encoding="utf-8")
    out = tmp_path / "out.stix.txt"
    result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "stix_export.py"),
         "--file", str(src), "--out", str(out)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 2
    assert "STIX_EXPORT_ERROR" in result.stderr
    assert not out.exists()


def test_cli_stderr_failclosed_on_bad_input(tmp_path):
    src = tmp_path / "xdr.json"
    src.write_text("not json", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(TOOLS_DIR / "stix_export.py"), "--file", str(src)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 2
    assert "STIX_EXPORT_ERROR" in result.stderr
