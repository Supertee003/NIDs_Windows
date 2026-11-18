"""STIX 2.1 export for XDR incidents (read-only, advisory).

Maps the `xdr.list` control view into a STIX 2.1 bundle so incidents can be
consumed by external tooling. The runtime is never touched: the tool either
reads a captured `xdr.list` JSON file or performs a read-only control query.

Scope and honesty rules:

- The control view carries the entity (``v4:``/``v6:``) plus severity,
  confidence, category/source/evidence counters. It does NOT carry a rule
  attribution or indicator value, so no ``indicator`` objects are produced.
- Each incident becomes one ``observed-data`` SDO referencing one
  cyber-observable (``ipv4-addr`` or ``ipv6-addr``).
- AEGIS-specific facts ride on custom properties (``x_aegis_*``), which STIX
  2.1 allows on SDOs.
- Cyber-observable ids use a deterministic UUIDv5 over our own namespace so
  the same entity always maps to the same id (spec recommends UUIDv5 for
  SCOs; the namespace constant below is fixed for reproducibility).
- Unknown entity formats are counted and skipped, never guessed.

Import hygiene: importing this module performs no I/O, binds no socket and
starts no worker. Host contact happens only inside the ``--daemon`` path.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Version 1 of the export scheme. Bump when the mapping changes so releases
# can tell which bundle layout a file came from.
SCHEMA_VERSION = "1"

# Own namespace for deterministic SCO ids (uuid5). Documented, fixed, and
# derived from the NIDS product name so other producers never collide.
STIX_NAMESPACE = uuid.UUID("f1e3b2d4-7ac6-4b8f-9d2e-0a1c3b5d7f91")

# STIX 2.1 identifier: <type>--<uuid>. Observable types carry digits
# (ipv4-addr, ipv6-addr), so the type part must accept them.
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*--([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
# STIX timestamps: RFC 3339, UTC, millisecond precision, trailing 'Z'.
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

SDO_REQUIRED = ("type", "spec_version", "id", "created", "modified")
SCO_REQUIRED = ("type", "spec_version", "id")


class ExportError(ValueError):
    """Raised when the input view or produced bundle is invalid."""


# ---------------------------------------------------------------------------
# Entity parsing
# ---------------------------------------------------------------------------

def parse_entity(entity: str) -> Optional[Tuple[str, str]]:
    """Split an ``xdr.list`` entity key into a STIX-ready value.

    Returns ``(kind, value)`` or ``None`` when the entity is not importable:

    - ``v4:`` expects a dotted-quad IPv4 string (validated).
    - ``v6:`` expects 32 hex digits: the packed IPv6 (no separators).
      The value is returned in compressed lowercase form.
    """
    if not isinstance(entity, str) or ":" not in entity:
        return None
    kind, _, raw = entity.partition(":")
    if kind == "v4":
        try:
            return kind, str(ipaddress.IPv4Address(raw))
        except ValueError:
            return None
    if kind == "v6":
        hexed = raw.strip().lower()
        if len(hexed) != 32 or any(c not in "0123456789abcdef" for c in hexed):
            return None
        ipv6 = ipaddress.IPv6Address(int(hexed, 16))
        return kind, str(ipv6)
    return None


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def stix_timestamp(dt: Optional[datetime] = None) -> str:
    """Render a datetime as a STIX 2.1 timestamp (RFC 3339, ms, 'Z')."""
    dt = dt.astimezone(timezone.utc) if dt is not None else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


def timestamp_from_epoch_ms(epoch_ms: int, fallback: datetime) -> datetime:
    """Convert an epoch-ms field (e.g. ``decision_made_ms``) to datetime.

    Zero or negative values mean "unset" in the control view and map to the
    fallback timestamp instead of 1970.
    """
    if epoch_ms <= 0:
        return fallback
    return datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)


# ---------------------------------------------------------------------------
# STIX object construction
# ---------------------------------------------------------------------------

def _sco_id(kind: str, value: str) -> str:
    """Deterministic STIX observable id for a single-value SCO."""
    payload = json.dumps({"type": kind, "value": value}, sort_keys=True, separators=(",", ":"))
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, payload)}"


def _observed_data_object(inc: Dict[str, Any], sco_ref: str, value: str, kind: str,
                          observed_at: datetime, bundle_time: str) -> Dict[str, Any]:
    evidence = inc.get("evidence", 0)
    first = inc.get("decision_made_ms", 0)
    first_dt = timestamp_from_epoch_ms(first, observed_at)
    obj: Dict[str, Any] = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{uuid.uuid4()}",
        "created": bundle_time,
        "modified": bundle_time,
        "first_observed": stix_timestamp(first_dt),
        "last_observed": stix_timestamp(observed_at),
        # Unused entities carry 0; STIX requires >= 1 observed object.
        "number_observed": int(evidence) if int(evidence) > 0 else 1,
        "object_refs": [sco_ref],
        "x_aegis_entity": f"{kind}:{value}",
        "x_aegis_incident_id": int(inc.get("id", 0)),
        "x_aegis_severity": int(inc.get("severity", 0)),
        "x_aegis_confidence": int(inc.get("confidence", 0)),
        "x_aegis_source_categories_used": int(inc.get("source_categories_used", 0)),
        "x_aegis_distinct_sources": int(inc.get("distinct_sources", 0)),
        "x_aegis_export_schema_version": SCHEMA_VERSION,
    }
    return obj


def build_bundle(view: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Map one ``xdr.list`` payload into a STIX 2.1 bundle.

    Determinism contract: the same view plus the same ``now`` yields the same
    SCO ids and timestamps; observed-data ids are random UUIDv4 per STIX 2.1.
    """
    if not isinstance(view, dict):
        raise ExportError("xdr.list payload must be a JSON object")
    incidents = view.get("incidents")
    if incidents is None:
        raise ExportError("xdr.list payload has no 'incidents' array")
    if not isinstance(incidents, list):
        raise ExportError("'incidents' must be an array")

    generated = now or datetime.now(timezone.utc)
    bundle_time = stix_timestamp(generated)
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)

    objects: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for inc in incidents:
        if not isinstance(inc, dict):
            raise ExportError("each incident must be an object")
        parsed = parse_entity(str(inc.get("entity", "")))
        if parsed is None:
            skipped.append({"id": inc.get("id"), "entity": inc.get("entity")})
            continue
        kind, value = parsed
        sco_type = "ipv4-addr" if kind == "v4" else "ipv6-addr"
        sco_id = _sco_id(sco_type, value)
        objects.append({
            "type": sco_type,
            "spec_version": "2.1",
            "id": sco_id,
            "value": value,
        })
        objects.append(_observed_data_object(inc, sco_id, value, kind, generated, bundle_time))

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "x_aegis_advisories_total": int(view.get("advisories_total", 0)),
        "x_aegis_export_skipped_entities": skipped,
        "x_aegis_incident_count": len(incidents),
    }


# ---------------------------------------------------------------------------
# Validation (shape-level; not a full STIX validator)
# ---------------------------------------------------------------------------

def validate_bundle(bundle: Dict[str, Any]) -> List[str]:
    """Return a list of structural problems (empty list = clean)."""
    errors: List[str] = []
    if bundle.get("type") != "bundle":
        errors.append("bundle type must be 'bundle'")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        errors.append("bundle objects must be an array")
        return errors
    for idx, obj in enumerate(objects):
        where = f"object[{idx}]"
        otype = obj.get("type")
        required = SDO_REQUIRED if otype == "observed-data" else SCO_REQUIRED
        for key in required:
            if key not in obj:
                errors.append(f"{where}: missing required key '{key}'")
        oid = str(obj.get("id", ""))
        if not ID_RE.match(oid):
            errors.append(f"{where}: bad id format {oid!r}")
        if otype == "observed-data":
            for key in ("first_observed", "last_observed"):
                if not TS_RE.match(str(obj.get(key, ""))):
                    errors.append(f"{where}: bad {key} timestamp")
            num = obj.get("number_observed")
            if not isinstance(num, int) or isinstance(num, bool) or num < 1:
                errors.append(f"{where}: number_observed must be int >= 1")
        for key in ("created", "modified"):
            if key in obj and not TS_RE.match(str(obj[key])):
                errors.append(f"{where}: bad {key} timestamp")
    return errors


# ---------------------------------------------------------------------------
# Inputs (file capture or read-only control query)
# ---------------------------------------------------------------------------

def load_view_file(path: Path) -> Dict[str, Any]:
    view = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(view, dict):
        raise ExportError("captured file must contain a JSON object")
    return view


def load_view_daemon() -> Dict[str, Any]:
    # Imported lazily: keeps module import free of host effects.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from aegisctl.api.control_api import query_control  # noqa: PLC0415

    view = query_control("xdr.list")
    if not isinstance(view, dict):
        raise ExportError("daemon returned no valid xdr.list view")
    return view


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Export xdr.list incidents as a STIX 2.1 bundle (read-only).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="captured xdr.list JSON file")
    src.add_argument("--daemon", action="store_true",
                     help="query the live daemon (read-only xdr.list)")
    ap.add_argument("--out", help="output .stix.json path (default: stdout)")
    ap.add_argument("--pretty", action="store_true", help="indent the output")
    args = ap.parse_args(argv)

    try:
        view = load_view_file(Path(args.file)) if args.file else load_view_daemon()
        bundle = build_bundle(view)
        errors = validate_bundle(bundle)
        if errors:
            raise ExportError("validation failed: " + "; ".join(errors))
        space = 2 if args.pretty else None
        payload = json.dumps(bundle, indent=space, ensure_ascii=False) + "\n"
        if args.out:
            out = Path(args.out)
            if out.suffix != ".json":
                raise ExportError("--out must end with .json")
            out.write_text(payload, encoding="utf-8")
            skipped = bundle.get("x_aegis_export_skipped_entities", [])
            print(f"WROTE {out} objects={len(bundle['objects'])} "
                  f"incidents={bundle['x_aegis_incident_count']} skipped={len(skipped)}")
        else:
            sys.stdout.write(payload)
        return 0
    # ValueError covers json.JSONDecodeError on malformed --file input
    # (ExportError also subclasses ValueError); fail-closed either way.
    except (ValueError, OSError) as exc:
        print(f"STIX_EXPORT_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
