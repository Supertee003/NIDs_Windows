#!/usr/bin/env python3
"""II10 - Configuration Schema Validator for AEGIS NIDS v5.0+

Validates a runtime config file against the JSON schema (configs/schema.json),
applies default values for missing fields, and produces a normalized config.

Usage:
    python tools/config_validator.py --config configs/runtime.toml
    python tools/config_validator.py --config configs/runtime.json --strict
"""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

try:
    import jsonschema
    from jsonschema import Draft7Validator
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def load_config(path: Path) -> Dict[str, Any]:
    """Load JSON or TOML config file."""
    if path.suffix.lower() == ".toml":
        if tomllib is None:
            raise RuntimeError("tomllib not available; install tomli for TOML support")
        with path.open("rb") as f:
            return tomllib.load(f)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_schema(schema_path: Path) -> Dict[str, Any]:
    with schema_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def apply_defaults(value: Any, schema: Dict[str, Any]) -> Any:
    """Recursively apply default values from schema."""
    if not isinstance(value, dict) or not isinstance(schema, dict):
        return value
    properties = schema.get("properties", {})
    out = dict(value)
    for key, prop in properties.items():
        if "default" in prop:
            out.setdefault(key, prop["default"])
        if key in out and isinstance(out[key], dict) and isinstance(prop, dict) and "properties" in prop:
            out[key] = apply_defaults(out[key], prop)
    return out


def validate_config(config: Dict[str, Any], schema: Dict[str, Any], strict: bool = False) -> list:
    """Validate config against schema. Returns list of errors."""
    if not HAS_JSONSCHEMA:
        # Fallback minimal validation
        errors = []
        required = schema.get("required", [])
        for r in required:
            if r not in config:
                errors.append(f"Missing required field: {r}")
        return errors
    validator = Draft7Validator(schema)
    errors = []
    for err in validator.iter_errors(config):
        path = ".".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"{path}: {err.message}")
        if strict:
            break
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS NIDS config validator")
    parser.add_argument("--config", required=True, type=Path, help="Path to config file (.json or .toml)")
    parser.add_argument("--schema", type=Path, default=Path(__file__).parent.parent / "configs" / "schema.json",
                        help="Path to JSON schema (default: configs/schema.json)")
    parser.add_argument("--strict", action="store_true", help="Stop at first error")
    parser.add_argument("--normalize", action="store_true", help="Output normalized config with defaults applied")
    parser.add_argument("--output", type=Path, help="Output path for normalized config (JSON)")
    args = parser.parse_args()

    if not args.config.exists():
        print(f"ERROR: config file not found: {args.config}", file=sys.stderr)
        return 2

    # CONFIG-VALIDATE-001: a bad input is a diagnostic, not a traceback. The
    # messages here used to be non-ASCII literals saved through a mis-encoded
    # conversion, which raised UnicodeEncodeError on a cp1252 console while
    # *reporting* a failure - the report could crash where the config did not.
    try:
        schema = load_schema(args.schema)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read schema {args.schema}: {exc}", file=sys.stderr)
        return 2
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read config {args.config} as JSON/TOML: {exc}", file=sys.stderr)
        return 2
    if not isinstance(config, dict):
        print(f"ERROR: {args.config} is not a JSON object", file=sys.stderr)
        return 2
    errors = validate_config(config, schema, strict=args.strict)
    if errors:
        print(f"FAIL: config validation failed ({len(errors)} errors):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"OK: config valid: {args.config}")
    if args.normalize:
        normalized = apply_defaults(config, schema)
        if args.output:
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(normalized, f, indent=2, ensure_ascii=False)
            print(f"OK: normalized config written to: {args.output}")
        else:
            # Console output stays ASCII: ensure_ascii=False used to be able to
            # raise UnicodeEncodeError half-way through printing a valid config.
            print(json.dumps(normalized, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
