#!/usr/bin/env python3
"""Dump the canonical-event golden vector descriptor table (EVT-166).

Reads tests/contracts/event_vectors/event_vectors/golden_vectors.json
(name -> {description, fields}) and prints one readable block per
vector. Read-only; exit 0 on success, 1 with a reason on unreadable
input. (Replaces the wire-hex decoder era: the file carries field
descriptors now, no hex payloads.)
"""
import json
import sys
from pathlib import Path

GOLDEN = Path("tests/contracts/event_vectors/event_vectors/golden_vectors.json")


def main() -> int:
    try:
        doc = json.loads(GOLDEN.read_text(encoding="utf-8"))
    except OSError as exc:
        print("golden vectors unreadable: %s" % exc)
        return 1
    except ValueError as exc:
        print("golden vectors not JSON: %s" % exc)
        return 1
    vectors = doc.get("vectors", {})
    if isinstance(vectors, list):
        vectors = {v.get("id", i): v for i, v in enumerate(vectors) if isinstance(v, dict)}
    if not isinstance(vectors, dict) or not vectors:
        print("no vectors in %s" % GOLDEN)
        return 1
    print("Golden vectors: %d (schema %s, wire %s)" % (
        len(vectors), doc.get("schema_version"), doc.get("wire_size")))
    for name in sorted(vectors):
        vec = vectors[name]
        if not isinstance(vec, dict):
            continue
        print("\n--- %s ---" % name)
        print("  description: %s" % vec.get("description", "?"))
        fields = vec.get("fields", {})
        if not isinstance(fields, dict):
            continue
        for key in sorted(fields):
            print("  %s: %s" % (key, fields[key]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
