"""B6: committed event-vector metadata must be verified, not merely recorded.

`vectors_metadata.json` carries sha256/size for all nine frozen vectors, but
no test checked those fields against the bytes until this module. This is a
read-only integrity pin: it never regenerates or rewrites a tracked vector.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

VECTOR_DIR = Path(__file__).resolve().parent / "event_vectors" / "event_vectors"
METADATA = VECTOR_DIR / "vectors_metadata.json"


def test_committed_event_vectors_match_recorded_digest_and_size() -> None:
    document = json.loads(METADATA.read_text(encoding="utf-8"))
    vectors = document["vectors"]
    assert len(vectors) == 9, "all nine frozen vectors must be listed"

    for entry in vectors:
        raw = (VECTOR_DIR / entry["file"]).read_bytes()
        assert len(raw) == entry["size"], (
            f"{entry['file']}: size {len(raw)} != recorded {entry['size']}"
        )
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == entry["sha256"], (
            f"{entry['file']}: sha256 {digest} != recorded {entry['sha256']}"
        )
