"""FP-FEEDBACK-001 — operator false-positive feedback, local file only.

This module is deliberately advisory-only:

* ``append_event`` writes one validated NDJSON line to the producer-owned
  ``logs/fp_feedback.ndjson`` (or ``$AEGIS_LOGS_DIR/fp_feedback.ndjson``).
* ``count`` reads that file; it never queries the daemon, edits rules, or
  changes any detection / correlation / policy / enforcement state.
* Marking a false positive must NEVER suppress a future detection. The only
  consumer is an operator-visible count (CLI output + loopback dashboard).

Path resolution reads ``AEGIS_LOGS_DIR`` at call time so tests can redirect
every write to ``tmp_path`` without reimporting or touching tracked tree state.
No import-time host effects (no socket, no pipe, no stdout).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

SCHEMA = "aegis.fp_feedback.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_LOGS_DIR = REPO_ROOT / "logs"
MAX_REASON = 256
# Maximum bytes scanned on read (bounded, like the dashboard's feed tail).
MAX_SCAN_BYTES = 8 * 1024 * 1024


def feedback_path() -> Path:
    """Resolve the producer-owned feedback file at call time."""
    return Path(os.environ.get("AEGIS_LOGS_DIR") or _DEFAULT_LOGS_DIR) / "fp_feedback.ndjson"


def _sanitize_reason(reason: str, max_len: int = MAX_REASON) -> str:
    """Strip control chars/newlines so one record stays exactly one line."""
    cleaned = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in str(reason or ""))
    return cleaned.strip()[:max_len]


def _valid_event_id(event_id: Any) -> bool:
    # bool is a subclass of int in Python; reject it explicitly.
    return isinstance(event_id, int) and not isinstance(event_id, bool) and event_id > 0


def read_all(path: Path | None = None) -> list[dict[str, Any]]:
    """Return all well-formed feedback records (malformed lines are skipped)."""
    target = path or feedback_path()
    if not target.is_file():
        return []
    records: list[dict[str, Any]] = []
    try:
        with target.open("rb") as handle:
            raw = handle.read(MAX_SCAN_BYTES)
    except OSError:
        return []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(record, dict) and record.get("schema") == SCHEMA:
            records.append(record)
    return records


def count(path: Path | None = None) -> int:
    """Number of valid feedback records. Advisory: not a detection counter."""
    return len(read_all(path))


def append_event(event_id: int, reason: str = "", source: str = "aegisctl mark-fp") -> dict[str, Any]:
    """Append one validated feedback record and verify persistence.

    Raises ValueError on invalid input, OSError on write failure, and
    RuntimeError if the postcondition re-read cannot find the exact record.
    Never touches detection, rules, policy, or enforcement.
    """
    if not _valid_event_id(event_id):
        raise ValueError("event_id must be a positive integer")
    target = feedback_path()
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "ts_ms": int(time.time() * 1000),
        "event_id": int(event_id),
        "reason": _sanitize_reason(reason),
        "source": _sanitize_reason(source, 64),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())

    # Postcondition: re-read and prove exactly one matching record exists.
    matches = [
        item for item in read_all(target)
        if item.get("event_id") == record["event_id"]
        and item.get("ts_ms") == record["ts_ms"]
        and item.get("reason") == record["reason"]
    ]
    if len(matches) != 1:
        raise RuntimeError("feedback persistence postcondition failed (record not found exactly once)")
    return {
        "ok": True,
        "persisted": True,
        "event_id": record["event_id"],
        "ts_ms": record["ts_ms"],
        "count": count(target),
        "path": str(target),
        "advisory": True,
    }
