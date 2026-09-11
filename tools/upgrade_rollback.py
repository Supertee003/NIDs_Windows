#!/usr/bin/env python3
"""T17 (Steps 46-52) - Upgrade / Rollback / Recovery orchestration.

Demonstrates the upgrade/rollback lifecycle to a known-good state and
measures the reliability telemetry the ticket requires:

  RPO  - Recovery Point Objective: wall-clock between the snapshot used for
         rollback and the moment the rollback triggers (the window of
         work-at-risk if a crash followed).
  RTO  - Recovery Time Objective: wall-clock the restore actually takes
         (measured, not asserted to a target - RB-005 documents the atomic
         config-swap rollback path at < 5s).
  restore_success - whether every snapshot path was restored.

Lifecycle covered:
  fresh-install  -> configs/trust/audit initialized (no snapshot needed)
  snapshot       -> capture configs/policy/trust/audit/forensic history
  upgrade        -> operator swaps binaries (out of band, via installer)
  failed-upgrade -> rollback --snapshot <id> restores the known-good state
  reinstall      -> installer preserves data\\ per tools/installer.py
  uninstall      -> installer keeps data\\ (see NSIS uninstall section)

Data preserved: configs/Rules.json (+ .sig), config/trust_store.json,
certs/, logs/audit/, logs/forensics/, logs/runtime/control_audit.ndjson -
the same set tools/installer.py ships into "$INSTDIR\\data".

See also: docs/runbooks/RB-005-config-rollback.md (atomic ruleset swap).

Usage:
    python tools/upgrade_rollback.py snapshot              # capture state
    python tools/upgrade_rollback.py report                # list snapshots
    python tools/upgrade_rollback.py rollback [--snapshot N] [--json]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Paths that must survive upgrade/rollback/reinstall (data plane).
PRESERVED_RELS = [
    "configs/Rules.json",
    "configs/Rules.json.sig",
    "configs/trust_store.json",
    "certs/",
    "logs/audit/",
    "logs/forensics/",
    "logs/runtime/control_audit.ndjson",
]

SNAPSHOTS_DIR = ROOT / "logs" / "snapshots"
REPORT_JSON = ROOT / "logs" / "runtime" / "upgrade_rollback.json"


def _preserved_path(rel: str) -> Path:
    return ROOT / rel


def _snapshot_id_from_dir(tag: Path) -> int:
    return int(tag.name.split("-", 1)[0])


def snapshot() -> dict:
    """Capture the current data plane into a timestamped snapshot dir."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    snap = SNAPSHOTS_DIR / f"{now.strftime('%Y%m%d%H%M%S')}-snap"
    snap.mkdir(parents=True, exist_ok=True)
    restored = copied = missing = 0
    for rel in PRESERVED_RELS:
        src = _preserved_path(rel)
        if rel.endswith("/"):
            base = src
            if not base.exists():
                missing += 1
                continue
            dest = snap / rel.rstrip("/")
            shutil.copytree(base, dest, dirs_exist_ok=True)
            copied += 1
            continue
        if not src.exists():
            missing += 1
            continue
        dest = snap / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        copied += 1
    result = {
        "operation": "snapshot",
        "snapshot_id": _snapshot_id_from_dir(snap),
        "snapshot_dir": str(snap),
        "created_at": now.isoformat(),
        "entries_copied": copied,
        "entries_missing": missing,
        "restored": restored,
    }
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def report() -> dict:
    snaps = sorted(SNAPSHOTS_DIR.glob("*-snap"), reverse=True)
    return {
        "operation": "report",
        "snapshot_count": len(snaps),
        "snapshots": [str(s.relative_to(ROOT)) for s in snaps],
        "preserved_paths": PRESERVED_RELS,
    }


def rollback(snapshot_id: int | None, write_json: bool) -> dict:
    """Restore the data plane to a snapshot and measure RPO/RTO."""
    from datetime import datetime, timezone
    snap = None
    if snapshot_id is not None:
        for cand in SNAPSHOTS_DIR.glob("*-snap"):
            if _snapshot_id_from_dir(cand) == snapshot_id:
                snap = cand
                break
    else:
        snaps = sorted(SNAPSHOTS_DIR.glob("*-snap"), reverse=True)
        if snaps:
            snap = snaps[0]
    if snap is None:
        return {"operation": "rollback", "ok": False,
                "error": "no snapshot found - run `snapshot` first"}

    start_ms = datetime.now(timezone.utc)
    restored = errors = 0
    for rel in PRESERVED_RELS:
        src = snap / rel.rstrip("/")
        if not src.exists():
            continue
        dest = _preserved_path(rel)
        try:
            if rel.endswith("/"):
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
            restored += 1
        except OSError as exc:
            errors += 1
            if write_json:
                print(f"  restore error {rel}: {exc}", file=sys.stderr)
    end_ms = datetime.now(timezone.utc)

    rto_ms = int((end_ms - start_ms).total_seconds() * 1000)
    rpo_ms = -1
    if snap is not None:
        try:
            from datetime import datetime as _dt
            created = _dt.strptime(snap.name.split("-", 1)[0], "%Y%m%d%H%M%S")
            rpo_ms = int((end_ms - created.replace(tzinfo=timezone.utc)).total_seconds() * 1000)
        except Exception:
            rpo_ms = -1
    ok = restored > 0 and errors == 0
    result = {
        "operation": "rollback",
        "ok": ok,
        "snapshot_used": str(snap.relative_to(ROOT)) if snap else None,
        "restored_count": restored,
        "restore_errors": errors,
        "rpo_ms": rpo_ms,
        "rto_ms": rto_ms,
        "recovered": ok,
    }
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="AEGIS upgrade/rollback/recovery (T17 AC5)")
    ap.add_argument("op", choices=["snapshot", "report", "rollback"])
    ap.add_argument("--snapshot", type=int, default=None, help="snapshot id to roll back to")
    ap.add_argument("--json", action="store_true", help="emit result as JSON")
    args = ap.parse_args()

    if args.op == "snapshot":
        result = snapshot()
    elif args.op == "report":
        result = report()
    else:
        result = rollback(args.snapshot, write_json=args.json)

    print(json.dumps(result, indent=2) if args.json or args.op == "report"
          else _human(result))
    return 0 if result.get("ok", True) else 1


def _human(result: dict) -> str:
    lines = [f"{result.get('operation','?').upper()}"]
    for k, v in result.items():
        if k != "operation":
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())