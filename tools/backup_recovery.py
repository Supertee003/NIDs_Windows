#!/usr/bin/env python3
"""II19 - AEGIS NIDS Backup & Recovery

Backs up AEGIS state (config, rules, forensic ring snapshot, incident DB)
to a single .zip archive. Restores from archive on demand.

Usage:
    python tools/backup_recovery.py backup --output aegis_backup.zip
    python tools/backup_recovery.py restore --input aegis_backup.zip
    python tools/backup_recovery.py security-review
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def backup_state(output: Path) -> int:
    """Backup AEGIS state to a zip archive."""
    if output.exists():
        print(f"âš  Overwriting existing file: {output}", file=sys.stderr)
        output.unlink()

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest: Dict[str, Any] = {
        "version": "5.0",
        "timestamp": timestamp,
        "files": [],
    }

    # Source paths (relative to project root)
    src_paths = [
        Path("configs/schema.json"),
        Path("configs/runtime.json"),
        Path("configs/cluster.example.json"),
        Path("Rules.json"),
        Path("src/contract/event.zig"),
        Path("src/contract/runtime_manifest.zig"),
        Path("build_manifest.json"),
    ]

    # Add forensic ring if exists
    forensic_path = Path("logs/forensic.bin")
    if forensic_path.exists():
        src_paths.append(forensic_path)

    # Add incident DB if exists
    incidents_path = Path("state/incidents.db")
    if incidents_path.exists():
        src_paths.append(incidents_path)

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in src_paths:
            if not p.exists():
                print(f"  skip (missing): {p}")
                continue
            arcname = str(p)
            zf.write(p, arcname)
            sha = _hash_file(p)
            manifest["files"].append({
                "path": str(p),
                "sha256": sha,
                "size": p.stat().st_size,
            })
            print(f"  added: {p} ({p.stat().st_size} bytes)")
        zf.writestr("__manifest__.json", json.dumps(manifest, indent=2))

    print(f"âœ… Backup written: {output}")
    print(f"   Total files: {len(manifest['files'])}")
    print(f"   Archive size: {output.stat().st_size} bytes")
    return 0


def restore_state(input_path: Path) -> int:
    """Restore AEGIS state from a zip archive."""
    if not input_path.exists():
        print(f"âŒ Backup file not found: {input_path}", file=sys.stderr)
        return 1
    with zipfile.ZipFile(input_path, "r") as zf:
        # Read manifest first
        try:
            manifest_data = zf.read("__manifest__.json").decode("utf-8")
            manifest = json.loads(manifest_data)
        except KeyError:
            print("âš  No manifest in backup; restoring all files")
            manifest = {"version": "?", "files": []}

        print(f"Backup version: {manifest.get('version')}")
        print(f"Timestamp:      {manifest.get('timestamp')}")
        print(f"Files:          {len(manifest.get('files', []))}")

        # Verify checksums then extract
        for entry in manifest.get("files", []):
            path = Path(entry["path"])
            expected_sha = entry["sha256"]
            try:
                data = zf.read(path.as_posix())
            except KeyError:
                print(f"  âš  Missing in archive: {path}")
                continue
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != expected_sha:
                print(f"  âŒ CHECKSUM MISMATCH: {path}")
                print(f"     expected: {expected_sha}")
                print(f"     actual:   {actual_sha}")
                return 1
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as f:
                f.write(data)
            print(f"  restored: {path}")

    print(f"âœ… Restore complete from {input_path}")
    return 0


def security_review() -> int:
    """Run a security review of the codebase (basic checks)."""
    print("=== AEGIS Security Review ===\n")
    issues: List[str] = []

    # 1. Check for hardcoded secrets
    secret_patterns = ["password", "secret", "api_key", "apikey", "private_key"]
    src_dirs = [Path("src"), Path("tools")]
    for d in src_dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.suffix not in (".zig", ".rs", ".py", ".c", ".h"):
                continue
            try:
                content = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            content_lower = content.lower()
            for pat in secret_patterns:
                if pat in content_lower:
                    # Check if it's an assignment vs just a comment
                    for line_num, line in enumerate(content.splitlines(), 1):
                        if pat in line.lower() and "=" in line and not line.strip().startswith("//"):
                            if not line.lower().startswith("pub const ") and not line.lower().startswith("var "):
                                issues.append(f"{p}:{line_num}: possible hardcoded secret ({pat})")

    # 2. Check for unsafe Rust blocks
    for p in Path("rust-src").rglob("*.rs"):
        try:
            content = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "unsafe" in content:
            for line_num, line in enumerate(content.splitlines(), 1):
                if "unsafe" in line and "fn " not in line:
                    issues.append(f"{p}:{line_num}: unsafe block in Rust")

    # 3. Check for shell=True in Python
    for p in Path("tools").rglob("*.py"):
        try:
            content = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "shell=True" in content:
            issues.append(f"{p}: subprocess with shell=True is unsafe")

    if not issues:
        print("âœ… No obvious security issues found")
        return 0
    print(f"âš  Found {len(issues)} potential issues:")
    for i in issues[:50]:
        print(f"  - {i}")
    if len(issues) > 50:
        print(f"  ... and {len(issues) - 50} more")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS NIDS backup & recovery")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_b = sub.add_parser("backup", help="Backup state to .zip")
    p_b.add_argument("--output", type=Path, default=Path("aegis_backup.zip"))
    p_r = sub.add_parser("restore", help="Restore state from .zip")
    p_r.add_argument("--input", type=Path, required=True)
    sub.add_parser("security-review", help="Run security review of codebase")
    args = parser.parse_args()
    if args.cmd == "backup":
        return backup_state(args.output)
    if args.cmd == "restore":
        return restore_state(args.input)
    if args.cmd == "security-review":
        return security_review()
    return 1


if __name__ == "__main__":
    sys.exit(main())
