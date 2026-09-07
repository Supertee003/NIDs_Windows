#!/usr/bin/env python3
"""II22 - AEGIS NIDS Release Engineering & Manifest

Generates build_manifest.json (single source of truth for the release),
computes SBOM (SPDX 2.3), and packages release artifacts.

Usage:
    python tools/release_engineering.py --manifest
    python tools/release_engineering.py --sbom
    python tools/release_engineering.py --package --version 5.0.0
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
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).parent.parent
VERSION = "5.0.0"
MANIFEST_PATH = ROOT / "build_manifest.json"


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_artifacts() -> List[Dict[str, Any]]:
    """Collect all source + build artifacts with their hashes."""
    artifacts: List[Dict[str, Any]] = []
    include_dirs = ["src", "rust-src", "tools", "configs", "tests", "kernel", "installer"]
    include_files = ["build.zig", "Cargo.toml", "CMakeLists.txt", "requirements.txt",
                     ".gitignore", "ROADMAP.md", "Rules.json"]
    for d in include_dirs:
        for p in (ROOT / d).rglob("*") if (ROOT / d).exists() else []:
            if p.is_file():
                artifacts.append({
                    "path": str(p.relative_to(ROOT)).replace("\\", "/"),
                    "size": p.stat().st_size,
                    "sha256": file_sha256(p),
                })
    for f in include_files:
        p = ROOT / f
        if p.exists():
            artifacts.append({
                "path": str(p.relative_to(ROOT)).replace("\\", "/"),
                "size": p.stat().st_size,
                "sha256": file_sha256(p),
            })
    return artifacts


def generate_manifest(version: str) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {
        "schema_version": "1.0",
        "product": "AEGIS NIDS",
        "version": version,
        "build_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "build_host": os.uname().nodename if hasattr(os, "uname") else "windows",
        "platform": {
            "os": "windows",
            "arch": "x86_64",
            "min_os_version": "Windows 10 1809",
        },
        "languages": {
            "zig": "0.13.0",
            "rust": "1.78.0",
            "python": "3.11+",
            "c": "MSVC 19.38+ (Visual Studio 2022)",
        },
        "components": [
            {"id": "core", "name": "aegis_nids.exe", "language": "zig", "type": "executable"},
            {"id": "pep", "name": "aegis_pep.dll", "language": "rust", "type": "library"},
            {"id": "wfp_user", "name": "aegis_wfp_user.dll", "language": "c", "type": "library"},
            {"id": "etw_helper", "name": "aegis_etw_helper.dll", "language": "c", "type": "library"},
            {"id": "fim_helper", "name": "aegis_fim_helper.dll", "language": "c", "type": "library"},
            {"id": "aegisctl", "name": "aegisctl.py", "language": "python", "type": "script"},
            {"id": "installer", "name": "installer.py", "language": "python", "type": "script"},
            {"id": "backup", "name": "backup_recovery.py", "language": "python", "type": "script"},
        ],
        "modules": {
            "I01": "build.zig, Cargo.toml, CMakeLists.txt, .github/workflows/ci.yml",
            "I02": "src/contract/event.zig",
            "I03": "src/contract/runtime_manifest.zig",
            "I04": "src/core/memory_pool.zig",
            "I05": "src/core/diagnostics.zig",
            "I06": "src/capture/npcap_adapter.zig",
            "I07": "src/capture/packet_decoder.zig",
            "I08": "src/capture/flow_table.zig",
            "I09": "src/capture/proto/parsers.zig",
            "I10": "src/capture/stream_reassembly.zig",
            "I11": "src/detection/signature_engine.zig",
            "I12": "src/detection/anomaly_detector.zig",
            "I13": "src/detection/proto_anomaly.zig",
            "I14": "src/detection/correlator.zig",
            "I15": "src/detection/threat_tracker.zig",
            "I16": "src/policy/policy_ir.zig",
            "I17": "src/policy/trust_store.zig",
            "I18": "rust-src/lib.rs, src/policy/pep_bindings.zig",
            "I19": "src/policy/action_dispatcher.zig",
            "I20": "src/forensic/forensic_pipeline.zig",
            "I21": "src/forensic/replay_engine.zig",
            "II01": "src/windows/etw_realtime.zig, src/windows/etw_native.c",
            "II02": "src/windows/fim.zig, src/windows/fim_native.c",
            "II03": "src/windows/registry_monitor.zig",
            "II04": "src/windows/injection_detector.zig",
            "II05": "src/windows/aegis_wfp.c",
            "II06": "src/windows/host_telemetry.zig",
            "II07": "src/reliability/watchdog.zig",
            "II08": "src/reliability/security_check.zig",
            "II09": "src/reliability/latency_histogram.zig",
            "II10": "tools/config_validator.py, configs/schema.json",
            "II11": "src/reliability/fault_injection.zig",
            "II12": "src/federation/cluster_coord.zig",
            "II13": "src/federation/node_registry.zig",
            "II14": "src/federation/aggregator.zig",
            "II15": "rust-src/lib.rs (federation_tls module)",
            "II16": "src/xdr/xdr_engine.zig",
            "II17": "tools/aegisctl.py",
            "II18": "tools/installer.py, installer/aegis.nsi",
            "II19": "tools/backup_recovery.py",
            "II20": ".github/workflows/ci.yml",
            "II21": "tests/test_golden_path.py",
            "II22": "tools/release_engineering.py",
        },
        "artifacts": collect_artifacts(),
    }
    return manifest


def generate_sbom(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Generate SPDX 2.3 SBOM from manifest."""
    packages: List[Dict[str, Any]] = []
    for art in manifest["artifacts"]:
        packages.append({
            "name": Path(art["path"]).name,
            "SPDXID": f"SPDXRef-{hash(art['path']) & 0xFFFFFFFF:08x}",
            "versionInfo": manifest["version"],
            "supplier": "Organization: AEGIS",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "Copyright (c) 2026 AEGIS",
            "checksums": [{"algorithm": "SHA256", "checksumValue": art["sha256"]}],
            "filePath": art["path"],
        })
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"AEGIS-NIDS-{manifest['version']}",
        "documentNamespace": f"https://aegis.local/spdx/{manifest['version']}",
        "creationInfo": {
            "creators": ["Organization: AEGIS", "Tool: release_engineering.py"],
            "created": manifest["build_date"],
        },
        "packages": packages,
    }
    return sbom


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS release engineering")
    parser.add_argument("--manifest", action="store_true", help="Generate build_manifest.json")
    parser.add_argument("--sbom", action="store_true", help="Generate SBOM (SPDX 2.3)")
    parser.add_argument("--package", action="store_true", help="Package release artifacts")
    parser.add_argument("--version", default=VERSION)
    args = parser.parse_args()

    if args.manifest or args.sbom or args.package:
        manifest = generate_manifest(args.version)
        if args.manifest:
            MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            print(f"âœ… Manifest written: {MANIFEST_PATH}")
            print(f"   Components: {len(manifest['components'])}")
            print(f"   Modules: {len(manifest['modules'])}")
            print(f"   Artifacts: {len(manifest['artifacts'])}")
        if args.sbom:
            sbom = generate_sbom(manifest)
            sbom_path = ROOT / "sbom.spdx.json"
            sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
            print(f"âœ… SBOM written: {sbom_path}")
            print(f"   SPDX packages: {len(sbom['packages'])}")
        if args.package:
            # Create release archive
            archive_path = ROOT / f"aegis-nids-{args.version}.zip"
            if archive_path.exists():
                archive_path.unlink()
            import zipfile
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for art in manifest["artifacts"]:
                    src = ROOT / art["path"]
                    if src.exists():
                        zf.write(src, art["path"])
                zf.write(MANIFEST_PATH, "build_manifest.json")
                if (ROOT / "sbom.spdx.json").exists():
                    zf.write(ROOT / "sbom.spdx.json", "sbom.spdx.json")
            print(f"âœ… Release archive: {archive_path}")
            print(f"   Size: {archive_path.stat().st_size:,} bytes")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
