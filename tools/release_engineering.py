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

# Path fragments that never become release artifacts (build/tool caches).
EXCLUDE_PARTS = ("node_modules", ".zig-cache", ".zig-cache", ".git", "target",
                 "__pycache__", ".venv", "venv", "zig-out", "dist", "eggs")


def git_source_commit() -> str:
    """Short SHA of the source commit every artifact maps back to."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown"


def normalized_bytes(path: Path) -> bytes:
    """File bytes as they must be hashed: LF line endings, regardless of the
    checkout. Without this the digests depend on the working-tree line endings,
    which forced CI to rewrite build_manifest.json (`--manifest`) just to keep
    `--verify` green instead of failing the drift gate honestly. `.gitattributes`
    (`* text eol=lf`) is the single source of line-ending truth; hashing is now
    consistent with it. Binary files (containing NUL) are hashed verbatim."""
    data = path.read_bytes()
    if b"\x00" in data:
        return data
    return data.replace(b"\r\n", b"\n")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(normalized_bytes(path)).hexdigest()


def file_size(path: Path) -> int:
    """Normalized (LF) size, so `size` and `sha256` always agree."""
    return len(normalized_bytes(path))


def collect_artifacts() -> List[Dict[str, Any]]:
    """Collect all source + build artifacts with their hashes.

    Maps to the actual repository layout (T17): walks the implementation
    source trees that ship in a release and assigns each artifact its
    SHA-256 digest. Every entry is later cross-checked against the working
    tree by --verify (an artifact maps to the source commit because the
    digest is recorded at that commit).
    """
    artifacts: List[Dict[str, Any]] = []
    include_dirs = ["core", "shield", "scripts", "tools", "config", "installer",
                    "go", "brain", "ts_policy", "bridge"]
    include_files = ["build.zig", "Cargo.toml", "CMakeLists.txt", "requirements.txt",
                     ".gitignore", "ROADMAP.md", "Rules.json", "runtime_manifest.json",
                     "ci_coverage.json", ".github/workflows/ci.yml",
                     ".github/workflows/host-regression.yml"]
    for d in include_dirs:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(ROOT)).replace("\\", "/")
            if any(part in rel for part in EXCLUDE_PARTS):
                continue
            artifacts.append({
                "path": rel,
                "size": file_size(p),
                "sha256": file_sha256(p),
                "language": _detect_language(rel),
            })
    for f in include_files:
        p = ROOT / f
        if p.exists():
            artifacts.append({
                "path": str(p.relative_to(ROOT)).replace("\\", "/"),
                "size": file_size(p),
                "sha256": file_sha256(p),
                "language": _detect_language(f),
            })
    artifacts.sort(key=lambda a: a["path"])
    return artifacts


def _detect_language(rel: str) -> str:
    if rel.endswith(".zig"):
        return "zig"
    if rel.endswith(".rs"):
        return "rust"
    if rel.endswith(".go"):
        return "go"
    if rel.endswith((".py", ".pyx", ".pyi")):
        return "python/cython"
    if rel.endswith((".ts", ".tsx")):
        return "typescript"
    if rel.endswith((".c", ".cpp", ".h", ".hpp", ".cc")):
        return "c/c++"
    if rel.endswith(".json"):
        return "json"
    if rel.endswith((".yml", ".yaml")):
        return "yaml"
    if rel.endswith((".nsi", ".ps1", ".bat")):
        return "script"
    return "data"


def generate_manifest(version: str) -> Dict[str, Any]:
    commit = git_source_commit()
    manifest: Dict[str, Any] = {
        "schema_version": "2.0",
        "product": "AEGIS NIDS",
        "version": version,
        "source_commit": commit,
        "build_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "build_host": os.uname().nodename if hasattr(os, "uname") else "windows",
        "platform": {
            "os": "windows",
            "arch": "x86_64",
            "min_os_version": "Windows 10 1809",
        },
        "languages": {
            "zig": "0.13.0",
            "rust": "1.88.0",
            "python": "3.11+",
            "cython": "3.0+",
            "c/cpp": "MSVC 19.38+ (Visual Studio 2022)",
            "go": "1.22+",
            "typescript": "5.x (node 20)",
        },
        # TRUTH-002: provenance paths must resolve to real files. `core/` and
        # `native/` do not exist; the canonical Zig root is src/main.zig, the
        # Rust PEP is rust-src/lib.rs, the C native helpers are src/windows/*.c,
        # and the canonical Go sensor is nose/ (aegis-nose.exe).
        "components": [
            {"id": "core", "name": "aegis_nids.exe", "language": "zig", "type": "executable",
             "required": True, "ci_job": "zig-build-test", "commit": commit, "source": "src/main.zig",
             "classification": "CANONICAL"},
            {"id": "pep", "name": "aegis_pep.dll", "language": "rust", "type": "library",
             "required": True, "ci_job": "rust-pep-build", "commit": commit, "source": "rust-src/lib.rs",
             "classification": "CANONICAL"},
            {"id": "wfp_user", "name": "aegis_wfp_user.dll", "language": "c", "type": "library",
             "required": True, "ci_job": "c-native-build", "commit": commit, "source": "src/windows/aegis_wfp.c",
             "classification": "CANONICAL"},
            {"id": "etw_helper", "name": "aegis_etw_helper.dll", "language": "c", "type": "library",
             "required": True, "ci_job": "c-native-build", "commit": commit, "source": "src/windows/etw_native.c",
             "classification": "CANONICAL"},
            {"id": "fim_helper", "name": "aegis_fim_helper.dll", "language": "c", "type": "library",
             "required": True, "ci_job": "c-native-build", "commit": commit, "source": "src/windows/fim_native.c",
             "classification": "CANONICAL"},
            {"id": "nose", "name": "aegis-nose.exe", "language": "go", "type": "executable",
             "required": True, "ci_job": "go-nose-build-test", "commit": commit, "source": "nose/main.go",
             "classification": "CANONICAL"},
            {"id": "aggregator", "name": "aegis-aggregator.exe", "language": "go", "type": "executable",
             "required": False, "ci_job": "go-aggregator-build-test", "commit": commit, "source": "go/aggregator/main.go",
             "classification": "SUPPORT"},
            {"id": "shield", "name": "sec_monitor.dll", "language": "rust", "type": "library",
             "required": False, "ci_job": "shield-build", "commit": commit, "source": "shield/src/lib.rs",
             "classification": "SUPPORT"},
            {"id": "aegisctl", "name": "tools/aegisctl.py", "language": "python", "type": "script",
             "required": True, "ci_job": "python-tests", "commit": commit, "source": "tools/aegisctl.py",
             "classification": "CANONICAL"},
            {"id": "installer", "name": "tools/installer.py", "language": "python", "type": "script",
             "required": True, "ci_job": "package-release", "commit": commit, "source": "tools/installer.py"},
            {"id": "ts-policy", "name": "ts_policy", "language": "typescript", "type": "toolchain",
             "required": True, "ci_job": "ts-policy-build", "commit": commit, "source": "ts_policy/"},
            {"id": "brain", "name": "brain/aegis_brain_cython/fast_scan.pyx", "language": "cython", "type": "library",
             "required": True, "ci_job": "python-tests", "commit": commit, "source": "brain/"},
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


def verify_manifest() -> int:
    """Recompute SHA-256 digests for artifacts present in the working tree
    and compare with build_manifest.json. Any mismatch -> FAIL (the release
    artifact no longer maps to the recorded source commit)."""
    if not MANIFEST_PATH.exists():
        print("build_manifest.json not found - run --manifest first", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    mismatches: List[str] = []
    checked = 0
    missing = 0
    for art in manifest.get("artifacts", []):
        p = ROOT / art["path"]
        if not p.exists():
            missing += 1
            continue
        checked += 1
        if file_size(p) != art["size"] or file_sha256(p) != art["sha256"]:
            mismatches.append(art["path"])
    print(f"Artifacts checked: {checked} (present), missing (not built locally): {missing}")
    if mismatches:
        print("FAIL - artifacts drifted from recorded commit digests:")
        for m in mismatches:
            print(f"  - {m}")
        return 1
    print(f"OK - {checked} artifacts match their recorded digests "
          f"(source_commit={manifest.get('source_commit', '?')})")
    return 0


def refresh_digests(commit: str) -> int:
    """Re-record digests for artifacts ALREADY listed in build_manifest.json.

    `--manifest` re-derives the whole artifact set from `collect_artifacts()`,
    whose directory rules drifted away from the committed manifest: it still
    lists the non-existent `core/` and `config/` trees, omits `src/` and
    `configs/`, and picks up gitignored Cython build output. Regenerating today
    therefore DESTROYS provenance instead of restoring it.

    This mode is the bounded alternative for a reviewed local change: it keeps
    the recorded artifact set exactly as-is, refreshes only digests/sizes, drops
    entries whose file is gone, and re-stamps source_commit. The artifact-set
    reconciliation is tracked separately as a build-truth task.
    """
    if not MANIFEST_PATH.exists():
        print("build_manifest.json not found - run --manifest first", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    kept: List[Dict[str, Any]] = []
    updated: List[str] = []
    dropped: List[str] = []
    for art in manifest.get("artifacts", []):
        p = ROOT / art["path"]
        if not p.exists():
            dropped.append(art["path"])
            continue
        digest = file_sha256(p)
        size = file_size(p)
        if digest != art["sha256"] or size != art["size"]:
            updated.append(art["path"])
            art["sha256"] = digest
            art["size"] = size
        kept.append(art)
    manifest["artifacts"] = kept
    manifest["source_commit"] = commit
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    print(f"Refreshed {MANIFEST_PATH}")
    print(f"   artifacts kept: {len(kept)}; digests updated: {len(updated)}; dropped: {len(dropped)}")
    for path in updated:
        print(f"   updated: {path}")
    for path in dropped:
        print(f"   dropped: {path}")
    return verify_manifest()


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS release engineering")
    parser.add_argument("--manifest", action="store_true", help="Generate build_manifest.json")
    parser.add_argument("--sbom", action="store_true", help="Generate SBOM (SPDX 2.3)")
    parser.add_argument("--package", action="store_true", help="Package release artifacts")
    parser.add_argument("--verify", action="store_true", help="Verify artifact digests vs manifest")
    parser.add_argument("--refresh-digests", action="store_true",
                        help="Re-record digests for already-manifested artifacts (no artifact-set change)")
    parser.add_argument("--version", default=VERSION)
    args = parser.parse_args()

    if args.verify:
        return verify_manifest()

    if args.refresh_digests:
        return refresh_digests(git_source_commit())

    if args.manifest or args.sbom or args.package:
        manifest = generate_manifest(args.version)
        if args.manifest:
            MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
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
