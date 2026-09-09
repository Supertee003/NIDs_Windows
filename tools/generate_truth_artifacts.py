#!/usr/bin/env python3
"""Generate inventory.json and reference_map.json — AEGIS truth artifacts."""
from __future__ import annotations
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

SOURCE_EXTS = {
    ".zig", ".rs", ".py", ".go", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".hh",
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".rb", ".php", ".pl",
    ".lua", ".r", ".jl", ".ex", ".erl", ".clj", ".hs", ".ml", ".fs", ".cs", ".scala", ".dart",
    ".nim", ".v", ".sv", ".m", ".mm", ".swift", ".kt", ".java", ".ps1", ".sh", ".bash",
}
BUILD_EXTS = {
    ".toml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".properties",
    ".cmake", ".bat", ".cmd",
}
DOC_EXTS = {".md", ".markdown", ".rst", ".adoc", ".txt"}
CONFIG_EXTS = {".json", ".xml"}
SKIP_DIRS = {
    ".git", ".zig-cache", "zig-out", "target", "__pycache__", "build", "dist",
    "node_modules", ".pytest_cache", ".venv", "venv", ".mypy_cache", ".ruff_cache",
    "logs", ".freebuff", ".agents",
}
SKIP_ROOT_FILES = {".gitignore", ".gitattributes", "LICENSE", "LICENSE.txt"}

LOCKFILE_NAMES = {
    "Cargo.lock", "bun.lock", "package-lock.json", "pnpm-lock.yaml",
    "yarn.lock", "go.sum", "composer.lock", "Gemfile.lock", "poetry.lock",
    "uv.lock", "Pipfile.lock", "mix.lock", "vcpkg.json", "conan.lock",
}

ROLE_MAP: Dict[str, str] = {}


def classify(path: str) -> str:
    name = Path(path).name
    ext = Path(path).suffix.lower()
    parts = Path(path).parts

    if name in LOCKFILE_NAMES:
        return "canonical-build"
    if ext in SOURCE_EXTS:
        if "test" in name.lower() or name.startswith("test_") or name.endswith("_test.py"):
            return "canonical-test"
        return "canonical-source"
    if ext in BUILD_EXTS:
        return "canonical-build"
    if ext in DOC_EXTS:
        return "canonical-docs"
    if ext in CONFIG_EXTS:
        if any(p in ("configs", "config") for p in parts) or name == "Rules.json":
            return "canonical-config"
        return "canonical-build"
    if ext in {".woff", ".woff2", ".ttf", ".otf", ".eot"}:
        return "vendor"
    if name == "CMakeLists.txt":
        return "canonical-build"
    if name in {"go.mod"}:
        return "canonical-build"
    if name == "Cargo.toml":
        return "canonical-build"
    if ext in {".bin", ".json"} and "test" in str(parts).lower():
        return "canonical-test"
    if ext == ".bin":
        return "canonical-test"
    if name.endswith(".ps1"):
        return "canonical-build"
    return "unclassified"


def assign_role(path: str, cls: str) -> str:
    parts = Path(path).parts
    name = Path(path).name

    if cls == "canonical-source":
        if "src/" in str(parts) or path.startswith("src/"):
            return "production-source"
        if "core/" in str(parts):
            return "legacy-source"
        if "go/" in str(parts) or path.startswith("go/"):
            return "go-source"
        if "rust-src/" in str(parts):
            return "rust-source"
        if "brain/" in str(parts):
            return "python-source"
        if "bridge/" in str(parts):
            return "bridge-source"
        if "nose/" in str(parts):
            return "nose-source"
        if "shared/" in str(parts):
            return "shared-source"
        if "aegis_dashboard/" in str(parts):
            return "dashboard-source"
        return "source"
    if cls == "canonical-build":
        if name.endswith(".ps1"):
            return "build-script"
        if name == "build.zig":
            return "zig-build"
        if name == "Cargo.toml":
            return "rust-build"
        if name == "CMakeLists.txt":
            return "cpp-build"
        if name == "Makefile":
            return "makefile"
        if name in LOCKFILE_NAMES:
            return "lockfile"
        return "build-config"
    if cls == "canonical-docs":
        if name.startswith("ADR") or name.startswith("000"):
            return "architecture-decision"
        if name.startswith("STEP-") or name.startswith("STEP_"):
            return "step-document"
        if name.startswith("G") and name[1:3].isdigit():
            return "gate-document"
        return "documentation"
    if cls == "canonical-config":
        return "config-data"
    if cls == "canonical-test":
        return "test-artifact"
    if cls == "vendor":
        return "vendor-asset"
    return "other"


def should_skip(path: Path) -> bool:
    parts = path.relative_to(REPO_ROOT).parts
    if any(d in SKIP_DIRS for d in parts):
        return True
    if path.name in SKIP_ROOT_FILES and len(parts) == 1:
        return True
    if path.suffix in {".exe", ".dll", ".pdb", ".obj", ".o", ".so", ".ilk", ".exp", ".lib", ".sys"}:
        return True
    return False


def scan_files() -> List[Dict]:
    entries = []
    for f in sorted(REPO_ROOT.rglob("*")):
        if not f.is_file():
            continue
        if should_skip(f):
            continue
        rel = f.relative_to(REPO_ROOT).as_posix()
        try:
            size = f.stat().st_size
        except OSError:
            size = 0
        cls = classify(rel)
        role = assign_role(rel, cls)
        entries.append({"path": rel, "class": cls, "role": role, "size": size})
    return entries


def build_inventory(entries: List[Dict]) -> Dict:
    by_class: Dict[str, int] = {}
    for e in entries:
        by_class[e["class"]] = by_class.get(e["class"], 0) + 1

    return {
        "schema_version": "1.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "generate_truth_artifacts.py",
        "repo_root": str(REPO_ROOT),
        "total_files": len(entries),
        "by_class": by_class,
        "files": entries,
    }


def build_reference_map(entries: List[Dict]) -> Dict:
    by_role: Dict[str, int] = {}
    source_of_truth: List[str] = []
    for e in entries:
        by_role[e["role"]] = by_role.get(e["role"], 0) + 1
        if e["role"] in ("production-source", "build-script", "zig-build", "rust-build", "cpp-build"):
            source_of_truth.append(e["path"])

    truth_files = [
        "AGENTS.md", "README.md", "ROADMAP.md",
        "inventory.json", "reference_map.json",
        "runtime_manifest.json", "build_truth.json",
        "build_manifest.json", "ci_coverage.json",
    ]
    for tf in truth_files:
        if tf not in source_of_truth:
            p = REPO_ROOT / tf
            if p.exists():
                source_of_truth.append(tf)

    return {
        "schema_version": "1.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "generate_truth_artifacts.py",
        "total_files": len(entries),
        "by_role": by_role,
        "source_of_truth": sorted(set(source_of_truth)),
        "files": {e["path"]: {"class": e["class"], "role": e["role"]} for e in entries},
    }


def main() -> int:
    print("=" * 60)
    print(" AEGIS Truth Artifact Generator")
    print(" inventory.json + reference_map.json")
    print("=" * 60)
    print()

    entries = scan_files()
    print(f" Scanned {len(entries)} files")

    by_class: Dict[str, int] = {}
    for e in entries:
        by_class[e["class"]] = by_class.get(e["class"], 0) + 1
    print(" Classification:")
    for c, n in sorted(by_class.items(), key=lambda x: -x[1]):
        print(f"   {c:<22} {n:>4}")
    print()

    inv = build_inventory(entries)
    inv_path = REPO_ROOT / "inventory.json"
    inv_path.write_text(json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f" Wrote: {inv_path} ({inv_path.stat().st_size:,} bytes)")

    ref = build_reference_map(entries)
    ref_path = REPO_ROOT / "reference_map.json"
    ref_path.write_text(json.dumps(ref, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f" Wrote: {ref_path} ({ref_path.stat().st_size:,} bytes)")

    print()
    print(" Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
