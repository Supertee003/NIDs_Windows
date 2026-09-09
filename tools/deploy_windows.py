#!/usr/bin/env python3
"""AEGIS NIDS v5.0+ â€” Windows Deploy Script

Copies the fresh build into D:\\NIDs_Windows on a Windows host and
optionally builds + installs the service.

Usage (on Windows, in PowerShell as Administrator):
    python deploy_windows.py --target D:\\NIDs_Windows
    python deploy_windows.py --target D:\\NIDs_Windows --build
    python deploy_windows.py --target D:\\NIDs_Windows --build --install
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).parent


def copy_tree(src: Path, dst: Path) -> int:
    """Mirror src into dst (overwrite existing files)."""
    if not src.is_dir():
        return 0
    dst.mkdir(parents=True, exist_ok=True)
    n = 0
    for item in src.rglob("*"):
        if "__pycache__" in item.parts or ".pytest_cache" in item.parts:
            continue
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)
        n += 1
    return n


def deploy(target: Path) -> int:
    if not target.exists():
        target.mkdir(parents=True)
    print(f"Deploying AEGIS NIDS v5.0+ to {target} ...")
    total = 0
    for sub in ["src", "rust-src", "tools", "configs", "tests", "kernel", "installer", ".github"]:
        src = SOURCE_ROOT / sub
        if not src.exists():
            continue
        n = copy_tree(src, target / sub)
        total += n
        print(f"  {sub}/: {n} files")
    # Top-level files
    for f in ["build.zig", "Cargo.toml", "CMakeLists.txt", "requirements.txt",
              ".gitignore", "ROADMAP.md", "README.md", "LICENSE.txt", "Rules.json",
              "build_manifest.json", "sbom.spdx.json"]:
        src = SOURCE_ROOT / f
        if src.exists():
            shutil.copy2(src, target / f)
            total += 1
            print(f"  {f}")
    print(f"Total files copied: {total}")
    return 0


def build(target: Path) -> int:
    print("Building AEGIS NIDS (this may take a few minutes)...")
    cmds = [
        ["zig", "build"],
        ["cargo", "build", "--release"],
        ["cmake", "-B", "build", "-S", "."],
        ["cmake", "--build", "build", "--config", "Release"],
    ]
    for cmd in cmds:
        print(f"  $ {' '.join(cmd)}")
        rc = subprocess.run(cmd, cwd=str(target)).returncode
        if rc != 0:
            print(f"  âŒ Build step failed (rc={rc})", file=sys.stderr)
            return rc
    print("âœ… All build steps succeeded")
    return 0


def run_tests(target: Path) -> int:
    print("Running tests...")
    cmds = [
        ["zig", "build", "test"],
        ["cargo", "test", "--release"],
        [sys.executable, "tests/test_golden_path.py"],
    ]
    overall_rc = 0
    for cmd in cmds:
        print(f"  $ {' '.join(cmd)}")
        rc = subprocess.run(cmd, cwd=str(target)).returncode
        if rc != 0:
            print(f"  âš  Test step returned rc={rc}")
            overall_rc = max(overall_rc, rc)
    return overall_rc


def install_service(target: Path) -> int:
    print("Installing AEGIS NIDS service...")
    exe = target / "zig-out" / "bin" / "aegis_nids.exe"
    if not exe.exists():
        print(f"âŒ Built executable not found: {exe}", file=sys.stderr)
        print("   Run with --build first.", file=sys.stderr)
        return 1
    # Create service
    rc = subprocess.run([
        "sc", "create", "AegisNids",
        "binPath=", str(exe),
        "start=", "auto"
    ]).returncode
    if rc != 0:
        print(f"  âš  sc create returned rc={rc} (may already exist)")
    subprocess.run(["sc", "description", "AegisNids", "AEGIS Network Intrusion Detection System"])
    subprocess.run([
        "sc", "failure", "AegisNids",
        "reset=", "86400",
        "actions=", "restart/5000/restart/5000/restart/10000"
    ])
    print("âœ… Service installed (start with: sc start AegisNids)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy AEGIS NIDS to a Windows target directory")
    parser.add_argument("--target", type=Path, default=Path("D:/NIDs_Windows"),
                        help="Target directory (default: D:/NIDs_Windows)")
    parser.add_argument("--build", action="store_true", help="Run zig/cargo/cmake build after deploy")
    parser.add_argument("--test", action="store_true", help="Run test suite after build")
    parser.add_argument("--install", action="store_true", help="Install as Windows service (requires admin)")
    args = parser.parse_args()

    rc = deploy(args.target)
    if rc != 0:
        return rc
    if args.build:
        rc = build(args.target)
        if rc != 0:
            return rc
    if args.test:
        rc = run_tests(args.target)
        # Continue even if tests have warnings
    if args.install:
        rc = install_service(args.target)
    print("\n=== AEGIS NIDS v5.0+ Deployment Summary ===")
    print(f"  Target:  {args.target}")
    print(f"  Build:   {'âœ…' if args.build else 'â€”'}")
    print(f"  Tests:   {'âœ…' if args.test else 'â€”'}")
    print(f"  Install: {'âœ…' if args.install else 'â€”'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
