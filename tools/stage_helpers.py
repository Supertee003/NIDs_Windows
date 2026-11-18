#!/usr/bin/env python3
"""Stage the CMake-built native helper DLLs into ``zig-out/bin``.

Why this exists (#30, PATCH-FIM-STOP-001)
-----------------------------------------
The native helpers are built by CMake into ``build/Release``, but every
packager reads them from ``zig-out/bin``:

    installer/aegis.nsi:69      File "zig-out\\bin\\aegis_fim_helper.dll"
    tools/installer.py:244      File "zig-out\\bin\\aegis_fim_helper.dll"
    tools/release_candidate.py  zig-out/bin/aegis_etw_helper.dll
    tools/golden_path_evidence.py ``zig-out/bin/aegis_fim_helper.dll``

Nothing copied one to the other, so ``zig-out/bin`` still held 2026-10-16
builds while the 2026-11-01 shutdown fix sat in ``build/Release``. Every
bundle from 10/16 to 11/10 shipped the pre-fix FIM helper, which is why the
service kept dying with exception ``0x80000003`` at
``aegis_fim_helper!aegis_fim_stop`` even after the fix was committed.

The same shape appears twice more in this tree (WFP driver in ``System32`` vs
``build/x64/wfp``, and ``installer/aegis.nsi`` vs ``tools/installer.py``
choosing different driver files), so the rule this tool enforces is general:

    a packaging input may never be older than the source it is built from.

Usage:
    python tools/stage_helpers.py --stage   # build -> zig-out/bin (fails when stale)
    python tools/stage_helpers.py --check   # packaging gate, no writes
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# dll -> the C sources it is built from (CMakeLists.txt: aegis_wfp_user,
# aegis_etw_helper, aegis_fim_helper).
HELPERS: dict[str, tuple[str, ...]] = {
    "aegis_wfp_user.dll": ("src/windows/aegis_wfp.c", "src/windows/wfp_ioctl.c"),
    "aegis_etw_helper.dll": ("src/windows/etw_native.c",),
    "aegis_fim_helper.dll": ("src/windows/fim_native.c",),
}
# Packaging must ship the Release build. A Debug helper sitting in the same
# tree is a developer artifact and is never a legal substitute: silently
# staging it would trade a stale binary for a different-class binary.
BUILD_DIRS = ("build/Release",)
STAGE_DIR = "zig-out/bin"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def newest_build(root: Path, dll: str) -> Path | None:
    """Return the most recently built copy of *dll* under the CMake build tree."""
    candidates = [root / d / dll for d in BUILD_DIRS]
    present = [p for p in candidates if p.is_file()]
    if not present:
        return None
    return max(present, key=lambda p: p.stat().st_mtime_ns)


def check_one(root: Path, dll: str) -> list[str]:
    """Return a list of problems for one helper (empty == good)."""
    problems: list[str] = []
    built = newest_build(root, dll)
    staged = root / STAGE_DIR / dll
    sources = [root / s for s in HELPERS[dll]]

    missing_src = [str(s.relative_to(root)) for s in sources if not s.is_file()]
    if missing_src:
        return [f"{dll}: source missing: {', '.join(missing_src)}"]

    if built is None:
        problems.append(f"{dll}: not built (run: cmake -B build && cmake --build build --config Release)")
        return problems

    src_newest = max(s.stat().st_mtime_ns for s in sources)
    if built.stat().st_mtime_ns < src_newest:
        problems.append(
            f"{dll}: build output {built.relative_to(root)} is older than its source "
            f"(rebuild: cmake --build build --config Release)"
        )

    if not staged.is_file():
        problems.append(f"{dll}: not staged at {STAGE_DIR}/{dll}")
        return problems

    if staged.stat().st_mtime_ns < src_newest:
        problems.append(
            f"{dll}: staged copy {STAGE_DIR}/{dll} predates its source "
            f"(stage it: python tools/stage_helpers.py --stage)"
        )
    elif sha256(staged) != sha256(built):
        problems.append(
            f"{dll}: staged copy differs from {built.relative_to(root)} "
            f"(built {sha256(built)[:12]}, staged {sha256(staged)[:12]})"
        )
    return problems


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for dll in HELPERS:
        problems.extend(check_one(root, dll))
    return problems


def stage(root: Path) -> int:
    problems: list[str] = []
    for dll in HELPERS:
        built = newest_build(root, dll)
        sources = [root / s for s in HELPERS[dll]]
        if built is None or not all(s.is_file() for s in sources):
            problems.append(f"{dll}: not built or source missing")
            continue
        src_newest = max(s.stat().st_mtime_ns for s in sources)
        if built.stat().st_mtime_ns < src_newest:
            problems.append(
                f"{dll}: refusing to stage a stale build "
                f"({built.relative_to(root)} older than its .c source)"
            )
            continue
        dest = root / STAGE_DIR / dll
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, dest)
        print(f"STAGED {dll} {sha256(dest)[:12]} <- {built.relative_to(root)}")

    if problems:
        for p in problems:
            print(f"FAIL {p}", file=sys.stderr)
        print(
            "FAIL - native helpers were not staged; rebuild the C helpers first:\n"
            "       cmake -B build && cmake --build build --config Release",
            file=sys.stderr,
        )
        return 1
    print(f"OK - {len(HELPERS)} native helpers staged into {STAGE_DIR}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--stage", action="store_true", help="copy build outputs into zig-out/bin")
    g.add_argument("--check", action="store_true", help="verify staged helpers match their build and source")
    args = ap.parse_args(argv)

    if args.stage:
        return stage(ROOT)

    problems = check(ROOT)
    if problems:
        for p in problems:
            print(f"FAIL {p}")
        print("FAIL - packaging input is stale; run: python tools/stage_helpers.py --stage")
        return 1
    for dll in HELPERS:
        print(f"OK {dll} {sha256(ROOT / STAGE_DIR / dll)[:12]} ({STAGE_DIR}/{dll})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
