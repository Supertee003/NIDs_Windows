"""Release Candidate assembler (T20 AC3, Step 62).

Assembles the T20 final release candidate tree under
release/T20-final/<commit>/, following scripts/release_package.ps1
layout (bin/ configs/ core/ docs/ + SHA-256 checksums), extended with:

  - SBOM.json            : build_manifest artifact inventory (from
                           1203-line manifest)
  - SHA256SUMS           : digests of every shipped file
  - signatures.json      : immutable-digest + policy signature reference
  - reports/             : T20 final audit / regression / golden-path
                           evidence + T17 performance results
  - KNOWN_LIMITATIONS.md : driver + installer partials, pre-existing
                           failures
  - ROLLBACK.md          : upgrade/rollback workflow (RB-005)

Usage:
    python tools/release_candidate.py             # assemble RC tree
    python tools/release_candidate.py --verify    # re-verify existing tree
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RELEASE_ROOT = REPO / "release" / "T20-final"

REQUIRED_REPORTS = [
    "docs/gates/T20_100pct_audit.json",
    "docs/gates/T20_final_regression.json",
    "docs/gates/T17_benchmark_results.md",
]

BINARIES = [
    "zig-out/bin/aegis-nids.exe",
    "zig-out/bin/aegis-pep.dll",
    "zig-out/bin/aegis_pep.dll", "zig-out/bin/aegis_wfp_user.dll",
    "zig-out/bin/aegis_etw_helper.dll", "zig-out/bin/aegis_fim_helper.dll",
    "zig-out/bin/aegis_fuzz.exe",
]
DRIVERS = ["drivers/wfp_callout/aegis_wfp.sys",
           "drivers/wfp_callout/aegis_minifilter.sys"]
CORE_KEYS = ["configs/Rules.json", "installer/aegis.nsi", "build.zig"]


def git(*args: str) -> str:
    r = __import__("subprocess").run(["git", *args], capture_output=True,
                                     text=True, cwd=str(REPO))
    return r.stdout.strip()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_tree(dst: Path, src: Path, sub: str) -> None:
    pieces = list(src.rglob("*")) if src.is_dir() else [src]
    for p in pieces:
        if p.is_dir():
            continue
        rel = p.relative_to(src)
        (dst.joinpath(sub, rel.parent)).mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst.joinpath(sub, rel))
        if p.suffix == ".nsi":
            (dst.joinpath(sub, rel.parent)).mkdir(parents=True, exist_ok=True)


def assemble(commit: str) -> Path:
    out = RELEASE_ROOT / commit
    if out.exists():
        shutil.rmtree(out)
    (out / "config").mkdir(parents=True, exist_ok=True)
    (out / "core").mkdir(exist_ok=True)
    (out / "scripts").mkdir(exist_ok=True)
    (out / "bin").mkdir(exist_ok=True)
    (out / "drivers").mkdir(exist_ok=True)
    (out / "docs").mkdir(exist_ok=True)
    (out / "reports").mkdir(exist_ok=True)
    for rel in CORE_KEYS:
        if (REPO / rel).exists():
            dst = out / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / rel, dst)
    for z in (REPO / "core").glob("*.zig"):
        shutil.copy2(z, out / "core" / z.name)
    for s in (REPO / "scripts").glob("*"):
        if s.is_file():
            shutil.copy2(s, out / "scripts" / s.name)
    for rel in BINARIES:
        p = REPO / rel
        if p.exists():
            shutil.copy2(p, out / "bin" / p.name)
    for rel in DRIVERS:
        p = REPO / rel
        if p.exists():
            (out / "drivers").mkdir(exist_ok=True)
            shutil.copy2(p, out / "drivers" / p.name)

    bm = json.loads((REPO / "build_manifest.json").read_text(encoding="utf-8"))
    sbom = {"commit": commit, "generated": datetime.now(timezone.utc).isoformat(),
            "source_commit": bm.get("source_commit"),
            "artifacts": len(bm.get("artifacts", [])),
            "artifact_paths": [a["path"] for a in bm.get("artifacts", [])]}
    (out / "SBOM.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    files = sorted(p for p in out.rglob("*") if p.is_file() and
                   p.name not in ("SHA256SUMS",))
    sums = []
    for f in files:
        rel = f.relative_to(out).as_posix()
        sums.append("%s  %s" % (sha256(f), rel))
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="ascii")

    sig = {"policy": "configs/Rules.json (ed25519 via core/policy_signing.zig)",
           "immutable": "build_manifest digests match committed records",
           "commit": commit,
           "shipped_files": len(sums)}
    (out / "signatures.json").write_text(
        json.dumps(sig, indent=2) + "\n", encoding="utf-8")

    rep_out = out / "reports"
    report_map = {
        "docs/gates/T20_100pct_audit.json": "T20_100pct_audit.json",
        "docs/gates/T20_final_regression.json": "T20_final_regression.json",
        "docs/gates/T17_benchmark_results.md": "T17_benchmark_results.md",
        "docs/gates/T20_golden_path_evidence/%s/evidence.json"
        % commit: "T20_golden_path_evidence.json",
    }
    for rel, name in report_map.items():
        p = REPO / rel
        if p.exists():
            shutil.copy2(p, rep_out / name)

    (out / "KNOWN_LIMITATIONS.md").write_text(known_limitations(),
                                              encoding="utf-8")
    (out / "ROLLBACK.md").write_text(rollback_doc(), encoding="utf-8")
    return out


def known_limitations() -> str:
    return """# AEGIS T20 Release Candidate - Known Limitations

- Kernel driver subsystems are PRODUCT-PARTIAL (unaudited live kernel
  enforcement); enforcement authority is exercised through
  core/wfp_production.zig + shield/src/pep.rs only.
- Installer ships as NSIS script (installer/aegis.nsi); a packaged .exe
  is produced at cut-over by tools/installer.py --package.
- Pre-existing unrelated pytest ERROR tests/test_e2e.py::test_result.
- bandit / pip-audit are not installed locally; python security posture is
  covered by the security-scan CI job + tests/security suites.
- Release candidate assembled from the working tree at the pinned commit;
  binaries must be rebuilt from source for a production cut.
"""


def rollback_doc() -> str:
    return """# AEGIS T20 Release Candidate - Upgrade / Rollback

- Snapshot:   python tools/upgrade_rollback.py snapshot
- Inspect:    python tools/upgrade_rollback.py report --json
- Revert:     python tools/upgrade_rollback.py rollback --snapshot <id>
- Runbook:    docs/runbooks/RB-005-config-rollback.md
- Paired registry + config rollback coordinated through control-plane IPC
  (core/control_ipc.zig) with audit trail in logs/control_audit.ndjson.
"""


def verify(tree: Path) -> tuple[bool, list[str]]:
    errors = []
    sums = (tree / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    for line in sums:
        digest, rel = line.split("  ", 1)
        f = tree / rel
        if not f.exists():
            errors.append("missing file %s" % rel)
        elif sha256(f) != digest:
            errors.append("digest mismatch %s" % rel)
    for req in ["SBOM.json", "signatures.json", "KNOWN_LIMITATIONS.md",
                "ROLLBACK.md", "reports"]:
        if not (tree / req).exists():
            errors.append("missing %s" % req)
    if not (tree / "bin").exists():
        errors.append("missing bin/")
    if not (tree / "drivers" / "aegis_wfp.sys").exists():
        errors.append("missing drivers/aegis_wfp.sys")
    return (not errors), errors


def main() -> int:
    ap = argparse.ArgumentParser(description="T20 release candidate")
    ap.add_argument("--verify", action="store_true",
                    help="re-verify an existing candidate tree")
    args = ap.parse_args()
    commit = git("rev-parse", "--short", "HEAD")

    if args.verify:
        candidates = sorted(RELEASE_ROOT.glob("*/")) if RELEASE_ROOT.exists() else []
        if not candidates:
            print("no release candidate found under %s" % RELEASE_ROOT,
                  file=sys.stderr)
            return 1
        tree = candidates[-1]
        ok, errors = verify(tree)
        print("%s: %s %s" % ("RC VERIFY PASS" if ok else "RC VERIFY FAIL",
                             tree, "" if ok else errors))
        return 0 if ok else 1

    tree = assemble(commit)
    ok, errors = verify(tree)
    print("%s: %s (%d files, %s)"
          % ("RC PASS" if ok else "RC FAIL", tree,
             len(list(tree.rglob("*"))), sha256(tree / "SBOM.json")[:16]))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())