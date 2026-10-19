"""RELEASE-TOOLING (2026-10-19): bundle pipeline truth pins.

The deep scan (admin-evidence/deep-scan-20261019 @ dba2d75) found the
release pipeline diverged from reality:

  * scripts/verify_release.ps1 verified a dead 2.x layout
    (aegis-nids-v*.zip, bin\\aegis_nids.exe, release-manifest.json,
    src\\release_info.zig) that no longer exists -> dead pipeline;
  * scripts/release_package.ps1 duplicated the packager with no
    deprecation marker (its sources are gone at HEAD);
  * scripts/install_aegis.ps1 (bundle path) registered no core service
    and had no uninstall (NSIS-path parity: tools/installer.py);
  * tools/release_candidate.py still copied dead REPO/core/*.zig and
    cited core/policy_signing.zig (pre-slice-2 tree).

Pins below freeze the corrected contract: the verifier targets the
current aegis-nids-windows-* bundle format and is read-only; the
deprecated packager fails closed; the bundle installer reaches
service/uninstall/signature parity; the RC assembler carries no core/-
era paths. One functional check runs the verifier against a synthetic
bundle (pass / tamper / missing-file / read-only) so the hash gate is
executed, not just scanned.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

VERIFY = REPO / "scripts" / "verify_release.ps1"
INSTALL = REPO / "scripts" / "install_aegis.ps1"
LEGACY_PACKAGER = REPO / "scripts" / "release_package.ps1"
PACKAGER = REPO / "scripts" / "package_release.ps1"
RC_ASSEMBLER = REPO / "tools" / "release_candidate.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------
# verify_release.ps1: current bundle format, read-only
# ---------------------------------------------------------------------


def test_verify_release_targets_current_bundle_format():
    text = _read(VERIFY)
    # Legacy 2.x markers must be gone (the dead pipeline).
    for legacy in ("aegis-nids-v", "release-manifest.json",
                   "release_info.zig", "nids_main.zig"):
        assert legacy not in text, (
            f"verify_release.ps1 still targets the dead 2.x layout: {legacy}"
        )
    # Current bundle discovery + manifest contract.
    assert "aegis-nids-windows-*" in text
    assert "manifest.json" in text
    assert "Get-FileHash" in text
    assert "$artifact.sha256" in text, "artifacts must be hash-verified"
    assert "$artifact.length" in text, "artifacts must be length-verified"


def test_verify_release_is_read_only_and_fails_closed():
    text = _read(VERIFY)
    # Read-only: the verifier must never extract, create, or delete.
    for mutator in ("Expand-Archive", "Compress-Archive", "New-Item",
                    "Remove-Item", "Set-Location"):
        assert mutator not in text, (
            f"verify_release.ps1 must stay read-only; found {mutator}"
        )
    assert "VERIFICATION PASSED" in text
    assert "VERIFICATION FAILED" in text
    assert "exit 1" in text


def test_verify_release_required_set_matches_bundle_layout():
    text = _read(VERIFY)
    for rel in ("runtime/aegis_nids.exe", "runtime/aegis_pep.dll",
                "configs/Rules.json", "configs/policies.json",
                "drivers/aegis_wfp.sys", "scripts/install_aegis.ps1",
                "README.txt"):
        assert rel in text, f"verify_release.ps1 required set lacks {rel}"


# ---------------------------------------------------------------------
# release_package.ps1: fail-closed deprecation tombstone
# ---------------------------------------------------------------------


def test_release_package_is_a_fail_closed_deprecation_stub():
    text = _read(LEGACY_PACKAGER)
    assert "DEPRECATED" in text
    assert "package_release.ps1" in text, "stub must point at the live packager"
    assert "verify_release.ps1" in text
    assert "exit 1" in text, "a deprecated pipeline must fail closed"
    for dead in ("release_info.zig", "aegis-nids-v", "Compress-Archive"):
        assert dead not in text, (
            f"release_package.ps1 still carries dead 2.x logic: {dead}"
        )


# ---------------------------------------------------------------------
# install_aegis.ps1: service + uninstall + signature parity
# ---------------------------------------------------------------------


def test_install_aegis_registers_and_starts_core_service():
    text = _read(INSTALL)
    assert "#Requires -RunAsAdministrator" in text, (
        "install / rollback / uninstall all mutate Program Files + SCM: "
        "elevation must be enforced, not assumed"
    )
    assert "'runtime\\aegis_nids.exe'" in text, (
        "service binary must be the canonical runtime\\aegis_nids.exe"
    )
    create = text.index(
        "sc.exe create AegisNids binPath= $svcBin start= auto")
    assert "sc.exe description AegisNids" in text
    assert ("sc.exe failure AegisNids reset= 86400 "
            "actions= restart/5000/restart/15000/restart/60000") in text, (
        "restart-on-failure recovery must match the NSIS installer / DEPLOYMENT.md"
    )
    assert "sc.exe query AegisNids" in text, (
        "service registration must be idempotent (query before create)"
    )
    start = text.index("sc.exe start AegisNids")
    assert create < start, "service must be created before it is started"


def test_install_aegis_uninstall_removes_service_but_preserves_configs():
    text = _read(INSTALL)
    assert "[switch]$Uninstall" in text
    assert "sc.exe delete AegisNids" in text
    assert "sc.exe qc AegisWfp" in text, (
        "driver service may only be removed when it belongs to this "
        "install root (an external/System32-managed AegisWfp survives)"
    )
    assert "foreach ($sub in 'runtime', 'drivers', 'scripts')" in text
    assert "Configs preserved: $InstallRoot\\configs" in text
    assert "Join-Path $InstallRoot 'configs'" not in text, (
        "uninstall must never remove operator configs"
    )
    assert "[switch]$Rollback" in text, "rollback must survive the rewrite"


def test_install_aegis_verifies_authenticode_status():
    text = _read(INSTALL)
    assert "Get-AuthenticodeSignature" in text
    assert "'NotSigned'" in text, "unsigned builds are the current reality: warn"
    assert "'NotTrusted'" in text, "lab/test certificates: warn, not fail"
    assert "HashMismatch" in text, "a broken signature must fail closed"
    assert "Authenticode invalid" in text
    assert "manifest.artifacts" in text, "hash gate must survive the rewrite"
    assert "Get-FileHash" in text
    # -BundleRoot is optional now so -Uninstall can run standalone.
    assert 'required for install' in text


# ---------------------------------------------------------------------
# package_release.ps1: canonical driver source + shipped verifier
# ---------------------------------------------------------------------


def test_package_release_uses_canonical_driver_and_ships_verifier():
    text = _read(PACKAGER)
    assert "build\\x64\\wfp\\aegis_wfp.sys" in text, (
        "the bundle must stage the canonical WDK output (DEPLOY-120), "
        "not the pre-EVT-231 in-tree copy"
    )
    assert "wfp_callout" not in text, (
        "drivers\\wfp_callout\\aegis_wfp.sys is a pre-EVT-231 artifact"
    )
    assert "verify_release.ps1" in text, (
        "the bundle must ship its own read-only verifier"
    )


# ---------------------------------------------------------------------
# tools/release_candidate.py: no core/-era paths
# ---------------------------------------------------------------------


def test_release_candidate_drops_core_era_paths():
    text = _read(RC_ASSEMBLER)
    for dead in ('REPO / "core"', '(out / "core")',
                 "core/policy_signing.zig"):
        assert dead not in text, (
            f"release_candidate.py still carries the dead core/ tree: {dead}"
        )
    assert "src/policy/policy_signing.zig" in text, (
        "the signature citation must point at the live policy authority"
    )


# ---------------------------------------------------------------------
# Functional: verify_release.ps1 against a synthetic bundle
# ---------------------------------------------------------------------


def _make_bundle(root: Path) -> None:
    files = {
        "runtime/aegis_nids.exe": b"MZ synthetic core",
        "runtime/aegis_pep.dll": b"synthetic pep",
        "configs/Rules.json": b"{}",
        "configs/policies.json": b"{}",
        "drivers/aegis_wfp.sys": b"synthetic driver",
        "scripts/install_aegis.ps1": b"# synthetic installer",
        "README.txt": b"synthetic readme",
    }
    artifacts = []
    for rel, blob in files.items():
        p = root / Path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)
        artifacts.append({
            "path": rel,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "length": len(blob),
        })
    manifest = {
        "product": "AEGIS NIDS",
        "version": "6.0.0",
        "platform": "windows-x86_64",
        "created_utc": "2026-10-19T00:00:00.0000000Z",
        "canonical_rules": "configs/Rules.json",
        "artifacts": artifacts,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2),
                                        encoding="utf-8")


def _run_verify(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-File", str(VERIFY),
         "-BundleRoot", str(bundle)],
        capture_output=True, text=True, timeout=180,
    )


def _tree_digest(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*") if p.is_file()
    }


def test_verify_release_functional_pass_tamper_missing(tmp_path):
    bundle = tmp_path / "aegis-nids-windows-6.0.0-synthetic"
    bundle.mkdir()
    _make_bundle(bundle)
    before = _tree_digest(bundle)

    ok = _run_verify(bundle)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "VERIFICATION PASSED" in ok.stdout
    assert _tree_digest(bundle) == before, "verifier must not touch the bundle"

    # Tampered artifact -> hash gate fails closed.
    (bundle / "configs" / "Rules.json").write_bytes(b'{"tampered": true}')
    bad = _run_verify(bundle)
    assert bad.returncode != 0, bad.stdout
    assert "VERIFICATION FAILED" in bad.stdout
    assert "SHA256 mismatch" in bad.stdout

    # Restore, then a missing required file -> required-set gate fails.
    (bundle / "configs" / "Rules.json").write_bytes(b"{}")
    (bundle / "scripts" / "install_aegis.ps1").unlink()
    missing = _run_verify(bundle)
    assert missing.returncode != 0, missing.stdout
    assert "missing required file" in missing.stdout


# ---------------------------------------------------------------------
# The changed scripts must parse under the Windows PowerShell parser
# ---------------------------------------------------------------------


def test_changed_scripts_parse_clean():
    for script in (VERIFY, INSTALL, LEGACY_PACKAGER, PACKAGER):
        ps = (
            "$t=$null; $e=$null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{script}', [ref]$t, [ref]$e) | Out-Null; "
            "if ($e.Count -gt 0) { $e | ForEach-Object { Write-Output $_.Message }; exit 1 } "
            "else { Write-Output 'PS_PARSE_OK' }"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"{script.name}: {proc.stdout}{proc.stderr}"
        assert "PS_PARSE_OK" in proc.stdout, script.name
