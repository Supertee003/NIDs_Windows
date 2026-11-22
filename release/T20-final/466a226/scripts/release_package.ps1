# ============================================================
# AEGIS NIDS - legacy 2.x release packager - DEPRECATED
# ============================================================
# SUPERSEDED: this script produced the legacy 2.x layout (bin\,
# release-manifest.json, src snapshots) whose source files no longer
# exist at the current HEAD. Running it now would silently produce a
# dead-layout bundle with an empty version.
#
# Current pipeline instead:
#   .\scripts\package_release.ps1    # builds the aegis-nids-windows-* bundle + zip
#   .\scripts\verify_release.ps1     # read-only verification of that bundle
#
# Kept as a fail-closed tombstone so no caller can silently produce a
# wrong-layout release. History: git log --follow -- scripts/release_package.ps1
# ============================================================

Write-Host "DEPRECATED: scripts/release_package.ps1 produced the legacy 2.x layout" -ForegroundColor Red
Write-Host "and is superseded by scripts/package_release.ps1 (current bundle format)." -ForegroundColor Red
Write-Host "Verify bundles read-only with scripts/verify_release.ps1." -ForegroundColor Yellow
exit 1
