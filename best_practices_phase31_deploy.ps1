# ============================================================
# AEGIS NIDS - Phase 31 Deploy Script (Blueprint Status)
# ============================================================
$ErrorActionPreference = 'Stop'
$DeployRoot = $PSScriptRoot
if (-not $DeployRoot) { $DeployRoot = (Get-Location).Path }
Write-Host "[DEPLOY] AEGIS Phase 31 - Blueprint Status Documentation"
Write-Host "[DEPLOY] Deploy root: $DeployRoot"

function Deploy-File {
    param([string]$RelativePath, [string]$Base64Content, [int]$ExpectedLines)
    $FullPath = Join-Path $DeployRoot $RelativePath
    $Dir = Split-Path $FullPath -Parent
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    $BackupPath = "$FullPath.phase31_backup"
    if (Test-Path $FullPath) {
        Copy-Item -Path $FullPath -Destination $BackupPath -Force
        Write-Host "  [OK] Backup created"
    }
    $Bytes = [System.Convert]::FromBase64String($Base64Content)
    [System.IO.File]::WriteAllBytes($FullPath, $Bytes)
    $ActualLines = (Get-Content $FullPath).Count
    if ($ActualLines -ne $ExpectedLines) {
        Write-Host "  [WARN] Line count: actual=$ActualLines expected=$ExpectedLines"
    } else {
        Write-Host "  [OK] Deployed: $ActualLines lines (expected $ExpectedLines)"
    }
}

$B64_1 = 'IyBBRUdJUyBCbHVlcHJpbnQgU3RhdHVzIChQaGFzZSAzMSkKCiMjIFNwcmludCAxIENvbXBsZXRpb24gU3RhdHVzOiAxMDAlIENPTVBMRVRFCgpBbGwgOCBCbHVlcHJpbnQgdGFza3MgZnJvbSB0aGUgRmlyc3QgSW1wbGVtZW50YXRpb24gU3ByaW50IGFyZSBjb21wbGV0ZSBhbmQgaW50ZWdyYXRlZC4KCiMjIEFFR0lTLTAwMSB0aHJvdWdoIEFFR0lTLTAwOCBTdGF0dXMKCnwgSUQgfCBUYXNrIHwgRmlsZSB8IFN0YXR1cyB8IFBoYXNlIHwgVGVzdHMgfAp8LS0tLXwtLS0tLS18LS0tLS0tfC0tLS0tLS0tfC0tLS0tLS18LS0tLS0tLXwKfCBBRUdJUy0wMDEgfCBBcmNoaXRlY3R1cmUgQm91bmRhcnkgfCBgZG9jcy9BUkNISVRFQ1RVUkVfQk9VTkRBUlkubWRgIHwg4pyFIENvbXBsZXRlIHwgMjMgfCBOL0EgfAp8IEFFR0lTLTAwMiB8IENhbm9uaWNhbCBFdmVudCB2MSB8IGBjb3JlL2Nhbm9uaWNhbF9ldmVudC56aWdgIHwg4pyFIENvbXBsZXRlIHwgMjMgfCAxMSB8CnwgQUVHSVMtMDAzIHwgV2lyZSBFdmVudCB2MSB8IGBjb3JlL3dpcmVfZXZlbnQuemlnYCB8IOKchSBDb21wbGV0ZSB8IDI0IHwgOSB8CnwgQUVHSVMtMDA0IHwgUmluZyBCdWZmZXIgc3RhYmlsaXR5IHwgYGNvcmUvZXZlbnRfcXVldWUuemlnYCB8IOKchSBDb21wbGV0ZSB8IDI0IHwgOCB8CnwgQUVHSVMtMDA1IHwgUHJpb3JpdHkgRXZlbnQgUXVldWUgfCBgY29yZS9wcmlvcml0eV9xdWV1ZS56aWdgIHwg4pyFIENvbXBsZXRlIHwgMjUgfCAxMCB8CnwgQUVHSVMtMDA2IHwgTm9zZSDihpIgRXZlbnQgRmFicmljIHwgYGNvcmUvbm9zZV9jb250cmFjdC56aWdgIHwg4pyFIENvbXBsZXRlIHwgMjUgfCAxMCB8CnwgQUVHSVMtMDA3IHwgRGV0ZWN0aW9uIEludGVyZmFjZSB8IGBjb3JlL2RldGVjdGlvbl9pbnRlcmZhY2UuemlnYCB8IOKchSBDb21wbGV0ZSB8IDI2IHwgMTAgfAp8IEFFR0lTLTAwOCB8IFBvbGljeS9QRVAgQ29udHJhY3QgfCBgY29yZS9wb2xpY3lfY29udHJhY3QuemlnYCB8IOKchSBDb21wbGV0ZSB8IDI2IHwgMTIgfAoKIyMgSW50ZWdyYXRpb24gU3RhdHVzCgp8IFBoYXNlIHwgV2hhdCB3YXMgaW50ZWdyYXRlZCB8IFN0YXR1cyB8CnwtLS0tLS0tfC0tLS0tLS0tLS0tLS0tLS0tLS0tLXwtLS0tLS0tLXwKfCAyNyB8IERldGVjdGlvbiArIFBvbGljeSArIFBFUCB3aXJlZCBpbnRvIGBpbnNwZWN0X3BhY2tldCgpYCB8IOKchSB8CnwgMjggfCBOb3NlIENvbnRyYWN0IHdpcmVkIGludG8gc2Vuc29ycyArIEV2ZW50IEZhYnJpYyBkcmFpbiB0aHJlYWQgfCDinIUgfAp8IDI5IHwgUnVzdCBTaGllbGQgcmVnaXN0ZXJlZCBhcyBUaWVyLTMgZGV0ZWN0b3IgKyBCbHVlcHJpbnQgZnVsbCBpbml0IHwg4pyFIHwKfCAzMCB8IEUyRSB0ZXN0cyB2ZXJpZnkgY29tcGxldGUgR29sZGVuIFBhdGggfCDinIUgfAoKIyMgR29sZGVuIFBhdGggKFZlcmlmaWVkIGJ5IEUyRSBUZXN0cykKCmBgYApTZW5zb3IgKFBpcGUvV0ZQL01pbmlmaWx0ZXIpCiAgICDihpMKbm9zZS5jcmVhdGVFdmVudCgpIOKGkiBub3NlLnN1Ym1pdEV2ZW50KCkgW0FFR0lTLTAwNl0KICAgIOKGkwpQcmlvcml0eVF1ZXVlIChISUdIID4gTk9STUFMID4gTE9XKSBbQUVHSVMtMDA1XQogICAg4oaTCmV2ZW50RmFicmljRHJhaW4oKSDihpIgbm9zZS5wb3BFdmVudCgpCiAgICDihpMKRGV0ZWN0aW9uTWFuYWdlci5kZXRlY3QoKSBbQUVHSVMtMDA3XQogICAg4pSc4pSA4pSAIFRpZXItMTogQUMgRW5naW5lIChaaWcsIGV4aXN0aW5nKQogICAg4pSc4pSA4pSAIFRpZXItMjogUmVnZXggKFB5dGhvbi9DeXRob24sIGV4aXN0aW5nKQogICAg4pSU4pSA4pSAIFRpZXItMzogUnVzdCBTaGllbGQgKGJlaGF2aW9yYWwpIFtQaGFzZSAyOV0KICAgIOKGkwpQb2xpY3lFbmdpbmUuZXZhbHVhdGUoKSBbQUVHSVMtMDA4XQogICAg4pSU4pSA4pSAIERFRkNPTi0xIGVzY2FsYXRpb24gdG8gQkxPQ0sKICAgIOKGkwpQRVAuZW5mb3JjZSgpIFtBRUdJUy0wMDhdCiAgICDihpMKRm9yZW5zaWNMb2c6IEZBQlJJQ19FVkVOVCArIFBPTElDWV9ERUNJU0lPTgpgYGAKCiMjIFRlc3QgQ292ZXJhZ2UKCnwgTW9kdWxlIHwgVGVzdHMgfAp8LS0tLS0tLS18LS0tLS0tLXwKfCBuaWRzX2FuYWx5emUuemlnIHwgMTcgfAp8IHdmcF9pb2N0bC56aWcgfCAxMyB8CnwgcGlwZV9tb25pdG9yLnppZyB8IDggfAp8IG1pbmlmaWx0ZXJfcmVhZGVyLnppZyB8IDIgfAp8IHdpbjMyX2lvLnppZyB8IDMgfAp8IGZvcmVuc2ljX2xvZy56aWcgfCAxMSB8CnwgY2Fub25pY2FsX2V2ZW50LnppZyB8IDExIHwKfCB3aXJlX2V2ZW50LnppZyB8IDkgfAp8IGV2ZW50X3F1ZXVlLnppZyB8IDggfAp8IHByaW9yaXR5X3F1ZXVlLnppZyB8IDEwIHwKfCBub3NlX2NvbnRyYWN0LnppZyB8IDEwIHwKfCBkZXRlY3Rpb25faW50ZXJmYWNlLnppZyB8IDEwIHwKfCBwb2xpY3lfY29udHJhY3QuemlnIHwgMTIgfAp8IGdvbGRlbl9wYXRoX3Rlc3QuemlnIChFMkUpIHwgNiB8CnwgKipUb3RhbCBaaWcgdGVzdHMqKiB8ICoqMTMwKiogfAoKQWRkaXRpb25hbCB0ZXN0czoKLSBHbyBhZ2dyZWdhdG9yOiAxNiB0ZXN0cyAoYWxlcnRfdGVzdC5nbyArIGNvcnJlbGF0b3JfdGVzdC5nbykKLSBQeXRob24gQ3l0aG9uOiAyNiB0ZXN0cyAodGVzdF9mYXN0X3NjYW4ucHkpCgojIyA1IFN5c3RlbSBDb250cmFjdHMgKGZyb20gQmx1ZXByaW50KQoKfCBDb250cmFjdCB8IFN0YXR1cyB8IEZpbGUgfAp8LS0tLS0tLS0tLXwtLS0tLS0tLXwtLS0tLS18CnwgMS4gQ2Fub25pY2FsIEV2ZW50IENvbnRyYWN0IHwg4pyFIHYxIHwgYGNhbm9uaWNhbF9ldmVudC56aWdgIHwKfCAyLiBJUEMgLyBXaXJlIENvbnRyYWN0IHwg4pyFIHYxIHwgYHdpcmVfZXZlbnQuemlnYCB8CnwgMy4gRGV0ZWN0aW9uIENvbnRyYWN0IHwg4pyFIHYxIHwgYGRldGVjdGlvbl9pbnRlcmZhY2UuemlnYCB8CnwgNC4gUG9saWN5IENvbnRyYWN0IHwg4pyFIHYxIHwgYHBvbGljeV9jb250cmFjdC56aWdgIHwKfCA1LiBFbmZvcmNlbWVudCBDb250cmFjdCB8IOKchSB2MSB8IGBwb2xpY3lfY29udHJhY3QuemlnYCAoUEVQKSB8CgojIyBOZXh0IFN0ZXBzIChTcHJpbnQgMiBjYW5kaWRhdGVzKQoKUGVyIEJsdWVwcmludCByZWNvbW1lbmRhdGlvbnMsIFNwcmludCAyIHNob3VsZCBjb25zaWRlcjoKMS4gKipISURTIHNlbnNvcnMqKiDigJQgSG9zdC1iYXNlZCBkZXRlY3Rpb24gKHByb2Nlc3MsIHJlZ2lzdHJ5LCBmaWxlIGludGVncml0eSkKMi4gKipJUFMgbW9kZSoqIOKAlCBJbmxpbmUgYmxvY2tpbmcgKGN1cnJlbnRseSBkZXRlY3Rpb24tb25seSkKMy4gKipSQUcgaW50ZWdyYXRpb24qKiDigJQgUmV0cmlldmFsLUF1Z21lbnRlZCBHZW5lcmF0aW9uIGZvciB0aHJlYXQgaW50ZWxsaWdlbmNlCjQuICoqWERSIGNvcnJlbGF0aW9uKiog4oCUIENyb3NzLXRpZXIgZXZlbnQgY29ycmVsYXRpb24gYXQgc2NhbGUKNS4gKipUeXBlU2NyaXB0IHBvbGljeSBwbGFuZSoqIOKAlCBQb2xpY3kgSVIgY29tcGlsZXIKCioqTm90ZSBmcm9tIEJsdWVwcmludDoqKiAi4Lii4Lix4LiH4LmE4Lih4LmI4LmA4Lie4Li04LmI4LihIExMTSwg4Lii4Lix4LiH4LmE4Lih4LmI4LmA4Lie4Li04LmI4LihIFN3aWZ0IOC5geC4peC4sOC4ouC4seC4h+C5hOC4oeC5iOC5gOC4m+C4tOC4lCBFbmZvcmNlbWVudCBwcm9kdWN0aW9uIgrigJQgU3ByaW50IDEgY29tcGxldGUsIHByb2R1Y3Rpb24gZW5mb3JjZW1lbnQgTk9UIHlldCBlbmFibGVkIChieSBkZXNpZ24pCgojIyBLZXkgTWV0cmljcwoKLSAqKkJsdWVwcmludCBtb2R1bGVzKio6IDggZmlsZXMsIH4xLDgwMCBsaW5lcyBaaWcKLSAqKkludGVncmF0aW9uIHBvaW50cyoqOiA0IChpbnNwZWN0X3BhY2tldCwgMiBzZW5zb3JzLCBuaWRzX21haW4pCi0gKipUb3RhbCBaaWcgY29kZWJhc2UqKjogfjcsMDAwIGxpbmVzIChmcm9tIH40LDkwMCBhdCBTcHJpbnQgMSBzdGFydCkKLSAqKlRvdGFsIHRlc3RzKio6IDEzMCBaaWcgKyAxNiBHbyArIDI2IFB5dGhvbiA9IDE3MiB0ZXN0cwo='
Deploy-File -RelativePath "docs/BLUEPRINT_STATUS.md" -ExpectedLines 104 -Base64Content $B64_1


Write-Host ""
Write-Host "[INFO] Phase 31 deploys documentation only (no build changes)"
Write-Host ""
Write-Host "Summary of changes:"
Write-Host "  Phase 31 changes (Blueprint Status Documentation):"
Write-Host "    DOC: docs/BLUEPRINT_STATUS.md (104 lines)"
Write-Host "         - Sprint 1 completion: 8/8 AEGIS tasks complete"
Write-Host "         - Integration status (Phases 27-30)"
Write-Host "         - Golden Path diagram (verified by E2E tests)"
Write-Host "         - Test coverage: 130 Zig + 16 Go + 26 Python = 172 tests"
Write-Host "         - 5 System Contracts status (all v1)"
Write-Host "         - Sprint 2 candidates (HIDS, IPS, RAG, XDR, TypeScript)"
Write-Host "    Effect: Blueprint Sprint 1 formally documented as complete"

Write-Host ""
Write-Host "Suggested git commands:"
Write-Host "  git add -A"
Write-Host "  git commit -m `"docs: phase 31 - blueprint sprint 1 status document`""
Write-Host "  git push"
