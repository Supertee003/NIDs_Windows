AEGIS NIDS Production Bundle
Version: 6.0.0
Platform: Windows x86_64

Install (elevated PowerShell):
  powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot .

Verify:
  Get-Content .\manifest.json | ConvertFrom-Json

Rollback:
  powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot . -Rollback
