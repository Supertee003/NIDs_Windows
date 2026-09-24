$ErrorActionPreference = 'Stop'
$root = 'D:\NIDs_Windows'
$files = Get-ChildItem -Path $root -Filter 'aegis_pep.dll' -Recurse -File -ErrorAction SilentlyContinue
foreach ($f in $files) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $ascii = [Text.Encoding]::ASCII.GetString($bytes)
    $symbols = @('aegis_pep_init','aegis_pep_provider_ready','aegis_pep_enforce','aegis_pep_shutdown','aegis_pep_quota_remaining','aegis_pep_unblock_ip')
    [PSCustomObject]@{
        Path = $f.FullName
        Length = $f.Length
        LastWriteTime = $f.LastWriteTime
        SHA256 = $hash
        SymbolsFound = (($symbols | Where-Object { $ascii.Contains($_) }) -join ',')
    }
}
