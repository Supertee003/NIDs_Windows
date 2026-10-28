# Inspect the real parent + command line of any aegis-nose.exe process so we
# know whether the daemon, a script, or a scheduler owns Nose's lifecycle.
# Read-only; no state changes.
$ErrorActionPreference = 'Continue'
$nose = Get-CimInstance Win32_Process -Filter "Name='aegis-nose.exe'"
if (-not $nose) {
    Write-Host 'NO aegis-nose.exe process on this host.'
} else {
    foreach ($n in $nose) {
        Write-Host ('nose pid={0} ppid={1}' -f $n.ProcessId, $n.ParentProcessId)
        Write-Host ('  CommandLine: {0}' -f $n.CommandLine)
        Write-Host ('  ExecutablePath: {0}' -f $n.ExecutablePath)
        Write-Host ('  CreationDate: {0}' -f $n.CreationDate)
        $p = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $n.ParentProcessId) -ErrorAction SilentlyContinue
        if ($p) {
            Write-Host ('  parent: pid={0} name={1}' -f $p.ProcessId, $p.Name)
            Write-Host ('  parent cmdline: {0}' -f $p.CommandLine)
            $gp = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $p.ParentProcessId) -ErrorAction SilentlyContinue
            if ($gp) {
                Write-Host ('  grandparent: pid={0} name={1} cmdline={2}' -f $gp.ProcessId, $gp.Name, $gp.CommandLine)
            } else {
                Write-Host '  grandparent: not running (exited)'
            }
        } else {
            Write-Host '  parent: not running (exited) — orphaned'
        }
    }
}
# Also check the daemon process chain for cross-reference.
$dam = Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'"
foreach ($d in $dam) {
    Write-Host ('daemon pid={0} ppid={1} started={2}' -f $d.ProcessId, $d.ParentProcessId, $d.CreationDate)
    Write-Host ('  cmdline: {0}' -f $d.CommandLine)
}
