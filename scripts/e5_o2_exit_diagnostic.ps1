# One controlled O2 service-stability diagnostic. Run elevated.
# Installs the hash-pinned candidate, verifies forensic direction readiness,
# attaches CDB to capture the process-exit path, then always restores the
# hash-pinned base daemon. It sends no test traffic and changes no gate/driver.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo

$runtime = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$candidate = Join-Path $repo 'zig-out\bin\aegis_nids.exe'
$evidenceDir = Join-Path $repo 'admin-evidence\e5-host-proof-20261026'
$backup = Join-Path $evidenceDir 'aegis_nids_pre_o2_direction_464e765b.exe'
$candidateHash = 'E19370F598507FBC9A1194EA8182059B319DFAF76DFF4D3DE34814C57386B407'
$baseHash = '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61'
$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$symPath = Join-Path $repo 'zig-out\bin'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $evidenceDir "e5d-o2-exit-$stamp.log"
$resultPath = Join-Path $evidenceDir "e5d-o2-exit-$stamp.json"
$cdbLog = Join-Path $evidenceDir "e5d-o2-exit-$stamp-cdb.log"
$cdbCommands = Join-Path $evidenceDir "e5d-o2-exit-$stamp-cdb.txt"

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}
function Wait-Service([string]$Name, [string]$Desired, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status.ToString() -eq $Desired) { return $true }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    return $false
}
function Invoke-JsonCommand([string[]]$Command) {
    $raw = & python @Command 2>&1 | Out-String
    $start = $raw.IndexOf('{')
    if ($start -lt 0) { throw "No JSON response from $($Command -join ' '):`n$raw" }
    return ($raw.Substring($start) | ConvertFrom-Json)
}
function Restore-BaseDaemon {
    $service = Get-Service AegisNids -ErrorAction SilentlyContinue
    if ($service -and $service.Status.ToString() -ne 'Stopped') {
        sc.exe stop AegisNids | Out-Host
        if (-not (Wait-Service 'AegisNids' 'Stopped' 45)) { throw 'Candidate service did not stop for rollback.' }
    }
    $current = Get-Sha256 $runtime
    if ($current -ne $baseHash) {
        $staged = "$runtime.exit-probe-rollback"
        Copy-Item -LiteralPath $backup -Destination $staged -Force
        if ((Get-Sha256 $staged) -ne $baseHash) { throw 'Rollback staging hash mismatch.' }
        Move-Item -LiteralPath $staged -Destination $runtime -Force
    }
    if ((Get-Sha256 $runtime) -ne $baseHash) { throw 'Base daemon hash mismatch after rollback.' }
    sc.exe start AegisNids | Out-Host
    if (-not (Wait-Service 'AegisNids' 'Running' 45)) { throw 'Base daemon did not return to RUNNING.' }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this diagnostic from elevated PowerShell.'
}
if (-not (Test-Path -LiteralPath $candidate -PathType Leaf) -or (Get-Sha256 $candidate) -ne $candidateHash) {
    throw 'ReleaseSafe candidate is missing or its pinned hash changed.'
}
if (-not (Test-Path -LiteralPath $backup -PathType Leaf) -or (Get-Sha256 $backup) -ne $baseHash) {
    throw 'Verified base-daemon backup is missing or its hash changed.'
}
if (-not (Test-Path -LiteralPath $cdb -PathType Leaf)) { throw "CDB not found: $cdb" }
if ((Get-Service AegisNids).Status.ToString() -ne 'Running' -or (Get-Service AegisWfp).Status.ToString() -ne 'Running') {
    throw 'Require both AegisNids and AegisWfp RUNNING before the diagnostic.'
}
if ((Get-Sha256 $runtime) -ne $baseHash) { throw 'Installed daemon is not the pinned base; refuse a second runtime swap.' }
$gateBefore = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
if ($gateBefore.prevention_gate -ne 'closed' -or $gateBefore.host_effect_capable) {
    throw 'Refusing diagnostic unless prevention_gate=closed and host_effect_capable=false.'
}

New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
@(
    'bu KERNELBASE!ExitProcess ".echo [O2EXIT] KERNELBASE!ExitProcess; kb 30; q"',
    'bu ntdll!RtlExitUserProcess ".echo [O2EXIT] ntdll!RtlExitUserProcess; kb 30; q"',
    'bu KERNELBASE!TerminateProcess ".echo [O2EXIT] KERNELBASE!TerminateProcess; kb 30; q"',
    'sxe -c ".echo [O2EXIT] ACCESS_VIOLATION; .exr -1; kb 30; q" 0xc0000005',
    'sxe -c ".echo [O2EXIT] ENTRYPOINT_NOT_FOUND; .exr -1; kb 30; q" 0xc0000139',
    'sxe -c ".echo [O2EXIT] FAIL_FAST; .exr -1; kb 30; q" 0xc0000409',
    'sxe -c ".echo [O2EXIT] BREAKPOINT; .exr -1; kb 30; q" 0x80000003',
    'g'
) | Set-Content -LiteralPath $cdbCommands -Encoding ASCII
Start-Transcript -Path $transcript -Force | Out-Null

$debugger = $null
$candidatePid = $null
$candidateStartedAt = $null
$readinessPassed = $false
$windowElapsed = $false
$exitObserved = $false
$exitTraceCaptured = $false
$rollbackOk = $false
$lastProbeError = $null
$errorText = $null
$exitSnapshot = $null
$gateAfter = $null
$forensicAfter = $null
$newServiceEvents = @()
$newLocalDumps = @()
$eventsBefore = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7031 } -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RecordId)

try {
    Write-Host "base=$baseHash candidate=$candidateHash prevention_gate=closed"
    sc.exe stop AegisNids | Out-Host
    if (-not (Wait-Service 'AegisNids' 'Stopped' 45)) { throw 'Base service did not stop.' }
    $staged = "$runtime.exit-probe-candidate"
    Copy-Item -LiteralPath $candidate -Destination $staged -Force
    if ((Get-Sha256 $staged) -ne $candidateHash) { throw 'Candidate staging hash mismatch.' }
    Move-Item -LiteralPath $staged -Destination $runtime -Force
    sc.exe start AegisNids | Out-Host
    if (-not (Wait-Service 'AegisNids' 'Running' 45)) { throw 'Candidate service did not reach RUNNING.' }

    $process = Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'" | Select-Object -First 1
    if (-not $process -or -not $process.ProcessId) { throw 'Candidate process disappeared before debugger attach.' }
    $candidatePid = [uint32]$process.ProcessId
    $candidateStartedAt = (Get-Process -Id $candidatePid).StartTime.ToString('o')
    if ((Get-Sha256 $runtime) -ne $candidateHash) { throw 'Installed candidate hash changed before debugger attach.' }
    Write-Host "candidate pid=$candidatePid started_at=$candidateStartedAt image=$($process.ExecutablePath)"

    $argLine = '-p {0} -y "{1}" -logo "{2}" -cf "{3}"' -f $candidatePid, $symPath, $cdbLog, $cdbCommands
    $debugger = Start-Process -FilePath $cdb -ArgumentList $argLine -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 1
    if ($debugger.HasExited) {
        $cdbText = if (Test-Path -LiteralPath $cdbLog) { Get-Content -LiteralPath $cdbLog -Raw } else { '' }
        $exitTraceCaptured = $cdbText -match '(?m)^\[O2EXIT\]'
        if ($exitTraceCaptured) { $exitObserved = $true }
        throw "CDB attach ended before the stability window; inspect $cdbLog"
    }

    $readinessDeadline = (Get-Date).AddSeconds(30)
    do {
        try {
            $probe = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'list', '--json', '--limit', '1')
            $records = @($probe.records)
            if ($records.Count -gt 0 -and $records[0].PSObject.Properties['direction']) {
                $readinessPassed = $true
                break
            }
            $lastProbeError = 'Control response did not contain a direction-bearing record.'
        } catch { $lastProbeError = $_.Exception.Message }
        if ((Get-Service AegisNids).Status.ToString() -ne 'Running' -or
            -not (Get-Process -Id $candidatePid -ErrorAction SilentlyContinue)) {
            $exitObserved = $true
            $exitSnapshot = sc.exe queryex AegisNids | Out-String
            throw "Candidate exited during forensic readiness: $lastProbeError"
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $readinessDeadline)
    if (-not $readinessPassed) { throw "Direction readiness timed out: $lastProbeError" }
    Write-Host "readiness=PASS pid=$candidatePid"

    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $serviceState = (Get-Service AegisNids).Status.ToString()
        $live = Get-Process -Id $candidatePid -ErrorAction SilentlyContinue
        if ($serviceState -ne 'Running' -or -not $live) {
            $exitObserved = $true
            $exitSnapshot = sc.exe queryex AegisNids | Out-String
            Write-Warning "Candidate exited before stability window; service=$serviceState pid_alive=$([bool]$live)"
            break
        }
        if ($debugger.HasExited) {
            $cdbText = if (Test-Path -LiteralPath $cdbLog) { Get-Content -LiteralPath $cdbLog -Raw } else { '' }
            $exitTraceCaptured = $cdbText -match '(?m)^\[O2EXIT\]'
            if ($exitTraceCaptured) {
                Write-Warning "CDB captured an exit/exception path; debugger log=$cdbLog"
                break
            }
            throw "CDB detached/exited without a captured exit marker; inspect $cdbLog"
        }
        Start-Sleep -Milliseconds 500
    }
    $windowElapsed = -not $exitObserved -and -not $exitTraceCaptured -and (Get-Service AegisNids).Status.ToString() -eq 'Running' -and
        $null -ne (Get-Process -Id $candidatePid -ErrorAction SilentlyContinue)
    if ($windowElapsed) {
        Write-Host 'Candidate remained RUNNING for the 30-second diagnostic window; stopping it now for rollback.'
    }
} catch {
    $errorText = $_.Exception.Message
    Write-Warning "Diagnostic failed: $errorText"
} finally {
    if (Test-Path -LiteralPath $cdbLog) {
        $cdbText = Get-Content -LiteralPath $cdbLog -Raw
        $exitTraceCaptured = $exitTraceCaptured -or ($cdbText -match '(?m)^\[O2EXIT\]')
    }
    if ($candidatePid -and -not (Get-Process -Id $candidatePid -ErrorAction SilentlyContinue)) {
        $exitObserved = $true
        if (-not $exitSnapshot) { $exitSnapshot = sc.exe queryex AegisNids | Out-String }
    }
    try {
        $svc = Get-Service AegisNids -ErrorAction SilentlyContinue
        if ((Get-Sha256 $runtime) -ne $baseHash -or -not $svc -or $svc.Status.ToString() -ne 'Running') {
            Restore-BaseDaemon
        }
        $gateAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
        $forensicAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify')
        $rollbackOk = (Get-Sha256 $runtime) -eq $baseHash -and
            (Get-Service AegisNids).Status.ToString() -eq 'Running' -and
            $gateAfter.prevention_gate -eq 'closed' -and -not $gateAfter.host_effect_capable -and
            $forensicAfter.verified -eq $true
    } catch {
        $errorText = if ($errorText) { "$errorText; rollback: $($_.Exception.Message)" } else { "rollback: $($_.Exception.Message)" }
        Write-Error $errorText
    }
    if ($debugger -and -not $debugger.HasExited) {
        try { Wait-Process -Id $debugger.Id -Timeout 3 -ErrorAction SilentlyContinue } catch { }
        if (-not $debugger.HasExited) { Stop-Process -Id $debugger.Id -Force -ErrorAction SilentlyContinue }
    }
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7031; StartTime = (Get-Date).AddMinutes(-5) } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'AegisNids' -and $_.RecordId -notin $eventsBefore }
        $newServiceEvents = @($events | Sort-Object TimeCreated | ForEach-Object {
            [ordered]@{ time = $_.TimeCreated.ToString('o'); record_id = $_.RecordId; message = $_.Message; xml = $_.ToXml() }
        })
    } catch { }
    try {
        if (Test-Path -LiteralPath (Join-Path $evidenceDir 'wer-localdumps')) {
            $newLocalDumps = @(Get-ChildItem (Join-Path $evidenceDir 'wer-localdumps') -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $candidatePid -and $_.Name -like "aegis_nids.exe.$candidatePid.*" -and $_.LastWriteTime -ge (Get-Date $candidateStartedAt) } |
                Select-Object -ExpandProperty FullName)
        }
    } catch { }
    $result = [ordered]@{
        started_at = $stamp
        candidate_sha256 = $candidateHash
        base_sha256 = $baseHash
        candidate_pid = $candidatePid
        candidate_started_at = $candidateStartedAt
        direction_readiness_passed = $readinessPassed
        exit_observed_in_window = $exitObserved
        exit_trace_captured_by_cdb = $exitTraceCaptured
        service_exit_snapshot = $exitSnapshot
        '30_second_window_elapsed' = $windowElapsed
        service_events_7031 = $newServiceEvents
        local_dumps = $newLocalDumps
        cdb_log = $cdbLog
        cdb_commands = $cdbCommands
        diagnostic_error = $errorText
        rollback_verified = $rollbackOk
        prevention_gate_before = $gateBefore.prevention_gate
        prevention_gate_after = if ($gateAfter) { $gateAfter.prevention_gate } else { $null }
        forensic_verified_after = if ($forensicAfter) { $forensicAfter.verified } else { $false }
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Host "RESULT readiness=$readinessPassed exit_observed=$exitObserved stable_30s=$windowElapsed rollback=$rollbackOk cdb=$cdbLog json=$resultPath"
    Stop-Transcript | Out-Null
}

if (-not $rollbackOk) { exit 1 }
