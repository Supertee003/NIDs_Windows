# AEGIS Recovery Handoff — Return the System to Normal

**Project:** AEGIS Windows-native NIDS/IPS  
**Date:** 2026-09-27  
**Audience:** Project owner, next Manus agent, Windows administrator, validation engineer  
**Purpose:** Restore one clean runtime owner, connect the canonical Go Nose sensor, prove live packet ingress, and leave the system in a reproducible healthy state.

---

## 1. Current truth

The system is not yet fully normal. The backend owner is running and the Administrator capability gate is healthy, but the data plane has not yet received a real packet in the latest evidence.

| Area | Current result | Meaning |
|---|---|---|
| Zig core | `RUNNING` | Runtime owner and control pipe are serving |
| Rust PEP | `READY` | Sole enforcement authority is available |
| WFP provider | `READY` | Provider and host-effect capability are available |
| Driver service | `RUNNING` | `AegisWfp` is installed and loaded |
| Core Nose reader | Ready | `\\.\pipe\aegis_nose` exists |
| Go Nose process | Running | Fresh `dist\\nose_dashboard.exe` was started |
| Nose pipe connection | `true` | Go Nose connected to the core pipe |
| Nose frames read | `0` | No canonical frame has reached the reader yet |
| Nose frames submitted | `0` | No event has entered the canonical fabric from live Nose |
| Packets captured | `0` | No packet was observed on the selected adapter |
| Blocks | `0` | No host-effect proof has been attempted |
| Automated regression | `267 passed` | Security/runtime contracts are passing |
| Go Nose build | Passing | Current source builds after fixing `model.go` |

The most important distinction is:

> `nose_connected=true` proves the producer/pipe relationship is up. It does not prove that a packet was captured, serialized, read, submitted, detected, or enforced.

The latest Nose log is:

```text
[NOSE RULES] loaded=22 path=configs/Rules.json
[NOSE CAPTURE] listening on \\Device\\NPF_{56055AA2-3423-483D-A7F9-278770579E3D} -> \\.\pipe\aegis_nose
[NOSE PIPE] connected to \\.\pipe\aegis_nose
```

The selected interface is VMware VMnet1, host address `192.168.126.1`, with the Npcap device:

```text
\\Device\\NPF_{56055AA2-3423-483D-A7F9-278770579E3D}
```

---

## 2. Recovery rules

1. Use one Administrator PowerShell for the complete recovery sequence.
2. Do not run `zig build run` while another `aegis_nids.exe` owns the control pipe.
3. Do not start two Go Nose processes. The Nose pipe is a single-producer path.
4. Do not run `--inject-observe` while live Nose owns `\\.\pipe\aegis_nose`.
5. Do not use a stale `dist` binary without rebuilding or recording its hash.
6. Do not call WFP, `netsh`, or Windows firewall APIs directly from a test or UI.
7. Do not claim `ENFORCED` from readiness, detections, logs, or a policy decision. Only a validated receipt with host-effect confirmation qualifies.
8. Do not perform a block proof until live ingress and detection have first been proven.
9. Keep the target disposable and isolated on VMware VMnet1.
10. Preserve all evidence; do not overwrite a failed proof with a later successful-looking file.

---

## 3. Clean recovery procedure

### 3.1 Open Administrator PowerShell

Use `Run as Administrator`, then:

```powershell
Set-Location D:\NIDs_Windows
New-Item -ItemType Directory -Force .\admin-evidence | Out-Null
```

Record the host and artifact state:

```powershell
Get-Date
whoami /groups | Select-String 'S-1-16-12288|Administrators'
Get-Item .\zig-out\bin\aegis_nids.exe, .\dist\nose_dashboard.exe |
  Select-Object FullName,Length,LastWriteTime
Get-FileHash .\zig-out\bin\aegis_nids.exe, .\dist\nose_dashboard.exe -Algorithm SHA256
sc.exe query AegisWfp
```

### 3.2 Stop stale owners cleanly

First request the normal control-plane stop if the daemon is serving:

```powershell
python tools\aegisctl.py stop
Start-Sleep -Seconds 3
```

If the CLI cannot reach the daemon, use diagnostic process cleanup only:

```powershell
Get-Process aegis_nids,nose_dashboard -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
```

Confirm no stale owner remains:

```powershell
Get-Process aegis_nids,nose_dashboard -ErrorAction SilentlyContinue
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match 'aegis_control|aegis_nose' }
```

If `AegisWfp` was manually changed during a failed test, restore the service before continuing:

```powershell
sc.exe query AegisWfp
```

Do not uninstall the driver during this recovery unless a separate driver-repair procedure is being executed.

### 3.3 Start exactly one elevated core

Use the current built binary, not a second `zig build run` owner:

```powershell
Start-Process -FilePath .\zig-out\bin\aegis_nids.exe `
  -WorkingDirectory (Get-Location) `
  -WindowStyle Hidden `
  -RedirectStandardOutput .\admin-evidence\recovery-core.stdout.log `
  -RedirectStandardError .\admin-evidence\recovery-core.stderr.log

Start-Sleep -Seconds 5
python tools\aegisctl.py health --json |
  Tee-Object .\admin-evidence\recovery-core-health.json
```

The core gate must show:

```text
runtime_state=RUNNING
state=RUNNING
degraded=false
rust_shield.state=READY
pep_ready=true
policy_authority=true
provider_ready=true
host_effect_capable=true
wfp=READY
workers.pipeline_ready=true
workers.sensor_ready=true
workers.nose_ready=true
workers.failed=false
```

If any of these are false, stop here and investigate the core logs. Do not start Nose against a degraded or unavailable core.

### 3.4 Start the canonical Go Nose process

The canonical binary must be freshly built from `nose/` and copied to `dist/`:

```powershell
$iface = '\Device\NPF_{56055AA2-3423-483D-A7F9-278770579E3D}'

Start-Process `
  -FilePath .\dist\nose_dashboard.exe `
  -ArgumentList @('--capture','--iface',$iface) `
  -WorkingDirectory (Get-Location) `
  -WindowStyle Hidden `
  -RedirectStandardOutput .\admin-evidence\recovery-nose.stdout.log `
  -RedirectStandardError .\admin-evidence\recovery-nose.stderr.log

Start-Sleep -Seconds 5
Get-Process nose_dashboard | Select-Object Id,Name,StartTime,Path
Get-Content .\admin-evidence\recovery-nose.stderr.log -Tail 80
```

Expected log:

```text
[NOSE RULES] loaded=22 path=configs/Rules.json
[NOSE CAPTURE] listening on ...VMnet1... -> \\.\pipe\aegis_nose
[NOSE PIPE] connected to \\.\pipe\aegis_nose
```

### 3.5 Prove live traffic from Kali

The lab topology is:

```text
Kali attacker: 192.168.126.10
AEGIS/NIDS host: 192.168.126.1
Victim VM:       192.168.126.20
Network:         VMware VMnet1 / host-only
```

From Kali, first verify the interface and route:

```bash
ip -br addr
ip route
ping -c 3 192.168.126.1
```

Generate bounded, authorized lab traffic to the NIDS host:

```bash
sudo nmap -Pn -sS --max-rate 20 -p 22,80,443,8080 192.168.126.1
```

If a disposable HTTP target is intentionally running on the NIDS host:

```bash
curl --connect-timeout 3 http://192.168.126.1:8080/
```

Do not infer success from Kali output alone. On Windows immediately capture:

```powershell
python tools\aegisctl.py health --json |
  Tee-Object .\admin-evidence\recovery-health-after-kali.json
python tools\aegisctl.py metrics --compact |
  Tee-Object .\admin-evidence\recovery-metrics-after-kali.json
Get-Content .\admin-evidence\recovery-nose.stderr.log -Tail 120
```

The ingress gate passes only if:

```text
nose_connected=true or the process is actively reconnecting
nose_frames_read > 0
nose_frames_submitted > 0
packets_captured > 0 or the Nose capture counter equivalent is > 0
nose_frames_rejected=0
nose_pipe_errors=0
nose_duplicate_event_ids=0
nose_non_monotonic_event_ids=0
```

### 3.6 If live frames remain zero

Check these in order:

1. Kali has an address in `192.168.126.0/24`.
2. Kali's route points through VMnet1.
3. The Victim/NIDS traffic is actually traversing VMnet1.
4. The Windows VMnet1 adapter is `Up` and has `192.168.126.1`.
5. Npcap service is running:

   ```powershell
   Get-Service npcap -ErrorAction SilentlyContinue
   ```

6. The selected Npcap device is still the VMnet1 device; adapter GUIDs can change after VMware changes.
7. Windows firewall rules permit the intended lab traffic.
8. `nose-capture.stderr.log` contains `first packet captured`.
9. Only one Nose process owns the pipe.
10. The target traffic is not confined to a different virtual switch.

Re-enumerate devices if needed:

```powershell
.\dist\nose_dashboard.exe --list-devices *>&1 |
  Tee-Object .\admin-evidence\nose-devices-recovery.txt
```

Never solve a zero-frame problem by enabling the direct Zig Npcap path at the same time as Go Nose. The architecture deliberately uses Go Nose as the canonical network ingress to preserve exactly-once identity.

---

## 4. Controlled observe-only pipe proof

Use this only when live Nose is stopped and no other producer owns the pipe. It verifies serialization, named-pipe framing, Zig reading, queue submission, and forensic observation. It does not prove real packet capture and does not create a WFP effect.

```powershell
Get-Process nose_dashboard -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

.\dist\nose_dashboard.exe --inject-observe --inject-count 10 *>&1 |
  Tee-Object .\admin-evidence\recovery-observe-injection.txt

python tools\aegisctl.py health --json
python tools\aegisctl.py metrics --compact
```

Expected:

```text
[NOSE INJECT] observe-only sent=10 dropped=0 count=10
nose_frames_read >= 10
nose_frames_submitted >= 10
nose_frames_rejected=0
nose_pipe_errors=0
```

After this proof, restart live Nose and repeat the real Kali traffic gate. Do not leave the system in injection-only mode if the intended product is a live sensor.

---

## 5. Normal-state acceptance checklist

The system may be called operationally normal only when all of the following are true in one captured Administrator session:

| Gate | Required evidence |
|---|---|
| Single owner | One `aegis_nids.exe`, one canonical Nose process |
| Runtime | Core health `RUNNING`, not degraded |
| Authority | PEP ready, policy authority true |
| WFP | Provider ready and host-effect capable |
| Workers | Pipeline, sensor, Nose, ETW/FIM/registry ready; failure mask zero |
| Nose | Correct VMnet1 adapter selected and pipe connected |
| Ingress | Real Kali packet causes non-zero capture/frame counters |
| Queue | Submitted frames are non-zero and rejected count remains zero |
| Identity | No duplicate or non-monotonic event IDs |
| Forensics | Integrity verified after the observed traffic |
| Dashboard | Shows live runtime state and does not invent blocks |
| Cleanup | No stale process, pipe, filter, or temporary target remains |

A system with only core/WFP readiness but zero ingress is **not normal as a NIDS**.

---

## 6. Recovery failure classification

| Symptom | Classification | Action |
|---|---|---|
| `runtime_state` empty / control unavailable | Runtime owner absent | Start one elevated core |
| WFP `0x5` | Non-elevated process | Restart from Administrator token |
| `nose_connected=false` | Nose absent or ACL/pipe issue | Start canonical Nose elevated; verify pipe |
| `nose_connected=true`, frames zero | No traffic or wrong adapter | Verify Kali route/VMnet1/Npcap |
| Observe injection says consumer unavailable while live Nose runs | Expected single-producer collision | Stop live Nose before injection |
| Nose build fails | Stale artifact risk | Fix source, run `go test ./...`, rebuild `dist` |
| Frames rejected | Contract mismatch or malformed wire data | Stop proof; inspect Go/Zig fixture compatibility |
| WFP readiness true but no receipt | Readiness is not enforcement | Run controlled receipt proof only after ingress gate |
| `blocks>0` without complete receipt | Metrics/UI bug | Fail closed; inspect receipt validation |

---

## 7. Handoff completion

The next agent should first complete Section 3 and attach the following files to the handoff:

```text
admin-evidence/recovery-core-health.json
admin-evidence/recovery-health-after-kali.json
admin-evidence/recovery-metrics-after-kali.json
admin-evidence/recovery-nose.stderr.log
admin-evidence/nose-devices-recovery.txt
```

Only after `frames_read` and `frames_submitted` are non-zero should the agent proceed to the separate WFP host-effect proof. The WFP proof must use a disposable victim service and a direction-correct filter implementation.
