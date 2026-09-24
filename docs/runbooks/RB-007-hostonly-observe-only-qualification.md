# RB-007 Host-only Observe-only Qualification

## Purpose

This runbook qualifies the Windows WFP telemetry path using a benign TCP/HTTP connection from an isolated Kali VM on a host-only network. It does not test blocking, filter installation, PEP enforcement, or cleanup.

## Safety contract

The procedure uses a disposable TCP listener, a normal HTTP GET, and read-only WFP device access. It does not use exploit payloads, scanning, credential access, firewall commands, `BLOCK_FLOW`, `UNBLOCK_FLOW`, or `enforcement.block`. Keep the global prevention gate closed.

## Windows Host

Run an elevated PowerShell window:

```powershell
Set-Location D:\NIDs_Windows
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_wfp_hostonly_observe_only.ps1 -ExpectedKaliIp <KALI_HOST_ONLY_IP> -ListenPort 49152 -WaitSeconds 30
```

The command creates a `READY.txt` marker. It starts a disposable listener, accepts one connection, and then runs the existing WFP read-only collector requiring a frame from the expected Kali IP and destination port.

## Kali VM

Copy `scripts/kali_hostonly_probe.sh` to Kali, make it executable, and run:

```bash
chmod +x kali_hostonly_probe.sh
./kali_hostonly_probe.sh <WINDOWS_HOST_ONLY_IP> 49152
```

The optional third argument is a nonce for operator correlation:

```bash
./kali_hostonly_probe.sh <WINDOWS_HOST_ONLY_IP> 49152 AEGIS_L4_001
```

## Acceptance

The run is `L4_HOSTONLY_TRANSPORT_PASS` only when the Windows evidence shows:

- driver service is running;
- device access is `GENERIC_READ`;
- only `GET_STATS` and `READ_EVENTS` were requested;
- `BLOCK_FLOW` and `UNBLOCK_FLOW` were not called;
- a complete 44-byte frame exists;
- `expected_flow.required` is true;
- a frame matches the expected Kali source IP and listener destination port;
- `prevention_gate` is `closed` and `host_effect` is `none`.

This proves transport telemetry correlation. It does **not** prove a rule match when `rule_id=0`, and it does not prove L7 payload inspection. L7 requires an application/payload sensor that reports the nonce or payload-derived canonical event.

## Failure interpretation

A timeout or missing expected frame is a sensor, routing, firewall, binding, or driver-layer failure—not a reason to enable enforcement. A run with frames but no expected-flow match is `L4_DEVICE_READBACK_PASS` only.

Do not run WFP block or PEP tests from this runbook.
