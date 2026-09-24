# AEGIS Phase 10 — VMware Isolated Lab Plan

**Date:** 2026-09-19  
**Purpose:** Prepare an isolated VMware environment for observe-only validation and a later reversible WFP host-effect proof.

## Conclusion

VMware is the preferred lab boundary for the next acceptance phase because it provides explicit virtual networks, snapshots, controlled routing, and separate attacker and target machines. The first Phase 10 step is a **read-only lab preflight**. It must prove that the Windows host can see the intended VMware interface while the AEGIS runtime remains fail-closed. It must not generate attack traffic or change WFP state.

The WFP host-effect proof is a separate gated operation. It requires a user-confirmed target and cleanup plan because it changes host filtering state and tests a real network effect.

## Required topology

The initial proof should use one isolated VMware network, such as a host-only VMnet. Kali and the test target must be attached only to this network during the first proof. NAT and bridged adapters should be disabled for the proof window.

A suitable lab network is the detected VMware VMnet1 host-only network:

| Role | Example address | Network |
|---|---:|---|
| Windows host AEGIS endpoint | `192.168.126.1` | VMnet1 host-only |
| Kali attacker | `192.168.126.10` | VMnet1 host-only |
| Test target VM | `192.168.126.20` | VMnet1 host-only |

These addresses are a proposed lab allocation. The actual guest addresses must be confirmed from VMware and the guest operating systems before testing. VMnet8 (`192.168.5.0/24`) is NAT and must not be used for the first host-effect proof. Wi-Fi (`192.168.1.0/24`) is the active physical network and must not be used as the isolated proof network.

## Safety boundary

The lab must not include a production subnet, a real gateway, a real DNS server, an employee endpoint, or an Internet-facing bridged interface. A snapshot should be taken for both guest machines before any generated traffic. The target should expose only a disposable test service.

The first stage must not use localhost, the Windows host's primary LAN address, the VMware gateway, or any critical infrastructure address as a WFP target. A private address may be visible in the lab, but it should not be selected for a block proof until the PEP safety rules and the exact target isolation are explicitly confirmed.

## Read-only preflight

Run the following command from an elevated PowerShell while AEGIS is already running:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File '.\scripts\run_vmware_lab_preflight.ps1' `
  -ExpectedLabSubnet '192.168.126.0/24'
```

The script inspects VMware/VMnet adapters, IPv4 addresses, and live AEGIS health. It does not start or stop a service, install a driver, generate attack traffic, submit an enforcement request, or alter the enforcement gate.

A passing preflight requires a visible VMware adapter, a running runtime, ready Tier-3 PEP authority, and `host_effect_capable=false`. A passing preflight is not evidence of WFP host effect.

## Observe-only traffic proof

After the topology is confirmed, run only benign traffic from Kali to the disposable target. The first proof should use connection attempts and a known test service rather than exploitation. The acceptance evidence must show that a packet observed on the VMware interface becomes a canonical event, reaches the Zig pipeline, and is recorded in the forensic ring.

The proof must report event deltas, dropped frames, pipe errors, duplicate event IDs, non-monotonic event IDs, and forensic verification. It must not report `BLOCKED` unless a verified `EnforcementReceipt` confirms a real host effect.

## WFP host-effect proof entry gate

The host-effect proof is not authorized by the read-only preflight alone. Before it starts, all of the following must be known:

1. The Kali and target VMs are isolated on the intended VMnet.
2. NAT and bridged paths are disabled for the proof window.
3. The exact test target, protocol, port, and duration are recorded.
4. The target service is disposable and reachable before the test.
5. A cleanup action is defined and can be independently verified.
6. The Rust PEP is ready and the WFP provider is independently attested.
7. The user has confirmed the exact block payload.

The proof must collect a precondition, PEP decision, provider response, filter identity, observed host-effect postcondition, receipt, forensic linkage, cleanup result, and post-cleanup reachability. If any postcondition is missing or ambiguous, the proof fails closed.

## Production-readiness rule

Production readiness cannot be declared from a policy decision, a loaded DLL, a running service, or a successful API response. The claim requires a verified host-effect postcondition and a verified cleanup result in the isolated lab, followed by lifecycle recovery and full-chain acceptance.

Until those requirements pass, the required state is:

```text
overall_gate         = false
host_effect_capable  = false
production_ready     = false
```

## Current status

Phase 8 lifecycle recovery is accepted. Phase 9 Tier-3 authority separation is complete. Phase 10 VMware lab preflight is prepared. Attack traffic and WFP host-effect proof remain intentionally unexecuted.

## References

[1]: https://docs.vmware.com/ "VMware documentation"
