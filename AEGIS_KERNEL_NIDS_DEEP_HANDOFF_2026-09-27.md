# AEGIS Kernel-Level NIDS/IPS — Deep Development Handoff

**Document date:** 2026-09-27  
**Repository HEAD observed in the latest audit:** `7623d1cf08f9e7dc0768d1043f458cb7fa100c35`  
**Target runtime:** Windows 11 Host with VMware isolated lab  
**Lab roles:** Windows Host = AEGIS NIDS/IPS; Kali VM = attacker; Windows 11 VM = victim  
**Document purpose:** Continue development with another Manus AI session without losing architecture, authority boundaries, evidence rules, or the distinction between runtime readiness and proven host effect.

---

## 1. Executive conclusion

AEGIS has reached a meaningful vertical-slice stage. The current design separates packet acquisition, event normalization, detection, policy evaluation, privileged enforcement, receipt validation, forensic recording, lifecycle control, and operator presentation. The selected Python security, contract, health, lifecycle-authority, Rust Shield/PEP, and WFP static tests previously passed with **90 tests**. The Windows Host also has the native toolchain required for the next verification phase, and the latest health snapshot reported all workers ready, Rust PEP as the canonical enforcement authority, and the WFP provider as ready.

These facts do **not** yet prove production enforcement. The current remaining proof boundary is host effect:

> A policy decision must cause a real, attributable WFP effect on the Windows Host, and the system must produce a validated receipt whose filter identity, request identity, event identity, trace identity, and forensic audit identity all correspond to the observed effect.

The next development phase must therefore be evidence-driven rather than feature-driven. Do not add alternate enforcement paths, promiscuous-mode assumptions, VLAN tricks, or a second Rust Shield authority. Stabilize the single-owner lifecycle, make Brain health deterministic, validate the VMware topology, and then run a narrowly scoped WFP canary in the isolated lab.

---

## 2. Current evidence snapshot

The latest Windows evidence reported:

```text
Host executable: D:\NIDs_Windows\zig-out\bin\aegis_nids.exe
Runtime PID: 9732
Health PID: 9732
Runtime state: RUNNING
Health state: RUNNING
degraded: false
```

Worker readiness was reported as:

```text
pipeline_ready = true
sensor_ready   = true
nose_ready     = true
etw_ready      = true
fim_ready      = true
registry_ready = true
```

Data-plane counters were clean in that snapshot:

```text
errors                 = 0
dropped                = 0
nose_frames_read       = 15
nose_frames_submitted  = 15
nose_frames_rejected   = 0
nose_pipe_errors       = 0
duplicate_event_ids     = 0
non_monotonic_ids      = 0
```

The latest health payload also reported:

```text
canonical_enforcement_authority = rust_pep
rust_pep.authority               = sole_enforcement_authority
rust_pep.canonical               = true
rust_pep.pep_ready               = true
rust_pep.policy_authority        = true
rust_pep.provider_ready          = true
rust_pep.host_effect_capable     = true
rust_pep.wfp                     = READY
```

Tier-3 was reported as ready with an artifact at:

```text
D:\NIDs_Windows\zig-out\bin\aegis_pep.dll
```

This is **runtime readiness evidence**. It is not yet host-effect evidence. The proof still needs an actual controlled traffic test and postcondition verification.

Two integration failures remain material:

1. The Brain UDP health test received `WinError 10054` instead of a valid `{"op":"HEALTH"}` response.
2. A core lifecycle test started a process with PID `29276` but received health from an older runtime PID `9732`. The test correctly rejected the stale response.

The second failure indicates a lifecycle/test isolation problem, not that PID `9732` was necessarily unhealthy. A control pipe must have exactly one runtime owner for a single-instance production profile.

---

## 3. System contract and authority model

The intended production flow is:

```text
Network adapter / VMware VMnet
        |
        v
Go Nose / native capture path
        |
        v
CanonicalEvent contract
        |
        v
Zig runtime spine and pipeline
        |
        v
Detection and correlation
        |
        v
Policy decision / severity / action request
        |
        v
Rust PEP authorization and enforcement
        |
        v
WFP provider or kernel callout effect
        |
        v
Validated EnforcementReceipt
        |
        +--> forensic record and audit chain
        +--> Rust Mouth/operator presentation
```

The authority boundaries are:

| Component | Owns | Must not own |
|---|---|---|
| Go Nose | Packet acquisition, collector I/O, canonical event submission | Policy, block/allow decisions, WFP mutation |
| C/C++ adapters | Windows telemetry and native adapter functions | Policy decisions or final enforcement authority |
| Zig Core | Runtime fabric, event flow, detection orchestration, correlation, forensics, lifecycle | Privileged enforcement authority |
| Python Brain/Cython | Tier-2 analytics and measured hot loops | Privileged OS mutation or final block decision |
| TypeScript policy layer | Policy authoring, validation, simulation, advisory compilation | Runtime enforcement or kernel calls |
| Rust PEP | Authorization, trust, cryptographic checks, enforcement request, receipt authority | Detection logic |
| WFP provider/callout | The actual host filtering effect | Policy interpretation outside the authorized request |
| Rust Mouth | Displaying verified outcome and operator state | Inferring `BLOCKED` from an unverified decision |

The critical invariant is:

> Detection can produce a finding. Policy can produce an action request. Only the authorized Rust PEP/WFP path can produce a confirmed enforcement receipt.

A Boolean such as `block_ip=true` is insufficient for production acceptance because it cannot prove which filter was installed, whether the provider acted, or whether the host effect corresponds to the event.

---

## 4. What WFP does and does not provide

Windows Filtering Platform is built from layers, filters, shims, and callouts. A filter selects traffic and invokes a callout or returns an action. The network shim applies the final classification result to the packet, stream, or event [1].

The following distinction is essential:

- `FWPM_LAYER_INBOUND_IPPACKET_V4` observes the receive path after the IP header is parsed and before IP header processing.
- `FWPM_LAYER_OUTBOUND_IPPACKET_V4` observes the send path before fragmentation evaluation.
- `FWPM_LAYER_IPFORWARD_V4` observes packets at the forwarding path.
- Transport, datagram, and stream layers provide different visibility and different conditions.

The IP-packet layers are not an automatic L2-to-L7 tap. They are not equivalent to an Ethernet promiscuous capture device. They do not guarantee application payload visibility, especially for encrypted protocols. Microsoft documents that the layer determines what data and conditions are available, and that a classification occurs at a specific layer [2].

Therefore the following claim must not be used as an unqualified production assumption:

```text
A WFP callout at inbound/outbound IP packet layers automatically sees every VMware packet and can inspect all L2-L7 payloads.
```

The correct statement is narrower:

> If traffic is deliberately routed through the Windows Host network stack, a WFP callout can enforce and observe the relevant IP forwarding or transport path. Visibility depends on the selected layer, routing path, protocol, encryption, and available metadata.

For L7 inspection, AEGIS must choose an explicit strategy:

- inspect unencrypted application data at an appropriate stream/datagram layer;
- inspect protocol metadata and flow behavior rather than payload;
- use endpoint instrumentation for encrypted traffic;
- or keep the detection result at the network metadata level and never claim decrypted L7 visibility.

The system must not claim L7 packet inspection merely because a WFP driver is loaded.

---

## 5. Recommended VMware topology

### 5.1 Preferred topology: two isolated host-only networks with the Host as router

Use two separate host-only VMnets rather than relying on a single shared host-only segment:

```text
Kali attacker VM
  NIC-A: VMnet-A / attacker subnet
             |
             | enters Windows Host adapter A
             v
      Windows Host routing boundary
      AEGIS WFP IPFORWARD/transport path
             ^
             | exits Windows Host adapter B
             |
Windows 11 victim VM
  NIC-B: VMnet-B / victim subnet
```

Example addressing:

```text
VMnet-A: 192.168.126.0/24
Host A:  192.168.126.1
Kali:    192.168.126.10

VMnet-B: 192.168.127.0/24
Host B:  192.168.127.1
Victim:  192.168.127.10
```

The exact subnets may differ. The important property is that Kali and the victim are on **different IP networks**, with the Windows Host as the gateway for both. Host-only networking is designed as a private network containing the VM and host virtual adapter, and VMware documents separate host-only networks with routing between them as the design for complex test networks [3].

This topology creates a deterministic routing boundary. A packet from Kali to the victim must be forwarded by the Host. The primary WFP enforcement observation point should therefore include the forwarding path, not only inbound and outbound local-host assumptions.

### 5.2 Why one shared host-only segment is insufficient

If Kali and the victim are on the same host-only Ethernet segment, VMware can switch frames between the VMs without making the Windows Host an IP router. The Host may have an adapter on that network, but that does not mean every peer-to-peer frame traverses the Host's IP forwarding path.

Consequently:

```text
same VMnet + host adapter present != host sees every peer packet
```

A single shared VMnet may still be useful for basic connectivity tests, but it is not the preferred topology for proving that the Host's WFP forwarding enforcement sees the traffic.

### 5.3 VLAN trunking is not the default plan

Do not make VLAN tagging the first solution. VMware host-only networking is an isolated virtual Ethernet design, not automatically a trunk carrying arbitrary tagged VLANs to Windows subinterfaces. VLAN behavior depends on VMware virtual switch configuration, guest driver support, Windows adapter support, and routing configuration.

A VLAN design may be explored later, but it requires a separate proof of:

- VLAN tag preservation;
- VMware virtual switch behavior;
- Windows adapter and driver support;
- routing between VLAN interfaces;
- WFP layer visibility;
- absence of leakage to physical networks.

For the first production-oriented proof, two host-only VMnets with explicit Host routing are simpler, more deterministic, and easier to roll back.

---

## 6. Npcap and WFP are different observation paths

Npcap is a packet capture path. WFP is a filtering and enforcement platform. They should not be treated as interchangeable.

The production architecture should use:

- WFP/Rust PEP for authoritative host enforcement;
- Go Nose/Npcap only where packet acquisition is required and the adapter path is supported;
- a routing topology that makes the Host the traffic boundary;
- explicit health reporting for capture readiness and enforcement readiness.

Do not rely on an assumption that Npcap can universally alter VMware's virtual-switch delivery behavior or unlock peer traffic. That behavior must be demonstrated for the exact VMware version, adapter, Npcap mode, and host configuration. It must never be a prerequisite for the WFP enforcement proof.

The system must distinguish:

```text
capture_ready
provider_ready
host_effect_capable
host_effect_proven
```

These are four different states.

---

## 7. Production gate model

The overall enforcement gate should remain closed unless all conditions below are true:

```text
canonical authority is Rust PEP
policy is authorized and valid
WFP provider is loaded
WFP device/IOCTL contract is valid
request identity is valid
filter installation returns a real filter identity
host effect is independently observed
receipt links request/event/policy/filter/trace/audit identities
forensic record is integrity-valid
cleanup removes the exact filter by receipt identity
restart does not leave stale filters
```

Suggested state model:

```text
DETECTION_ONLY
  -> POLICY_READY
  -> PEP_READY
  -> PROVIDER_READY
  -> ENFORCEMENT_REQUESTED
  -> HOST_EFFECT_CONFIRMED
  -> RECEIPT_VERIFIED
  -> FORENSICALLY_COMMITTED
```

The UI may display a decision such as `BLOCK_REQUESTED` before the host effect is proven, but it must display `BLOCKED_CONFIRMED` only after a validated receipt.

A provider capability flag must never by itself cause the Mouth to display `BLOCKED`.

---

## 8. End-to-end proof design

### 8.1 Preflight

Before any blocking test:

1. Confirm the Host is elevated.
2. Confirm exactly one AEGIS runtime owner.
3. Confirm the control pipe belongs to the expected PID.
4. Confirm the two host-only VMnets and interface indexes.
5. Confirm Kali and victim routes.
6. Confirm the Host is not connected to the physical production network through the lab path.
7. Confirm the target addresses are test-only addresses.
8. Confirm WFP provider and callout identity.
9. Confirm forensic storage is writable and starts with a known generation.
10. Confirm rollback and cleanup commands are available.

### 8.2 Observe-only proof

Use a harmless synthetic event or benign traffic first:

```text
traffic/event -> Nose -> CanonicalEvent -> Zig -> detection -> forensic record
```

Acceptance conditions:

```text
requested events > 0
submitted events == accepted events
rejected events == 0
duplicate IDs == 0
non-monotonic IDs == 0
forensic integrity == ok
no enforcement request emitted
no WFP filter installed
```

### 8.3 Controlled enforcement canary

Use a unique test flow between Kali and the victim. The test must define:

```text
source IP
source port
victim IP
victim port
protocol
correlation ID
policy ID
request ID
```

The first canary should block a narrow flow, not an entire subnet. The policy should have an explicit expiration or cleanup condition.

Acceptance requires all of the following:

```text
policy decision = block request
Rust PEP authorizes request
provider returns success
filter_id != 0
WFP query confirms filter state
controlled connection fails as expected
unrelated control traffic remains available
receipt validates
forensic record validates
Mouth displays confirmed state only
```

### 8.4 Cleanup proof

Cleanup must use the exact `filter_id` from the receipt. Do not delete by IP alone because an IP-only delete cannot prove ownership of the filter.

After cleanup:

```text
filter query = absent
victim flow = restored
forensic cleanup record = valid
no stale filter remains
```

### 8.5 Restart proof

After cleanup, perform orderly shutdown and restart:

```text
old PID stops
old control pipe releases
new PID starts
new PID owns control pipe
workers recover
provider reloads
forensic generation is valid
old filter is absent
```

The lifecycle test must not accept a health response from a previous PID. The latest observed failure demonstrates why PID matching is required.

---

## 9. Required fixes before WFP attack testing

### P0 — Single-owner lifecycle

Fix the integration harness and runtime startup contract so that a second daemon cannot silently use a control pipe owned by an older daemon.

Required behavior:

```text
if control pipe already has a live owner:
    fail startup explicitly
    report owner PID if possible
    do not continue as a second runtime
```

The lifecycle test must cleanly stop the old runtime or use a unique isolated endpoint. A stale health response must remain a hard failure.

### P0 — Brain health endpoint

Make the UDP Brain health contract deterministic. The endpoint must either:

- respond to `{"op":"HEALTH"}` on the documented address and port;
- or be explicitly marked optional and excluded from the required readiness gate.

The current `WinError 10054` must not be hidden by changing the test to ignore connection resets.

### P1 — Current truth and change-set hygiene

The latest working tree contains many modified and deleted documents plus new evidence files. Before committing:

- classify deleted documents as intentional archive moves or accidental deletions;
- ensure the current `AGENTS.md` HEAD is synchronized with the actual HEAD;
- regenerate truth artifacts using their generators;
- preserve evidence files with explicit provenance and test command;
- do not manually edit hashes or manifests;
- normalize CRLF/LF policy for Windows source and generated artifacts.

### P1 — Native build evidence

Record the following on Windows:

```text
zig version
zig build
zig build test
go version
go test ./...
rustc --version
cargo test
cmake --build build
```

Each result must record the exit code, artifact path, and hash where applicable.

### P1 — WFP contract proof

Verify that userspace, Rust PEP, native adapter, device name, IOCTL numbers, and provider exports all use the same generated or canonical contract. The provider must expose a query operation that can confirm the exact filter identity installed for a request.

---

## 10. Recommended implementation order

### Phase A — Stabilize ownership and health

1. Stop all AEGIS processes.
2. Start exactly one runtime.
3. Verify PID-to-health identity.
4. Fix Brain UDP health response.
5. Run health and lifecycle tests with clean state.
6. Record evidence.

### Phase B — Prove topology

1. Create VMnet-A and VMnet-B as host-only networks.
2. Assign static addresses.
3. Put Kali on VMnet-A.
4. Put victim on VMnet-B.
5. Configure Windows Host routing.
6. Verify Kali-to-victim traffic crosses the Host.
7. Verify no physical network leakage.
8. Record interface indexes and routes.

### Phase C — Prove observe-only packet path

1. Run benign traffic.
2. Confirm capture and canonical event counters.
3. Confirm forensic records.
4. Confirm no policy block.
5. Confirm no enforcement receipt is emitted.

### Phase D — Prove WFP host effect

1. Install one narrow canary policy.
2. Generate one controlled flow.
3. Verify the flow is blocked.
4. Query the exact filter identity.
5. Validate the receipt.
6. Confirm unrelated traffic remains available.
7. Remove the exact filter.
8. Verify the flow is restored.

### Phase E — Recovery and release acceptance

1. Restart runtime after cleanup.
2. Verify old filter absence.
3. Verify new PID and control pipe owner.
4. Verify provider reload.
5. Rebuild truth artifacts.
6. Run full regression suite.
7. Package artifacts.
8. Only then issue a production acceptance statement.

---

## 11. Evidence record format

Every proof should produce one immutable evidence record containing:

```json
{
  "proof_id": "wfp_host_effect_YYYYMMDD_NNN",
  "head_sha": "...",
  "host_os": "Windows 11 ...",
  "aegis_pid": 0,
  "control_pipe": "\\\\.\\pipe\\aegis_control",
  "attacker_vm": "...",
  "victim_vm": "...",
  "vmnet_a": "...",
  "vmnet_b": "...",
  "interface_indexes": {},
  "source": {},
  "destination": {},
  "protocol": "TCP",
  "policy_id": 0,
  "request_id": 0,
  "event_id": 0,
  "filter_id": 0,
  "trace_id": 0,
  "audit_id": 0,
  "provider_ready": false,
  "host_effect_observed": false,
  "receipt_verified": false,
  "cleanup_verified": false,
  "restart_verified": false,
  "passed": false
}
```

The evidence must include raw command output or references to raw output. A summary JSON without the underlying observation is not sufficient for the final acceptance gate.

---

## 12. Safety and rollback rules

The first enforcement proof must run only in the isolated VMware lab. Do not test against the Host's normal Wi-Fi, LAN, corporate network, or Internet route.

Use a narrow test tuple and a short lifetime. Keep the control pipe and operator access outside the test filter. If the provider behaves unexpectedly:

1. stop the canary policy;
2. remove the exact filter by receipt identity;
3. verify the filter is absent;
4. restore the lab route;
5. stop AEGIS through the control plane;
6. inspect the forensic record;
7. do not broaden the filter to “make the block obvious.”

A failed proof is evidence. It must not be converted into a pass by relaxing the postcondition.

---

## 13. What must not be claimed yet

The following claims are premature until their evidence exists:

```text
“WFP sees every VMware packet.”
“WFP provides automatic L2-L7 visibility.”
“Npcap unlocks VMware peer traffic universally.”
“VLAN tagging forces all traffic through the Host.”
“provider_ready means traffic was blocked.”
“host_effect_capable means host effect was proven.”
“health state RUNNING means the newly started process owns the pipe.”
“the system is Production-ready.”
```

The accurate current statement is:

> AEGIS has a structurally separated detection-to-enforcement architecture, a working Windows runtime snapshot with Rust PEP/WFP readiness reported, and a defined isolated-lab path for proving real host effect. Lifecycle ownership and Brain health still require closure before the first controlled WFP enforcement proof.

---

## 14. Handoff checklist for the next AI session

The next AI should begin by reading:

```text
AGENTS.md
AI_CONTEXT.md
SYSTEM_MAP.json
FLOW_MAP.json
AUTHORITY_MAP.json
CONTRACT_MAP.json
EVIDENCE_INDEX.json
build_truth.json
runtime_manifest.json
AEGIS_DEEP_SYSTEM_HEALTH_AUDIT_2026-09-27.md
```

Then it should perform, in order:

1. Verify the repository HEAD and whether machine maps match it.
2. Verify whether `AGENTS.md` still carries an old HEAD.
3. Inspect the current diff and classify document deletions.
4. Fix or classify the Brain UDP health failure.
5. Fix single-owner lifecycle/test isolation.
6. Run native Windows build and test commands.
7. Validate the two-VMnet routed topology.
8. Run observe-only proof.
9. Run only the narrowly scoped WFP host-effect canary.
10. Rebuild truth artifacts and write evidence.

Do not start with broad attack traffic. Do not bypass the control plane. Do not add a second enforcement authority.

---

## 15. References

[1]: https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation "Microsoft WFP Operation"

[2]: https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers- "Microsoft Filtering Layer Identifiers"

[3]: https://techdocs.broadcom.com/us/en/vmware-cis/desktop-hypervisors/workstation-pro/17-0/using-vmware-workstation-pro/configuring-network-connections/configuring-host-only-networking.html "Broadcom VMware Workstation Pro Configuring Host-Only Networking"

[4]: https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer "Microsoft Filtering Conditions Available at Each Filtering Layer"
