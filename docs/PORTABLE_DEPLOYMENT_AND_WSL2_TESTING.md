# Portable Deployment and WSL2 Attack-Lab Runbook

AEGIS NIDS is portable when host-specific values remain in a deployment profile rather than in source code. The runtime spine, Rust PEP, Shield screening layer, event contracts, and policy schema stay identical across hosts. Only the capture provider, interface selector, storage paths, and local service identity change.

## Deployment model

Copy `config/deployment_profile.example.json` to `config/deployment_profile.json` on the target Windows host. Select `npcap` for packet capture, `wfp` for flow enforcement telemetry, `etw` for process and kernel telemetry, or `replay` for deterministic offline testing. The fallback order is used only for acquisition availability; it never changes the Rust PEP enforcement authority.

For a Wi-Fi host, use `provider=npcap` and `interface_selector.mode=auto` or specify the adapter description. For a wired LAN host, keep the same provider and select the Ethernet adapter by description or MAC. The detector must not infer that Wi-Fi is the only supported network. Virtual, VPN, and Hyper-V adapters can be excluded explicitly when they are not part of the observation scope.

The deployment procedure is:

1. Install the pinned Zig, Rust, CMake, Go, Node.js, and Python toolchains listed in the Windows pre-flight gate.
2. Build the canonical Zig runtime, Rust PEP, Rust Shield, native helpers, C++ bridge, and Go acquisition component.
3. Copy the release artifacts, `config/`, `trust_store/`, `tools/`, and the selected deployment profile. Do not copy build caches or developer-only state.
4. Run `aegisctl rules validate`, `aegisctl health`, and the release manifest verification before starting capture.
5. Select the adapter and capture providers in the deployment profile. Start in replay or shadow mode before enabling enforcement.
6. Confirm that the health payload reports the selected provider, interface identity, readiness, and any fallback reason.

## Rule management

Rules are stored in the canonical `config/Rules.json` file. The schema supports network L4/L7 signatures, kernel file and process telemetry, and named-pipe telemetry. Rules are validated before an atomic replacement of the file is committed.

```powershell
python tools/aegisctl.py rules validate
python tools/aegisctl.py rules list --category Injection
python tools/aegisctl.py rules show --id R0056
python tools/aegisctl.py rules add --id R9100 --rule-json '{"rule_id":"R9100","name":"Lab marker","category":"Lab","layer":"L7","match_pattern":"AEGIS_LAB","severity":"Medium","action":"Alert"}'
python tools/aegisctl.py rules update --id R9100 --rule-json '{"rule_id":"R9100","name":"Lab marker v2","category":"Lab","layer":"L7","match_pattern":"AEGIS_LAB_V2","severity":"High","action":"Alert"}'
python tools/aegisctl.py rules delete --id R9100
```

Production enforcement changes must go through the protected control plane and Rust PEP authorization. CRUD modifies policy data; it does not directly modify WFP or firewall state.

## WSL2 attack-lab topology

Use an isolated lab network. The WSL2 attacker must never target an unapproved production host or public address. The Windows host runs AEGIS in replay, shadow, or explicitly approved canary mode. The attacker uses generated traffic only inside the lab subnet.

Recommended flow:

```text
WSL2 attacker -> Windows host LAN/Wi-Fi interface -> Npcap/WFP/ETW -> Go Nose/C++ bridge -> Zig pipeline -> Python Tier-2 -> Rust PEP -> WFP adapter
```

Before each test, record the Windows host IP, WSL2 address, selected adapter, provider, active rule-set digest, and enforcement mode. Start with safe probes and detection-only assertions. Use block or drop tests only after the event and decision trace are confirmed.

Suggested non-destructive test phases are:

1. Connectivity and interface discovery.
2. HTTP signature tests for SQL injection, command injection, XSS, and path traversal using a disposable local test service.
3. ICMP and TCP scan-rate tests with low bounded volume.
4. Replay of canonical NDJSON events for deterministic regression.
5. Kernel file and process monitor tests using harmless marker files and benign process arguments. Do not execute malware or credential theft tooling on the host.
6. Canary enforcement tests with explicit scope, expiry, rollback, and audit verification.

Every test must produce an event identifier, rule identifier, policy version, request identifier, PEP decision, enforcement result, and forensic trace identifier. A test is not considered passed when only an alert is printed; the entire identifier chain and fail-closed behavior must be verified.

## Portability acceptance criteria

A target host is ready when the selected adapter is identified without source changes, capture health is READY, LAN and Wi-Fi traffic can be selected independently, replay mode works without a live adapter, the rules validate successfully, the Rust PEP and Shield versions match the manifest, and the WSL2 lab tests produce complete traces. If a provider is unavailable, the runtime must report the degraded reason and must not silently allow a privileged action.
