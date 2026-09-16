# AEGIS NIDS User Operations Guide

AEGIS is operated as a single Windows security appliance. The operator should use `aegisctl.py` and the deployment profile rather than editing source files or calling component binaries independently. The Rust PEP is the only enforcement authority. If the PEP, WFP adapter, driver, or required worker is unavailable, AEGIS reports degraded or detection-only mode and does not silently claim that enforcement succeeded.

## First installation

Install the pinned toolchains and Windows dependencies described in `docs/runtime/LOCAL_RUNBOOK.md`. Install Npcap when packet capture is required. Install the signed or test-signed WFP driver only on an isolated test host when enforcement testing is explicitly enabled. Create the runtime directories and copy `config/deployment_profile.example.json` to `config/deployment_profile.json`.

Build from the repository root:

```powershell
scripts\build_all.bat
python tools\release_engineering.py --manifest
python tools\release_engineering.py --verify
python tools\aegisctl.py rules validate
```

A clean installation is not ready until the release verifier reports that every recorded artifact is present and its digest matches.

## Configure the host

Edit only `config/deployment_profile.json` for host-specific values. Set the capture provider and adapter selector. Use `mode=auto` for a portable profile or specify the Ethernet/Wi-Fi adapter description or MAC address for a fixed host. Keep `fallback_order` enabled for replay and diagnostics, but never treat replay as live capture.

The same ruleset can be used on Wi-Fi, wired LAN, VPN, or a selected virtual adapter. The profile controls acquisition scope; it does not create a second policy or enforcement path.

## Start and verify

Start the bridge first, then the core, then optional acquisition and analytics components. The exact binary paths are documented in `docs/runtime/LOCAL_RUNBOOK.md`; do not start stale copies from old `build`, `target`, or developer directories.

After startup, run:

```powershell
python tools\aegisctl.py status
python tools\aegisctl.py health
python tools\aegisctl.py diagnose
```

The expected result is `RUNNING` when all required dependencies are available. `DEGRADED` is correct when a required acquisition or enforcement dependency is absent. In that state, use detection-only or replay mode until the health payload reports the required worker and PEP readiness.

## Manage rules and policy

Use the command center for rules and policy state:

```powershell
python tools\aegisctl.py rules list
python tools\aegisctl.py rules show --id R0056
python tools\aegisctl.py rules validate
python tools\aegisctl.py policy list
python tools\aegisctl.py policy disable --id R0056
python tools\aegisctl.py policy enable --id R0056
python tools\aegisctl.py policy reload
```

Rule CRUD is atomic and validates the complete ruleset before replacing the canonical file. Use `rules add`, `rules update`, and `rules delete` only for reviewed changes. Policy enable/disable is runtime state; it does not mutate WFP directly.

## Observe and investigate

Use `events count`, `events tail`, and `events stats` for live observation. Use `forensic search`, `forensic show`, and `forensic export` for evidence. A complete decision must preserve event, incident, policy, request, forensic, and enforcement identifiers. Exported evidence should be copied into the release or incident case directory, not edited in place.

## Test safely with WSL2

Create an isolated WSL2 test network and use only a disposable local service on the Windows host. Record the attacker and host addresses, selected adapter, active ruleset digest, and enforcement mode before testing. Start with replay and detection-only tests. Then test bounded HTTP signatures, ICMP/TCP reconnaissance markers, and benign file/process markers. Enable block/drop canaries only after the decision trace is complete and rollback has been tested.

Do not run credential theft tools, ransomware, destructive payloads, or uncontrolled flood commands. The supported `simulate` and replay commands provide deterministic regression coverage without requiring harmful payloads.

## Stop, recover, and update

Stop components through the control plane or the documented service stop procedure. Confirm that `aegisctl status` reports stopped and that no stale process owns the control pipe. For an update, snapshot configuration and evidence first, install the new release, run manifest verification and rule validation, then start in detection-only mode. Promote to enforcement only after the canary sequence reports success and rollback remains available.

## Final operational checklist

A deployment is operationally complete when the profile identifies the intended interface, health reports every required worker, the ruleset validates, Rust PEP and Shield versions match the manifest, events and forensic records are observable, replay is deterministic, a WSL2 lab test produces the full identifier chain, and shutdown leaves no orphan process or stale control endpoint.
