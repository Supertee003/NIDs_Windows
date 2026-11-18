# RB-023: Capture segment selection (prove the sensor watches the zone you attack)

## Objective

Choose, change, and prove **which network segment the sensor reads**, without
guessing a device name and without accidentally running two readers on one
adapter.

Two readers can exist on this host:

| Reader | Knob | Default |
|---|---|---|
| Go Nose (canonical ingress) | `AEGIS_NOSE_IFACE` | auto-select: first physical adapter with an address (`nose/capture.go:firstUpDevice`, skips WAN Miniport, Hyper-V, VMware, Bluetooth, Wi-Fi Direct, TeamViewer, loopback) |
| Daemon direct Npcap (lab reader) | `AEGIS_DAEMON_IFACE` | unset = disabled. Allowed only when its resolved device differs from the nose device (EVT-200) |

Both are machine-scope environment variables read at process start. Hand-typing
a `\Device\NPF_{GUID}` is how a lab watches Wi-Fi while the attacker sits on
VMnet1: real packets, zero detections, and an operator who blames the detector
(measured in `analysis/current-head/LAB-WIFI-001-20261116.md`).

`tools/capture_select.py` turns the decision into one validated command:
it enumerates the devices Npcap exposes, resolves a selector the way the runtime
does (exact canonical name, then a **unique** case-insensitive description
substring), refuses ambiguity, enforces disjointness on the **resolved device**
(not on the spelling), and mutates only with `--apply`.

## Prerequisites

- `nose\aegis-nose.exe` built (`cd nose; go build -o aegis-nose.exe .`).
- An **elevated** PowerShell only for `--apply` and for `Restart-Service`.
  `--list`, `--show`, `--plan`, and `--verify` need no elevation.
- A running runtime for `--verify` (`python scripts\aegis_open.py status`).
- A decision about the restart cost: **`Restart-Service AegisNids` ends a
  running soak window** (`analysis/current-head/SOAK2-20261115.md`). Read-only
  modes never restart anything.

## Steps

### 1. See what Npcap exposes

```powershell
python tools\capture_select.py --list
```

Each row is `#index`, the canonical `\Device\NPF_{...}` name, the adapter
description, and usable IPv4 addresses. `<AUTO>` marks what Nose would pick on
its own, `<NOSE>`/`<DAEMON>` mark the current pins.

### 2. Read the current verdict

```powershell
python tools\capture_select.py --show
```

Expected shape on this host (2026-11-18):

```
  nose pin          : \Device\NPF_{5FD31C6E-...}
  nose watches      : \Device\NPF_{5FD31C6E-...} (pin)
  attack target IP  : 192.168.1.39
  daemon pin        : \Device\NPF_{CE375996-...}
  direct capture    : enabled (selectors resolve to two devices)
  verdict           : CAPTURE_SELECT_OK
```

`attack target IP` is what the attacker must hit. If the nose pin is unset, the
row says `auto-select` and names the adapter Nose chose -- that is a fact about
the host, not a preference.

Verdict `CAPTURE_SELECT_BLOCKED` means one of: a pin matches no device, a pin is
ambiguous, or a daemon pin exists without a verifiable nose pin. Fix it before
attacking anything; a blocked selection yields silence, not evidence.

### 3. Plan the change (writes nothing)

```powershell
# Watch Wi-Fi only (bridged Kali, no direct reader)
python tools\capture_select.py --plan --nose "#5"

# Watch host-only VMnet1 as well, with Wi-Fi still canonical
python tools\capture_select.py --plan --nose "#5" --daemon "VMnet1"

# Make VMnet1 the only network sensor
python tools\capture_select.py --plan --nose "VMnet1" --clear --role daemon
```

The plan prints the exact `setx /M` / `reg delete` commands. A selector is
pinned as the **canonical device name** even when you typed a description, so a
later rename of the adapter description cannot silently move the sensor.

Refused by design (exit `2`):

- `--nose "Wi-Fi"` when a Wi-Fi Direct adapter also matches -> ambiguous;
- `--nose X --daemon Y` when both resolve to one adapter -> the direct reader
  would duplicate canonical events, and a duplicate is not a second detection.

### 4. Apply, then pay the restart cost

```powershell
python tools\capture_select.py --apply --nose "#5" --daemon "VMnet1"
Restart-Service AegisNids     # ends a running soak window; do it deliberately
```

The running processes keep the old values until the restart: the pins are read
at process start. `--apply` writes only the two machine-scope variables.

### 5. Verify ingress before firing anything

```powershell
python tools\capture_select.py --verify
```

Exit `0` and `PREFLIGHT OK: the sensor is receiving frames on this device` means
the selected device is live. Exit `3` means ingress did not advance: **stop**.
Any attack result after a blind preflight is a false negative.

Then bracket the attack with `tools/lab_attack_window.py` (RB-021 or RB-022) so
the evidence records the same device the preflight proved.

## Verification

| Check | Pass condition |
|---|---|
| `--show` verdict | `CAPTURE_SELECT_OK` |
| `--show` target IP | the address the attacker will hit |
| `--plan` | `CAPTURE_SELECT_PLAN_OK`, commands name canonical devices |
| `--verify` | exit `0`, ingress advancing |
| `lab_attack_window.py --preflight` | same device as `--show` reports |
| After the attack | at least one row attributed to the attacker IP (exit `0`, not `2`) |
| Integrity | `aegisctl.py queue` -> `dropped=0`, `nose_duplicate_event_ids=0` |

## Rollback

Return both knobs to their default (Nose auto-selects, direct reader off):

```powershell
python tools\capture_select.py --plan --clear --role both
python tools\capture_select.py --apply --clear --role both     # elevated
Restart-Service AegisNids
python tools\capture_select.py --show
```

Anything the tool wrote can also be removed by hand:

```powershell
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /V AEGIS_NOSE_IFACE /F
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /V AEGIS_DAEMON_IFACE /F
```

## Safety contract

- Read-only modes (`--list`, `--show`, `--plan`, `--verify`) write nothing, start
  nothing, and restart nothing.
- `--apply` writes the two machine-scope variables only. It never writes rules,
  policy, or WFP state, and it never restarts a service.
- Disjointness is judged on the resolved device (`selectorsResolveDisjoint` in
  `src/capture/npcap_adapter.zig`), because a GUID and a description can name
  one adapter. Ambiguous or unresolvable selectors fail closed.
- The prevention gate stays `closed` throughout; this runbook is about
  visibility, not enforcement.
