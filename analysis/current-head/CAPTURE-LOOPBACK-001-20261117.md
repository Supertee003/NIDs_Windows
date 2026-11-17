# CAPTURE-LOOPBACK-001 — loopback capture works on the shipped nose; the gap was the binding

**Date:** 2026-11-17
**Gap:** `CAPTURE-LOOPBACK-001` (P2, was E4)
**Shipped image:** `aegis_nids.exe` sha256 `7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18`
**Nose binary:** `nose\aegis-nose.exe` sha256 `731D4186A6DFF51C1935337EA129FFACE832EBA982B6ED090723E53DAD1A0E10`
**Result:** PASS, E5 (host verification, no restart, no product change)

## What the gap said

The install saw no loopback records, so a self-test that attacked `127.0.0.1`
could not feed detection. That was read as "this install cannot capture
loopback". The 2026-11-17 check shows the capability is present; the sensor was
simply bound to another interface.

## Device inventory

`dumpcap -D` lists the Npcap loopback device on this host:

```
11. \Device\NPF_Loopback (Adapter for loopback traffic capture)
```

So Npcap loopback support is installed. The production daemon is pinned to
VMnet1 (`AEGIS_DAEMON_IFACE`) and Go Nose to Wi-Fi (`AEGIS_NOSE_IFACE`); neither
opens `NPF_Loopback`, which is why the earlier windows contained no loopback
rows.

## Measurement

The shipped nose probe opens the named device, reads raw frames for 15 s and
writes nothing else (`nose/capture.go:404-438`). Two runs, same binary, same
device:

| Run | Stimulus | Result |
|---|---|---|
| idle | none (ambient loopback only) | `packets=66 timeouts=6` |
| active | local HTTP server on `127.0.0.1:18080`, 200 TCP requests | `packets=2378 timeouts=2` |

Commands:

```powershell
nose\aegis-nose.exe -capture-probe -iface "\Device\NPF_Loopback"
python -m http.server 18080 --bind 127.0.0.1
python -c "import socket; ... 200 connects ..."
```

The active run is **36x** the idle run and shows the first three raw packets,
so the device delivers loopback frames to the shipped binary. The probe stops
before BPF, decoding and the pipe, which is the exact question this gap asked:
can this interface deliver raw frames?

## Resolution

- **Capability:** yes. The shipped nose captures `NPF_Loopback` when asked.
- **Root cause of the gap:** interface binding, not a missing Npcap feature.
- **Scope decision:** production keeps watching the real link (Wi-Fi); loopback
  is a **self-test** interface. A loopback run must pin
  `-iface "\Device\NPF_Loopback"`; it is never the production binding.
- **No restart, no source change, no reinstall.** The 24.62 h process window was
  not interrupted.

## Evidence artifacts

- `admin-evidence/capture-loopback-20261117/probe-idle.err` (`packets=66`)
- `admin-evidence/capture-loopback-20261117/probe-active.err` (`packets=2378`)
- This record; `EVIDENCE_INDEX.json#CAPTURE-LOOPBACK-001-E5-20261117`

## Limit

The probe proves raw capture, not a full Nose → pipe → Zig detection row on
loopback. A full self-test still needs a loopback-pinned sensor instance or a
lab interface; that is a runbook choice, not a missing capability. The gap's
P2 risk (self-test cannot feed detection) is removed for the shipped binary.
