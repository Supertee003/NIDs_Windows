# Go Nose/Npcap to Canonical Pipe Handoff — 2026-09-22 23:41

## Result

`NPCAP_TO_CANONICAL_PIPE_HANDOFF_PASS`.

The foreground Go Nose capture process produced authoritative runtime evidence:

```text
[NOSE RULES] loaded=22 path=configs/Rules.json
[NOSE CAPTURE] listening on \\.\Device\\NPF_{56055AA2-3423-483D-A7F9-278770579E3D} -> \\\\.\\pipe\\aegis_nose
[NOSE PIPE] connected to \\\\.\\pipe\\aegis_nose
[NOSE CAPTURE] first packet captured: len=74
[NOSE PIPE] first canonical frame sent: 113 bytes event_id=1
```

The interface is the VMware Host-only adapter with host address `192.168.126.1`. The capture process loaded all 22 rules and successfully completed:

```text
Npcap interface -> pcap.ReadPacketData -> CanonicalEvent.Serialize -> FrameWriter.Send -> \\.\pipe\aegis_nose
```

The frame size is correct for the ABI:

```text
4-byte little-endian length + 109-byte canonical payload = 113 bytes
```

## Scope and remaining proof

This proves capture and pipe handoff, but the foreground output alone does not yet prove the Zig health counters increased for the same probe. The next step is to keep the capture process running, send the benign Kali HTTP request, and run the L7 coordinator/health check to confirm positive `nose_frames_read` and `nose_frames_submitted` deltas.

## Promotion state

```text
Raw Npcap packet delivery       = PASS
Go Nose capture                 = PASS
Canonical frame serialization   = PASS
Go Nose -> Zig pipe handoff     = PASS
Zig pipe counter correlation    = PENDING
L7 configured rule match        = PENDING
prevention_gate                 = CLOSED
```
