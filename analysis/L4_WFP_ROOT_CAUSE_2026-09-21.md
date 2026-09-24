# L4/WFP Root Cause — 2026-09-21

## Conclusion

The WFP service and device path are healthy, but the installed driver is not the current project build. The active driver is a stale artifact from 2026-09-04, while project driver artifacts were produced on 2026-09-21 with different sizes. Therefore the current `events_read_bytes=0` result cannot be used to qualify the current source implementation.

## Evidence from host

| Item | Observed |
|---|---|
| Driver service | `AegisWfp`, `Running`, `Status=OK`, `Started=True` |
| Installed path | `C:\Windows\System32\drivers\aegis_wfp.sys` |
| Installed hash | `49F7B3E35680F3C827FFBCEAF21FD19293288E0746617C00CF39BBDFA1D33739` |
| Installed size | `11752` bytes |
| Installed timestamp | `2026-09-04 21:57:42` |
| Current project artifacts | `build\drivers\wfp\aegis_wfp.sys` (14224 bytes), `build\Release\aegis_wfp.sys` (12800 bytes) |
| Expected path queried | `build\x64\wfp\aegis_wfp.sys` does not exist |
| WFP device | Opens successfully |
| Read-only IOCTL | `GET_STATS` and `READ_EVENTS` succeed |
| Event ingress | `0` bytes from localhost probe |

## Stale filters found

The WFP export contains the current-looking capture filter:

```text
AEGIS Inbound Transport V4 Capture
layer: FWPM_LAYER_INBOUND_TRANSPORT_V4
```

It also contains stale dynamic block filters:

```text
AEGIS IPS Block
AEGIS_BLOCK_10.0.0.99
description: Blocked by Aegis NIDS Tier-2 Rule R0056
```

Multiple filters with the same `AEGIS_BLOCK_10.0.0.99` name were found. These filters must be treated as stale/unknown ownership until their exact filter IDs, runtime generation, and cleanup receipts are reconciled.

## Safety decision

Do not run attack traffic or valid block tests while stale filters exist. Do not claim `BLOCK_PROVEN`. Keep the prevention gate closed. A stale filter can change host traffic independently of the current daemon and can invalidate any proof result.

## Correct next sequence

1. Record the current WFP export and installed/project hashes as evidence.
2. Stop the old AEGIS daemon and stop the driver using the user's elevated maintenance procedure.
3. Rebuild the driver from the current source using the WDK build script.
4. Verify the new driver hash and size before installation.
5. Install/start the new driver and verify its service path/hash.
6. Export WFP filters again and reconcile/remove stale AEGIS filters using the project's controlled cleanup procedure.
7. Confirm no stale `AEGIS_BLOCK_*` filters remain and prevention gate is still closed.
8. Rerun the read-only L4 proof.

The existing WFP capture filter proves that a filter object exists in the WFP store; it does not prove that the installed driver binary matches the current source or that the classify callback wrote to the ring.
