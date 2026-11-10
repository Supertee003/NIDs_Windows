# BOOT-RING-LOSS-E5 — boot order + 1 s retry: zero ring loss on 21A875CF

**Created:** 2026-11-11
**Measured on:** installed `21A875CF8F103E3BCC6AFC516A9F7AA097A568A1E5C562E2B4C2EBBD03A17585`
(source `1ca18c4`), boot **2026-11-11 02:09:14**
**Level:** E5 (Windows host, installed image hash-asserted, boot task transcript)

---

## 1. Result

| Check | Value |
|---|---|
| boot | 2026-11-11 02:09:14 |
| boot task start | 02:09:44 |
| `AegisNids` start (demand) | 02:09:50 |
| `AegisMinifilter` start (after daemon) | 02:09:53 |
| installed `aegis_nids.exe` | `21A875CF…` |
| services | all four `RUNNING` |
| `health.state` | `RUNNING`, `degraded=false` |
| `minifilter_ring_dropped` | **0** |
| `queue_dropped_total` | **0** |
| `scm_7031` since boot | none |
| `shed_overload` at first read | 18,035 |
| `shed_overload` delta over the next 120 s | **0** (pushed +31,868) |

The boot task log shows the intended order:

```
02:09:44  boot sequence start
02:09:50  starting AegisNids (minifilter reader will retry until its driver loads)
02:09:50  AegisNids -> RUNNING
02:09:53  drivers: AegisWfp STOPPED -> RUNNING; AegisMinifilter STOPPED -> RUNNING (started after daemon)
02:10:02  boot sequence done; probe written
```

## 2. What this proves

- Starting the daemon before the minifilter, with a 1 s port retry, produces a
  ring that starts empty and never overflows during the boot burst.
- The two earlier shapes are now measured and separated:
  - 2026-11-11 01:30 (AUTO_START, driver-first, 10 s retry): **448** drops;
  - 2026-11-11 01:49 (DEMAND_START, driver-first, 10 s retry): **4,012** drops;
  - 2026-11-11 02:09 (DEMAND_START, daemon-first, 1 s retry): **0** drops.
- The 18,035 `shed_overload` is the ETW admission policy (`QLOSS-ETW-PRIORITY-001`)
  working during the boot write storm, **not** queue loss and **not** minifilter
  loss. Its steady-state delta over two minutes is zero, so it is a boot
  transient, not a continuous shed.

## 3. What remains

1. **24 h soak:** the queue/shed counters are per-process and already carry the
   boot transient. A steady-state arm restarts the daemon (and reloads the
   minifilter) so the 24 h window starts at 0/0; the boot proof above is kept
   separately. This is the R-08 gate, still open.
2. **#30:** no crash in this window; a crash-free 24 h is still the evidence.
3. **Installer:** the boot order and task still live in `admin-evidence`
   (local-only). `tools/installer.py` creates `AegisNids` `AUTO_START` and never
   registers `AegisBootSequence`; a fresh install would reintroduce the gap.
4. **One host, one boot:** this is not fleet behaviour.

## 4. Evidence artifacts

| Artifact | Content |
|---|---|
| `admin-evidence/host-window-006-20261111/post-boot/post-boot-probe.json` | services, hashes, health, queue, SCM 7031 |
| `admin-evidence/host-window-003-20261110/boot-sequence.log` | boot task transcript with the new order |
| `admin-evidence/host-window-006-20261111/deploy-window-006-result.json` | hash-asserted deploy of `21A875CF…` |
