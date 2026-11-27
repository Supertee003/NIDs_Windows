# Late finalizer of the voided `214622` soak — real FAIL, runtime swap, STOP-THE-LINE

**RECORD-ID:** `SOAK-VOID-GAPS-FIRST-LATE-FINALIZER-AA3B7B0-20261127`  
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged; records-only)  
**RUN-ID:** `20261126-214622` (voided at `2026-11-26T22:28:41`)  
**FINALIZER OUTPUT:** `2026-11-27T21:47:03+07:00` — `verdict=FAIL`  
**RELATED:** issue #55 (STOP-THE-LINE), issue #54 (post-soak rebaseline), `docs/PATH-TO-COMPLETE.md`

This is an **addendum**, not a rewrite. `SOAK-ATTEMPT-VOID-GAPS-FIRST-AA3B7B0-20261126.md` and its `EVIDENCE_INDEX` entry remain the record of the owner-directed void at `22:28:41` on `11/26`. This page records a later, independently observed event: the finalizer that was believed deleted was still alive and produced a verdict the next day.

## What actually happened

1. Window `214622` was voided before 24 h. The void record states the task was deleted and the baseline restored with `restore.verified=true`, `errors=[]`. That statement is accurate **as of the void**.
2. A finalizer process from that window nevertheless kept running. At `21:46:50` on `11/27` it ran the final check against the `22:59`-era host and wrote `soak-final.json` at `21:46:51` and `result.json` at `21:47:03`, then restored the pre-soak binaries with `restore.verified=true`.
3. The verbatim verdict is **FAIL**, not PASS:

| Field | Value |
|---|---|
| `check_exit` | `3` |
| `verdict` | `FAIL` |
| `soak_start` / `target_end` | `2026-11-26T21:46:50` / `2026-11-27T21:46:50` |
| `elapsed_hours` | `24.0` |
| `daemon_uptime_hours` | `22.8` |
| `daemon_health_state` | `DEGRADED` |
| `queue_dropped_total` delta | `238597` |
| `minifilter_ring_dropped` delta | `3336713` |
| `minifilter_pipeline_dropped` delta | `58970` |
| `process_generation_ms` | `1795704400212 → 1795708740368` |
| `restore.verified` | `true` |
| `errors` | `[]` |

The six recorded problems are: daemon uptime shorter than the window (process restarted mid-soak); daemon `DEGRADED`; process generation changed inside the window so counter deltas are meaningless; and the three counter deltas above exceeding the loss budget `0` used by the checker. No value was relaxed, edited or re-labelled.

4. That restore wrote the pre-`214622` binaries into `C:\Program Files\AEGIS NIDS\runtime` at `21:47:03`. Read-only hash verification at `21:48:01` found:

| File | Installed at `21:48:01` | Pinned for live window `225843` |
|---|---|---|
| `aegis_nids.exe` | `FBD9BDB3456C9C7DAFCBF1B0C3FBDAD9778F61C3186167856E373CC376185474` | `6F548AF7641C1C476FB591D165ED734027ED18D93F980AFEA755C20A716BBB98` |
| `aegis-nose.exe` | `AEAB9B6324E3A7EA0498B0A338E406C012139F15D883465AE574CAC773BC79C2` | `8C05FE485D2548DF50C83F5BEA792F4228FEAE387306668A439912A39A7D24D4` |
| `aegis_pep.dll` | `870CB9626EDD75AD2552F1CDFE6475D8A7804163354E3A588FED1E4360996C5E` | `6E05AAE1BAE000C8D2C1A841EFF9B65035E5131066FFB43800AD414659564926` |

Window `225843` started at `2026-11-26T22:59:10` with those pinned hashes, `nose_connected=true` and `health_state=RUNNING`, and was still heartbeating to `22:59:10` on `11/27`. Its runtime therefore changed about 72 minutes before the window end. This is a **build/runtime mismatch and a silent runtime swap during a live soak** — a STOP-THE-LINE trigger under `AGENTS.md`.

5. `AegisNidsSoakFinalize_20261126-225843` was no longer listed by `Get-ScheduledTask` or `schtasks /Query` when checked; only a watcher process and the heartbeat loop remained. An owner-side elevated run of `owner_soak_start.ps1` at about `21:46` exited `0` but created no new `owner-soak-aa3b7b0-*` directory and no task, so it produced no clean replacement window. The agent did not run that script and did not touch the host.

## Consequences (no extrapolation)

- `225843` is **VOID** for current-source soak evidence even if a later `result.json` says `PASS`; no counter delta after `21:47:03` can be attributed to a stable `aa3b7b0` runtime.
- The `214622` FAIL is recorded honestly for a void window. It neither closes nor independently fails a gate; `soak_24h` stays **OPEN** and the board stays **5/6 — NOT SHIPPABLE**.
- No PASS, E5 host proof, E6/E7, new signature, signed driver or driver-load claim arises from this record.
- Product-source changes, gate/guard edits and verdict edits remain frozen pending owner decisions.

## Verbatim artifacts and integrity

`analysis/current-head/raw-aa3b7b0-20261126/soak-void-gaps-first-late-finalizer/`

| File | SHA-256 | Source equality |
|---|---|---|
| `result.json` | `0E3D136EB5FFE817192E239B3625379336F8BB5FDDDB3F8570E5504DAF6E4C70` | byte-exact copy verified |
| `soak-final.json` | `9438E1B4716908B2BEA46C02C0B1AE9153CF9F6EFDCCC96EDD4F06F9B876A855` | byte-exact copy verified |
| `finalize.log` | `3E3FC801ECD52DFBEA211A0ECE03F95EA04707B53A188F37018497053DEFA732` | byte-exact copy verified |
| `verbatim-manifest.json` | records source/copy hashes, byte counts, source timestamps and the no-claim boundary | — |

The script timestamps are labelled `Z` but match the operator's `+07:00` filesystem clock; they are reported as local clock labels, not verified UTC.

## Owner action required before further host work

1. Stop/clean the stale finalizer and watcher from `225843` so no overlapping restore can touch a live window.
2. Arm exactly one clean 24 h window with a single verifiable finalizer and no concurrent host work; recycle the minifilter gauge before the window; keep `loss_budget` unchanged.
3. Only then consume a real verdict under the acceptance rules in issue #54: `verdict=PASS`, `elapsed_hours>=24`, `problems=[]`, `restore.verified=true`, counter deltas consistent with the raw transcript. Otherwise record VOID/FAIL honestly.
