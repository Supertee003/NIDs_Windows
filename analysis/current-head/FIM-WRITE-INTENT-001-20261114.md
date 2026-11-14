# FIM-WRITE-INTENT-001 — the minifilter emits writes and creates, not every open

**Created:** 2026-11-14
**Build source before this patch:** `e4c2188`
**Finding:** R1005 (hosts File Modification) and R1001 (System32 Write Attempt)
fired on a read-only `Get-Content`; the minifilter emitted every
`IRP_MJ_CREATE`, and the rules match paths without an operation filter.
**Level:** E2 (driver build/sign + source pins). The host read/write canary is
the E5 gate.

---

## 1. Why the path rules fired on a read

`AegisPostOperation` in `drivers/minifilter/aegis_minifilter_file.c` wrote an
event for every successful create/open, with no access check. On a read of
`C:\Windows\System32\drivers\etc\hosts` the minifilter produced a create record,
the AC matched the `hosts` path, and R1005 raised a High "modification" alert.
The same happened for R1001 on System32 DLL reads.

The record struct has no desired-access field, and adding one would be a
kernel/user ABI change. The classification can be done entirely in the driver.

## 2. What changed

`drivers/minifilter/aegis_minifilter_file.c`:

- `AegisWriteIntent(data)` reads
  `Parameters.Create.SecurityContext->DesiredAccess` and the high-byte
  `CreateDisposition`:
  - write intent when access has `FILE_WRITE_DATA`, `FILE_APPEND_DATA`,
    `FILE_WRITE_ATTRIBUTES`, `DELETE`, `WRITE_DAC` or `WRITE_OWNER`;
  - write intent when disposition is `FILE_SUPERSEDE`, `FILE_CREATE`,
    `FILE_OVERWRITE` or `FILE_OVERWRITE_IF`;
  - otherwise read-only.
- `AegisPreCreate` stores a one-bit sentinel in the callback context
  (`(PVOID)1` for write intent, `NULL` otherwise) and still requests the
  post-op callback.
- `AegisPostOperation` returns immediately when `ctx == NULL`, so a read-only
  open never reaches the ring.

No record, IOCTL, ring or user-mode ABI change. The post-op does not touch the
create security context (which may be gone after completion); it only reads the
sentinel.

## 3. Build and signature

```
scripts\wdk_build_minifilter.ps1 -> BUILD OK, 10,240 bytes
  (unsigned hash printed by the build; not retained after signing)
scripts\minifilter_sign.ps1      -> Valid (CN=AEGIS Test Signer)
  signed SHA-256   8AC348372321ECFE5BD535B9A9A19F6F6567C58145395359764AFCAF5C2480E0
```

Source pins: `tests/release/test_fim_write_intent.py` (classification tokens;
post-op sentinel gate; no `UNREFERENCED_PARAMETER(ctx)` in the post-op).

## 4. E5 gate (not yet run)

Deploy with `admin-evidence/host-window-006-20261111/deploy-driver-007.ps1`
(elevated, hash-asserted, rollback copy first), then:

1. read `hosts` -> **no R1005**;
2. write `hosts` (backup/restore) -> **R1005**;
3. read a System32 DLL -> **no R1001/R1004**;
4. drop a benign `.dll` in System32 -> **R1004**;
5. verify `queue` losses and `minifilter_ring_dropped` stay 0.

The driver is test-signed; the host already trusts `CN=AEGIS Test Signer`.

## 5. Limitations

- `FILE_OPEN_IF` with read-only access is treated as read-only even if the file
  is created; a create that needs write access normally requests it.
- Rename/delete via `SetInformation` is still not emitted; R1002 relies on the
  create of the new name.
- Test-signed driver; no production signing custody.
- The change reduces FIM volume, which also reduces queue pressure, but it has
  not been measured for 24 h.
