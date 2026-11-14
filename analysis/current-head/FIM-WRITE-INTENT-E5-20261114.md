# FIM-WRITE-INTENT-E5 — read-only opens are gone; writes still alert

**Created:** 2026-11-14
**Measured on:** installed minifilter
`8AC348372321ECFE5BD535B9A9A19F6F6567C58145395359764AFCAF5C2480E0`
(previous `10C41E80…`), daemon `680510AB…` (source `87e780e`)
**Level:** E5 (host, driver hash-asserted, live read/write canaries)

---

## 1. Sequence and result

| Canary | Expected | Observed |
|---|---|---|
| read `hosts` | no R1005 | **R1005 = 0** in the read capture |
| write `hosts` | R1005 | **R1005 = 2** (seq 6610, 6611) |
| restore `hosts` (write) | R1005 | R1005 at 7413, 7414, 7493 |
| read `kernel32.dll` | no R1004 | **R1004 = 0** in the read capture |
| drop benign `.dll` in System32 | R1004 | **R1004 = 1** (seq 8034) + R1001 8035/8064 |

The read-only captures contain no new R1005/R1004 records; the write captures do
contain them. The driver swap itself is hash-asserted:

```
pre  10C41E8043EE08E0…
post 8AC348372321ECFE…   (expected)
service RUNNING, health RUNNING, minifilter_ring_dropped=0
```

## 2. What this proves

- The pre-create classification and the post-op sentinel work on the live
  filter manager: read-only opens no longer reach the ring, so R1005/R1001 no
  longer fire on a plain read.
- Writes/creates still reach the ring: R1005 on a hosts write, R1004 on a DLL
  drop.
- No record/ABI change was needed; the ring stayed at 0 drops through the swap.

## 3. The remaining R1001 noise is not a read false positive

`fim-read.json` still contains 16 R1001 records (seq 2354–3825). They are
**background System32 writes/creates by services**, not the hosts read: R1001
matches every `C:\Windows\System32` path and the host performs legitimate
System32 writes continuously. The read-only hosts open did not add an R1005,
and the read-only DLL open did not add an R1004.

So the operation filter fixed the read-trigger class; R1001 remains a broad
path rule that fires on legitimate system writes. Tuning it (path allow-list,
file-owner, or write-size) is a separate detection-quality decision.

## 4. Limitations

- One host, one driver swap, one canary set.
- Test-signed driver (`CN=AEGIS Test Signer`); no production signing custody.
- `FILE_OPEN_IF` with read-only access is treated as read-only even if it
  creates; a create normally requests write access.
- Rename/delete via SetInformation is still not emitted.
- R1001 is noisy on legitimate System32 writes; not addressed here.
- The FIM volume reduction was not measured over 24 h.
