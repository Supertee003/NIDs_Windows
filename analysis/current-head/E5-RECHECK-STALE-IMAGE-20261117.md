# E5-RECHECK-STALE-IMAGE-20261101 — current image re-proven with live canaries

**Date:** 2026-11-17
**Gap:** `E5-RECHECK-STALE-IMAGE-20261101` (was E1)
**Result:** PASS, E5 (live Kali -> this host window on the installed image)
**Window:** `e5-recheck-20261117`, 120 s

## Previous blocker

The RB-021 recheck was blocked because the installed runtime did not match the
source it was supposed to prove. That half was already resolved on 2026-11-15:
the installed image and `zig-out\bin\aegis_nids.exe` are both
`7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18`. What
remained was the canary run itself; it needed a peer on the sensor's link.

## Method (RB-022, no restart)

Kali 2025.2 was moved from host-only to bridged and given DHCP
`192.168.1.44`; the sensor watches the Killer Wi-Fi AX1650i at
`192.168.1.39`. The service was **not** stopped, restarted or reconfigured.
A host HTTP listener on `:8080` gave the L7 payloads a completed handshake.

```
python tools\lab_attack_window.py --label e5-recheck-20261117 \
  --seconds 120 --expect-src 192.168.1.44
```

While the window was open, Kali sent: SQLi (`R0056`), XSS (`R9059`), path
traversal (`R0088`), command injection (`R9064`), HTTP anomalies `10004` and
`10001`, an `nmap -sS` 60-port burst (`R9006`) and a 120-packet ICMP flood
(`R9002`).

## Result

- preflight: wire ingress advancing, **+823 frames / 5 s**
- frames gained: **9,017**
- new rows: 44; **attributed to 192.168.1.44: 15**
- `dropped_total`, `shed_overload`, `source_quota_shed`: **all delta 0**
- verdict: **PASS (exit 0)**

| rows | rule |
|---:|---|
| 2 | `R0056` SQL Injection (Auth Bypass) |
| 2 | `R9059` Cross-Site Scripting (Basic) |
| 2 | `R0088` Path Traversal (Sensitive) |
| 2 | `R9064` OS Command Injection (Semicolon) |
| 2 | protocol anomaly `10004` |
| 2 | protocol anomaly `10001` |
| 2 | `R9002` ICMP Flood (DoS) |
| 1 | `R9006` TCP SYN Stealth Scan |

Two rows per stimulus are expected on this adapter: `CAPTURE-DUP-WIFI-001`
documents that this Wi-Fi/Npcap path delivers every frame twice. Attribution
and verdicts are correct; the counts are 2x. The anomaly ids are observe-only
and correctly appear as `UNKNOWN` in the catalog table (`10004`/`10001` are not
in `Rules.json`).

## What this closes

The canaries ran against the **current installed image** on the sensor's real
link, with zero loss, and every firing was attributed to the attacker IP. The
stale-image blocker is gone and the canary half is now proven. This is the E5
result the gap was waiting for; no restart was required and the 24.62 h process
window stayed intact.

## Evidence artifacts

- `admin-evidence/lab-e5-recheck-20261117/attack-window-20261116T202547Z.json`
- `admin-evidence/lab-e5-recheck-20261117/attack-window-20261116T202547Z.md`
- This record; `EVIDENCE_INDEX.json#E5-RECHECK-STALE-IMAGE-001-E5-20261117`

## Restore

Kali was returned to host-only `192.168.126.10` (vmx restored from
`*.bak-e5recheck-20261117`, NetworkManager profile set back to manual) and the
host HTTP listener was stopped. The sensor binding was never changed.
