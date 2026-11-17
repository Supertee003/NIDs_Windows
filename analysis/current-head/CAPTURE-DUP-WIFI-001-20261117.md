# CAPTURE-DUP-WIFI-001 — the Wi-Fi capture path delivers every frame twice

**Created:** 2026-11-17T03:15+07:00
**Status:** **CLOSED (2026-11-17)** — not reproducible with a byte-level metric; see §Update at the end
**Original status:** OPEN — environmental capture behaviour, not a product defect
**Severity:** P3 (evidence/throughput inflation on one adapter)
**Measured at:** records HEAD `d7f9223`, build source `7c604d5`, runtime
`7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18`

## Finding

On the Killer Wi-Fi 6 AX1650i (`\Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B`),
Npcap delivers **every frame twice** to a capture handle. AEGIS therefore sees
two events for one wire frame: detections and anomaly rows are doubled, and
`nose_frames_read` / `nose_frames_submitted` count roughly twice the wire
frame count. Attribution stays correct; the detection logic is not at fault.

Found while closing `IDS-L7-003`: one malformed HTTP request produced two
`protocol_anomaly` rows with distinct `event_id`/`audit_id`, the same
`src_port`, and `mono_ns` identical or up to ~0.5 ms apart.

## Measurement

A single `dumpcap` handle on the Wi-Fi device, no promiscuous mode, one
synthetic request from the host bound to local port 45007:

```powershell
dumpcap -p -i "\Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}" `
  -f "tcp port 45007" -a duration:14 -w wifi-dup-45007.pcapng
python dup_probe.py 45007   # one connect + one GET / HTTP/1.1 without Host
```

Result (`wifi-dup-45007.tshark.txt`): 14 frames, every outbound frame twice:

| Pair | Same `ip.id` | Same TCP seq | Same payload | Δt |
|---|---|---|---|---|
| SYN | `0x29f9` | 0 | - | 7.1 µs |
| PSH/ACK | `0x29fb` | 1 | 18 B `GET / HTTP/1.1\r\n\r\n` | 7.0 µs |
| FIN/ACK | `0x29fd` | 19 | - | 12.7 µs |

The capture file has **one** interface block, Ethernet encapsulation, and the
two copies carry identical bytes. A retransmission would not reuse `ip.id`,
and no retransmission occurs 7 µs after the original.

Control (`vmnet1-control-arp.pcapng`): a capture on the VMware VMnet1 adapter
during three pings recorded three ARP requests — **no duplication**. The
behaviour is specific to this Wi-Fi adapter/Npcap path, not generic Npcap.

## Product checks that exclude a double enqueue

- `nose/capture.go:154-183`: one `ReadPacketData` result → one event →
  one `SendWithPayload`.
- `src/capture/nose_pipe_reader.zig:381-430`: one pipe frame → one
  `pushDecodedFrame`.
- `nose_frames_read` and `nose_frames_submitted` move together (718/718 in a
  short probe); `nose_duplicate_event_ids=0`; `nose_non_monotonic_event_ids=0`.
- The same doubling appears when the stimulus originates on the host itself,
  so it is not a VMware/bridged artifact.

## Impact

- Detection/evidence counts on this adapter are 2× the wire count. Halve them
  when reading `protocol_anomaly`, `signature_match`, and `nose_frames_*` on
  this host. Correctness of each verdict is unaffected.
- Queue admission and detection work are roughly doubled for the same wire
  load; this is visible in the soak budgets but has not caused loss
  (`capture_npcap` dropped 0 in every measured window).
- The IDS evidence receipts are per delivered event, so receipt sequences
  advance twice per wire frame. They remain internally consistent.

## Options (not taken in this release)

1. **No product change in T20.** Deduplicating by `(ip.id, tcp.seq, payload
   hash)` at ingress is a `src/` change, would need a new build/signature/
   install and a new 24 h window, and risks suppressing legitimate
   retransmissions if the window is wrong.
2. **Host/adapter fix.** Check Npcap's "raw 802.11" option and the Killer
   driver's packet-prioritisation path; a different adapter may not duplicate.
3. **v1.1 candidate.** If dedup is ever added, it must be bounded, counted
   (never silent), and proven not to drop a real retransmission.

## Evidence artifacts

Local-only (`admin-evidence/` is git-ignored):

- `admin-evidence/wifi-dup-20261117/wifi-dup-45007.pcapng`
- `admin-evidence/wifi-dup-20261117/wifi-dup-45007.tshark.txt`
- `admin-evidence/wifi-dup-20261117/vmnet1-control-arp.pcapng`
- `admin-evidence/wifi-dup-20261117/vmnet1-control-arp.tshark.txt`

Tracked summary: this record; context in
`analysis/current-head/IDS-L7-003-20261117.md` §5.

---

## Update 2026-11-17 (closure)

The finding above stands for the capture taken at 02:39, but the *counter* used to
generalise it could not distinguish a capture-path duplicate from a protocol-level
repeat: it matched frames on (src, dst, ip.id, tcp.seq|udp.length, len), and a TCP
Dup ACK repeats Seq/Ack with Len=0 and no payload. 	shark labels those pairs
[TCP Dup ACK] and they carry no IPv4 addresses, so they are not the same frame.

Re-measured with raw frame bytes (equal capture length AND equal sha256 within
2 ms):

- wifi-dup-45007.pcapng (02:39) → 5 identical-byte pairs in 14 frames,
  3.1-12.6 us apart, all host_tx (reproduces this record)
- 19 captures taken 09:34-09:52 UTC → 0 identical-byte pairs in 29,060 frames,
  including Dot11Support 0 vs 1, a narrow port filter shaped like the 02:39 run,
  and 1,126 fps with the Go Nose handle attached
- nose reported packets=26300 canonical=26300 dropped=0 (one event per frame)

The WLAN event log shows the association that produced this capture ended at
03:35:05 (11004) and the current one started at 14:31:01 (11010/11005), which is
where the behaviour is confined. **Root cause of the 02:39 event is not claimed.**
Reopen only if the byte-level probe reports a nonzero identical-byte pair count.

Full record: nalysis/current-head/CAPTURE-DUP-WIFI-20261117.md
