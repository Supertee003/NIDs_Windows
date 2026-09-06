# AEGIS NIDS - Phase 32: Npcap Real Traffic Capture (v3)

**Risk**: MEDIUM | **Tier 3 - Core Capability Expansion** | **Status: FIELD-VERIFIED + v3 (ARP visibility)**

Real packet capture sensor for AEGIS NIDS using Npcap (WinPcap-compatible API).
The capture library is loaded **dynamically at runtime** - no import libs,
no `build.zig` changes, and graceful fallback when Npcap is not installed.

## v3 ARP-Visibility Update (after "only TCP, no ARP" field report)

Field report: `auto 30` showed only TCP frames, `arp=0`. **Root cause is traffic
conditions, not the capture code**: `auto 30` is a *30-packet* window, and on a
busy network 30 TCP packets arrive in about a second - the window closes long
before any ARP frame happens to pass. ARP is bursty by nature: a frame only
appears when some host needs an IP->MAC resolution (first contact / ARP-cache
expiry), so packet-count windows on TCP-heavy links routinely miss it.

v3 changes to `npcap_test_live` (capture core unchanged, still 25 tests):

1. **Duration mode**: `auto 30s` captures for 30 *seconds* regardless of packet
   count - bursty protocols get a fair chance to appear. `30` (no suffix)
   still means 30 packets. Packet-count mode hard time cap raised 30s -> 120s.
2. **Live progress tick** every 5s in duration mode:
   `[t=10s] tcp=812 udp=31 icmp=0 ipv6=64 arp=2 eapol=0 l2=12+3`
   so you can watch the ARP counter grow while the window is open.
3. **Zero-ARP diagnostic hint**: when a run ends with `arp=0` (but packets
   were captured), the tool prints exact commands to force ARP traffic and
   retest (flush cache, ping gateway, rerun with `arp` BPF focus).

### How to see ARP traffic (3 steps, admin PowerShell)

```
arp -d *                          # 1) flush the ARP cache (forces re-resolution)
ping 192.168.1.1 -n 3             # 2) ping your gateway ('ipconfig' -> Default Gateway) -
                                  #    generates ARP request + reply on the wire
.\npcap_test_live.exe auto 30s arp   # 3) rerun with ARP-focused 30s window
```

Expected: lines like `#3 ARP request 192.168.1.41 -> 192.168.1.1` and
`#4 ARP reply 192.168.1.1 -> 192.168.1.41`, plus `arp N` (N >= 2) in the
statistics block. `arp -d *` needs admin because the capture session already
runs elevated in Npcap admin-only mode.

## v2 Field-Test Update (Killer Wi-Fi 6 AX1650i, 192.168.1.41)

First live capture succeeded: `auto 30` picked the physical Wi-Fi adapter,
**32/32 frames parsed (rate 100%)**, TCP flows read correctly with direction
(e.g. `192.168.1.41:63087 -> 47.239.134.228:443 [PA]`).

v2 was driven by what the field test revealed:

1. **30/32 frames showed as `L2 ethertype=0x0 len=0`** - these are
   **802.11 null-data / power-save keepalive frames**. Npcap converts them to
   Ethernet-style headers with type=0 and NO payload. They are benign L2
   chatter (often from the station <-> AP pair, others visible due to
   promiscuous mode) - not a parser bug. v2 classifies them as
   `dot11_null` and prints `dot11-null keepalive (wifi L2 chatter, no IP)`.
2. **Event policy fix**: v1 emitted a CanonicalEvent for EVERY frame,
   including keepalives (all-zero-IP events). v2 emits events **only for
   L3 frames (IPv4 / IPv6 / ARP)**; L2 chatter is counted in stats instead.
3. **New protocol coverage**: IPv6 (fixed 40-byte header + extension-header
   walk), ARP (request/reply with spa/tpa - groundwork for future ARP-spoof
   detection), EAPOL (802.1X auth over raw ethertype or LLC/SNAP),
   802.3 + 802.2 LLC / SNAP encapsulation, STP detection.
4. **`pollFrames()` API** returns rich `FrameInfo` (L2Class + IPv6 + ARP)
   for diagnostics/UI, while `pollEvents()` remains the frozen
   CanonicalEvent pipeline contract.

---

## Design (DevSecOps)

| Property | Value |
|---|---|
| Capture mode | **PASSIVE ONLY** - no packet injection anywhere in the module |
| Enforcement | Unchanged - blocking stays in the WFP kernel driver |
| Library loading | Dynamic (`std.DynLib`) - tries `System32\Npcap\wpcap.dll`, then legacy paths |
| Fallback | Without Npcap: module compiles, all 25 tests pass, parsing helpers remain usable (offline analysis) |
| Cross-platform | Same module also loads `libpcap.so` on Linux (host regression friendly) |
| Rollback | Delete the module / do not wire it into the pipeline - zero impact on running system |

## Files

| File | Purpose |
|---|---|
| `core/npcap_capture.zig` | Capture module (loader + parser + sensor + canonical events), **25 tests** |
| `core/npcap_test_live.zig` | Standalone live-capture verification CLI (v3: duration mode + ARP hint) |
| `PHASE32_README.md` | This document |

## Architecture

```
NpcapLoader          - loads wpcap.dll/libpcap.so, resolves pcap_* symbols
        |
enumerateDevices     - lists adapters with name, description, IPv4, flags
        |
NpcapSensor          - capture session
   open()            - pcap_open_live (snaplen, promisc, read timeout)
   setBpfFilter()    - pcap_compile + pcap_setfilter (kernel-level filtering)
   readPacket()      - pcap_next_ex -> one PacketFrame (or null on timeout)
   pollFrames()      - batch parse into FrameInfo[] (EVERYTHING, incl. L2)
   pollEvents()      - batch parse into CanonicalEvent[] (L3 only)
        |
PacketParser (pure)  - classifyEthernetFrame -> L2Class
        |             Ethernet / VLAN / LLC-SNAP / ARP / IPv4 / IPv6 /
        |             TCP / UDP / ICMP / ICMPv6 / EAPOL
CanonicalEvent       - normalized event for the AEGIS detection pipeline
```

Supported link types: `DLT_EN10MB` (Ethernet, incl. 802.1Q VLAN + LLC/SNAP),
`DLT_RAW` (raw IPv4/IPv6), `DLT_NULL` (BSD loopback).

### L2Class - what the wire actually carries

| Class | Meaning | Pipeline event? |
|---|---|---|
| `ipv4` / `ipv6` / `arp` | L3 traffic (ARP via SNAP included) | YES |
| `vlan` | 802.1Q tag, inner L3 parsed transparently | YES (inner) |
| `eapol` | 802.1X authentication frames | stats only |
| `dot11_null` | 802.11 null-data/keepalive (type=0, no payload) | stats only |
| `llc_stp` | 802.1D spanning tree | stats only |
| `llc_snap_other` / `llc_other` / `l2_unknown` | other L2 chatter | stats only |

## Quick Start (Zig integration)

```zig
const npcap = @import("npcap_capture.zig");

// Load capture library (graceful if missing)
var loader = npcap.NpcapLoader.load();
defer loader.deinit();
if (!loader.available) return error.NpcapUnavailable;

// List devices, pick one with an IPv4
var devices: [npcap.MAX_DEVICES]npcap.DeviceInfo = undefined;
const count = try npcap.enumerateDevices(&loader, &devices);

// Open sensor
var sensor = try npcap.NpcapSensor.init(allocator, &loader, devices[0].name());
defer sensor.deinit();
try sensor.open(npcap.SNAPLEN, true, 500);          // promiscuous, 500ms timeout
sensor.setAdapterIp(if (devices[0].has_ipv4) devices[0].ipv4 else null);
try sensor.setBpfFilter("tcp or udp");               // optional kernel filter

// In the capture loop:
var frame_buf: [npcap.MAX_FRAME_SIZE]u8 = undefined;
var events: [64]npcap.CanonicalEvent = undefined;
while (running) {
    const n = try sensor.pollEvents(events[0..], &frame_buf);
    for (events[0..n]) |ev| {
        // ev.protocol (6=TCP/17=UDP/1=ICMP), ev.src_ip/dst_ip, ports,
        // ev.tcp_flags, ev.direction (in/out), ev.timestamp_ns
        // -> feed into detection_engine / flow_engine pipeline
    }
}
```

### CanonicalEvent fields

| Field | Type | Meaning |
|---|---|---|
| `timestamp_ns` | i64 | Packet timestamp (unix epoch, nanoseconds) |
| `src_ip` / `dst_ip` | [4]u8 | IPv4 addresses |
| `src_port` / `dst_port` | u16 | Transport ports (0 for non-TCP/UDP) |
| `protocol` | u8 | 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, 0=other |
| `tcp_flags` | u8 | FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20 |
| `payload_len` | u16 | L4 payload bytes seen |
| `event_type` | enum | packet_tcp / packet_udp / packet_icmp / packet_other |
| `direction` | enum | inbound / outbound / unknown (vs adapter IP) |

Field mapping note: adapt these into the repo's canonical event contract
(`core/canonical*.zig`) inside a thin adapter function when wiring the sensor
into `nids_capture.zig`.

## Live Verification Tool

```
zig build-exe core\npcap_test_live.zig -lc

npcap_test_live.exe                          # 1) list devices + recommendation
npcap_test_live.exe auto                     # 2) auto-pick best real adapter, 20 packets
npcap_test_live.exe auto 30s                 # 3) 30 SECONDS, all protocols, live ticks
npcap_test_live.exe auto 30s arp             # 4) 30s window, ARP-only (see ARP traffic)
npcap_test_live.exe auto 50 "ip or arp"      # 5) 50 packets, hide wifi L2 chatter
npcap_test_live.exe auto 50 "tcp port 80"    # 6) 50 packets with BPF filter
npcap_test_live.exe 5 30                     # 7) explicit device index
```

**Important**: Windows exposes many virtual devices (WAN Miniports, Hyper-V,
VMware, Wi-Fi Direct, VPN adapters) that carry NO traffic - capturing on
them yields `packets_seen 0`. Use `auto` mode: it skips virtual adapters
and APIPA (169.254.x.x) addresses and picks the physical adapter with a
real routable IPv4. The device list also marks suspects with
`[virtual/no-traffic?]` and prints a `Recommendation:` line.

Expected output on a healthy system: device list with IPs, then lines like
`#1    TCP 192.168.1.41:63087 -> 47.239.134.228:443 [PA] len=51`,
`#7    ARP request 192.168.1.41 -> 192.168.1.1`,
`#12   L2  ... dot11-null keepalive (wifi L2 chatter, no IP)`
followed by capture statistics (parse rate ~100%).

## Statistics

The sensor tracks: `packets_seen`, `packets_captured`, `packets_parsed`
(+`parseRate()`), per-protocol counters (`tcp`/`udp`/`icmp`, `other-ip`,
`ipv6`, `arp`, `eapol`), L2 buckets (`l2_keepalive`, `l2_other`),
`packets_malformed`, `packets_truncated`, `timeouts`, `errors`,
`pipeline_events` (L3-only events), `last_event_ts`.

## Windows Notes

- Install Npcap from https://npcap.com/ with **"Install Npcap in WinPcap
  API-compatible Mode"** checked (default).
- If Npcap was installed with **"Restrict Npcap driver's access to
  Administrators only"**, run AEGIS (and the test tool) as Administrator -
  same requirement as the WFP BLOCK path.
- Promiscuous mode is enabled by `open(..., promiscuous=true, ...)`; on
  Wi-Fi adapters Npcap may deliver 802.11-converted frames only when the
  vendor driver supports native monitor mode (Ethernet NICs recommended
  for first verification).

## Verification Checklist

```powershell
# 1. Unit tests (all 25 must pass, Npcap installed or not)
zig test core\npcap_capture.zig -lc

# 2. Build the live tool
zig build-exe core\npcap_test_live.zig -lc

# 3. Live capture (Administrator PowerShell)
.\npcap_test_live.exe auto
.\npcap_test_live.exe auto 30 "ip or arp"
```

- [ ] `zig test` reports **All 25 tests passed**
- [ ] `npcap_test_live.exe` lists adapters with correct IPv4
- [ ] Live capture shows real TCP/UDP traffic while browsing
- [ ] Wi-Fi keepalives labeled `dot11-null keepalive` (not `ethertype=0x0`)
- [ ] AEGIS core runtime unaffected (Bridge/Core/Brain/Nose/Mouth 5/5)

## DevSecOps Tier Progress

- Tier 1 (Safety Foundation): Phase 35 Backup, Phase 40 Compliance - DONE
- Tier 2 (Additive Integrations): Phase 33 SIEM, Phase 34 Config Hot-Reload - DONE
- **Tier 3 (Core Expansion): Phase 32 Npcap Capture - DONE (this phase)**
- Tier 3 next: Phase 38 Web UI Dashboard (isolated Next.js service)
