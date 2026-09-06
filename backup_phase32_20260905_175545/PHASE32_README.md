# AEGIS NIDS - Phase 32: Npcap Real Traffic Capture

**Risk**: MEDIUM | **Tier 3 - Core Capability Expansion** | **Status: DEPLOYED MODULE**

Real packet capture sensor for AEGIS NIDS using Npcap (WinPcap-compatible API).
The capture library is loaded **dynamically at runtime** - no import libs,
no `build.zig` changes, and graceful fallback when Npcap is not installed.

---

## Design (DevSecOps)

| Property | Value |
|---|---|
| Capture mode | **PASSIVE ONLY** - no packet injection anywhere in the module |
| Enforcement | Unchanged - blocking stays in the WFP kernel driver |
| Library loading | Dynamic (`std.DynLib`) - tries `System32\Npcap\wpcap.dll`, then legacy paths |
| Fallback | Without Npcap: module compiles, all 17 tests pass, parsing helpers remain usable (offline analysis) |
| Cross-platform | Same module also loads `libpcap.so` on Linux (host regression friendly) |
| Rollback | Delete the module / do not wire it into the pipeline - zero impact on running system |

## Files

| File | Purpose |
|---|---|
| `core/npcap_capture.zig` | Capture module (loader + parser + sensor + canonical events), 17 tests |
| `core/npcap_test_live.zig` | Standalone live-capture verification CLI |
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
   pollEvents()      - batch parse into CanonicalEvent[]
        |
PacketParser (pure)  - Ethernet / VLAN / IPv4 / TCP / UDP / ICMP
        |
CanonicalEvent       - normalized event for the AEGIS detection pipeline
```

Supported link types: `DLT_EN10MB` (Ethernet, incl. 802.1Q VLAN), `DLT_RAW`
(raw IP), `DLT_NULL` (BSD loopback).

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
| `protocol` | u8 | 6=TCP, 17=UDP, 1=ICMP, 0=other |
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
npcap_test_live.exe auto 50 "tcp port 80"    # 3) 50 packets with BPF filter
npcap_test_live.exe 5 30                     # 4) explicit device index
```

**Important**: Windows exposes many virtual devices (WAN Miniports, Hyper-V,
VMware, Wi-Fi Direct, VPN adapters) that carry NO traffic - capturing on
them yields `packets_seen 0`. Use `auto` mode: it skips virtual adapters
and APIPA (169.254.x.x) addresses and picks the physical adapter with a
real routable IPv4. The device list also marks suspects with
`[virtual/no-traffic?]` and prints a `Recommendation:` line.

Expected output on a healthy system: device list with IPs, then lines like
`#1    TCP 192.168.1.5:51298 -> 93.184.216.34:443 [SA] len=0` followed by
capture statistics (parse rate ~100%).

## Statistics

The sensor tracks: `packets_seen`, `packets_captured`, `packets_parsed`
(+`parseRate()`), per-protocol counters (tcp/udp/icmp/other),
`packets_malformed`, `packets_truncated`, `timeouts`, `errors`,
`events_emitted`, `last_event_ts`.

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
# 1. Unit tests (all 17 must pass, Npcap installed or not)
zig test core\npcap_capture.zig -lc

# 2. Build the live tool
zig build-exe core\npcap_test_live.zig -lc

# 3. Live capture (Administrator PowerShell)
.\npcap_test_live.exe
.\npcap_test_live.exe 0 30
```

- [ ] `zig test` reports **All 17 tests passed**
- [ ] `npcap_test_live.exe` lists adapters with correct IPv4
- [ ] Live capture shows real TCP/UDP traffic while browsing
- [ ] AEGIS core runtime unaffected (Bridge/Core/Brain/Nose/Mouth 5/5)

## DevSecOps Tier Progress

- Tier 1 (Safety Foundation): Phase 35 Backup, Phase 40 Compliance - DONE
- Tier 2 (Additive Integrations): Phase 33 SIEM, Phase 34 Config Hot-Reload - DONE
- **Tier 3 (Core Expansion): Phase 32 Npcap Capture - DONE (this phase)**
- Tier 3 next: Phase 38 Web UI Dashboard (isolated Next.js service)
