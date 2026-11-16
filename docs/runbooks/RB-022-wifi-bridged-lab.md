# RB-022: Wi-Fi LAN Lab Proof (bridged Kali → this host, no restart)

## Objective

Prove that AEGIS detects a real attacker over the segment the sensor is
actually watching, with **this Windows host as the victim** and a Kali VM as
the attacker — without stopping, restarting, or reconfiguring any AEGIS
service.

RB-021 proves the isolated host-only path, but that path needs the machine
`AEGIS_DAEMON_IFACE` pin plus a service restart. A restart ends a running soak
window (see `analysis/current-head/SOAK2-20261115.md`: a restart means a third
24 h window). This runbook is the alternative that costs nothing: attack the
same link the canonical Go Nose already listens on.

**Why this section exists.** The daemon's production network ingress is Go
Nose, which auto-selects the first physical adapter that has an address
(`nose/capture.go:firstUpDevice`; adapters labelled WAN Miniport, Hyper-V,
VMware, Bluetooth, Wi-Fi Direct, TeamViewer, or loopback are skipped). On a
host whose only live link is Wi-Fi, that is the Wi-Fi NIC. A Kali VM on a
**host-only** VMnet therefore attacks a virtual switch the sensor never opens:
every packet is real, and every detection is zero. That silence is a capture
topology fact, not a detector defect, and it is the single most common way a
lab run gets misread.

Measured on this host (2026-11-15, for reference only — never hardcode it):

| Fact | Value |
|---|---|
| Selected capture device | `\Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}` |
| Description | Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter |
| Host IPv4 on that device | `192.168.1.39` |
| Ingress preflight | `+5219` frames in 5 s |
| `queue.stats` source ordinal 1 | `capture_npcap`, pushed 1,169,815, dropped 0 |

## Prerequisites

- AEGIS runtime running (`aegisctl.py status` shows the core operational and
  `data_plane.nose_connected: true`).
- Kali VM configured with a **Bridged** network adapter (not Host-only, not
  NAT) bound to the same physical adapter the sensor watches.
- Admin PowerShell on this host only if you need to read
  `C:\Windows\System32\logs\aegis_core.ndjson`; the tool itself needs nothing.
- Nothing in this runbook writes policy, rules, or WFP state. The prevention
  gate stays `closed`; `tier3_enforcing` stays `false`.

## Steps

### 1. Prove the capture path before firing anything

```powershell
python tools\lab_attack_window.py --preflight
```

Expected shape:

```
capture device : \Device\NPF_{...}
  description  : <physical adapter>
  target IPv4  : 192.168.1.39
preflight      : wire ingress advancing (+<N> frames)
PREFLIGHT OK: the sensor is receiving frames on this device
```

`target IPv4` is what the attacker must hit. Exit code `3` means ingress did
not advance: **do not continue** — the sensor is not on that segment, and any
result after it would be a false negative.

### 2. Put Kali on the same link

In the VM settings set the network adapter to **Bridged**, replicating the
physical adapter named in step 1. Then confirm from Kali:

```bash
ip -4 addr show | grep inet          # must be the same /24 as target IPv4
ping -c 3 192.168.1.39               # host must answer
```

If ping fails, stop: many access points enable client isolation, which blocks
VM-to-host frames at the AP. That is a network property, not a NIDS fault.
Move the lab to a switch/AP without isolation, or wait for the RB-021 window.

Check the address Kali received before trusting anything else. `192.168.5.x` is
VMware NAT, `192.168.126.x`/`192.168.127.x` are the host-only VMnets, and neither
is the sensor's link. If Bridged (Automatic) picked the wrong NIC - common when a
wired adapter exists but is disconnected - open Virtual Network Editor -> VMnet0
-> Bridged to a specific adapter and select the physical Wi-Fi adapter named in
step 1, then re-check with `ip -4 addr`.

### 3. Open the measurement window, then fire

Start this first (it samples, waits, then measures):

```powershell
python tools\lab_attack_window.py --label wifi-bridged-20261116 `
  --seconds 240 --expect-src <kali-ip>
```

While it waits, run the attacks from Kali. Thresholds come from
`configs/Rules.json`; anything below them is a probe bug, not a detector miss:

```bash
# R9006 needs >= 20 distinct destination ports from one source in 10 s
nmap -sS -Pn -n -p 1-60 --max-retries 1 --host-timeout 30s 192.168.1.39
# R9007 is per-packet: exact FIN|PSH|URG
nmap -sX -Pn -n -p 1-30 --max-retries 1 --host-timeout 30s 192.168.1.39
# R9002 needs >= 50 ICMP in 1000 ms
sudo ping -c 120 -i 0.005 192.168.1.39
```

L7 rules need a listening service on the victim and payload bytes on the wire
(`R0056` SQLi, `R9059` XSS, `R0088` traversal, `R0089` RFI, `R9064` command
injection). Without a listener the TCP handshake never completes and no
application payload exists to match — start one, then point the probes at the
port it listens on:

```powershell
python -m http.server 80
```

#### Protocol-anomaly lane (separate from `Rules.json`)

The five L7 rules above are **signature** rules: text matched by Aho-Corasick,
identified by the FNV-1a hash of their `Rules.json` id. A second, independent
lane parses HTTP/DNS/TLS/SMB structure and reports RFC-shape anomalies with
`rule_id = 10000 + kind` (`src/detection/proto_anomaly.zig`). Those numeric ids
are **not** in `Rules.json`; the event processor records them as observe-only
evidence and never promotes them to `matched_rule_id`, so they cannot reach
policy, PEP, or the ActionDispatcher (`event_processor.zig:335-352`).

The lane only runs for `source == .capture_npcap` with a non-empty payload, and
it needs the raw Ethernet frame. Canonical Go Nose satisfies both: it attaches
the raw Npcap frame bytes as the v3 payload (`nose/capture.go:180,232-264`), the
pipe reader submits those bytes (`nose_pipe_reader.zig:427`), and the queue maps
`npcap_sensor` to `capture_npcap` (`event_queue.zig:322`). `l7_payload.zig`
then accepts Ethernet + IPv4/IPv6 + TCP with a valid data offset (at least 20
bytes) or UDP, and returns the transport payload. Supported ports: HTTP
`80/8080/8000/8081`, DNS `53`, TLS `443/8443`, SMB `445/139`.

A minimal HTTP stimulus, no admin required:

```powershell
# victim: listening so the handshake completes and a payload exists
python -m http.server 8080
```

```bash
# Kali: HTTP/1.1 without a Host header -> kind 4, rule 10004
printf 'GET / HTTP/1.1\r\n\r\n' | nc -w 3 192.168.1.39 8080
```

Expected row in `C:\Windows\System32\logs\aegis_core.ndjson`:

```
"event":"protocol_anomaly","rule":"10004","level":"warn",
"enforcement_status":"observed","host_effect_confirmed":false
```

Read it with the same window tool (`--expect-src <kali-ip>`), but interpret the
`per rule` table by hand: `lab_attack_window.py` resolves numeric ids against
`Rules.json`, so this lane prints as `rule=10004 UNKNOWN`. **`UNKNOWN` here is
the expected label, not an error** — the control signal is the `10004` row with
the attacker's `src_ip`, not a catalog name. If `enforcement_status` ever reads
`enforced`, stop: the lane is observe-only by construction.

Known kinds an operator can aim at deliberately: `10001` invalid method, `10003`
invalid version, `10004` missing Host, `10005` oversize DNS label, `10008` TLS
zero ciphers, `10011` malformed SMB. The request must arrive within the first
1024 payload bytes (the Nose v3 bound); ordinary requests are far below it. One
well-formed request produces no row, so send the malformed shape **and** keep a
well-formed control in the same window.

### 4. Read the verdict

The tool prints and writes `admin-evidence/lab-<label>/attack-window-*.{json,md}`:

| Verdict | Exit | Meaning |
|---|---:|---|
| `PASS` | 0 | ingress advanced **and** at least one row names the attacker |
| `NO_ATTRIBUTION` | 2 | ingress advanced, no attacker row: check target port, payload, thresholds |
| `BLIND` | 3 | ingress did not advance: wrong segment (step 2) |
| `INVARIANT` | 5 | a row claimed a host effect: STOP-THE-LINE, the product is detection-only |

`per rule` lists the numeric rule ids resolved against the shipped catalog, so
`1745456278` prints as `R9006 TCP SYN Stealth Scan`.

## Verification

Pass conditions, all required:

1. `--preflight` prints `PREFLIGHT OK` and names a physical adapter.
2. The window verdict is `PASS` for the attacker IP.
3. Every listed rule is explained by bytes or flags that crossed the wire in
   that window (not by ambient text).
4. `deltas` shows `dropped`, `shed`, and `quota_shed` growth at or near zero.
   A lab run that sheds frames proves the attack DoSed the NIDS, not that
   detection works.
5. `aegisctl.py enforce status` still reports `prevention_gate: closed` and
   `tier3_enforcing: false`.

Rows are appended to the same production evidence log, marked by their
attacker `src_ip`. There is no second ring (single-owner contract), so a lab
row and a production row are distinguishable only by address and timestamp —
keep the window artifact next to the commit for exactly that reason.

## Rollback

Nothing was enforced, so nothing needs undoing. To leave the lab: set the Kali
adapter back to its previous network mode, stop any listener started for L7
probes, and keep the artifacts. Do not delete evidence rows; the log is
append-only by design.

## Honest limits

- **Promiscuous capture is off** (`pcap.OpenLive(..., false, ...)`). On Wi-Fi
  the sensor sees frames addressed to this host (and broadcast), not other
  stations' traffic. Attacks aimed at the host work; a scan of a *third* party
  from Kali does not.
- **Wi-Fi client isolation** silently breaks step 2 on many APs. Test with ping
  before trusting any zero result.
- **Booting a VM is real load.** During an active soak window a Kali boot plus
  a flood can burn the drop budget (see the soak record). Prefer running this
  proof outside a soak window; the tool never restarts a service, so it cannot
  invalidate one by itself.
- **A `BLIND` result is not a bug report.** It means the sensor and the attack
  were on different segments. Fix the topology, re-run step 1.
- L7 detections require a completed connection and payload. A SYN-only scan
  exercises L4 only, by design.
- **The protocol-anomaly lane is not a signature match.** It reports structural
  anomalies under ids `10000 + kind`, which are absent from `Rules.json` and
  therefore print as `UNKNOWN` in the window tool. Do not add them to the
  catalog to make the label nicer: they are observe-only evidence, not policy.
  Each malformed request produces one row, so a flood of them grows the evidence
  log at line rate — keep anomaly stimuli short.
