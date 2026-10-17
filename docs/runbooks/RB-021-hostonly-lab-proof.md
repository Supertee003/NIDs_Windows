# RB-021: Host-Only Lab Proof (Kali → Victim, Kernel Detection)

## Objective

Prove kernel-level network intrusion detection end to end on isolated
host-only VMs: Kali `192.168.126.10` attacks victim `192.168.126.20`
while the NIDS host (`192.168.126.1`, VMnet1) watches passively, and
every firing is attributable to the attacker IP. Network rules fire
from wire traffic alone (no victim cooperation needed); host rules run
as canaries on the monitored host itself.

## Prerequisites

- VMware host-only network up: Kali .10, victim Win11 .20, NIDS host
  .1 on VMnet1. NIDS service + nose + brain running on the host.
- Npcap device name for VMnet1 (it moves between installs; never
  hardcode the GUID):
  `nose\aegis-nose.exe --list-devices`
- Kali scripts copied to Kali: `scripts/kali_attacks/R*.py` (all refuse
  targets outside `192.168.126.0/24` by construction).
- Elevation: restarting the service and setting machine env need Admin;
  reads need nothing. No second nose is used (retired -- see Step 2).
- Victim listener on :80 (Admin PowerShell on the victim ONCE — any TCP
  payload needs an established connection before it exists on the wire;
  without it every L7 script reports `port closed` and nothing is sent):
  `python -m http.server 80`
- L7 scripts send via raw socket (urllib mangles spaces the Tier-1
  regexes match literally); R9002 prefers hping3 flood volume.

## Steps

### 1. Prove visibility first (writes nothing)

On the NIDS host, count raw VMnet1 frames without touching any pipe.
Generate traffic from Kali (ping the victim), expect packets > 0:

```
nose\aegis-nose.exe -capture-probe -iface "\Device\NPF_{...VMnet1...}"
```

Stays silent until frames cross. No packets with live VMs = stop here
and check the VMnet wiring, not the NIDS. Also check the target
resolves in the ARP/neighbour table: unicast to an address without a
live entry is dropped by the host stack pre-wire and produces zero
frames (2026-10-17: a 50-frame unicast burst to a dead .10 -> 0 rows;
a 1000-frame burst to .10 while an entry existed -> 999/1000 rows in 236 ms).
Broadcast always transmits -- it is the capture-liveness test.

### 2. Point daemon capture at VMnet1 (one Admin round-trip)

The daemon's own capture carries full packets WITH payloads, so Tier-1
L7 can match -- unlike nose-pipe frames (metadata-only: lengths and
hashes, no bytes), which is why four dark rounds never produced a
single lab event. Pin it with a machine env var, then restart:

```
setx /M AEGIS_DAEMON_IFACE "\Device\NPF_{CE375996-106D-46F7-A67C-0168EAE8C96F}"
sc.exe stop AegisNids
(wait STATE: 1 STOPPED)
sc.exe start AegisNids
```

A description substring works too (`VMnet1`); the exact GUID is
preferred (it cannot drift). Unset keeps the historical auto-select;
a SET-but-unmatched value fails closed (no capture + loud error),
never a silent wrong interface. Deliberately NOT the nose knobs
(`AEGIS_CAPTURE_IFACE`/`AEGIS_NOSE_IFACE`): sharing one would swing
the prod nose onto the lab interface at the next keeper restart. No
second nose is needed anymore -- retire window B (it fought the single
reader loop and dropped most frames).

Restore prod afterwards (bounded lab window -- VMnet capture is blind
to host Wi-Fi traffic while set):

```
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /V AEGIS_DAEMON_IFACE /F
sc.exe stop AegisNids
(wait STATE: 1 STOPPED)
sc.exe start AegisNids
```

### 3. Fire the network rules from Kali (in this order)

```
python3 R9006_syn_stealth_scan.py --target 192.168.126.20
python3 R9007_xmas_scan.py --target 192.168.126.20
python3 R9002_icmp_flood.py --target 192.168.126.20
python3 R9059_xss_basic.py --target 192.168.126.20
python3 R0056_sqli_auth_bypass.py --target 192.168.126.20
python3 R9064_cmdi_semicolon.py --target 192.168.126.20
python3 R0088_path_traversal.py --target 192.168.126.20
python3 R0089_rfi_param.py --target 192.168.126.20
```

`--intense` repeats 3x. Every script prints its own verify hint.

Fire only at a live, resolved victim: .20 must be up, present in
`arp -a -N 192.168.126.1`, and answer a captured ping. Unicast
scripts against an unresolvable host send nothing on the wire -- a
silent fire there is a dead target, not a NIDS fault (see Step 1).

### 4. Attribute every firing to the attacker (on the NIDS host)

```
python tools/aegisctl.py events count --src-ip 192.168.126.10
python tools/aegisctl.py events tail --count 20 --src-ip 192.168.126.10
python tools/aegisctl.py forensic search --field rule --value R0056
python tools/aegisctl.py alerts
```

The ring has no IP field by design; `--src-ip` filters the evidence
log client-side (no daemon change). Expect: count > 0, per-rule
searches hit, alerts list the firings.

### 5. Host rules (canaries on the monitored host, never Kali)

R1001-R1005, R2001-R2005, R3001-R3005 need local execution. Run their
scripts ON a lab-monitored host (canary filenames only, observe-only
NIDS side), then verify with the Step-4 commands. R3002 PsExec is the
remote-shaped one: run it Kali→victim and watch the pipe rule fire.

### 6. Close the lab

Restore the daemon interface (Step 2, second block) and restart: prod
(Wi-Fi) flow resumes on the next start. Lab records stay in the ring,
marked `.126.x` and attributable -- detection-only means nothing was
ever blocked, so there is nothing to unblock.

Close-out record (2026-10-17, operator round): the machine-env pin was already absent (the delete returned not-found); the daemon came up on a fresh process (PID 12140, ~12:01 local). Post-restart, prod flow verified: nose connected with frames flowing, event rows continuing, zero VMnet1-sourced rows -- see the lab-run record below.

## Lab-run record (2026-10-17, host-only capture re-verification)

Run in this window: daemon pinned to VMnet1 per Step 2; probes were
host-sent (broadcast + unicast) because both lab VMs were down
(no .10/.20 ARP entries -- see item 3). What the run proved:

1. Ingestion verdict. Every lab row came from the daemon's OWN
direct Npcap capture on VMnet1 (the Step-2 pin) -- not the sensor
pipe (zero pushes; queue bucket ordinal 99 empty all run) and not
nose. Evidence: consecutive event ids on the direct-capture stream
(e.g. eids 4923-4930 for one 8-frame send; 3769-4767 for the
1000-frame burst), ring source_name npcap_sensor, deployed source diffs vs
HEAD empty for every capture/pipeline/detection file involved. Display note:
`system.state` `packets_captured` reports the NOSE submitted-frame
counter (state_machine.zig), so it does NOT measure the direct-capture
path -- measure lab capture via events/forensic rows and the queue
buckets instead.

2. Capture path is live. Broadcast liveness probe 10/10 rows in 63 ms
(eids 4857-4866, 04:09:19; 5 own-payload + 5 window-only matches, see
item 4); broadcast attribution probe 5/5 rows in one millisecond
(eids 4868-4872; F1 R9064 window-only, F2 R9064 own, F3 R9059,
F4 R1005, F5 R9002 -- hashes FNV-1a checked against the deployed
catalog); unicast to .254 while its ARP entry existed: 8/8 twice
(eids 4923-4930, 4934-4941).

3. Transmission model (closes the silent-burst anomaly). A unicast fire
reaches the wire ONLY if the destination resolves in the
ARP/neighbour table; otherwise the host stack drops it pre-wire and
the NIDS correctly records nothing. Observed: 1000-frame burst to .10
while an entry for it existed -> 999 rows in 236 ms (eids 3769-4767); a 50-frame
repeat 7 min later (entry flushed, target dead) -> 0 rows;
unicast to unresolvable .10/.20 (16 frames) -> 0 rows; broadcast and
resolved-neighbour sends -> 1:1 capture. A silent fire at a dead
target is a lab-hardware state, not a NIDS fault: check `arp -a -N
.126.1` first.

4. The 1500-byte match window (corrects the earlier display-side note).
Direct capture on VMnet1 queues/stores each frame as a >=1500-byte
slice (payload_len 1500 on ring records for ~50-byte frames); Tier-1
scans the whole window, so text rules can fire on trailing window
bytes. Control proof: a frame whose own payload was F1 (no pattern)
matched R9064 via a following frame's ;whoami bytes inside its
window; the five plain broadcast frames (self-declared no-signature
payload) all matched R9064 the same way; payloadless ICMP/DHCP-class
rows matched R9064 all session (e.g. eids 4873-4886, 04:15:05).
matchFirst leftmost semantics keep a frame's own-payload match winning, so
attacker-side attribution stands; plain frames can false-positive via
the window. Fix = trim the match slice to the frame's truth length
before AC: follow-up slice, no code changed in this run (deployed pins
frozen).

UPDATE 2026-10-17 (same-day follow-up; EVT-216). Root cause CORRECTED.
The >=1500-byte window was not driver behavior and not a slice-trim
matter: the daemon's pcap_next_ex FFI declaration was one indirection
short (Npcap SDK pcap/pcap.h:574 takes `struct pcap_pkthdr **`), so the
DLL's header pointer landed in our struct and caplen/len were never
written -- safety builds read the 0xAA fill (2863311530 >= 1500), making
EVERY direct frame's slice >=1500. Reproduced byte-exactly with a
repo-code probe on VMnet1 (before: 30/30 frames caplen=len=2863311530
while the data bytes were the real frames; after the source fix:
caplen==len==83/75 exact, timestamps sane). The fix landed in source the
same day: declaration corrected, both call sites read through the
published pointers, compile-time ABI pin test added; zig-out rebuilt,
deployed copies unchanged. The section-4 "trim the match slice"
follow-up is superseded (with caplen read correctly, the window IS the
frame). Daemon-side re-proof (rows payload_len == frame size, no
window-only matches) happens at the next operator pin round on the
rebuilt binary.

5. Counter semantics. `detections` increments twice per matched +
policy-matched event (event_processor.zig: signature match then policy
match; `policies_matched` once), so the earlier burst delta of about
2x frames is exactly that accounting -- a controlled 8-frame send showed
+16 detections / +8 policies_matched, with the rest ambient.

6. Close-out. Operator round 2026-10-17: the AEGIS_DAEMON_IFACE machine-env value was found already absent (the delete returned not-found; no per-service Environment key either); the daemon came up on a fresh process (PID 12140, ~12:01 local) -- a registry delete alone does not touch a running process, and the restarted process starts unpinned. Post-restart checks: 7/7 subsystems RUNNING, nose connected with frames flowing (packets_captured advancing in lockstep with the capture_npcap queue bucket and nose_frames_submitted), event rows continuing through 12:05, and zero rows with src 192.168.126.* in the 11:54-12:07 window (0 of 1,634). Lab records stay in the append-only log; no code changed or binary rebuilt in this run.

## Verification

Per-rule table, one row each: script ran (rc 0) AND a detection row
with the attacker IP exists (events --src-ip) AND the rule search
hits. 8/8 network rules from Kali, 15/15 host rules from canaries.
`forensics verify` stays ok + verified true throughout.

Attribution rules (2026-10-17 findings): count a row as wire-fire proof
only if the target resolved (Step 1/3) AND the rule's own pattern
can explain the match. Direct VMnet1 capture stores each frame as
a >=1500-byte window and Tier-1 scans the whole window, so text
rules can also fire on trailing window bytes (own-payload matches win
leftmost; see the lab-run record). Payloadless/protocol-control rows
(ICMP port-0, DHCP) matching a text rule are always window artifacts,
never fire proof. Zero rows after a fire = check target liveness first,
not the NIDS. (Same-day UPDATE: the >=1500-byte window described above applies to the pre-fix build only; root cause was the pcap_next_ex FFI indirection, fixed in source -- EVT-216.)

## Rollback

Restore the Step-2 interface block (env delete + restart); delete
nothing (evidence is append-only by design). If a proof filter was
installed during recon (T11-style), remove it by its printed id. No
host effect was ever applied, so no effect needs undoing.

## Honest limits

- Lab frames enter the PROD ring (marked traffic, operator-sanctioned,
  same precedent as the marked-canary demo). A fully isolated ring
  needs a second daemon, which does not exist (single-owner contract).
- Recon scans draw victim RSTs; irrelevant -- detection keys on the
  attack payload crossing the wire, not on victim cooperation.
- `--intense` floods are bounded (3x); do not loop scripts -- the
  queue sheds overload and the test becomes a DoS of your own NIDS.
- The WFP proof slot holds one filter; concurrent BLOCK proofs
  serialize, they do not parallelize.
- Direct VMnet1 capture stores every frame as a >=1500-byte window
  (frame + trailing bytes) and Tier-1 matches the whole window: own
  bytes win leftmost, but plain frames can false-positive on trailing
  bytes (2026-10-17). Treat ambient text-rule rows on the lab path as
  window artifacts unless the rule's bytes are in the frame's own payload
  (see the lab-run record).
- Unicast fires need a live, resolved target: unresolvable .10/.20
  drop pre-wire and record nothing (not a NIDS fault). Broadcast
  and resolved-neighbour sends are the capture-liveness tests.
- `system.state` packets_captured is the nose counter; it does not
  count the daemon's direct-capture frames (lab-run record item 1).
