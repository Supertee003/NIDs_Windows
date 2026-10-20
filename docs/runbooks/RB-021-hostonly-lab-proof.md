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

7. Same-day re-proof of the EVT-216 fix (daemon deploy round; EVT-217).
The fixed exe (sha256 65CCD7CD..., repo zig-out == deployed) went live
as the AegisNids service with the Step-2 VMnet1 pin; the previous build
was kept as aegis_nids.exe.pre-evt216 (aegis_nids.exe.pre-evt213 holds
the same 6D03115B build; both hash-verified -- check hashes before
using either for an exe rollback). The identical send shapes now behave
exactly as the fix predicts: broadcast probe -- 5/5 own-payload rows at
plen=83 for the red frames (eids 1-5, ports 56300-56304) and ZERO rows
for the five plain frames (pre-fix: all ten matched at plen=1500);
attribution set F1-F5 -- F1 (no pattern) silent, F2-F5 own-pattern rows
only (R9064/R9059/R1005/R9002) at plen 49/50/47/52 (eids 12-15). Ring
records for all 15 frames carry payload_len == frame size
(83/75/44/49/50/47/52) -- no >=1500 slices anywhere; the capture_npcap
queue bucket advanced 15->49 during the round, dropped=0. Restore
(Step-2 second block + restart, PID 22884): prod rows continuing, zero
192.168.126.* rows after the lab window; the fixed binary stays
deployed. Operator note: the service can sit in STOP_PENDING for a
while -- copy the exe only after `sc.exe query` prints STATE: 1 STOPPED
(a copy while stopping fails with the file in use).

8. Backup-artifact inventory + restore anchors (EVT-219, 2026-10-17).
   Runtime dir `C:\Program Files\AEGIS NIDS\runtime` -- exe anchors:
   `.pre-evt213` / `.pre-evt216` hold 6D03115B (hash-equal pair; older
   snapshots pre-evt211 / pre-wfptele / pre-endian / pre-gap020 /
   pre-iface / pre-shield also present). pep.dll: deployed 617FA3C7; the
   last pre-10/16 build is kept as `aegis_pep.dll.pre-evt211` (7226B648;
   `.pre-fresh` holds 4BAFE8D7). pep `.pre-evt213` == current deployed
   build (not a distinct anchor). `aegis_wfp_user.dll.pre-evt213` ==
   current (EF9BFD22) and is NOT a usable standalone rollback: the WFP
   user DLL pairs with the driver build-era layout (EVT-213), so any WFP
   rollback is a paired driver+DLL operation. Driver: the running image
   `System32\drivers\aegis_wfp.sys` = EC4A5683 (EVT-213 signed); the
   pre-EVT-213 build D58E2EEF survives only as stale copies inside the
   9/16 release bundles and `C:\Program Files\AEGIS NIDS\drivers\`
   (inert -- the loader path is System32). Check hashes before using any
   backup for a rollback.

   Same-day UPDATE (EVT-219 operator completion, 2026-10-17): the pep
   `.pre-evt213` slot was refreshed from `.pre-evt211` -- both now hold
   7226B648 (a distinct pre-10/16 anchor; the deployed `aegis_pep.dll`
   itself remains 617FA3C7 and `.pre-fresh` stays 4BAFE8D7). The stale
   Program Files driver copy was refreshed to EC4A5683 (== the running
   System32 image); D58E2EEF now survives only inside the 9/16 + T20
   release bundles. No service restart was needed (only backup/inert
   files changed).

## Lab-run record (2026-10-20, pre-fix: Kali .10 -> Win11 .20, live host .1)

This run predates the L4 matcher; its L4 rows are historical. The
close-out record below supersedes only the L4 result.

Run at HEAD `e616bad`; deployed daemon sha256 `F223DCCE...` (PID 10032,
started 08:56:47) with the machine `AEGIS_DAEMON_IFACE` pinned to VMnet1;
gate `closed`/detection-only throughout. Baseline: 4 `.10` rows at
08:30:53 (pre-pin). The post-pin R0088 canary produced 2 new `.10` rows
at 08:57:23 (R0088 + R1005), proving the direct capture path. The full
8-script wrapper ran rc=0 in 43.8 s; supplementary real `nmap -sS` /
`nmap -sX` and `hping3 --icmp 300` tests ran for the L4 rules. There are
18 `.10` events total (4 pre-pin baseline + 14 new; 11 real-traffic rows
+ 3 synthetic-token rows); every row is `observed`, gate closed.

| rule | real-traffic rows | token-smoke rows | verdict |
|---|---|---|---|
| R0056 | 1 (first payload) | - | PASS (second payload lacks `' OR 1=1`) |
| R0088 | 2 (+ R1005 x2) | - | PASS (`/etc/passwd`) |
| R0089 | 1 | - | PASS |
| R9059 | 1 | - | PASS |
| R9064 | 0 from script; 2 from `;whoami` query/body | - | CONDITIONAL (script uses `;id`/`;cat`) |
| R9002 | 0 (`hping3` 300 ICMP) | 1 | NOT DETECTED (L4); token-only |
| R9006 | 0 (`nmap -sS`) | 1 | NOT DETECTED (L4); token-only |
| R9007 | 0 (`nmap -sX`) | 1 | NOT DETECTED (L4); token-only |

The L4 result is structural, not a capture failure: the canonical matcher
(`src/pipeline/rule_loader.zig`) loads each rule's `match_pattern` as a
literal (payload-only contract; `target_protocols`/`target_ports` are not
consulted). R9002/R9006/R9007 use `PROTO:ICMP`/`FLAGS:S`/`FLAGS:FPU`
tokens, so real L4 frames cannot match; HTTP payloads containing the
tokens fire the rule IDs (eids 1288/1297/1329) as a rule-engine smoke
only. This matches the documented synthetic qualification caveat
(`docs/AEGIS_PRODUCTION_HANDOFF_2026-09-22.md`: synthetic fixture
matching is not real-sensor/IPS evidence) and is tracked as gap
`RB-021-L4-MATCHER`. `forensics verify` stayed `verified: true`, but a
prod `0.0.0.0` host-event storm churned the 16K ring; per-rule
`forensic search` returned 0 for the real rows (the append-only
`aegis_core.ndjson` is the durable evidence; the session rows are in
the rotated `aegis_core.1.ndjson`, 18 `.10` rows). Restore: env delete +
restart, PID 9384, 7/7 subsystems, packets advancing, gate still
`closed`, zero `.126` rows in the new log generation. Evidence kit
(gitignored): `admin-evidence/lab-session-20261020/`
(RESULTS-20261020.md, captures/, closeout/).

## Lab-run record (2026-10-20, L4 matcher close-out: Kali .10 -> host .1)

Source `fd7b424`; deployed exe `47AB808505...` (PID 3912) with the
machine `AEGIS_DAEMON_IFACE` pinned to VMnet1. The Win11 `.20` victim was
off (its VM also needs an encryption password), so the live NIDS host
`.1` was the target; the L4 predicate is target-independent. Gate
`closed`/detection-only throughout. The daemon's own direct capture path
was used; `events count --src-ip` filters the durable evidence log.

| step (Kali .10 -> .1) | `.10` before -> after | rows | rule hash |
|---|---|---|---|
| preflight `ping` (1 + 3) | 0 -> 5 | 5 | `1812566754` R9002 |
| negative: TCP ACK + `FLAGS:S FLAGS:FPU PROTO:ICMP` | 5 -> 5 | 0 | -- |
| `nmap -sS -Pn -n -p 1-100 --max-retries 1 --host-timeout 20s` | 5 -> 205 | 200 | `1745456278` R9006 |
| `nmap -sX ...` (same range) | 205 -> 405 | 200 | `1762233897` R9007 |
| `hping3 --icmp -i u1000 -c 300` | 405 -> 705 | 300 | `1812566754` R9002 |
| positive: TCP ACK + `../../etc/passwd` | 705 -> 706 | 1 | `4254503461` R0088 |
| negative: same ACK shape + L4 tokens | 706 -> 706 | 0 | -- |

Final: 706 `.10` rows (R9002 305, R9006 200, R9007 200, R0088 1); every
row `signature_match`/`observed`/`host_effect_confirmed=false`;
`metrics.blocks = 0`; `enforce status` `prevention_gate: closed`,
`tier3_enforcing: false`; `readiness` 23 rules/6 policies, `ready: true`.
`forensic verify` `verified: true`; the 16K ring churned under the prod
`0.0.0.0` host-event storm (records 626247, retained 16384), so the
durable rows were snapshotted before the live log rotates:
`admin-evidence/lab-session-20261020-l4/lab-rows-706.ndjson`
(sha256 `90EF0BAF...`).

The two ACK controls use the same shape (one ACK, port 80, no reply,
40/20 data bytes). The L7 payload in the positive control fired R0088
(`payload_len=74`), proving the ACK-with-payload path was captured; the
L4-token ACK then produced no row. This is the regression proof that the
L4 rules are no longer Aho-Corasick payload-token rules: they are parsed
into the separate L4 table and evaluated only for `.capture_npcap` events
when no payload rule matched. TCP flags ride the in-memory
`QueuedEvent.tcp_flags` sidecar; the wire contract is unchanged.

A 100-port nmap scan produced 200 matching packets (retry or duplicate
capture); counts are matching packets, not distinct ports. The five
preflight R9002 rows are real pings and are included in 305.

Restore (operator, elevated): `OPERATOR-RESTORE.ps1` removed the machine
pin and restarted `AegisNids` (PID 7420); `AEGIS_DAEMON_IFACE=absent`;
deployed exe unchanged `47AB8085...`; rules 23; gate still `closed`;
nose frames 15597 -> 16543 -> 17207; no new `.10` rows. Evidence kit
(gitignored): `admin-evidence/lab-session-20261020-l4/`
(RESULTS-L4-20261020.md, lab-rows-706.ndjson, captures).

## Verification

Per-rule table, one row each: script/command ran (rc 0) AND a detection
row with the attacker IP exists (events --src-ip) AND the rule's own
bytes/flags explain the match. The pre-fix 2026-10-20 record has 5/8
network rule IDs from real traffic (R9064 conditional) and the three L4
rule IDs token-only. The L4 close-out record above has real per-packet
rows for R9002/R9006/R9007 (305/200/200) plus paired ACK
negative/positive controls; R9064 remains conditional. Those 706 rows
were produced by the pre-rate source `fd7b424` and are historical
per-packet evidence, not rate/scan/flood verdicts. 15/15 host rules from
canaries.

## Rate/window semantics (2026-10-20)

The current source adds an opt-in rate block to the L4 matcher; the
canonical `configs/Rules.json` opts in for two rules:

| Rule | State | Threshold | Window | Emission |
|---|---|---:|---:|---|
| `R9002` ICMP Flood | per source packet count | 50 ICMP | 1000 ms | first packet reaching 50; one per window |
| `R9006` TCP SYN Stealth Scan | per source distinct destination ports | 20 ports | 10000 ms | first packet reaching 20; one per window |
| `R9007` TCP XMAS | per-packet exact `FIN|PSH|URG` | n/a | n/a | every matching packet |

The state is keyed by rule id + full source address + IPv4/IPv6 identity;
the table is fixed-size (256 entries) and reset on a rules reload. A
normal single handshake is a valid SYN predicate but does not reach the
scan threshold; normal pings below 50/1000 ms do not fire. The negative
and positive controls are Zig unit tests in
`src/pipeline/l4_matcher.zig` and the configuration pins are
`tests/security/test_l4_rate_config.py` (E2).

This closes the rate/window code semantics at E2. The rate-enabled
artifact `04F9E0DB...` was installed on 2026-10-20 and the live verifier
passed 22/22. A host-generated TEST-NET run proved `R9002` live on the
canonical path: 10 pings produced no new row and a 60-packet burst
produced exactly one new row. `R9006` could not be assessed there:
canonical Go Nose events carried no TCP-flags sidecar (`pushEvent` set
`QueuedEvent.tcp_flags=0`), so the flags-gated `R9006`/`R9007` rules were
inert unless the daemon was pinned to direct Zig Npcap. A live 20-port
SYN scan produced 0 `R9006` rows even though the independent wire capture
proved 20 distinct ports. This is a production-path detection gap
(`RB-021-NOSE-FLAGS`, P1), not a rate-tracker failure.

Source patch `RB021-NOSE-FLAGS-001` records the raw TCP flags byte in
the existing `ContextFlags` transport lane (bits 16..23, valid bit 24)
without changing the 109/133-byte wire layout. Go Nose sets the lane in
`eventFromPacket`; Zig `pushDecodedFrame` extracts it into
`QueuedEvent.tcp_flags`; Go, Zig, and Python contract tests plus `zig
build` pass (E2). DEPLOY-131 (source `de574b6`) was installed on
2026-10-20; the live verifier passed 22/22. The installer replaced the
Nose file but did **not** restart the running process: PID 21568 was
created 2026-10-15, five days before the patched binary was built at
17:20:01. A quiet 20-port control produced 0 R9006 rows and five exact
`FIN|PSH|URG` frames produced 0 R9007 rows even though the wire saw the
traffic, with zero new queue drops. The operator stopped PID 21568 and
started PID 3632 at 19:51:55 from the patched binary.

Post-restart live pass (2026-10-20 19:53-19:54): `R9006` one-port
negative 0 / 20 distinct ports exactly 1; `R9007` normal SYN 0 / five
exact `FIN|PSH|URG` frames -> 5 rows (using the TEST-NET-only raw sender
`admin-evidence/deploy131-nose-flags-20261020/send-xmas.py`); `R9002`
10 ICMP 0 / 60 ICMP 1. Queue dropped stayed 10,337 and shed stayed
56,936; readiness was RUNNING and the gate stayed closed. This closes
`RB-021-NOSE-FLAGS` at EVI `RB-021-NOSE-FLAGS-LIVE-PASS-20261020`.
The stale-process gap `DEPLOY-131-NOSE-STALE-PROCESS` is closed at EVI
`DEPLOY-131-VERIFY-PROCESS-20261020`: the verifier now rejects
missing/duplicate/stale/mixed daemon or Nose process images and passes
24/24 on the current host; its self-test fails stale/mixed/empty and
passes fresh. The installer still needs the operator restart step, but a
future stale image can no longer silently pass verification. The isolated
Kali->Win11 E5 re-proof
(normal handshake/ping below threshold, scan/flood above threshold, one
row per window) remains tracked as `DEPLOY-130-L4-RATE-E5`; do not claim
it from unit tests or from the TEST-NET run. `forensics verify` stays ok
+ verified true throughout.

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
  attack payload or L4 header fields crossing the wire, not on victim
  cooperation.
- `--intense` floods are bounded (3x); do not loop scripts -- the
  queue sheds overload and the test becomes a DoS of your own NIDS.
- The 2026-10-20 305/200/200 L4 rows were per-packet: R9006 matched any
  exact SYN (normal handshakes included), R9002 any ICMP, R9007 exact
  FIN+PSH+URG. They were produced by the pre-rate source and must not be
  described as scan/flood verdicts. The current installed artifact
  carries the rate/window state, but only R9002 has live rate proof so far.
- The installed `04F9E0DB...` artifact still has no TCP flags on the
  canonical Nose path; `R9006`/`R9007` remain unmatched there. Source
  patch `RB021-NOSE-FLAGS-001` fixes the path at E2, but until the patched
  artifact is installed and live-proven, gap `RB-021-NOSE-FLAGS` (P1)
  stays OPEN. Do not use the pre-patch 20-port scan to claim a rate or
  flags failure, and do not use the E2 tests to claim E5.
- A 100-port nmap scan can produce 200 matching packets (retry or
  duplicate capture); the old per-packet rows count packets, not ports.
  The current R9006 state counts distinct destination ports instead.
- The WFP proof slot holds one filter; concurrent BLOCK proofs
  serialize, they do not parallelize.
- Direct VMnet1 capture stores every frame as a >=1500-byte window
  (frame + trailing bytes) and Tier-1 matches the whole window: own
  bytes win leftmost, but plain frames can false-positive on trailing
  bytes (2026-10-17). Treat ambient text-rule rows on the lab path as
  window artifacts unless the rule's bytes are in the frame's own payload
  (see the lab-run record). (Same-day UPDATE: fixed at source -- EVT-216; re-proven on the deployed build -- EVT-217.)
- Unicast fires need a live, resolved target: unresolvable .10/.20
  drop pre-wire and record nothing (not a NIDS fault). Broadcast
  and resolved-neighbour sends are the capture-liveness tests.
- `system.state` packets_captured is the nose counter; it does not
  count the daemon's direct-capture frames (lab-run record item 1).
