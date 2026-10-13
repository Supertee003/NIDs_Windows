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
and check the VMnet wiring, not the NIDS.

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

## Verification

Per-rule table, one row each: script ran (rc 0) AND a detection row
with the attacker IP exists (events --src-ip) AND the rule search
hits. 8/8 network rules from Kali, 15/15 host rules from canaries.
`forensics verify` stays ok + verified true throughout.

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
