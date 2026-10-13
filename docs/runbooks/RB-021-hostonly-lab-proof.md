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
- Elevation: starting the lab nose feed needs a shell that may open the
  sensor pipe (administrators); reads need nothing.
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

### 2. Feed lab traffic (marked, operator-sanctioned)

Start a SECOND nose on VMnet1 (the prod nose keeps its own
interface). Lab frames enter the prod ring carrying `192.168.126.x`,
attributable and separable via Step 4. Stop it with Ctrl+C when done:

```
nose\aegis-nose.exe -capture -iface "\Device\NPF_{...VMnet1...}" -require-iface
```

`-require-iface` refuses auto-selection: a lab feed must never
silently fall back to the wrong interface.

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

Ctrl+C the lab nose. Prod flow (own nose, own interface) never
stopped. Lab records stay in the ring, marked `.126.x` and
attributable -- detection-only means nothing was ever blocked, so
there is nothing to unblock.

## Verification

Per-rule table, one row each: script ran (rc 0) AND a detection row
with the attacker IP exists (events --src-ip) AND the rule search
hits. 8/8 network rules from Kali, 15/15 host rules from canaries.
`forensics verify` stays ok + verified true throughout.

## Rollback

Kill the lab nose process; delete nothing (evidence is append-only by
design). If a proof filter was installed during recon (T11-style),
remove it by its printed id. No host effect was ever applied, so no
effect needs undoing.

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
