# Demo — Traffic → Event → Detection → Dashboard → Forensic Record

**Length:** 2:27. **Source:** real running AEGIS daemon on a Windows lab host.
**Boundary:** detection-only — no host blocking, no WFP mutation, no synthetic host evidence.

This file is both the recording script and the viewer's chapter guide for
[`demo.mp4`](images/demo.mp4). The clip is a silent screen recording with on-screen chapter
captions; every command output and dashboard row in it is live, not staged.

**Recorded result:** a bounded 40-SYN burst from `192.168.1.39` to `192.0.2.1:1–40` during a
`lab_attack_window` measurement produced `VERDICT: PASS (exit 0)`, one attributed row, and
`1 R9006 TCP SYN Stealth Scan`, with drop/shed/quota deltas all `0`.

---

## Chapter guide

| Time | Scene | What is real |
|---|---|---|
| 0:00–0:20 | Title + one-sentence product statement | On-screen chapter caption |
| 0:20–0:40 | Safety posture first | `aegisctl status` / `enforce status` |
| 0:40–0:55 | Sensor is on the right segment | `capture_select.py --show` / `--verify` |
| 0:55–1:40 | Traffic created, measurement window open | `lab_attack_window.py` + 40-SYN TEST-NET burst |
| 1:40–1:50 | Event + detection attributed | `events tail`, attributed R9006 row |
| 1:50–2:15 | Dashboard shows the live feed | real read-only web dashboard |
| 2:15–2:27 | Forensic proof + safety close | `forensic verify`, `enforce status` |

---

## 0:00 — Title

> "AEGIS NIDS Windows — a Windows kernel-assisted network intrusion detection system.
> This demo follows one event all the way from traffic to a verified forensic record.
> It is detection-only: nothing here blocks or quarantines a host."

---

## 0:25 — Show the safety posture first

```powershell
cd <REPO_ROOT>   # replace with the path to your clone
python tools\aegisctl.py status
python tools\aegisctl.py enforce status
```

Talk track:

> "Before any traffic, the invariant: `prevention_gate = closed`, `tier3_enforcing = false`,
> `host_effect_capable = false`. Rust PEP is present and ready, but 'ready' is a capability, not a
> block. A `BLOCK` label in this product is an intent recorded as evidence."

---

## 0:55 — Prove the sensor sees the segment under test

```powershell
python tools\capture_select.py --show
python tools\capture_select.py --verify
```

Talk track:

> "Capture topology matters. A host-only VM attacking a Wi-Fi sensor produces real packets and zero
> detections — that is a wiring fact, not a detector bug. `--verify` proves framers are advancing
> on the selected device before we interpret any result."

---

## 1:20 — Create real traffic inside a measured window

```powershell
python tools\lab_attack_window.py --preflight
python tools\lab_attack_window.py --label lab-demo --seconds 120 --expect-src <ATTACKER_IP>
```

From the authorized attacker host on the same segment (bounded, owned systems only):

```bash
nmap -sS -Pn -n -p 1-60 --max-retries 1 --host-timeout 30s <WINDOWS_TARGET_IP>
nmap -sX -Pn -n -p 1-30 --max-retries 1 --host-timeout 30s <WINDOWS_TARGET_IP>
```

Talk track:

> "Everything this tool prints is a measurement: it takes a byte offset into the durable evidence
> log plus runtime counters, waits, then re-reads both and reports only the delta. We never write
> policy, rules, or WFP state."

**Evidence shown in the proven lab run:** ingress advanced by 9,017 frames; 15 rows attributed to
the attacker, including `R0056`, `R9059`, `R0088`, `R9064`, `R9002`, and `R9006`; drop, shed, and
quota deltas all `0`.

---

## 1:40 — Event received, detection attributed

```powershell
python tools\aegisctl.py events tail --count 20
python tools\aegisctl.py alerts
```

Talk track:

> "Here is the canonical event and the matched rule. The row says `status=observed` and
> `host_effect_confirmed=false`. That is deliberate — the detector produced evidence, not an
> effect. The R9006 SYN-burst rule also has a negative control: 10 ports produced zero hits,
> while 40 ports produced one attributed detection."

---

## 1:50 — Show the live operator dashboard

```powershell
$env:DASHBOARD_PORT = "5000"
python -m tools.aegisctl.web_dashboard.app
```

Open `http://127.0.0.1:5000/` and point at: Detection Feed, `OBSERVE_ONLY`, `prevention gate
closed`, and Forensic Integrity `OK`.

Talk track:

> "The dashboard is a read-only view of the daemon-owned snapshot. It is not a second supervisor
> and it cannot change policy. What you see is the live feed and the authoritative state."

---

## 2:15 — Close with forensic proof and the safety invariant

```powershell
python tools\aegisctl.py forensic verify
python tools\aegisctl.py enforce status
```

Talk track:

> "The forensic log verifies — hash-chained records, decision trace, evidence receipt. And the
> closing check: the prevention gate is still closed. That is the whole point of the design:
> high-confidence detection and verifiable evidence, with no implied host effect."

---

## Recording notes

- Use the real daemon and real logs. Do not stage a mock UI or fabricate evidence.
- If live lab traffic is unavailable, narrate the recorded evidence instead (`analysis/current-head/`
  and `EVIDENCE_INDEX.json`) and say explicitly that the clip is a walkthrough of recorded proof.
- Keep the camera on actual command output and the real dashboard; avoid editing detection rows.
- A `DEGRADED` badge on the lab host is truthful — all subsystems can still be `RUNNING` while the
  control-pipe responder reports a degraded detail. Do not hide or repaint it.
- Do not claim EV/HLK/Microsoft attestation, Signed-IR promotion, or production fleet deployment.
