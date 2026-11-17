# FINAL CLOSEOUT STATUS — 2026-11-17

**Read this before claiming the project is closed.** It states what is proven, what
is open, and what cannot be closed from this host at all.

---

## Release gate board (`python tools/final_audit.py --release-check`)

```
PASS  truth_artifacts     TRUTH_VALID, build source 10e19fa
PASS  component_audit     modules 66/66, prod failures 0, part_ii 5/5, golden path declared
PASS  release_signature   release/T20-final/a101c4f signs SHA256SUMS (B9299AA30FEA2D0B...)
                          and commit a101c4f contains runtime 10e19fa
PASS  clean_host_e5       preflight PASS with the boot loader under C:\Program Files\AEGIS NIDS
OPEN  soak_24h            window started 2026-11-17T17:32:43 at 0.0/24.0 h on the final build
PASS  evidence_debt       unnamed product files 0
release: NOT SHIPPABLE (1/6 gates open)
```

**The only release gate still open is the 24 h window on the final build.** It
cannot be closed by writing code: it needs 24 hours in which the daemon is not
restarted, and every install, build or reboot resets it. That is why the two
earlier windows are voids, not failures of the product:

| window | outcome | why |
|---|---|---|
| `2026-11-14T22:20` | FAIL at 16.95 h | `shed_overload` 15,163 vs 4,000 because the adversarial gates ran inside it |
| `2026-11-15T16:50` | FAIL at 48.43 h | daemon uptime 0.49 h — the process was restarted mid-window |
| `2026-11-17T17:32` | IN_PROGRESS | started on the final layered build, nothing else touches the host until it closes |

Check it with:

```
python tools/host_soak_check.py --start 2026-11-17T17:32:43 \
  --baseline admin-evidence/e5-clean-host-20261117-soak3/soak-24h.baseline.json \
  --hours 24 --loss-budget 3500 --shed-budget 20000 \
  --json admin-evidence/e5-clean-host-20261117-soak3/soak-24h-delta-latest.json
```

## Open gaps (2)

### 1. `RULE-LAYER-SCOPE-001` — source fixed, E5 attribution unproven

Layered automata are in source and in the installed binary (`2ffc565b...`), with
E2 pins and a live check that 23 rules load and readiness is ready. What is **not**
proven is the attribution: that a payload containing `IEX` over the wire carries a
network rule id or none, never `R2003`. That needs an HTTP listener on
VMnet1:8080 plus payloads from the Kali VM, and `aegisctl forensics` read with
payload (the summary rows carry `rule_id: 0`). Loopback is not captured on this
install, so a local listener cannot stand in.

### 2. `GAP-QLOSS-ISOLATION-002` — needs a product decision, not just code

ETW `NameDelete` is the largest ingress lane (18.15 M rows) and the fair-share
arithmetic was already fixed at E2. Closing it is one of three deliberate choices:
filter ETW deletes that match no rule path (with a mass-delete aggregate so
ransomware stays visible), batch the forensic append, or accept an envelope with a
documented budget and an owner sign-off. Each has a different product meaning, so
this is the owner's call, not an implementation detail.

## Not closable here at all

* **D1 — EV certificate + HLK/attestation.** Needs a legal entity, an EV cert with
  token/HSM, Partner Center access and an HLK target that is not the controller.
  Kali cannot serve as the target. A test-signed driver must never be called
  production-signed.
* **Clean-machine boot model.** This host has the toolchain, Npcap and a test cert
  by construction; an in-place reinstall is not that evidence and is recorded as a
  limitation instead.
* **D2 — 6.0.0 version bump.** Deliberately deferred into a single v1.1 batch so it
  costs one build, one signature and one window instead of two.

## What was verified in this session (not claimed, run)

`zig build` 0 · `zig build test` 0 (2,113 tests, includes the new layer pins) ·
`zig build test-network-integration` 0 · full pytest at the pre-layer HEAD
1,371 passed / 4 skipped / 2 xfailed · `tests/release tests/security` 580 passed
after the records work · installed sha256 equals build sha256 · `status`
RUNNING/RUNNING · `readiness` ready true, 23 rules, 6 policies ·
`host_preflight` PASS, failed [] · RC `a101c4f` rebuilt from this source, signed
and verified · `truth.py verify` TRUTH_VALID · evidence debt 0.
