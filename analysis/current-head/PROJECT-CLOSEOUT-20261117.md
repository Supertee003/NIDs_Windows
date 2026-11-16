# PROJECT-CLOSEOUT-20261117 — v2.0.0 shipped as a detection-only E5 release

**Created:** 2026-11-17T03:10+07:00
**Records HEAD at writing:** `7b484a1` (tagged `v2.0.0`)
**Build source:** `7c604d5` (unchanged since 2026-11-15)
**Runtime:** `aegis_nids.exe` sha256
`7955A6E3C9BB8AC4E5872114B33316AADA74F09E39F48C0513BA6FFA58D71A18`
**Signed release tree:** `release/T20-final/9ebee9b`, `SHA256SUMS` digest
`9F87BF36D28149F5FEF22B997DC6928C8846A69D5468D1BD3D5E91367A6931BC`
**Tag:** `v2.0.0` (annotated) → `7b484a1`, pushed to `origin`
**Supersedes:** `PROJECT-CLOSEOUT-20261109.md` and `RC-CLOSEOUT-20261113.md`
as the current project status record. Those two remain the history of the
2026-11-09 status and the 2026-11-13 RC envelope.

---

## 1. What "closed" means here

The project closes as a **shippable, detection-only release at E5**:

- every release gate is PASS and no gate is waived;
- the runtime, the signed release tree and the installed image are the same
  image, proven by hash;
- a 24 h process window passed on that image;
- the L7 anomaly lane was proven against a real attacker VM on the production
  sensor's own link;
- every remaining gap is either environmental (needs different hardware or a
  lab peer), an explicit v1.1 source change, or a distribution step that
  requires key material this repository does not hold.

It does **not** close as E7, does **not** authorize enforcement, and does
**not** claim production driver signing. Those are stated as limitations in
§6, not as defects discovered late.

Product boundary is unchanged and authoritative: `prevention_gate=closed`,
`tier3_enforcing=false`, `host_effect_capable=false`. No production path may
add an AEGIS-owned `FWP_ACTION_BLOCK` filter, mutate traffic, or emit
`host_effect_confirmed=true`.

## 2. Release identity and gate state

| Gate | State | Basis |
|---|---|---|
| `truth_artifacts` | PASS | `TRUTH_VALID`, artifacts carry build source `7c604d5` |
| `component_audit` | PASS | modules 66/66, prod failures 0, part_ii 5/5, golden path declared |
| `release_signature` | PASS | `release/T20-final/9ebee9b/signatures.json` (ed25519) signs `SHA256SUMS`; commit `9ebee9b` contains runtime `7c604d5` |
| `clean_host_e5` | PASS | `admin-evidence/e5-clean-host-20261114-222014/preflight-20261114-222014.json` |
| `soak_24h` | PASS | `SOAK3-PROCESS-E5-20261117`, 24.62 h, `problems []`, `scm_restarts []` |
| `evidence_debt` | PASS | unnamed product files 0 ≤ baseline 0 |

`release_engineering.py --verify`: **648 artifacts** match their recorded
digests at source `7c604d5`. `final_audit.py --release-check`: **SHIPPABLE,
0/6 gates open**.

Runtime identity: the installed image at
`C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`, the workspace build and
`zig-out\bin\aegis_nids.exe` are the same sha256. No rebuild, reinstall,
re-sign or restart happened during the L7 work; the 24.62 h process window was
not interrupted.

## 3. What closed since the 2026-11-09 closeout

| Item | State | Evidence |
|---|---|---|
| `#25` WFP/PEP host-blocking source paths vs detection-only | CLOSED | block IOCTL hard-fails, PEP returns ESCALATE, projection is observe-only; `release/T20-final/9ebee9b/KNOWN_LIMITATIONS.md` |
| `#28` ingestion payload/provenance contract | CLOSED | wire v3 bounded payload + provenance (`PAYLOAD-ENVELOPE-V3-001`), all codecs |
| `#29` minifilter rows dropped | CLOSED at the accepted envelope | `SOAK3`: `queue_dropped_total` 1,377/3,500 (all ETW `reg_change`), `shed_overload` 984/20,000 (Kernel-File storm), nose/minifilter 0 |
| `#30` heap corruption / SCM restart | CLOSED | 24.62 h with `problems []` and `scm_restarts []` |
| `READY-PROMOTION-001` build/runtime mismatch | CLOSED | installed = built = `7955A6E3...` |
| `DETECT-L4-001` L4 detection | CLOSED, E5 | 40-port SYN burst tagged R9006; 10-port control clean |
| `IDS-L7-003` L7 anomaly lane | CLOSED, E5 | live `protocol_anomaly` `10004`/`10001`/`10003` from bridged Kali `192.168.1.207` |
| `SOAK2` | VOID, replaced | host rebooted 8.9 h in; `SOAK3` is the process-start window |

## 4. Remaining work, and where it is tracked

The full list with costs is `docs/BACKLOG-v1.1.md`. Summary: **9 open gaps**
(one of them new, §5), plus distribution steps.

| Group | Items | Why not in v2.0.0 |
|---|---|---|
| Needs different hardware or a lab peer | `CAPTURE-LOOPBACK-001` (P2), `E5-RECHECK-STALE-IMAGE-20261101`, `EVI-G2-PEP-CACHE-001-LAB`, `KIDS-002`, `CAPTURE-DUP-WIFI-001` (P3) | no Npcap loopback adapter, no second host, no enforcement rights, one adapter |
| v1.1 source change | `RULE-LAYER-SCOPE-001` (P3), `CAPTURE-DUP-WIFI-001` dedup option, `GAP-QLOSS-ISOLATION-002` / `ADR-0012-DUP-RATIO-E5` | a `src/` change forces rebuild + re-sign + a new 24 h soak; the signed tree must not drift |
| Distribution | EV certificate + Microsoft attestation/HLK for the drivers, a 6.0.0 installer, `bandit`/`pip-audit` locally | requires key custody, NSIS tooling and CI, not source work |

None of them is a defect that invalidates a v2.0.0 detection verdict. The P2
item (`CAPTURE-LOOPBACK-001`) limits self-testing, not detection on a real
link; the P3 items inflate or mislabel evidence on specific paths.

## 5. Findings recorded during the L7 work

- **`CAPTURE-DUP-WIFI-001` (P3, OPEN).** This Killer Wi-Fi adapter/Npcap path
  delivers every frame twice. Single-handle `dumpcap`: identical `ip.id`, TCP
  sequence and bytes, ~7 µs apart, one Ethernet interface block; a VMware
  VMnet1 ARP control showed no duplication. The product emits one event per
  captured frame (`nose_duplicate_event_ids=0`). Counts on this adapter are 2×
  the wire count. Record: `CAPTURE-DUP-WIFI-001-20261117.md`.
- **`REL-EOL-DIGEST-001` (P3, OPEN, new).** The signed `SHA256SUMS` digest is
  the digest of the CRLF file on disk (`9F87BF36...`); the git blob stores LF
  and hashes to `668C26B1...`. Verification from a clean checkout with
  `core.autocrlf=false` therefore fails even though the content is identical.
  This does not change what ships; it limits how a third party can re-derive
  the signed digest. Tracked in the index and in `docs/BACKLOG-v1.1.md`.

## 6. Declared limitations (ship notes, not open defects)

1. **Detection-only.** Drivers are test-signed; the WFP callout is
   observe-only and its block IOCTL hard-fails as unsupported. `prevention_gate`
   stays closed and no row claims a host effect.
2. **One host, one adapter, one VM.** All E5 claims are for this Windows host,
   the Killer Wi-Fi AX1650i path and one Kali 2026.2 VM. No fleet, no kernel
   qualification.
3. **L7 coverage is partial.** Only HTTP `10004`/`10001`/`10003` were
   exercised live. `10002`, DNS (`10005`/`10006`), TLS (`10008`/`10010`) and
   SMB (`10011`/`10012`), IPv6 and multi-segment requests remain unit-pinned
   only.
4. **Loss envelope, not zero loss.** `queue_dropped_total` 1,377/3,500 and
   `shed_overload` 984/20,000 in the 24.62 h window; all ETW ingress. Network
   and minifilter loss zero.
5. **Signed RC from the working tree.** `KNOWN_LIMITATIONS.md` states binaries
   must be rebuilt from source for a production cut; the tracked tree is not
   byte-identical to a fresh `git archive` because of the EOL behaviour in §5.
6. **Audit stamp.** `docs/gates/T20_100pct_audit.*` is generated from `HEAD` at
   run time; this record's audit was generated at `7b484a1`, the tagged release
   commit. A later records commit does not invalidate it (ADR-0008 build-source
   rule), but the stamp is one commit behind this file by construction.

## 7. Verification actually run (and what did not pass)

| Check | Result |
|---|---|
| `python tools/truth.py verify` | `TRUTH_VALID` |
| `python tools/release_engineering.py --verify` | OK, 648 artifacts, source `7c604d5` |
| `python tools/final_audit.py --release-check` | SHIPPABLE, 0/6 open, exit 0 |
| `pytest tests/release tests/tools` | **1 failed, 480 passed** — see below |
| `pytest tests/tools/test_runbooks.py tests/tools/test_lab_attack_window.py tests/release/test_evidence_index_valid.py tests/security/test_evidence_index_integrity.py` | 35 passed |

The single failure is `tests/release/test_native_build_and_scripts.py::test_bridge_builds_into_dist`:
`LINK : fatal error LNK1104: cannot open file 'D:\NIDs_Windows\dist\aegis_ipc.dll'`.
The existing DLL is exclusively locked by a running process (verified with an
exclusive open). This is an environment condition, not a code regression; the
test builds into a temporary directory but links against the in-tree `dist\`
output.

## 8. Branch and worktree disposition

Kept, local-only, **not** part of v2.0.0 and not pushed:

| Branch / worktree | Commit | Disposition |
|---|---|---|
| `supertee003-repository-baseline-alignment` (`.../supertee003-fluffy-engine`) | `5e62f23` | KEEP as unvalidated v1.1 archive (29 files: layer-scoped AC, FIM coalescing, loopback prep) |
| `supertee003-loopback-capture-support` (`.../supertee003-silver-adventure`) | `16cbbff` | KEEP as unvalidated v1.1 archive (13 files: `DLT_LOOP` prep, different `test_e6` variant) |
| `supertee003-soak-closeout-prep` (`.../supertee003-studious-waddle`) | `daf9088` | KEEP pending owner decision; not part of the release |
| `copilot-prewarm-vigilant-giggle` (detached at `main` `2d19381`) | — | disposable; can be pruned |

The two Copilot commits are unvalidated and their `src/` halves are
byte-identical. Nothing from them is installed, claimed, or signed. Deleting
any of them is a separate owner decision; this record only prevents them from
being mistaken for release content.

## 9. Honest completion statement

AEGIS NIDS Windows v2.0.0 is a **shippable detection-only release at E5**:
signed, hash-pinned, soak-proven for 24.62 h, and live-proven for L4 and for
three L7 HTTP anomaly rules against a real attacker VM. It is not a
production-signed kernel product (drivers are test-signed), not an enforcement
product, and not fleet-qualified. Nine gaps remain open with named causes and
costs; none of them blocks a detection verdict on the path this release ships.

Closing the remaining gaps is a v1.1 program, not a continuation of this
release. Do not patch the signed tree to close them.
