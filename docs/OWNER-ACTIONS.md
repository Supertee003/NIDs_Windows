# Owner action card — what blocks us and what the agent can do now

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged by records commits)  
**BOARD:** **5/6 PASS — `soak_24h` OPEN — NOT SHIPPABLE**  
**STATUS:** the real `225843` finalizer verdict is `FAIL`; the window is also VOID for a runtime swap (#55).

This page is a **decision card, not evidence**. It changes no gate, verdict, level, signature, authority or source file. `docs/PATH-TO-COMPLETE.md` holds the full sequence; this page is the short version of what exactly is waiting and what can proceed immediately.

## 1. Split at a glance

| Bucket | Items | Who acts |
|---|---|---|
| **DONE — no waiting** | Real finalizer consumed and recorded as FAIL/VOID; verbatim artifacts + SHA-256 manifests; EVIDENCE_INDEX entries; status surfaces rebased; all local gates green; CI green; issue comments #47–#55 | Agent — complete |
| **WAITING — hard blockers** | (A) clean soak window; (B) source rebaseline decision + host window; (C) owner key / real E7 or signed-driver evidence | Owner |
| **CAN DO NOW — without touching those blockers** | Prepare patch-transaction skeletons and checklists; re-run any read-only verification; keep status surfaces honest; consume a verdict the moment a real artifact appears | Agent — on request |

No combination of local tests, documentation or static review substitutes for A/B/C.

## 2. Card A — clean soak window (closes / fails `soak_24h`)

**Owner must do:** stop/remove the stale `214622` finalizer and the `225843` watcher; ensure exactly **one finalizer per window**; arm one fresh 24 h window with no concurrent host work, driver swap or agent I/O; leave the finalizer's real artifact at its own path.

**What the agent needs to know:** the new run directory / `result.json` path and confirmation that cleanup is done and the window is armed. The agent does not need the key or the verdict pasted into chat — it reads the artifact read-only.

**Acceptance the agent will apply (unchanged):** `verdict=PASS`, `elapsed_hours>=24`, `problems=[]`, `restore.verified=true`, counter deltas consistent with the raw transcript, and a stable binary set for the whole window. Anything else is recorded honestly as VOID/FAIL and `soak_24h` stays OPEN. No `loss_budget=3500` is added, no old PASS is reused.

**Agent's immediate next actions once A exists:** read the artifact and raw traces; byte-exact copy into tracked raw artifacts with SHA-256 manifest; apply the acceptance rule; re-run truth/summary/doc/release/final_audit; rebaseline with the real verdict; commit/push and comment #54/#55. A PASS is still only a gate input — never E7, a new signature or a new release by itself.

## 3. Card B — source rebaseline decision (#47/#50/#51/#53)

**Owner must decide:** whether to authorize patch transactions for #47 items 1–3 (minifilter unload UAF/race, `FltCloseClientPort`, persistent WFP block filters) and 6 (per-file release-gate verification), plus #50 kernel/WFP, #51 network parity and #53 testing maturity; and whether a new **authorized host window** is granted for driver-load / full matrix checks.

**Agent can prepare now (no source touched):** a PATCH-ID / FLOW-ID / TARGET HEAD / TARGET FILES / TARGET SYMBOLS / IN-SCOPE / OUT-OF-SCOPE / CONTRACT / ABI / AUTHORITY / STATE / TEST / EVIDENCE skeleton per issue, per `AGENTS.md`. Each would be a separate vertical slice with its own build source and fresh verification; none inherits the void soak.

**Until B exists:** all those source files stay frozen. No guard, gate, test, skip, xfail, waiver or verdict is edited. E5 host claims stay NOT_PROVEN unless an authorized window produces them.

## 4. Card C — signature / E7 / signed driver

**Agent action completed 2026-11-28:** under owner delegation, the approved
current-source Ed25519 key signed a records-tip identity attestation
(`analysis/current-head/OWNER-KEY-ATTESTATION-AA3B7B0-20261128.md`, verify PASS,
digest `A810F023E1871427...`). No private key was tracked or printed. This is
integrity of the honest record only — **not** a new release, E7, signed driver
or soak credit. The remaining part of Card C (real HLK/catalog/Authenticode
evidence) still needs artifacts produced by external tooling; none exists here.

**Owner must supply:** confirmation whether a **new** Ed25519 release signature is wanted (key stays owner-held at `D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519`; never paste it into chat or commit it), and real HLK/catalog/Authenticode evidence for E7 or signed drivers — or say "none".

**Agent can prepare now:** record the exact paths and the no-fabrication boundary; keep the published identity `v1.1` / `466a226` / `a53eda8` and existing digest `94F65BCC…` unchanged.

**Until C exists:** no new signature, no E7, no driver-load or signed-driver claim. `tools/final_audit.py` has no HLK/E7 gate; a soak PASS does not create one.

## 5. What the agent will not do unilaterally

- Create or edit `result.json`, `soak-final.json` or any finalizer artifact.
- Touch the host, service, driver, installed binaries, scheduled tasks or a live soak window.
- Reuse the historical 36.52 h PASS for `aa3b7b0`, add `loss_budget=3500`, or relabel a FAIL/VOID as PASS.
- Sign with the owner-held key, invent E7/HLK evidence, or expand policy/enforcement authority.
- Move the build source before a separate owner-authorized patch transaction.

## 6. Immediate answer

- **Still waiting:** A (clean window), B (source/host decision), C (key/E7 evidence).
- **Can do right away, without A/B/C:** prepare the patch-transaction skeletons and verification checklists, keep records honest, and consume a real artifact the moment owner produces one.
- **Everything else is already done** at records tip `git rev-parse HEAD` with build source `aa3b7b0`.
