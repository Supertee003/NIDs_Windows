# Current-head closeout — build source `aa3b7b0` — 2026-11-26

**RECORD-ID:** `CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126`
**RECORDS HEAD:** moves with records-only patches (last recorded `8bf2a18d9f0e521db0d4e376e14632e1ca347ed1`); the build source does not move
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (ADR-0008)
**BOARD:** **5/6 PASS — NOT SHIPPABLE** (`soak_24h` OPEN). No E7 claim.

This is the single-page combined view of what is proven at the current source, what is only documented, and what is still open. Nothing here promotes evidence to a higher level.

## 1. Source and release truth

- Build source `aa3b7b0` is the loopback-BPF fix; records-only commits after it (through `ad55d55`) do not move the build source. `python tools/truth.py verify` = `TRUTH_VALID`.
- Published identity remains `v1.1` / signed candidate `466a226` / build source `a53eda8` — **unchanged**. Source: `analysis/current-head/V1.1-RELEASE-CLOSEOUT-20261122.md`.
- New **additive** signed record: `release/T20-final/6c94b47`, digest `94F65BCC…`, owner-approved public anchor `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=`. Private key is owner-held outside the tree. `sign_release.py --verify` and `final_audit.py::release_signature` PASS. Details: `RELEASE-SIGNATURE-AA3B7B0-20261126.md`; anchor policy: `docs/gates/RELEASE_TRUST_ANCHOR.md`.

## 2. Evidence actually produced at this source

| Scope | Level | Result | Record |
|---|---|---|---|
| narrowing loopback capture, two `host_live` tests, attributable R9006 rows | E6 narrow | PASS | `MASTER-AUDIT-LOOPBACK-BPF-E6-AA3B7B0-20261126.md` |
| S2 byte-identical control replay denial + S3 durable producer generation/sequence | E5 narrow | PASS | `S2S3-HOST-PROOF-E5-AA3B7B0-20261126.md` |
| canonical pipe-reader bounded shutdown + exact counter deltas | E5 narrow | PASS | `PIPE-READER-SHUTDOWN-E5-AA3B7B0-20261126.md` |
| R2003 `CommandLine` producer host re-measurement (one positive, two negative controls) | E5 narrow | PASS | `R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md` |
| controlled 100 connections/s loopback offered load, 6000/6000, zero loss deltas | E5 narrow | PASS | `CURRENT_HEAD_FUZZ_BENCH-20261126.md` (and raw `netbench/`) |
| deterministic 1,000-case fuzz smoke + in-process benchmarks | E2 | PASS thresholds | same page; **coverage-guided fuzz NOT_RUN** |
| Ed25519 release record + trust anchor | E2 | PASS | `RELEASE-SIGNATURE-AA3B7B0-20261126.md` |
| consolidated gate matrix | E2 | PASS with honest host_live note | `TEST-MATRIX-AA3B7B0-20261126.md` |
| AEGIS-001..020 | E1/E2 / documented gap | closed honestly | `EVIDENCE_INDEX.json` |

All elevated host runs swapped current-source binaries and restored hash-identical baselines with `restore.verified=true`.

## 3. Gates

`python tools/final_audit.py --check` with the current-source anchor reports:

- PASS `truth_artifacts` — TRUTH_VALID + SUMMARY_VALID
- PASS `component_audit` — 66/66 modules, 0 production failures, Part II 5/5
- PASS `release_signature` — owner trust anchor, commit `6c94b47` contains runtime `aa3b7b0`
- PASS `clean_host_e5` — owner-attested preflight bound to pinned hashes (historical host window)
- **OPEN `soak_24h`** — no fresh 24 h verdict at this source
- PASS `evidence_debt` — 0 unnamed product files

Local suite: `python -m pytest -q -m "not host_live"` → `1520 passed, 1 skipped, 18 deselected, 27 subtests`; `go test ./...` ok. One run of this suite intermittently failed at `tests/brain/test_cython_prefilter.py::test_case2_event_reaches_the_prefilter_without_nameerror`: the `[CYTHON MATCH]` marker appeared before `logs/anomalous.json` had a flushed line, so the probe read an empty file. The same file passed alone and the immediate full rerun passed `1520/1520`. No test was skipped, xfailed, relaxed or edited to hide this; the flake is recorded, not claimed as a product detection failure. A bare `pytest -q` includes two `host_live` tests that require the current-source host to be installed; on the restored baseline they fail because no R9006 rows are attributed to their ports. They passed only in the elevated owner run.

## 4. Honest failures and voids

- First 24 h window (`162907`) was voided because agent file I/O (release assembly, WDK build, pytest, doc checks) moved `minifilter_ring_dropped` to 37,361 and the daemon became `DEGRADED`. Record: `SOAK-ATTEMPT-VOID-AA3B7B0-20261126.md`.
- Second window (`172958`) was voided after a harness server restart killed the detached finalizer; baseline was restored with `restore.verified=true`. Record: `SOAK-ATTEMPT-VOID-DEFER-AA3B7B0-20261126.md`.
- Third window (`214622`) was voided by owner direction so the gaps could be closed first; finalizer deleted, baseline restored with `restore.verified=true`, service `Running`, `errors=[]`. Record: `SOAK-ATTEMPT-VOID-GAPS-FIRST-AA3B7B0-20261126.md`.
- None contributes evidence. No loss budget was raised and no failure was relabelled.

## 5. Remaining work — the only open gap

Start a **fresh** 24 h soak after this records commit, with no other work on the host during the window, then:

1. read the evaluated `soak-final.json` and `result.json` (verdict, `elapsed_hours >= 24`, `problems=[]`, `restore.verified=true`, zero counter deltas);
2. copy them into `admin-evidence/` and tracked raw artifacts;
3. record the verdict honestly (PASS or VOID/FAIL);
4. re-run all gates to reach 6/6, rebaseline, commit and push;
5. only then discuss E7 — a soak PASS alone is not production release qualification.

Coverage-guided fuzzing remains NOT_RUN; no such toolchain result is claimed. All remaining
non-soak gaps are dispositioned in
[`REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md`](REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md):
coverage-guided fuzz, the full 23-rule matrix, VLAN/IPv6 host visibility, Go capture-adapter
shutdown, signed driver/lifecycle/full Windows E5, E7 and clean install/uninstall are
`CLOSED as documented gap`. That is a documentation status only — no evidence `status`, `level`,
`result`, `status_basis` or gate verdict was promoted.
