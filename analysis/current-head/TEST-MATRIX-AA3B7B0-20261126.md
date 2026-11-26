# Test / gate matrix at build source `aa3b7b0` — 2026-11-26

**RECORD-ID:** `TEST-MATRIX-AA3B7B0-20261126`
**RECORDS HEAD:** `6c94b47dc95acfef283cf24727e6edf2f2647e47`
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`

This page records the **exact commands and results** observed in this worktree before the final 24 h soak was armed. It does not promote any result to a level it did not earn.

## Gates observed

| Command | Exit | Result |
|---|---:|---|
| `python tools/truth.py verify` | 0 | `TRUTH_VALID` — artifacts carry build source `aa3b7b0`, ancestor of HEAD, source history and worktree clean |
| `python scripts/check_summary.py` | 0 | `SUMMARY_VALID` — summary/artifact/scope markers match entries |
| `python scripts/doc_checker.py` | 0 | `0 FAIL, 0 WARN, 23 total` |
| `python tools/release_candidate.py --verify --dir release/T20-final/6c94b47` | 0 | `RC VERIFY PASS` |
| `python tools/sign_release.py --verify --dir release/T20-final/6c94b47` | 0 | signature verifies `SHA256SUMS` digest `94F65BCC…` |
| `go test ./...` (in `nose/`) | 0 | `ok aegis-nose 10.852s` |
| `python -m pytest -q -m "not host_live"` | 0 | `1520 passed, 1 skipped, 18 deselected, 27 subtests passed in 335.92s` |
| `python tools/final_audit.py --check` (with owner trust anchor) | 0 | `5/6 PASS`; only `soak_24h` OPEN at the time of this record |

## Honest note about the bare pytest run

`python -m pytest -q` **without** the marker filter produced `1536 passed, 2 failed, 1 skipped, 27 subtests passed`. The two failures were:

- `tests/integration/test_e6_attack_burst.py::test_a_localhost_port_scan_is_captured_and_scored`
- `tests/integration/test_e6_l4_scan_detection.py::test_a_syn_scan_is_tagged_by_an_l4_rule`

Both are marked `host_live` in `pytest.ini` and require a live daemon with the **current-source** binaries installed and `AEGIS_NOSE_IFACE` pinned to the loopback selector. At the time of this run the elevated owner script had already restored the installed baseline binaries, so the host no longer satisfied that precondition and no R9006 rows were attributed to the test-owned ports. This is an environment precondition failure, not a hidden test change: no test was skipped, xfailed, relaxed or edited. The same two tests **passed** during the current-source owner-run and are recorded with their durations in `EVIDENCE_INDEX.json` entry `LOOPBACK-BPF-E6-AA3B7B0-20261126`. The canonical local suite therefore remains `-m "not host_live"`; host_live proof comes only from the owner-run evidence.

## Evidence produced in this session

| Scope | Level | Result |
|---|---|---|
| narrow loopback `host_live` pair at `aa3b7b0` | E6 | PASS (2 tests, attributable R9006 rows) |
| S2 replay denial + S3 durable producer identity | E5 narrow | PASS (owner-run, verified restore) |
| controlled 100/s loopback offered load | E5 narrow | PASS (6000/6000, zero loss deltas) |
| deterministic fuzz smoke + in-process microbenchmarks | E2 | PASS thresholds; coverage-guided fuzz **NOT_RUN** |
| Ed25519 release record at `6c94b47` | E2 | signature + trust anchor verified |
| first 24 h soak attempt | E0 | **VOIDED** after agent file I/O contaminated counters; no credit |

The fresh 24 h soak is deliberately started **after** all of the above work so that no file-heavy command runs inside its window. Its verdict will be recorded separately; nothing here pre-declares it.
