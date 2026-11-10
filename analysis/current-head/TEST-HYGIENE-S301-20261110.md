# TEST-HYGIENE-S301 — a test wrote tracked tree state; the CLI now redirects

**Patch ID:** TEST-HYGIENE-S301
**Flow ID:** VER (evidence integrity) / Test hygiene item 2
**Target HEAD:** `d2f6c00`-equivalent working tree (source `e68cd96` + this patch)
**Evidence level:** E2

## The defect (S3-01 from SYSTEM-SURVEY-001)

`tests/security/test_candidate_labels.py` created and unlinked
`logs/blocked_ips.json` and `logs/quarantine.json` **inside the repository**:

```python
BLOCK_FILE = REPO / "logs" / "blocked_ips.json"
QUAR_FILE = REPO / "logs" / "quarantine.json"
BLOCK_FILE.write_text(...)   # in the test body
cleanup()                    # unlink in finally / setup / teardown
```

AGENTS.md TEST HYGIENE item 2 forbids exactly this: a test that writes tracked
tree state dirties every subsequent tree and invalidates `truth.py` and the
release gates depending on run order. The `cleanup()` calls hid the problem in
the happy path; a single assertion failure or a `--forked`/parallel run leaves
the file behind, and any concurrent run sees it.

## Why it could not simply be "moved to tmp_path"

The CLI resolved those two paths by hand:

```python
path = TOOLS_DIR.parent / "logs" / "blocked_ips.json"   # tools/aegisctl.py
qpath = TOOLS_DIR.parent / "logs" / "quarantine.json"
```

`tools/aegisctl/config.py` already declared `BLOCKED_IPS_FILE` /
`QUARANTINE_FILE`, but the commands did not use them, so no environment or
fixture could redirect the read. The two path schemes were silently duplicated.

## Fix

| File | Change |
|---|---|
| `tools/aegisctl/config.py` | `LOGS_DIR` honours `AEGIS_LOGS_DIR` (defaults to `<repo>/logs`) |
| `tools/aegisctl.py` | new `_logs_dir()` helper; `block list` and `quarantine list` use it instead of a hand-built path |
| `tests/security/test_candidate_labels.py` | fixture state written to `tmp_path`; CLI invoked with `AEGIS_LOGS_DIR`; an autouse fixture asserts the two tracked paths do not appear or disappear around every test |

The override is test/lab-only by construction: the installed service starts from
the SCM, which does not export `AEGIS_LOGS_DIR`, so production state stays at
`<repo>/logs`. `tests/runtime/conftest.py` already assumed this variable existed
(`os.environ.get("AEGIS_LOGS_DIR", "logs")`); this patch makes the assumption
true for the CLI as well.

## Proof

| Check | Result |
|---|---|
| `pytest tests/security/test_candidate_labels.py` | 4 passed |
| mutation control: a test that writes `logs/blocked_ips.json` | **fails** — `test wrote tracked-tree state under logs/ (TEST HYGIENE item 2): [('blocked_ips.json', True), ...]` |
| `pytest tests/security tests/tools` | 391 passed |
| `python tools/aegisctl.py block list` / `quarantine list` (no env, production default) | unchanged output, no file created |
| `git status --short` after the suite | only the patch's own files |

The mutation control matters more than the green run: it proves the guard fires
on the exact violation it exists to prevent, rather than passing because nothing
was checked.

## Adjacent pins corrected in the same patch

Removing the Go classifier (VERDICT-AUTH-001) invalidated six pins in
`tests/security/test_detection_contract_pin.py` that encoded "detection happens
in two engines". They now encode the actual contract:

- **one** tier reads `configs/Rules.json` (Zig, through the bundle resolver);
- **no** acquisition file may load a rule file, decode `match_pattern`, gate on
  `fast_pattern`, or carry a rule action;
- the FNV-1a rule-id table is shared by Zig, the Python reference and the CLI;
- the nose package must still build without its deleted matcher
  (`go build` in the pin, not just `go test`).

`analysis/current-head/evidence-debt-baseline.json` was regenerated
(`python tools/evidence_debt.py --write`) because the two deleted
`nose/signature_classifier*` files were named by evidence and the ratchet
refuses a stale baseline.

## Invariant

> No test writes inside the repository's tracked runtime tree; runtime paths
> have exactly one resolver, and it is redirectable without touching production
> defaults.

## Residual

- `tools/aegisctl.py` still hand-builds four other runtime paths
  (`aegis_core.ndjson` at two sites, `canary_last.json`, `anomalous.json`). They
  are not currently written by tests, so this patch does not touch them; a
  follow-up should route them through `_logs_dir()` for the same reason.
- The 24 h soak (#30) was running throughout this source-only patch, so no host
  observation belongs to it.
