# CLI-LOGS-RESOLVER-001 — the residual runtime paths now share the one resolver

**Created:** 2026-11-14
**Build source:** `68a6caa` (touches `tools/`, `tests/`)
**Level:** E2
**Closes:** the residual recorded in `TEST-HYGIENE-S301` §Residual

---

## 1. What was left over

`TEST-HYGIENE-S301` fixed the two candidate-list commands (`block list`,
`quarantine list`) and recorded the rest as residual, because no test wrote them:

| Site | Path |
|---|---|
| `_event_log_candidates()` | `<repo>/logs/aegis_core.ndjson` |
| `_event_log_path()` fallback | `<repo>/logs/aegis_core.ndjson` |
| `canary report` | `<repo>/logs/canary_last.json` |
| `canary run` receipt write | `<repo>/logs/canary_last.json` |
| `brain inbox` | `<repo>/logs/anomalous.json` |

Same defect class as S3-01: a runtime path that no fixture can redirect, so any
test or lab run that exercises those commands writes tracked tree state (or
silently reads the wrong file). The fact that nothing writes them *today* is
luck, not design — and the canary receipt is written by a command an operator
runs.

## 2. Fix

All five go through `_logs_dir()`, the single resolver introduced by S3-01:

```python
def _logs_dir() -> Path:
    override = os.environ.get("AEGIS_LOGS_DIR")
    return Path(override) if override else TOOLS_DIR.parent / "logs"
```

The installed service never sets `AEGIS_LOGS_DIR`, so production state stays at
`<repo>/logs`; the resolver exists so tests and lab runs can point elsewhere.

## 3. Structural pin

`tests/tools/test_aegisctl_logs_resolver.py`:

- the literal `TOOLS_DIR.parent / "logs"` may appear **exactly once**, inside
  `_logs_dir()` — a new command that hand-builds a path fails the suite;
- the two other spellings (`parent / "logs" / "`, `REPO_ROOT / "logs" /`) are
  refused outright;
- behavioural proof: `canary report` with `AEGIS_LOGS_DIR` pointing at
  `tmp_path` reads the receipt from there and exits 0;
- `canary report` with no receipt returns `available: false`, exit 3, and
  creates **no** file — a read command must not write.

The behavioural half matters because the static half alone would pass a
resolver that nothing actually calls.

## 4. Verification

| Check | Result |
|---|---|
| `pytest tests/tools/test_aegisctl_logs_resolver.py` | 4 passed |
| `pytest tests/security tests/tools` | 428 passed |

## 5. Residual

None on this path: every `<repo>/logs` reference in `tools/aegisctl.py` now
originates in one function. `tools/*.py` other than `aegisctl.py` were not
audited by this slice and are not claimed.
