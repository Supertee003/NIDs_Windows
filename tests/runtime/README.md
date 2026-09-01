# AEGIS NIDS — Runtime Tests

Contract tests for the AEGIS runtime. These tests verify that every
component conforms to the runtime contract defined in
`docs/runtime/RUNTIME_CONTRACT.md`.

## Quick start

From the repo root:

```bash
python -m pytest tests/runtime/ -v
```

Or with `unittest`:

```bash
python -m unittest discover -s tests/runtime -v
```

## What is covered

| Test file                     | Contract section                          |
|-------------------------------|-------------------------------------------|
| `test_states.py`              | Lifecycle states (RUNTIME_CONTRACT §2)    |
| `test_timeouts.py`            | Timeout budgets (RUNTIME_CONTRACT §3)     |
| `test_health.py`              | Health probe schema (RUNTIME_CONTRACT §4) |
| `test_restart.py`             | Restart policy + quarantine (§5)          |
| `test_wire.py`                | Wire envelope + error classes (§6)        |
| `test_version.py`             | `--version` requirement (MATRIX §7)        |
| `test_component_matrix.py`    | Doc/fixture drift (COMPONENT_MATRIX)       |
| `test_harness_integration.py` | Live lifecycle tests (gated)              |
| `test_harness_scaffold.py`    | Future supervisor interface (TODO)         |

## Static vs. live tests

- **Static** tests (no process spawn): `test_states`, `test_timeouts`,
  `test_health`, `test_restart`, `test_wire`, `test_version`,
  `test_component_matrix`. These run on every platform and every CI stage.
- **Live** tests (`test_harness_integration`) actually spawn a binary
  and observe its lifecycle. They are skipped automatically when the
  binary is missing or the platform does not support the required
  transport (e.g. named pipes on non-Windows).

## CI integration

These tests belong to the **runtime-contract** CI stage, which runs
AFTER the build stage and BEFORE the integration-test stage.

```yaml
# .github/workflows/ci.yml excerpt
runtime-contract:
  needs: zig  # bridge + core must be built first
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: '3.12' }
    - run: pip install pytest
    - run: python -m pytest tests/runtime/ -v
```

## Adding a new component

1. Add a row to `COMPONENTS` in `conftest.py` (mirror the row you added
   to `docs/runtime/COMPONENT_MATRIX.md`).
2. Verify `test_component_matrix.py` passes (it cross-checks the
   fixture against the markdown table).
3. Add an integration test in `test_harness_integration.py` following
   the pattern of `TestBridgeLifecycle`.
4. If the component declares a new transport, extend `RuntimeProbe`
   in `conftest.py` and add a test in `test_health.py`.

## Future work

The `test_harness_scaffold.py` module documents the interface that the
Gate-B supervisor (`aegisctl`) must implement. Once that exists, the
integration tests will be rewritten to call `start_component` /
`stop_component` instead of spawning subprocesses directly.
