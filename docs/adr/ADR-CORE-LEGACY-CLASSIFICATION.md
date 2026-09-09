# ADR-CORE-LEGACY-CLASSIFICATION

**Status:** Accepted
**Date:** 2026-09-09
**Supersedes:** —
**Superseded by:** —
**Owner:** AEGIS Core Team
**Related:** ADR-RUNTIME-CONVERGENCE, BLOCKER A (Runtime Truth)

---

## Context

The repository contains two parallel sets of Zig source files:

1. **`src/`** — 70 files, compiled by `build.zig` (line 14: `src/main.zig`)
2. **`core/`** — 144 files, NOT compiled by `build.zig`

`core/` contains proof modules, integration tests, CLI tools, and legacy implementations
that predate the `src/` migration. Many files are named `*_proof.zig`, `*_integration.zig`,
`*_cli.zig`, and `*_config.json` — indicating they are validation/tooling artifacts,
not production source.

The `AGENTS.md` and `runtime_manifest.json` have been updated (PATCH-01) to reflect this,
but no formal ADR documents the classification.

---

## Decision

### 1. `src/` is Canonical Source

All production code lives in `src/`. The build system (`build.zig`) compiles only from `src/`.

### 2. `core/` is LEGACY / EXPERIMENTAL

`core/` files are classified as:

| Class | Count | Examples |
|---|---|---|
| `proof` | ~30 | `*_proof.zig`, `*_integration.zig` |
| `cli` | ~15 | `*_cli.zig`, `*_cli_config.json` |
| `legacy` | ~50 | Old implementations superseded by `src/` |
| `experimental` | ~20 | Features not yet migrated to `src/` |
| `config` | ~10 | `*_config.json` for CLI/proof modules |

### 3. `core/` Must NOT Be Compiled in Production

`build.zig` must never reference `core/` files. Any import from `core/` into `src/`
is a **STOP-THE-LINE** violation.

### 4. `core/` May Be Referenced for Design

Developers may read `core/` for design context, proof-of-concept patterns, and
historical decisions. But production code must live in `src/`.

---

## Verification

```bash
# build.zig must NOT reference core/
grep -r "core/" build.zig  # should return empty

# src/ must NOT import from core/
grep -rn '@import(".*core/' src/  # should return empty
```

---

## Impact

- **Build:** No change (build.zig already only compiles from `src/`)
- **Tests:** No change (test files are in `src/tests/`)
- **Documentation:** This ADR + AGENTS.md + runtime_manifest.json already updated
- **Future work:** New modules should be created in `src/`, not `core/`

---

## References

- ADR-RUNTIME-CONVERGENCE (canonical runtime definition)
- PATCH-01 (build truth + runtime manifest correction)
- AGENTS.md (language ownership + STOP-THE-LINE triggers)
