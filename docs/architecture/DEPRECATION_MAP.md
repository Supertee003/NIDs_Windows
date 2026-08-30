# Deprecation Map

**Status**: AUTHORITATIVE
**Date**: 2026-08-31

---

## Deprecated Documents

The following documents are DEPRECATED and point to `docs/architecture/ARCHITECTURE_CANONICAL.md`:

| Document | Status | Replacement |
|----------|--------|-------------|
| `docs/ARCHITECTURE_BOUNDARY.md` | DEPRECATED | `docs/architecture/ARCHITECTURE_CANONICAL.md` |
| `docs/ARCHITECTURE.md` (if exists) | DEPRECATED | `docs/architecture/ARCHITECTURE_CANONICAL.md` |
| `docs/STRUCTURE.md` (if exists) | DEPRECATED | `docs/architecture/ARCHITECTURE_CANONICAL.md` |
| `docs/DEPLOYMENT.md` (if exists) | DEPRECATED | `docs/runbooks/RB-009-hot-reload-config.md` |

**Action**: Each deprecated document must have a header:

```markdown
# [Original Title]

**DEPRECATED** - This document is superseded by `docs/architecture/ARCHITECTURE_CANONICAL.md`.
Do not update this file. All architecture decisions are now in the canonical document.
```

---

## Legacy Files (Migration Candidates)

### nids_analyze.zig

**Status**: DEPRECATED (G22 replaced stub with dispatcher wrapper)
**Replacement**: `core/dispatcher.zig` (delegates via `drainQueue()` and `processEvent()`)
**Action**: Prove zero runtime dependency, then remove

**Migration path**:
```
LEGACY (stub)
  -> DEPRECATED (dispatcher wrapper, G22)
  -> MIGRATED (zero runtime dependency proven)
  -> VERIFIED (clean build without it)
  -> REMOVED
```

### legacy_removal.zig

**Status**: ADAPTER (migration controller)
**Authority**: Migration proof tool, NOT permanent runtime subsystem
**Action**: Keep until all legacy paths removed, then deprecate

---

## File Status Values

| Status | Description |
|--------|-------------|
| ACTIVE | Required for production runtime |
| ADAPTER | Connects runtime boundaries (legitimate) |
| PROOF | Test-only (verifies invariant) |
| TEST | Behavioral tests |
| TOOL | Utility scripts |
| LEGACY | Old implementation awaiting removal |
| DEPRECATED | Marked for removal (do not update) |
| GENERATED | Auto-generated (do not edit) |
| REMOVE | Safe to remove (zero-authority proven) |

---

## Removal Procedure

A file is safe to remove only when:

```
no runtime import
+ no build dependency
+ no test dependency
+ no deployment dependency
+ no generated source dependency
```

### Audit Procedure (10 steps)

```
AUDIT-01: List all source files
AUDIT-02: For each file find incoming references
AUDIT-03: Classify references (runtime / test / tooling / docs)
AUDIT-04: Mark files with zero runtime references
AUDIT-05: Check whether they are test/proof-only
AUDIT-06: Mark legacy candidates
AUDIT-07: Create removal PR
AUDIT-08: Run full regression
AUDIT-09: Delete
AUDIT-10: Run clean build
```

---

## Cleanup Targets (P0)

### Tracked files that should NOT be in source repository

```
.zig-cache/                    # build cache (should be gitignored)
build_r15_stdout.txt           # build log
build_r15_stderr.txt           # build log
build_r15c_stdout.txt          # build log
build_r15c_stderr.txt          # build log
build_r16_stdout.txt           # build log
build_r16_stderr.txt           # build log
build_stdout.txt               # build log
build_stderr.txt               # build log
verify_build.stdout            # build log
verify_build.stderr            # build log
build.zig.phase*_backup        # backup files
core/*.phase*_backup           # backup files
backup_g*/                     # G-phase backup directories
```

### Cleanup commands

```powershell
# Remove tracked build cache
git rm -r --cached .zig-cache

# Remove tracked build logs
git rm --cached build_*.txt verify_build.*

# Remove tracked backup files
git rm --cached *.phase*_backup
git rm --cached core/*.phase*_backup

# Remove G-phase backup directories
git rm -r --cached backup_g*/

# Remove stray Python marker
git rm --cached config/__init__.py
```

### .gitignore update

The `.gitignore` must include:

```
# Build cache
.zig-cache/
zig-cache/

# Build logs
build_*.txt
verify_build.*

# Backup files
*.phase*_backup
backup_phase*/
backup_hotfix*/
backup_pre_rewrite/
backup_g*/
backup_*/

# Logs
logs/
*.log
*.ndjson
```

---

## Compliance Wording Fix

### Incorrect (current README)

```
AEGIS satisfies SOC 2, ISO 27001, and NIST CSF controls.
```

### Correct (mapped to control objectives)

```
AEGIS maps selected product controls and evidence mechanisms to
SOC 2, ISO 27001, and NIST CSF control objectives.
```

**Action**: Update README.md compliance section immediately.

---

## Do Not Allow

```
NEW + LEGACY
```

to become permanent architecture.

**Rule**: Every legacy path must have a removal plan. No permanent "compatibility" code.
