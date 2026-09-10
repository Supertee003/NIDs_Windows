# Version Definitions

**Contract ID:** VERSION
**Version:** 1.0
**Status:** FROZEN
**Languages:** All

## Purpose

Standardized versioning across all AEGIS subsystems.
Every component MUST report its version in a consistent format.

## Version Format

```
MAJOR.MINOR.PATCH
```

- **MAJOR:** Incompatible API changes
- **MINOR:** Backwards-compatible functionality
- **PATCH:** Backwards-compatible bug fixes

## Current Versions

| Component | Version | Language |
|-----------|---------|----------|
| AEGIS NIDS | 5.0.0 | All |
| Canonical Event | 1.0 | All |
| Wire Protocol | 1.0 | All |
| PEP ABI | 1.0 | Zig/Rust |
| Policy IR | 5.0 | TypeScript/Zig |
| Control Protocol | 1.0 | TypeScript/Zig |
| Rust PEP | 5.0.0 | Rust |
| Go Nose | 5.0.0 | Go |
| Python Brain | 5.0.0 | Python |
| TypeScript Policy | 5.0.0 | TypeScript |

## Protocol Versions

| Protocol | Version | Magic |
|----------|---------|-------|
| Canonical Event | 1 | 0x41454731 ("AEG1") |
| Wire Protocol | 1 | 0x57455631 ("WEV1") |
| Control Protocol | 1 | 0x4354524C ("CTRL") |
| Policy IR | 5 | 0x50495231 ("PIR1") |

## Version Negotiation

### Startup
1. Zig Runtime reports version to all subsystems
2. Subsystems validate compatibility (major version match)
3. Incompatible major versions → startup failure

### Runtime
- Version changes require restart
- Hot-reload is NOT supported for version changes
- Backwards-compatible changes (minor/patch) are safe

## Invariants

- Version is semantic (MAJOR.MINOR.PATCH)
- Major version mismatch is a hard failure
- All subsystems must agree on protocol versions
- Version changes are logged in audit trail
- No silent version upgrades

## References

- `shared/protocol/protocol_version.json` - Protocol versions
- `CONTRACT_MAP.json` - Contract registry
- `AI_CONTEXT.md` - System context
