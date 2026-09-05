# AEGIS AI Governance Framework (P3 Phase X)

**Date:** 2026-09-02
**Status:** Active
**Applies to:** Every AI agent, automated tool, and human contributor that
modifies the AEGIS NIDS repository or its release artifacts.

---

## 1. Purpose

AEGIS is a security product: a mistake in the runtime spine, the policy
plane, or the enforcement path (PEP) can silently disable protection on
customer machines. AI agents accelerate development, but they must work
inside a bounded authority envelope with machine-checkable gates. This
document defines that envelope, the context contract an agent must load
before writing code, and the gates that prove a change is safe to merge.

The framework is deliberately small: an authority map, a context contract
template, and a verification gate list. Anything not covered here follows
the standard engineering rules in `docs/ARCHITECTURE.md` and
`docs/ARCHITECTURE_BOUNDARY.md`.

---

## 2. Authority Map

### 2.1 Change Classes

| Class | Examples | AI may execute | Required approval |
|---|---|---|---|
| C1 - Mechanical | ASCII/Unicode fixes, CRLF normalization, backup removal | Yes, direct | None (run gates) |
| C2 - Additive | New module + tests, new docs, new aegisctl read-only commands | Yes, direct | None (run gates) |
| C3 - Behavioral | Detector logic, flow engine, dispatcher pipeline order | Yes, with proof | Tests + golden must pass |
| C4 - Security boundary | PEP behavior, policy signing, capability checks, fail-closed cells | Propose only | Human review required |
| C5 - Release | Version bumps, installer, signing, provenance manifests | Propose only | Human signs + publishes |
| C6 - Infrastructure | CI stages, build scripts, deploy generator scripts | Yes, with dry run | None (run gates) |

### 2.2 Hard Rules (all classes)

1. Never weaken a fail-closed cell in `core/fault_matrix.zig` without a
   human decision recorded in an ADR (`docs/adr/`).
2. Never add a path that writes to `blocked_ips.json` directly; all
   enforcement goes through the Rust PEP (P0.4 decision, G53).
3. Never replace real crypto with placeholders. SHA-256 is the floor
   (P0.2); Ed25519 signing is a Phase J upgrade, not a downgrade target.
4. Never leave a deployed file with non-ASCII content. The deploy
   pipeline is base64 + ASCII by design (cp1252 safety on Windows).
5. Never bypass the canonical event schema (`core/canonical_event.zig`);
   new producers extend the schema, they do not fork it.

---

## 3. Context Contract (Agent Bootstrap Template)

Before writing any code, an AI agent MUST load and acknowledge the
following context. The acknowledgment is the first entry in its work log.

```text
CONTEXT CONTRACT - AEGIS task <TASK_ID>

1. Spine:      core/dispatcher.zig is the single orchestrator.
               Pipeline order is frozen: fabric -> flow -> detection ->
               aggregation -> correlation -> TI -> RAG -> brain ->
               policy -> PEP -> forensics.
2. Ownership:  Zig owns the runtime spine; Rust owns enforcement (PEP);
               C owns drivers (WFP/minifilter); C++ owns the bridge;
               Go owns the perf monitor; Python owns aegisctl + console;
               Cython owns feature extraction. No cross-language logic
               duplication.
3. Contracts:  Canonical Event v1 (core/canonical_event.zig) and
               shared/runtime/components.json are single sources of
               truth. Changing them requires an ADR.
4. Fail-soft:  Overflow, timeouts, and missing dependencies degrade the
               stage, never panic the process. Enforcement paths are
               the exception: they fail CLOSED.
5. Gates:      zig build test, python scripts/aegisctl.py golden,
               python scripts/doc_checker.py --self-test must pass
               before any commit claim.
6. Deploy:     Deliverables ship as generated PowerShell bundles
               (UTF-8 BOM + pure ASCII + base64). No manual file edits
               on the target machine.
```

---

## 4. Verification Gates

A change is "proven" only when every applicable gate passes:

| Gate | Command | Proves |
|---|---|---|
| G1 Unit tests | `zig build test` | Module behavior, fail-soft paths |
| G2 Golden path | `python scripts/aegisctl.py golden` | End-to-end pipeline health |
| G3 Docs vs code | `python scripts/doc_checker.py` | Documented commands/vars exist |
| G4 Provenance | `aegisctl` release verify (Phase V) | Artifacts untampered |
| G5 Fault drills | `core/fault_matrix.zig` drill runner | Recovery matches matrix |
| G6 Conflict sim | `core/policy_ir.zig` simulateConflict | Policy changes are deterministic |

Rule: a gate that is not run does not count. An agent MUST NOT claim a
gate passed without recording the command and its result in the work log.

---

## 5. Human-in-the-Loop Triggers

The following actions require explicit human approval, even when every
gate passes:

1. Driver signing changes (test certificate to WHQL, or vice versa).
2. Release publication (tag push, installer upload, provenance manifest).
3. Any change that alters a fail-closed recovery behavior.
4. Any change to the PEP IPC contract between aegisctl and the Rust PEP.
5. Removal of a documented aegisctl command (breaks operators' scripts).
6. Policy precedence or tie-break order changes in `ConflictResolver`.

---

## 6. Release Governance (ties to Phase V)

Every release package MUST carry:

1. A provenance manifest produced by `core/release_provenance.zig`:
   product, version, git sha, per-artifact SHA-256, artifact sizes.
2. A signed installer (signtool output) - the manifest complements, it
   does not replace, Authenticode signing.
3. A verification command record: the exact command an operator runs to
   verify artifact digests before deployment.

An artifact whose digest fails verification is quarantined, never
deployed, and the failure is reported upstream in the incident log.

---

## 7. Incident Response and Rollback

1. Runtime rollback: `aegisctl stop` + service recovery restarts the
   last known-good spine (fault matrix: process_crash x dispatcher).
2. Policy rollback: policy packages are versioned; activation of an
   older version goes through the same PEP validation path.
3. Driver rollback: the installer keeps the previous .sys files for one
   generation; `sc stop` + file swap + `sc start` is the documented path.
4. Every rollback MUST be recorded with: trigger, decision owner, gates
   re-run afterward, and the provenance manifest of the restored build.

---

## 8. Compliance Checklist (per task)

- [ ] Context contract acknowledged in the work log
- [ ] Change class identified (C1-C6)
- [ ] Gates G1-G3 (minimum) recorded with results
- [ ] No hard rule from section 2.2 violated
- [ ] Human approval recorded for C4/C5 triggers
- [ ] Work log appended to the shared worklog
