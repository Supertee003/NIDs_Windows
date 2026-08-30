# AI Development Guide

**Status**: AUTHORITATIVE
**Audience**: AI coding assistants (Claude, GPT, etc.) and developers using AI tools

---

## AI Role Model

Use four AI roles:

| Role | Name | Scope |
|------|------|-------|
| A0 | Observer | Analyze only (no edits) |
| A1 | Implementer | Implement within a frozen contract |
| A2 | Refactorer | May propose structural changes |
| A3 | Architect | May propose contract/boundary changes |

**Normal development**: Use A1 (Implementer).

**Escalation**:
- A1 discovers boundary problem -> STOP -> escalate to A2
- Contract must change -> A2 writes ADR -> A3 review

This prevents an AI from turning a local bug into an architecture rewrite.

---

## What AI Should Receive Before Editing

Never give a coding AI only:
```
"Fix this file."
```

Always provide:
```
SYSTEM
SEMANTIC POSITION
CURRENT PHASE
OWNER LANGUAGE
CONTRACT
ALLOWED FILES
FORBIDDEN FILES
FAILURE MODEL
TEST REQUIREMENT
EXIT GATE
```

### Example Context Block

```
SYSTEM:
AEGIS Windows security platform

SEMANTIC POSITION:
STATE / FLOW

OWNER:
Zig

TASK:
Replace linear flow lookup

ALLOWED:
core/flow_engine.zig
core/flow_state_proof.zig

FORBIDDEN:
policy
pep
brain
driver

CONTRACT:
FlowSnapshot v1

FAILURE:
No dangling pointer
No duplicate active flow

TEST:
concurrency + stress

EXIT:
10K flows x 10 packets passes
```

---

## AI Context Files

The following files in `docs/ai-context/` are the shared context for every AI session:

| File | Purpose |
|------|---------|
| `00-system-context.md` | System overview, identity, principles |
| `01-semantic-map.md` | 13 semantic positions with definitions |
| `02-runtime-spine.md` | Single runtime path (12 stages) |
| `03-language-ownership.md` | Which language owns what |
| `04-contracts.md` | Contract definitions (12 contracts) |
| `05-data-lifecycle.md` | Event lifecycle from source to replay |
| `06-security-boundary.md` | Rust PEP authority, no bypass |
| `07-error-policy.md` | Error classes, fail-soft model |
| `08-testing-policy.md` | Test layers, proof modules, CI gates |
| `09-change-policy.md` | Definition of Done, ADR process |
| `10-current-phase.md` | Current phase status and goals |

**Rule**: Every AI session starts by reading these files.

---

## Human Review Rule

AI-generated security code must receive human review when it changes:

- drivers
- FFI (foreign function interface)
- ABI (application binary interface)
- IPC (inter-process communication)
- policy
- PEP (policy enforcement point)
- privilege operations
- cryptographic verification
- event persistence

**AI may implement. Human must approve the security semantics.**

---

## Definition of Done (Task Level)

Every task is complete only when ALL of these are checked:

```
[ ] Correct semantic position
[ ] Correct language owner
[ ] Contract unchanged or versioned
[ ] Only intended files changed
[ ] Build passed
[ ] Tests passed
[ ] Proof/invariant passed
[ ] Security impact reviewed
[ ] Performance impact considered
[ ] Legacy path handled
[ ] Documentation updated
```

---

## Definition of Done (Phase Level)

A Phase is complete only when:

```
implementation
+ test
+ proof
+ integration
+ documentation
+ rollback
```

are complete.

**Time is not the gate. Completeness is the gate.**

---

## Task Sizing

Each task should be small:

```
Task
  -> Change
  -> Build
  -> Test
  -> Proof
  -> Commit
```

**NOT**:

```
Task 1
Task 2
Task 3
Task 4
Task 5
  -> test everything
```

The latter makes failures difficult to localize.

---

## Error Handling Procedure

When AI or a developer hits an error:

```
ERROR
  -> CLASSIFY (build/compile/runtime/concurrency/ABI/security/semantic)
  -> LOCALIZE (find root cause)
  -> MINIMAL FIX (smallest change that fixes root cause)
  -> TARGETED TEST (test the specific fix)
  -> REGRESSION (run full test suite)
  -> CONTINUE
```

---

## Stop-the-Line Conditions

These errors require immediate halt and human review:

- Memory corruption
- ABI mismatch
- Event loss (fabric failure)
- Race/deadlock
- Policy bypass
- Unauthorized enforcement
- Forensic inconsistency (hash chain broken)

---

## Forbidden AI Actions

An AI must NEVER:

1. Create a competing runtime path
2. Add decision state to CanonicalEvent
3. Allow detection to call PEP directly
4. Allow Brain to execute enforcement
5. Allow Policy to bypass Rust PEP
6. Delete proof modules without replacement
7. Modify frozen contracts without ADR
8. Add new language without ownership table update
9. Bypass CI gates
10. Mark a phase "done" because code compiles

---

## AI Session Protocol

1. **Start**: Read all `docs/ai-context/` files
2. **Context**: Receive task context block (SYSTEM, POSITION, CONTRACT, etc.)
3. **Implement**: Make changes only to ALLOWED files
4. **Test**: Run targeted tests for the change
5. **Proof**: Run proof module for the invariant
6. **Review**: Human reviews if security-sensitive
7. **Commit**: Use conventional commits with phase reference

---

## Commit Hygiene

Use conventional commits with phase reference:

```
feat(G14): add audit trail tamper detection
fix(G15): correct shift operand type (u6 -> u5)
docs(G22): add runbook content files
chore(G23): canonicalize architecture documentation
```

**Rule**: One logical change per commit. Granular, well-described commits.
