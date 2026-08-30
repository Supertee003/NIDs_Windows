# 09 - Change Policy

## Definition of Done (Task)

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

## Definition of Done (Phase)

```
implementation + test + proof + integration + documentation + rollback
```

Time is not the gate. Completeness is the gate.

## AI Role Escalation

| Role | Action |
|------|--------|
| A1 (Implementer) | Normal dev within frozen contract |
| A2 (Refactorer) | Propose structural changes |
| A3 (Architect) | Propose contract/boundary changes |

Escalation:
- A1 discovers boundary problem -> STOP -> escalate to A2
- Contract must change -> A2 writes ADR -> A3 review

## ADR (Architecture Decision Record)

When a contract or boundary must change:

1. A2 (Refactorer) writes ADR
2. ADR includes: context, decision, consequences, alternatives
3. A3 (Architect) reviews
4. If approved, contract version bumped
5. Migration plan created
6. Proof modules updated

## Commit Hygiene

- One logical change per commit
- Conventional commits with phase reference:
  - `feat(G14): add audit trail tamper detection`
  - `fix(G15): correct shift operand type`
  - `docs(G22): add runbook content files`
  - `chore(G23): canonicalize architecture`

## Task Sizing

```
Task -> Change -> Build -> Test -> Proof -> Commit
```

NOT:
```
Task 1, Task 2, Task 3, Task 4, Task 5 -> test everything
```

## Forbidden

- Marking a phase "done" because code compiles
- Letting AI infer architecture from source alone
- Creating competing runtime paths
- Adding decision state to CanonicalEvent
- Bypassing Rust PEP
- Deleting proof modules without replacement
