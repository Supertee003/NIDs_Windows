# Technology Decisions

> Why this project uses six languages. This is a component-boundary decision, not language
> experimentation. Each language owns a specific responsibility and a specific constraint.
> Related records: `AGENTS.md` (language ownership), `docs/architecture/GO_ARCHITECTURE_DECISION.md`,
> `docs/architecture/SHIELD_ARCHITECTURE_DECISION.md`, `AI_CONTEXT.md`.

| Technology | Why chosen | Alternative considered | Trade-off accepted |
|---|---|---|---|
| **Zig** — runtime spine | Native control over memory, event queue, control plane, and lifecycle; one authoritative owner | C++ or Rust | Smaller ecosystem; more manual safety work. Kept because the runtime must own everything without GC or hidden authority |
| **Go** — Nose packet ingress | Strong networking/concurrency for Npcap capture and pipe serialization; clean separation from detection logic | Rust or C++ | GC and less direct memory control. Accepted because acquisition is I/O-bound, not policy-bearing |
| **C/C++** — Windows native adapters | Direct WFP/ETW/FIM/Registry and Windows API access; kernel-adjacent boundary | Rust bindings alone | Manual memory safety at the native boundary; constrained by strict contracts and tests |
| **Rust** — PEP + crypto | Memory-safe, constrained policy evaluator and Ed25519/TLS authority; there is deliberately no host-effect path | C++ | Complexity and FFI ABI discipline; accepted because authority boundaries must be enforceable in code |
| **Python** — brain, analytics, tooling | Fast iteration for analytics/RAG, CLI, verification scripts | Go | Runtime overhead and no privileged role. Explicitly not an enforcement authority |
| **TypeScript** — policy authoring | Schema-checkable policy artifacts, simulation, compiler feedback | YAML/JSON only | Extra toolchain; accepted because policy changes need validation before reaching runtime |
| **Cython** — hot loops only | Measured optimization of Python hot paths | Rewrite in Rust/Go | Added build complexity; allowed only after profiling, never for new logic |

## Why the architecture is a hub, not a mesh

Zig is the hub; every other language is a spoke. Components do not negotiate authority with each
other. They connect through C ABI / FFI and canonical contracts. This prevents duplicate workers,
stale ownership, control-pipe conflicts, and language-to-language authority sprawl.

**Cost we accept:** more build steps, cross-language contract tests, harder debugging, and a larger
dependency surface. In exchange, there is exactly one place where runtime authority lives, and it
can be verified.

## Why detection-only

Host enforcement introduces separate risks: verified authorization, provider execution, host
postcondition verification, cleanup, rollback, and recovery. Separating detection from enforcement
keeps the current release auditable and safe to operate. Historical lab enforcement code is
retained only as evidence of the boundary — it is not a production feature and not a pending one
(`RETIRE-HOST-EFFECT-001`).

## Why the canonical event schema exists

Sensors produce different native shapes (packets, WFP events, file notifications). One schema with
N codecs means a wire change must update every language plus the shared vector in the same patch.
That constraint is intentional: it makes silent divergence a test failure rather than a field bug.

## Why evidence is part of the product

Findings without verifiable records are just alerts. Hash-chained forensic records and evidence
receipts make the system's claims checkable after the fact. We describe them as **tamper-evident**,
not tamper-proof: they help detect modification; they do not defend against a malicious kernel-mode
administrator.

## Why loopback is not the production binding

Loopback gives repeatable full-path self-tests, including exact 5-tuple attribution and negative
controls, but it is not a real network segment. Production keeps a real interface binding; loopback
is used only for self-test and demo evidence, with rollback to the production binding.
