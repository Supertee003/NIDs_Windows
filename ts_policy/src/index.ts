/**
 * ts_policy/src/index.ts
 *
 * Public API of the AEGIS TypeScript Policy Plane (T6).
 *
 * Exports:
 *   - types: ConditionType, ConditionOperator, PolicyAction, PolicyIR,
 *     PolicyRuleDef, PolicyCondition, TypedValue, SealedPolicy, ...
 *   - typed value constructors: ipv4, ipv6, cidr, port, time, domain,
 *     process_, file, identity
 *   - compiler: compile() with deterministic conflict resolution
 *   - exporter: exportIRJson() canonical policy_ir.json (pure, no I/O)
 *   - seal: seal() / verifySeal() with runtime deep-freeze
 *   - ed25519: signIrBytes() / verifyIrBytes() sidecar v1 (operator key
 *     in, never stored; custody stays operator-side per ADR-0005)
 *
 * Non-goals (T6 AC4):
 *   - No child_process / network / firewall / WFP / PEP bindings, no fs
 *     writes in src/ (file output belongs to operator CLIs outside src/)
 *   - No policy mutation after seal (Object.freeze + Readonly<>)
 *   - No enforcement (Zig/Rust do that, not TS)
 */
export * from "./types.js";
export * from "./compiler.js";
export * from "./exporter.js";
export * from "./seal.js";
export * from "./ed25519.js";
