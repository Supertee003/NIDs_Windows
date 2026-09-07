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
 *   - seal: seal() / verifySeal() with runtime deep-freeze
 *
 * Non-goals (T6 AC4):
 *   - No child_process / network / firewall / WFP / PEP bindings
 *   - No policy mutation after seal (Object.freeze + Readonly<>)
 *   - No enforcement (Zig/Rust do that, not TS)
 */
export * from "./types.js";
export * from "./compiler.js";
export * from "./seal.js";
