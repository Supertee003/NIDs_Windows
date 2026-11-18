/**
 * ts_policy/src/exporter.ts
 *
 * Deterministic `policy_ir.json` exporter (T3-TSIR-024). Turns a
 * `CompileResult` into the canonical on-disk artifact that cross-language
 * consumers (Zig loader, Python validator) read.
 *
 * Guarantees:
 *   - Stable key order at every level (no JSON.stringify key drift).
 *   - `hash_hex` carries the EXACT SHA-256 hex. The numeric `hash` field is
 *     a legacy u64 that loses precision past 2^53 in JS numbers — consumers
 *     must compare `hash_hex`, never `hash`.
 *   - No I/O anywhere in this module (pure functions only). File writes
 *     belong to operator CLIs outside src/ (the T6 AC4 no-fs-write pin
 *     enforces this). No child_process / network / firewall.
 */
import type { CompileResult } from "./compiler.js";

export interface ExportedPolicyIR {
  readonly magic: number;
  readonly version: number;
  readonly rule_count: number;
  readonly rules: readonly unknown[];
  readonly hash: number;
  readonly hash_hex: string;
  readonly signature: number;
  readonly compiled_at_ms: number;
  readonly compiler_version: string;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableValue);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = stableValue((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/** Render the canonical policy_ir.json document (stable key order). */
export function exportIRJson(result: CompileResult, hashHex: string): string {
  if (!/^[0-9a-f]{64}$/.test(hashHex)) {
    throw new Error(`exportIRJson: hashHex must be 64 lowercase hex chars`);
  }
  const doc: ExportedPolicyIR = {
    magic: result.ir.magic,
    version: result.ir.version,
    rule_count: result.ir.rule_count,
    rules: result.ir.rules,
    hash: result.ir.hash,
    hash_hex: hashHex,
    signature: result.ir.signature,
    compiled_at_ms: result.ir.compiled_at_ms,
    compiler_version: result.ir.compiler_version,
  };
  return JSON.stringify(stableValue(doc)) + "\n";
}
