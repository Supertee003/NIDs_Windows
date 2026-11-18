#!/usr/bin/env node
/**
 * Generate the frozen policy-signing cross-language golden vectors.
 *
 * Writes tests/contracts/policy_signing/:
 *   policy_ir_golden.json  — fixed IR bytes (the signed message)
 *   policy_ir_golden.sig.json — v1 sidecar (Ed25519 over those bytes)
 *   policy_ir_golden.pub.hex  — trust anchor (32-byte pubkey, hex)
 *   README.md
 *
 * The keypair is ephemeral per run and never persisted: only the public
 * key and signature are committed (public information). Regenerate with
 * `node tests/contracts/policy_signing/generate_policy_vectors.mjs`
 * from the repo root; every consumer (Zig decode+verify test, TS shape
 * test) must still pass on the new files in the same patch.
 *
 * Consumers prove TS-signed bytes verify under the Rust/Zig stack:
 * Zig reads these files and calls verifyViaRust (ring Ed25519).
 */
import { webcrypto } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)));
mkdirSync(OUT, { recursive: true });

const IR_JSON = '{"magic":1347374129,"version":1,"rule_count":1,"rules":[{"id":7,"name":"golden"}]}';
const KEY_ID = 7;

const toHex = (b) => Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, "0")).join("");
const enc = new TextEncoder();
const subtle = webcrypto.subtle;

const pair = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const [privBuf, pubBuf] = await Promise.all([
  subtle.exportKey("pkcs8", pair.privateKey),
  subtle.exportKey("spki", pair.publicKey),
]);
// SPKI wraps the 32-byte raw key last; Zig/Rust need the raw 32 bytes.
const pubSpki = new Uint8Array(pubBuf);
const pubRaw = pubSpki.slice(-32);
const privKey = await subtle.importKey("pkcs8", privBuf, { name: "Ed25519" }, false, ["sign"]);
const sig = new Uint8Array(await subtle.sign("Ed25519", privKey, enc.encode(IR_JSON)));
const digest = new Uint8Array(await subtle.digest("SHA-256", enc.encode(IR_JSON)));

const sidecar = {
  version: 1,
  key_id: KEY_ID,
  ed25519_sig_hex: toHex(sig),
  ir_sha256_hex: toHex(digest),
};

writeFileSync(join(OUT, "policy_ir_golden.json"), IR_JSON + "\n");
writeFileSync(join(OUT, "policy_ir_golden.sig.json"), JSON.stringify(sidecar, null, 2) + "\n");
writeFileSync(join(OUT, "policy_ir_golden.pub.hex"), toHex(pubRaw) + "\n");

const readme = [
  "# Policy Signing Golden Vectors",
  "",
  "TS-signed fixture proving the author plane and the verify stack agree:",
  "the signature here was produced by `ts_policy/src/ed25519.ts` equipment",
  "and must verify under Zig `verifyViaRust` (Rust ring Ed25519).",
  "",
  "## Files",
  "",
  "- `policy_ir_golden.json` — the exact signed bytes.",
  "- `policy_ir_golden.sig.json` — v1 sidecar (key_id 7).",
  "- `policy_ir_golden.pub.hex` — trust anchor, 64 hex chars.",
  "",
  "## Regeneration",
  "",
  "Run `node tests/contracts/policy_signing/generate_policy_vectors.mjs`",
  "from the repo root. The keypair is ephemeral (never persisted); only",
  "public outputs are committed. Zig + TS consumers must pass on the new",
  "files in the same patch (one schema, N codecs).",
  "",
].join("\n");
writeFileSync(join(OUT, "README.md"), readme);
console.log("policy golden vectors written to " + OUT);
