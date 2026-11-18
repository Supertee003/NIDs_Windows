/**
 * ts_policy/src/ed25519.ts
 *
 * T7 author-side Ed25519 signing for the policy IR sidecar
 * (`policy_ir.sig.json`, parsed strictly by
 * `src/policy/policy_signing.zig::parseSidecar` and verified over the
 * exact IR bytes by the Rust PEP through `aegis_policy_verify`).
 *
 * Custody rule (ADR-0005 Q3 still open): this module never generates
 * production keys, never stores keys, and never touches the network
 * or filesystem. Keys arrive as function arguments from the operator's
 * own offline tooling, are used transiently inside one call, and are
 * never retained. The only key generation here,
 * `generateEphemeralKeypair`, is for isolated tests.
 *
 * Pure node:crypto (WebCrypto Ed25519) — no new dependencies. Async
 * only because WebCrypto is async; there is no top-level await and no
 * module-load side effect (see no_enforcement.test.ts).
 */

import { webcrypto } from "node:crypto";

const subtle = webcrypto.subtle;
const encoder = new TextEncoder();

/** Sidecar envelope v1. Field names must match the Zig strict parser. */
export interface Ed25519Sidecar {
  readonly version: 1;
  readonly key_id: number;
  /** 128 lowercase hex chars (64-byte signature). */
  readonly ed25519_sig_hex: string;
  /** 64 lowercase hex chars (SHA-256 of the exact IR bytes; hint only). */
  readonly ir_sha256_hex: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(digest));
}

function assertKeyId(keyId: number): void {
  if (!Number.isInteger(keyId) || keyId <= 0 || keyId > 0xffffffff) {
    throw new Error(`key_id must be a u32 non-zero, got ${keyId}`);
  }
}

/**
 * Sign exact IR file bytes with an operator-provided PKCS#8 private key.
 * Returns the sidecar object (caller serializes + places it next to the
 * IR file; file output belongs to operator CLIs outside src/).
 */
export async function signIrBytes(
  irJson: string,
  privateKeyPkcs8: Uint8Array,
  keyId: number,
): Promise<Ed25519Sidecar> {
  assertKeyId(keyId);
  if (irJson.length === 0) {
    throw new Error("refusing to sign empty IR bytes");
  }
  const key = await subtle.importKey(
    "pkcs8",
    privateKeyPkcs8,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const data = encoder.encode(irJson);
  const sig = new Uint8Array(await subtle.sign("Ed25519", key, data));
  return {
    version: 1,
    key_id: keyId,
    ed25519_sig_hex: toHex(sig),
    ir_sha256_hex: await sha256Hex(data),
  };
}

/**
 * Verify a sidecar against exact IR bytes and an SPKI public key.
 * False on any mismatch (bad signature, wrong bytes, wrong key) —
 * never throws for verification outcomes (throws only on malformed
 * key encodings, which are caller bugs, not verdicts).
 */
export async function verifyIrBytes(
  irJson: string,
  sidecar: Ed25519Sidecar,
  publicKeySpki: Uint8Array,
): Promise<boolean> {
  try {
    if (sidecar.version !== 1) return false;
    assertKeyId(sidecar.key_id);
    if (!/^[0-9a-f]{128}$/.test(sidecar.ed25519_sig_hex)) return false;
    const key = await subtle.importKey(
      "spki",
      publicKeySpki,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const sig = new Uint8Array(
      (sidecar.ed25519_sig_hex.match(/../g) ?? []).map((h) =>
        parseInt(h, 16),
      ),
    );
    return await subtle.verify(
      "Ed25519",
      key,
      sig,
      encoder.encode(irJson),
    );
  } catch {
    return false;
  }
}

/**
 * Ephemeral keypair for isolated tests only. Production keys are
 * operator-generated offline and never enter this repo.
 */
export async function generateEphemeralKeypair(): Promise<{
  privateKeyPkcs8: Uint8Array;
  publicKeySpki: Uint8Array;
}> {
  const pair = (await subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const [privBuf, pubBuf] = await Promise.all([
    subtle.exportKey("pkcs8", pair.privateKey),
    subtle.exportKey("spki", pair.publicKey),
  ]);
  return {
    privateKeyPkcs8: new Uint8Array(privBuf),
    publicKeySpki: new Uint8Array(pubBuf),
  };
}
