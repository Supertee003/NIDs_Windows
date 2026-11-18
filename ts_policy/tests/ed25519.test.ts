/**
 * ts_policy/tests/ed25519.test.ts
 *
 * T7 author-side Ed25519 (TS-SIGN-080): signIrBytes produces the v1
 * sidecar the Zig strict parser accepts; verifyIrBytes round-trips it
 * and fails closed on every non-match. Keys are ephemeral per test
 * (generateEphemeralKeypair) — no committed secrets, no key storage.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  generateEphemeralKeypair,
  signIrBytes,
  verifyIrBytes,
  type Ed25519Sidecar,
} from "../src/index.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const GOLDEN_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "tests",
  "contracts",
  "policy_signing",
);

function readGolden(name: string): string {
  return readFileSync(join(GOLDEN_DIR, name), "utf8").replace(/[\r\n]+$/, "");
}

const IR_JSON = '{"magic":1347374129,"version":1,"rule_count":1,"rules":[]}';

async function signedFixture(keyId = 7): Promise<{
  ir: string;
  sidecar: Ed25519Sidecar;
  pub: Uint8Array;
}> {
  const { privateKeyPkcs8, publicKeySpki } = await generateEphemeralKeypair();
  const sidecar = await signIrBytes(IR_JSON, privateKeyPkcs8, keyId);
  return { ir: IR_JSON, sidecar, pub: publicKeySpki };
}

test("ed25519: sidecar has the v1 envelope shape", async () => {
  const { sidecar } = await signedFixture();
  assert.equal(sidecar.version, 1);
  assert.equal(sidecar.key_id, 7);
  assert.match(sidecar.ed25519_sig_hex, /^[0-9a-f]{128}$/);
  assert.match(sidecar.ir_sha256_hex, /^[0-9a-f]{64}$/);
});

test("ed25519: verify round-trips a matching triple", async () => {
  const { ir, sidecar, pub } = await signedFixture();
  assert.equal(await verifyIrBytes(ir, sidecar, pub), true);
});

test("ed25519: verify fails on tampered bytes, key, and shape", async () => {
  const { ir, sidecar, pub } = await signedFixture();
  assert.equal(await verifyIrBytes(ir + " ", sidecar, pub), false);
  const other = await generateEphemeralKeypair();
  assert.equal(await verifyIrBytes(ir, sidecar, other.publicKeySpki), false);
  assert.equal(
    await verifyIrBytes(
      ir,
      { ...sidecar, version: 2 } as unknown as Ed25519Sidecar,
      pub,
    ),
    false,
  );
  assert.equal(
    await verifyIrBytes(ir, { ...sidecar, ed25519_sig_hex: "00" }, pub),
    false,
  );
});

test("ed25519: sign refuses empty bytes and bad key ids", async () => {
  const { privateKeyPkcs8 } = await generateEphemeralKeypair();
  await assert.rejects(signIrBytes("", privateKeyPkcs8, 7));
  await assert.rejects(signIrBytes(IR_JSON, privateKeyPkcs8, 0));
  await assert.rejects(
    signIrBytes(IR_JSON, new Uint8Array([1, 2, 3]), 7),
  );
});

test("ed25519: committed golden triple verifies (cross-language pin)", async () => {
  // Same files the Zig test reads: TS equipment signed them, every
  // consumer must agree. Regenerate via generate_policy_vectors.mjs.
  const ir = readGolden("policy_ir_golden.json");
  const sidecar = JSON.parse(
    readGolden("policy_ir_golden.sig.json"),
  ) as Ed25519Sidecar;
  const pubRaw = Buffer.from(readGolden("policy_ir_golden.pub.hex"), "hex");
  assert.equal(sidecar.version, 1);
  assert.equal(sidecar.key_id, 7);
  const { webcrypto } = await import("node:crypto");
  const pub = new Uint8Array(pubRaw);
  const key = await webcrypto.subtle.importKey(
    "raw",
    pub,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const sig = new Uint8Array(
    Buffer.from(sidecar.ed25519_sig_hex, "hex"),
  );
  const ok = await webcrypto.subtle.verify(
    "Ed25519",
    key,
    sig,
    new TextEncoder().encode(ir),
  );
  assert.equal(ok, true);
});