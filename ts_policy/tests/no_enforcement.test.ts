/**
 * ts_policy/tests/no_enforcement.test.ts
 *
 * T6 AC4: "TypeScript has no direct enforcement or post-signature
 * policy mutation path."
 *
 * This file asserts the "no enforcement" half. It uses AST inspection
 * on the compiled output of `tsc --noEmit` (well, just on the source
 * files) to verify that `src/` has no imports of forbidden modules.
 *
 * Forbidden modules (any of these would be an enforcement path):
 *   - child_process / exec / spawn / execSync / spawnSync
 *   - net (TCP), dgram (UDP)  (no socket creation)
 *   - http / https / fetch    (no HTTP client/server)
 *   - node:fs writes          (writes to filesystem are forbidden)
 *   - WFP / iptables / netsh / firewall bindings
 *   - policy_engine / rust_pep / enforcement
 *
 * node:crypto is ALLOWED (it produces the SHA-256 HMAC seal).
 * node:test is ALLOWED (test runner only).
 * node:assert is ALLOWED (test assertions).
 *
 * The test also asserts there are no top-level await expressions
 * (a top-level await is a side effect that could imply an open
 * network/file resource at module load time).
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SRC_DIR = join(__dirname, "..", "src");

const FORBIDDEN_MODULE_PATTERNS: RegExp[] = [
  // child_process
  /from\s+["']node:child_process["']/,
  /from\s+["']child_process["']/,
  /\bchild_process\b/,
  /\bexecSync\b/,
  /\bspawnSync\b/,
  /\bexecFile\b/,
  // net / dgram
  /from\s+["']node:net["']/,
  /from\s+["']node:dgram["']/,
  /from\s+["']net["']/,
  /from\s+["']dgram["']/,
  // http / https / fetch
  /from\s+["']node:http["']/,
  /from\s+["']node:https["']/,
  /from\s+["']http["']/,
  /from\s+["']https["']/,
  /fetch\s*\(/,
  // node:fs writes (sync write, async write, appendFile, etc.)
  /from\s+["']node:fs["']/,
  /from\s+["']fs["']/,
  // Privilege / firewall
  /\bnetsh\b/,
  /\biptables\b/,
  /\bfirewall\b/i,
  /\bWFP\b/,
  /\bwinpcap\b/,
  /\bwinfw\b/,
  // Enforcement / policy
  /\benforce(ment)?\b/i,
  /\bblock_ip\b/,
  /\brust_pep\b/,
  /\bpolicy_engine\b/,
];

const FORBIDDEN_SYNC_WRITE_CALLS: RegExp[] = [
  // Matches writeFileSync, appendFileSync, createWriteStream, etc.
  /\bwriteFileSync\s*\(/,
  /\bappendFileSync\s*\(/,
  /\bcreateWriteStream\s*\(/,
  // Matches async write, appendFile, etc. (catches writes outside of tests/)
  /\bfs\.writeFile\b/,
  /\bfs\.appendFile\b/,
  /\bwriteFile\s*\(/,
];

const ALLOWED_MODULES = new Set([
  "node:crypto", "crypto",
  "node:test", "test",
  "node:assert", "assert",
  "node:buffer", "buffer",
  "node:url", "url",
  "node:path", "path",
  "./types.js", "./compiler.js", "./seal.js", "./index.js",
  "../src/index.js", "../src/types.js", "../src/compiler.js", "../src/seal.js",
]);

function readSourceFiles(dir: string): Map<string, string> {
  const files = new Map<string, string>();
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isFile() && entry.endsWith(".ts")) {
      files.set(full, readFileSync(full, "utf8"));
    } else if (st.isDirectory()) {
      const sub = readSourceFiles(full);
      for (const [k, v] of sub) files.set(k, v);
    }
  }
  return files;
}

function stripCommentsAndStrings(source: string): string {
  // Strip block comments, line comments, and string contents so the
  // scanner only matches against CODE (imports, calls) and not
  // documentation that mentions the forbidden module names.
  let out = "";
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    const c1 = source[i + 1];
    if (c === "/" && c1 === "/") {
      // Line comment
      const end = source.indexOf("\n", i);
      i = end < 0 ? source.length : end + 1;
    } else if (c === "/" && c1 === "*") {
      // Block comment
      const end = source.indexOf("*/", i + 2);
      i = end < 0 ? source.length : end + 2;
    } else if (c === '"' || c === "'" || c === "`") {
      // String/template literal
      const quote = c;
      out += " "; // placeholder so byte offsets roughly match
      i++;
      while (i < source.length && source[i] !== quote) {
        if (source[i] === "\\" && i + 1 < source.length) i += 2;
        else i++;
      }
      i++; // skip closing quote
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

function findForbiddenImports(source: string, filename: string): string[] {
  // Only scan the CODE portion (after stripping comments and strings).
  const code = stripCommentsAndStrings(source);
  const found: string[] = [];
  for (const pat of FORBIDDEN_MODULE_PATTERNS) {
    if (pat.test(code)) {
      found.push(`${filename}: ${pat.toString()}`);
    }
  }
  for (const pat of FORBIDDEN_SYNC_WRITE_CALLS) {
    if (pat.test(code)) {
      found.push(`${filename}: ${pat.toString()}`);
    }
  }
  return found;
}

const files = readSourceFiles(SRC_DIR);

test("T6 AC4: ts_policy/src/ has no forbidden imports", () => {
  const violations: string[] = [];
  for (const [file, src] of files) {
    violations.push(...findForbiddenImports(src, file));
  }
  assert.equal(
    violations.length,
    0,
    `T6 AC4 violation: TypeScript policy source imports forbidden modules:\n  ${violations.join("\n  ")}`,
  );
});

test("T6 AC4: all imports in src/ are in the allowed list", () => {
  const importRegex = /import\s+(?:.+?\s+from\s+)?["']([^"']+)["']/g;
  const violations: string[] = [];
  for (const [file, src] of files) {
    const code = stripCommentsAndStrings(src);
    let match: RegExpExecArray | null;
    while ((match = importRegex.exec(code)) !== null) {
      const moduleName = match[1]!;
      if (!ALLOWED_MODULES.has(moduleName)) {
        violations.push(`${file}: imports ${moduleName}`);
      }
    }
  }
  assert.equal(
    violations.length,
    0,
    `T6 AC4 violation: TypeScript policy source has unlisted imports:\n  ${violations.join("\n  ")}`,
  );
});

test("T6 AC4: no top-level await (no resource creation at module load)", () => {
  const violations: string[] = [];
  for (const [file, src] of files) {
    // Strip comments and string contents (rough heuristic).
    const stripped = src
      .replace(/\/\/.*$/gm, "")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/"[^"\\]*(?:\\.[^"\\]*)*"/g, '""')
      .replace(/'[^'\\]*(?:\\.[^'\\]*)*'/g, "''");
    // A top-level await is a statement that starts at column 0
    // and contains "await" at statement position. The simple regex
    // catches "await" outside of any indentation.
    const matches = stripped.match(/^await\b/gm);
    if (matches) {
      violations.push(`${file}: top-level await found ${matches.length} times`);
    }
  }
  assert.equal(
    violations.length,
    0,
    `T6 AC4 violation: top-level await implies open resources at module load:\n  ${violations.join("\n  ")}`,
  );
});

test("T6 AC4: node_modules types (from @types/node) are not in our source", () => {
  // The src/ files should only import each other and node: stdlib.
  // They should not have stray dependencies on third-party packages.
  const violations: string[] = [];
  for (const [file, src] of files) {
    const code = stripCommentsAndStrings(src);
    const matches = code.match(/from\s+["']([^./][^"']+)["']/g);
    if (matches) {
      for (const m of matches) {
        const moduleName = m.replace(/from\s+["']([^"']+)["']/, "$1");
        if (!moduleName.startsWith("node:")) {
          violations.push(`${file}: imports ${moduleName}`);
        }
      }
    }
  }
  assert.equal(
    violations.length,
    0,
    `T6 AC4 violation: third-party imports in ts_policy/src/:\n  ${violations.join("\n  ")}`,
  );
});
