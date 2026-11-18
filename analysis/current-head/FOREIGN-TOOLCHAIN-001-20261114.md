# FOREIGN-TOOLCHAIN-001 — the TypeScript plane and the aggregator ran only by memory

**Created:** 2026-11-14
**Build source:** no product source changed — this slice adds
`tests/tools/test_foreign_toolchains.py` only.
**Level:** E2 (5 pins; 2 of them execute a real 76-case suite)

---

## 1. What was found

Two modules sit outside both `zig build` and `nose/`:

* `ts_policy/` — the advisory TypeScript policy plane: 6 `src/*.ts`, 8
  `tests/*.test.ts`, a strict `tsc --noEmit`, and **76 `node --test` cases**
  covering typed values, the compiler, sealing, no-enforcement, no-post-seal
  mutation, the cross-language contract, the exporter and Ed25519.
* `go/aggregator/` — the alert correlator, a second Go module (8 `.go` files,
  its own `go.mod`).

Neither was invoked by anything in `tests/`. The TypeScript plane is the module
that *must never enforce* (`no_enforcement.test.ts`), and its tests — the ones
that would catch a regression there — were the ones nothing ran.

Measured before the change, all green today:

| Check | Result |
|---|---|
| `npm run typecheck` | exit 0 |
| `npm test` | 76 pass, 0 fail |
| `go vet ./...` (aggregator) | exit 0 |
| `go build .` (aggregator) | exit 0 |
| `go test -run XXXNO_MATCH -count=1 ./...` | exit 0, all test files compile |

## 2. What changed

`tests/tools/test_foreign_toolchains.py`, 5 pins:

1. `npm run typecheck` exits 0 — the project's own strict script, not one
   invented here;
2. `npm test` exits 0, reports `fail 0`, and does not drop below 76 cases
   (dropping a test file is the regression this catches, proven below);
3. `go vet ./...` on the aggregator, with empty stderr;
4. `go build` produces a binary;
5. compile-only `go test -run XXXNO_MATCH -count=1 ./...`.

Both groups skip when their toolchain or `node_modules` is missing, so a fresh
clone does not fail — it reports a skip.

Two things had to be got right to make pin 2 trustworthy: the child's output is
decoded as UTF-8 regardless of host code page (the summary line uses `ℹ`), and
the summary is read with a tolerant `pass (\d+)` / `fail (\d+)` search because
npm output passes through codes and glyphs. A first attempt that matched the line
anchored on `ℹ` failed on this host and was replaced, not loosened into
meaninglessness — pin 2 still reads the two numbers `node --test` prints.

## 3. Verification

| Check | Result |
|---|---|
| `pytest -q tests/tools/test_foreign_toolchains.py` | 5 passed |
| mutation: rename `tests/exporter.test.ts` so the suite shrinks to 72 | 1 failed (`test_typescript_suite_passes_and_does_not_shrink`) |
| restored | 5 passed |
| `npm test` inside the pin | 76 pass, 0 fail |

## 4. Limitations

1. **E2.** The TypeScript suite runs, but it is a unit suite: nothing here
   proves the compiler output is consumed by the Python or Zig side at runtime.
2. **`npm test` timing on CI.** The pin assumes `node_modules` is present; on a
   clean checkout it skips rather than installing (no network in a gate run).
3. **The aggregator is only built and vetted**; its tests are compiled but not
   executed — some open sockets, and the pins are meant to be safe to run while
   the agent is live.
4. **`no_enforcement.test.ts` proves the TypeScript plane does not enforce
   within TypeScript.** The claim that the *product* is detection-only is
   established elsewhere (lab gate compile-time off), not by this pin.
