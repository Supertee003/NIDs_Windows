# NOSE-TOOLCHAIN-001 — the Go half of the product had no gate that ran the Go tools

**Created:** 2026-11-14
**Build source:** no product source changed — this slice adds
`tests/tools/test_nose_toolchain.py` only, so the soak/build source commit does
not move.
**Level:** E2 (6 pins, 5 of which are real toolchain runs)
**Module:** `nose/` — 24 tracked `.go` files, `go.mod` / `go.sum`

---

## 1. What was found

`nose/` is the packet-acquisition half of the product: capture, collectors,
talkers, the pipe writer and the canonical-event encoder. Nothing in
`tests/` invoked `go vet`, `go build` or a test compile, so a break there was
found only by a human running `go test` by hand. Measured on this host, before
any change:

| Check | Result |
|---|---|
| `go vet ./...` | exit 0, no output |
| `go build .` | exit 0 |
| `go test -run XXXNO_SUCH_TEST -count=1 .` | exit 0, `no tests to run` (all test files compile) |
| `GOOS=linux GOARCH=amd64 go build .` | **fails**, inside `github.com/google/gopacket/pcap@v1.1.19` (cgo + libpcap), before our code is reached |
| `gofmt -l` on the 24 tracked files | lists **all 24**, alignment only (`colorBlue    = ...    // Primary panel border`) |

So the module is healthy today, but (a) nothing kept it that way, and (b)
`nose/traffic_sys_other.go` (`//go:build !windows`) is compiled by **no build
available in this repository**: Windows excludes it by tag, Linux dies in the
dependency. A syntax error or grown logic in it would have been found by nobody.

## 2. What changed

`tests/tools/test_nose_toolchain.py`, 6 pins:

1. `go vet ./...` exits 0 with empty stderr;
2. `go build` produces a binary;
3. `go test -run XXXNO_SUCH_TEST -count=1 .` compiles every test file without
   opening a live capture adapter;
4. the build-constrained set is exactly
   `capture_pipe_test.go [windows]`, `traffic_sys_other.go [!windows]`,
   `traffic_sys_windows.go [windows]` — a new platform-excluded file has to be
   looked at rather than silently skipped;
5. `traffic_sys_other.go` stays ≤ 60 non-blank lines (11 today): it is a stub,
   and logic there is unverified by definition;
6. `traffic_sys_other.go` parses under `gofmt -e`.

Go tests skip when the toolchain is absent (`shutil.which("go")`), the same way
the PowerShell pins behave, so a host without Go does not fail the suite — it
reports a skip.

## 3. Verification

| Check | Result |
|---|---|
| `pytest -q tests/tools/test_nose_toolchain.py` | 6 passed |
| mutation: append `func broken( {` to `traffic_sys_other.go` | 1 failed (`test_the_uncompilable_fallback_still_parses`) |
| restored | 6 passed |
| `go vet ./...` / `go build` / compile-only `go test`, run by the pins | exit 0 each |

## 4. Limitations

1. **E2.** The pins run the real Go toolchain, but no capture test is executed
   (that needs a live adapter and npcap); "compiles" is not "captures".
2. **`traffic_sys_other.go` behaviour is unverified on every platform.** It is
   excluded on Windows and unreachable on Linux because the dependency needs
   libpcap at build time. Only its syntax and its size are pinned.
3. **Formatting is not pinned.** All 24 files differ from `gofmt` by alignment
   only. Reformatting `nose/` while a 24-hour soak sample is running would move
   the source commit for whitespace, so it is deliberately left alone and this
   paragraph is the record.
4. **`go.mod` / `go.sum` are exercised implicitly** by `go build`/`go vet`; no
   separate pin asserts their content.
5. **The `.bat` helpers in `nose/`** (`run_nose.bat`, `cleanup_nose_mouth.bat`)
   are not covered by these pins.
