# Contributing to AEGIS NIDS Windows

## Toolchains (pinned versions)

- Zig 0.13.0 · Rust 1.88.0 · Python 3.11+ · Go 1.22+ · TypeScript 5.x (node 20) · MSVC 19.38+ (Visual Studio 2022, for the C helpers and any driver work)

## Canonical builds (one production runtime, no duplicates)

```powershell
zig build                                   # aegis_nids.exe (runtime spine)
cargo build --release                       # aegis_pep.dll (Rust PEP)
cmake -B build; cmake --build build         # C helpers (etw/fim/wfp user-mode)
cd nose; go build -o aegis-nose.exe .       # packet acquisition
python brain/windows_brain.py               # Tier-2 analytics (interpreted)
```

The kernel WFP callout driver is intentionally NOT built by CMake
(`BUILD_KERNEL_DRIVER` refuses by design) — driver work needs the WDK,
an isolated lab, and signing; see `docs/KERNEL_NIDS_COMPLETION_PLAN.md`.

## Gate battery (must be green before any PR)

```powershell
zig build test
python -m pytest tests/ tests/e2e -q
cargo test
python tools/truth.py verify
python tools/release_engineering.py --verify
python tools/final_audit.py --check          # component audit (Part I/II/III)
python tools/final_audit.py --release-check  # release gates; see the table it prints
```

`--check` and `--release-check` answer different questions. A complete
component audit is not a shippable release: `--release-check` additionally
requires a signature over the release `SHA256SUMS`, a clean-host preflight PASS,
and a 24 h soak recorded after the current runtime commit. When it fails it
names each open gate and its owner.

Rules that keep the tree healthy: product modules must import with no
side effects (no sockets, no serve loops, no banners, no `sys.exit`);
tests write to `tmp_path`, never into tracked tree state; the daemon's
`etw_ready` and friends report live state only, never assumed state.
See `AGENTS.md` for the full contributor contract (vertical slices,
patch transactions, evidence levels).

## What not to send

- Enforcement or driver changes without executed proof on an isolated
  host (blocking/quarantine/WFP mutation are lab-only by policy).
- Changes that touch the WFP path outside `rust-src/` (the Rust PEP is
  the sole enforcement authority).
- Secrets, keys, certificates, `.env` files, or trust material — see
  `SECURITY.md`. Policy and installer signing keys live off-repo.

## Reporting security issues

Do NOT open a public issue. Use private vulnerability reporting per
`SECURITY.md`.
