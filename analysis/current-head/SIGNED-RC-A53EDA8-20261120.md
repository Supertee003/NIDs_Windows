# SIGNED-RC-A53EDA8-20261120 — Patch Record (E2 build + E7 sign-verify)

## Declaration

| Field | Value |
|---|---|
| PATCH-ID | SIGNED-RC-A53EDA8-20261120 |
| FLOW-ID | REL-002 (build → assemble → sign → verify) |
| TARGET HEAD | `466a226` (build source `a53eda8344a20f86ad4f4e4001e9b3d648067671`) |
| FINAL HEAD | this commit |
| TARGET FILES | untracked build outputs (`zig-out/`, `target/`, `dist/`, `build/x64/`, `brain/**/build/`), `release/T20-final/466a226/**` (text only; binaries stay ignored), `docs/gates/T20_100pct_audit.{json,md}`, `EVIDENCE_INDEX.json`, this record |
| TARGET SYMBOLS | none — no product source symbol changed |
| IN-SCOPE | rebuild every component at build source `a53eda8`; test-sign both WDK drivers with the existing pinned AEGIS test certs; assemble a fresh candidate tree; Ed25519-sign its `SHA256SUMS` with the owner-approved existing key; verify with the owner trust anchor; re-run `final_audit --release-check` |
| OUT-OF-SCOPE | any `src/`, `drivers/`, `config/` source edit; Signed-IR promotion (STOP-THE-LINE — policy authority bypass, not release signing); host install, service restart, E5 preflight, 24 h soak, tag, push, publish |
| CONTRACT IMPACT | none — no `CanonicalEvent` wire/codec change |
| ABI IMPACT | none |
| AUTHORITY IMPACT | none — detection-only preserved; no WFP mutation, no host effect; PEP remains detection-only policy/evidence authority |
| STATE IMPACT | none at runtime |
| TEST IMPACT | no source change; `tests/release` 201/201 passed; full suite 1452 passed / 14 skipped / 1 xfailed / 1 xpassed / 26 subtests passed / **2 failed** (the same two E4 live-daemon host-state tests — DEGRADED installed daemon, not a source regression); component audit 66/66, prod failures 0 |
| EVIDENCE IMPACT | +1 E2 build record + E7 detached-signature verification; gate `release_signature` OPEN → PASS; no E5/E6 claim |

## Why this patch exists

The previously signed candidate (`b597e71`, build source `f4cde3c`) could not
close `release_signature`: `final_audit` requires the signed commit to contain
the **current** runtime commit `a53eda8`, and `f4cde3c` predates it. The owner
authorised finishing the remaining work including signing, with the soak
deferred to last. This patch rebuilds the runtime at the current build source
and produces a fresh signed candidate without rotating the trust anchor.

Key custody was re-verified read-only before signing: the existing private key
`D:\NIds_Windows\.keys\aegis-release.ed25519` derives public key
`txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=`, byte-for-byte the owner-approved
anchor in `docs/gates/RELEASE_TRUST_ANCHOR.md`. **No key generation and no
re-key** — trust continuity is preserved.

## Old flow → New flow

`final_audit --release-check` = 3/6 gates open (`release_signature` OPEN —
newest signed tree `7d91e30` did not contain runtime `a53eda8`)
→
`final_audit --release-check` = **2/6 gates open**; `release_signature` PASS via
`release/T20-final/466a226/signatures.json` (digest `A053C048C8B373C...`,
commit `466a226` is an ancestor of HEAD and contains runtime `a53eda8`).

Remaining OPEN gates are deliberately owner/time gates: `clean_host_e5`
(fresh install + preflight of the **new** candidate — the old `b597e71` E5
evidence does not apply to this tree) and `soak_24h`.

## Invariant

No source change: build source stays `a53eda8`; `tools/truth.py verify` stays
TRUTH_VALID. The signed digest is over the exact `SHA256SUMS` bytes shipped in
the candidate. All 23 rules stay covered; no `CanonicalEvent` wire change.

## Build result (all exit 0)

| Component | Command | Output |
|---|---|---|
| Zig runtime + tools | `zig build` | `zig-out/bin/aegis_nids.exe` 5,292,544 B, SHA-256 `FBD9BDB3456C9C7D...` (also refreshed `zig-out/bin/aegis_pep.dll` to the fresh Rust build) |
| Rust PEP | `cargo build --release` | `target/release/aegis_pep.dll` 2,702,336 B, SHA-256 `870CB9626EDD75...` |
| Shield support | `cargo build --release --manifest-path shield/Cargo.toml` | `shield/target/release/sec_monitor.dll` 112,128 B → staged to `zig-out/bin/` |
| Mouth support | `cargo build --release --manifest-path mouth/Cargo.toml` | `mouth/target/release/windows_sec_monitor.exe` 289,280 B → staged to `dist/` |
| Go Nose | `cd nose && go build -o aegis-nose.exe .` | `nose/aegis-nose.exe` 6,904,832 B (same source also staged as `dist/nose_dashboard.exe`) |
| C helpers + IPC | pre-existing staged `build/Release` + `dist/aegis_ipc.dll` / `aegis_adapter.dll`; `stage_helpers.py --check` = OK for all three helper DLLs | unchanged |
| Cython support | `python setup.py build_ext --inplace` in `brain/cython`, and (via short path, because the worktree path overflowed the linker's `.exp` path) in `brain/aegis_brain_cython` | 5 `.pyd` modules; Python fallback still present; tracked `fast_scan.c` restored after Cython regenerated it |
| WFP driver | `scripts/wdk_build_production.ps1` | `build/x64/wfp/aegis_wfp.sys` 41,472 B, unsigned SHA-256 `593A1299F9A1EB84...` |
| Minifilter driver | `scripts/wdk_build_minifilter.ps1` | `build/x64/minifilter/aegis_minifilter.sys` 10,240 B, unsigned SHA-256 `FFDB61A1F670C8...` |

## Windows result — driver test-sign decision (gate 9)

Decision taken on the owner's behalf under the standing signing authorisation:
**test-sign with the existing pinned lab certs; do not claim EV/HLK production
signing.** No new code-signing key was generated.

| Driver | Command | Result |
|---|---|---|
| WFP | `scripts/sign_wfp_driver_20261024.ps1 -ExpectedUnsignedSha256 593A1299...` (pinned thumbprint `00E92849867308596564D134BB981EF726798E97`) | `Valid`; signed SHA-256 `B26AC754C92B7BD...` |
| Minifilter | `signtool sign /sha1 60B05537FEB7A40D6F6624FF5C005C09DC245A63 /fd SHA256 /v …` | `Valid`; signed SHA-256 `C836A981AC74074...` |

`Get-AuthenticodeSignature` = `Valid` for both, with the expected signer
thumbprints. This is **lab test signing only** — the certs are local and
trusted on this host; no EV certificate, HLK, or Microsoft attestation is
claimed. The installer remains `NotSigned`; that limitation is unchanged.

## Sign result

```
python tools\release_candidate.py                 # RC PASS, release/T20-final/466a226
python tools\sign_release.py --sign \
    --dir release\T20-final\466a226 \
    --key-file D:\NIds_Windows\.keys\aegis-release.ed25519
signed digest : A053C048C8B373CF93E766D9C54F54D191B33D273627075A6121516591E4996C
public key    : txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=
AEGIS_RELEASE_TRUSTED_PUBLIC_KEY=txigr... python tools\sign_release.py --verify --dir release\T20-final\466a226
PASS: signatures.json signs SHA256SUMS (A053C048C8B373CF...) with an ed25519 key
AEGIS_RELEASE_TRUSTED_PUBLIC_KEY=txigr... python tools\final_audit.py --release-check
component audit: COMPLETE (modules 66/66, prod failures 0)
release: NOT SHIPPABLE (2/6 gates open)
  PASS release_signature   ... commit 466a226 contains runtime a53eda8
  OPEN clean_host_e5       no post-install preflight artifact for the new candidate
  OPEN soak_24h            no 24 h soak artifact
```

Candidate tree: 238 checksummed files; `release_candidate.verify()` = PASS.
Compared with `b597e71` the tree drops only stale/duplicate Cython build
intermediates (cp311 outputs and `zzprobe` objects) and two lab attack scripts,
and adds `tools/aegisctl/fp_feedback.py` from slice 3. No runtime file is
missing.

## Evidence level

- **E2** — every component rebuilt from the current source with exit 0; candidate tree verified by `release_candidate.verify()`.
- **E7** — detached Ed25519 signature verified with the owner-approved trust anchor and accepted by `final_audit --release-check` as a PASS gate.
- **Not claimed:** E5 (clean host) / E6 (24 h soak). Those gates remain OPEN and the release stays NOT SHIPPABLE.

## Evidence artifacts

- `release/T20-final/466a226/SHA256SUMS`, `signatures.json`, `SBOM.json`
- `docs/gates/T20_100pct_audit.{json,md}` (regenerated by `final_audit`)
- this record + `EVIDENCE_INDEX.json` entry

## Rollback

Delete the untracked `release/T20-final/466a226/` tree and revert the two
regenerated board files plus this record and the index entry. No source,
installed host state, service, or key material is touched by the rollback.

## Remaining risk

- The signed tree is assembled from the working tree at `466a226`; git tracks
  only its text files (binaries are ignored by design). `SHA256SUMS` covers the
  binaries present in the artifact tree, not in a fresh checkout — the same
  model as every prior candidate.
- `clean_host_e5` and `soak_24h` are open: no claim of a verified clean host or
  a 24 h stable soak exists for this new candidate.
- Lab test-signed drivers are not EV/HLK-signed; the installer is not
  Authenticode-signed.
- `src/control/protocol.zig:248` marks `policy.verify` as `.operate`. **Resolved
  as NOT a discrepancy on 2026-11-20:** `handlers.policyVerify` is read-only
  (`verifyEnvelope` only, `marks nothing trusted`, touches no enforcement
  authority, `is_mutation=false`, `has_postcondition=false`), and `.operate` is
  the normal role class shared by `forensics.verify`, `enforcement.verify` and
  `xdr.verify` (verification/diagnostic commands) — not an authority claim.
  `tests/tools/test_operator_honesty.py` passes (3/3). No source change needed;
  this is not a STOP-THE-LINE item.

## Open blockers

- Owner-run E5: install the new candidate on a clean host, run the preflight,
  and record a `PASS` artifact referencing `466a226`.
- Owner-named 24 h soak window with a real baseline; publish only after PASS.
  Blocker confirmed 2026-11-20: this shell is **not elevated** (`False`), so
  install/restart/preflight cannot be run by the agent; the installed daemon is
  DEGRADED (`queue_dropped_total=5177 > budget 3500`, uptime ~23.8 h), which is
  the host-state cause of the two E4 failures. `soak_24h` additionally needs
  24 h of wall clock; no command compresses it.
- Signed-IR promotion remains STOP-THE-LINE (owner trust anchor + authority
  review); explicitly out of scope.
- EV/HLK driver signing and installer Authenticode need an external CA; lab
  test-signing is the honest current state.

## Completion gate

**PASS for this patch**: build source unchanged, release tree verified, detached
signature verified with the owner anchor, `release_signature` gate PASS, no
host/soak/publish action taken. **Release as a whole stays NOT SHIPPABLE** until
`clean_host_e5` and `soak_24h` PASS.
