# RELEASE-BOARD-001 — one command said 100%, the release record said 85%

**Created:** 2026-11-14
**Build source:** `222cfe3` (this patch touches `tools/`, `tests/`, `CONTRIBUTING.md`)
**Level:** E2 (16 pure-function pins + one live run on the release host)
**Found while:** answering "are we at 100%?" with a tool rather than an opinion

---

## 1. The contradiction

```
$ python tools/final_audit.py
audit: 100% PRODUCTION VERIFIED (modules 66/66, prod failures 0, part_ii 5/5, golden_path declared=True)
```

and, one directory over, in the tracked ship-state record:

```
RC-FINAL-20261114.md §5: ~85% for a shippable production release
```

Both were written honestly, and both are wrong as a *pair*. `final_audit.py` was
answering "is every declared component documented across ten dimensions?" — a
real, useful question with a real answer of yes. `RC-FINAL` was answering "can
this ship?" — a different question with a different answer. The tool printed the
first answer in the vocabulary of the second.

`AGENTS.md` calls contradictory source-of-truth documents a stop-the-line
condition, and this is the most dangerous shape of one: a CI-green command that
tells a reader the release is done. The fix is not to lower the component audit.
It is to stop letting it speak for the release.

## 2. What the tool reports now

The declaration is split, and the release half is computed from recorded
artifacts:

```
component audit: COMPLETE (modules 66/66, prod failures 0, part_ii 5/5, golden_path declared=True)
release: NOT SHIPPABLE (3/6 gates open)
  PASS  truth_artifacts    [none]  TRUTH_VALID — artifacts carry build source 87e780e
  PASS  component_audit    [none]  modules 66/66, prod failures 0, part_ii 5/5
  OPEN  release_signature  [owner] release\T20-final\46b93dc\signatures.json is a reference
                                   record, not a signature (needs signature, public_key, signed_digest)
  OPEN  clean_host_e5      [owner] no PASS artifact (…preflight-20261114.json);
                                   open checks ['boot_task_loader_installed']
  OPEN  soak_24h           [time]  …soak-24h-delta-latest.json is IN_PROGRESS at 2.04/24.0 h
  PASS  evidence_debt      [none]  unnamed product files 528 <= baseline 528
```

| Gate | Owner | Closes when |
|---|---|---|
| `truth_artifacts` | none | `tools/truth.py verify` exits 0 |
| `component_audit` | none | Part I 66/66, Part II 5/5, golden path declared |
| `release_signature` | **owner** | a release tree carries `signature` + `public_key` + `signed_digest`, and `signed_digest` equals the SHA-256 of that tree's `SHA256SUMS` |
| `clean_host_e5` | **owner** | a preflight artifact is PASS **and** its boot-task loader lives under `C:\Program Files\AEGIS NIDS` (a lab-host PASS does not count) |
| `soak_24h` | **time** | a soak artifact with `required_hours ≥ 24`, verdict PASS, no problems, recorded **after** the newest runtime-tree commit |
| `evidence_debt` | none | the unnamed-product-file ratchet has not grown |

Every gate is fail-closed and names its owner when open. `--check` keeps its old
meaning (component audit complete); `--release-check` is the new one and exits 1
while any gate is open — which it does today, correctly.

## 3. Three rules worth stating explicitly

**A reference record is not a signature.** `release/T20-final/46b93dc/signatures.json`
holds `policy`, `immutable`, `commit`, `shipped_files`. It is a pointer to where a
signature would go. Requiring `signature`, `public_key` and `signed_digest`, then
matching `signed_digest` against the actual `SHA256SUMS`, means the gate cannot
be closed by editing a JSON file — it needs bytes signed by a key.

**A lab host PASS is not a clean install.** This host's preflight has 11 PASS and
one FAIL (`boot_task_loader_installed`) because the boot task points at
`admin-evidence\…\boot-sequence.ps1`. The gate requires the loader under the
install directory, so the one thing that makes this host *not* evidence of an
install is exactly the thing that keeps the gate open.

**An old PASS does not cover a new build.** A soak artifact is scored against the
commit time of the newest change under the runtime tree (`src`, `nose`, `brain`,
`ts_policy`, `shared`, `contracts`, `drivers`, `go`, `build.zig`, `CMakeLists.txt`,
`Cargo.toml`, `rust-src`). A 25 h PASS recorded before that commit is reported as
predating the build, not as a closed gate; if the commit time is unreadable the
gate fails closed rather than assuming freshness. This is the written rule
"never treat an old report as current truth" turned into code.

## 4. Verification

| Check | Result |
|---|---|
| `pytest tests/release/test_release_board.py` | 16 passed |
| `pytest tests/release tests/docs tests/security` | 360 passed, 5 failed — all 5 are `release_engineering --verify` refusing a worktree that still held this patch's uncommitted artifact edits (the preflight inside `fresh_deploy`); they pass on the committed tree |
| live run | `component audit: COMPLETE`, `release: NOT SHIPPABLE (3/6)`, both exit codes as designed |

Pins cover each way a false ship verdict could be produced: a complete component
audit read as shippable; a reference record read as a signature; a signature over
the wrong digest; a signature with no `SHA256SUMS`; a lab-host PASS; a FAIL
preflight (the open check is named); an IN_PROGRESS soak; a 21 h PASS against a
24 h gate; a PASS older than the runtime commit; unreadable freshness; a stale
PASS hidden behind a newer FAIL; debt growth; unreadable debt; a truth failure;
and a census so the gate set cannot shrink. One structural pin walks the AST with
the module docstring removed and refuses the string `100% PRODUCTION VERIFIED`
anywhere in executable code.

## 5. What was *not* changed

- The component audit is not weakened: 66/66 modules, 5/5 holds and the golden
  path still have to be satisfied, exactly as before.
- No gate is satisfied by an artifact that merely exists; every one checks a
  property of that artifact.
- `docs/gates/T20_100pct_audit.{json,md}` keep their file names (references stay
  valid) but their content is now split into "Component audit" and "Release
  readiness". The old JSON `declaration: "100% PRODUCTION VERIFIED"` string no
  longer exists anywhere in the tool's output; this record is the reason.

## 6. Consequence

The honest answer to "are we at 100%?" is now a command, not an opinion:

```
python tools/final_audit.py --release-check
```

It exits 1 today, and the three open gates are the three items no code change in
this repository can close: a signing key (custody), a clean Windows host (install
+ reboot), and 24 hours of wall clock on the current build. Two of them are the
owner's, one is time. When they are done, the same command turns green without
anyone editing a claim.
