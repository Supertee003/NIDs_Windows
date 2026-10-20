# ADR-0008: Truth Source-Commit Semantics

**Status:** Accepted
**Date:** 2026-10-20
**Deciders:** operator + agent
**Supersedes:** the "every map carries current HEAD" interpretation in
`AGENTS.md`

## Context

The truth gate (`tools/truth.py`) required every machine map, `AI_CONTEXT.md`,
`EVIDENCE_INDEX.json`, `build_manifest.json` and `runtime_manifest.json` to
carry the current `git rev-parse HEAD`. A commit cannot contain its own SHA, so
any commit that folded evidence either:

- left the maps at the previous HEAD (clean checkout failed `truth.py`), or
- restamped them in the working tree (clean checkout passed `truth.py`, but the
  release digests drifted because the runtime manifest had changed).

The 2026-10-20 CI pre-push dry-run (fresh `e616bad`) observed exactly this
inversion: clean checkout -> truth FAIL / release PASS; overlay -> truth PASS /
release FAIL (`runtime_manifest.json` digest drift). The first hosted CI run
was blocked by an unsatisfiable committed state, not by code.

The maps were also being moved by records-only commits (`e616bad`, `865217b`,
`6a4d248`), which record evidence but do not change any build input.

## Decision

Truth artifacts carry the **build source commit**: the last commit that touched
the source/build tree. Records-only commits do not move it.

`tools/truth.py` now:

1. computes the source commit with
   `git log -1 --format=%H -- <SOURCE_PATHS>`;
2. requires every `head_sha`, `**HEAD:**`, and `source_commit` field to carry
   that source commit (full SHA in maps/AI_CONTEXT/EVIDENCE_INDEX/
   `build_truth.json`/`runtime_manifest.json`; 7-char in `build_manifest.json`
   and `runtime_manifest.source_commit`);
3. requires the source commit to be an ancestor of HEAD; and
4. requires `git diff --quiet <source> HEAD -- <SOURCE_PATHS>`.

`SOURCE_PATHS` is the build-source boundary:

```
src  rust-src  shield  nose  go  brain  drivers  shared  bridge  mouth
configs  build.zig  Cargo.toml  Cargo.lock  CMakeLists.txt  requirements.txt
```

Docs, evidence, tests, tooling, CI metadata, and auxiliary material are
records-only and are deliberately excluded.

`tools/create_manifest.py` writes the source commit (not HEAD) into
`runtime_manifest.json`. `tools/rebuild_truth.py` stamps the source commit into
the machine maps, `AI_CONTEXT.md`, `EVIDENCE_INDEX.json`, `build_manifest.json`,
`build_truth.json`, and `runtime_manifest.json`; the stamp is deterministic and
idempotent, and the source is computed from git, never supplied by a caller.

Current source commit: `dcb22a5` (REL-CLOSURE, 2026-10-19). All artifacts carry
`dcb22a5a5b5a6f01f4b4106e3248e7f7b3df94b2`; HEAD is `6a4d248` at the time of
this decision.

## Consequences

1. A records-only commit leaves a clean tree. No head overlay, no release
   digest drift, and `truth.py` passes on a fresh checkout.
2. A source/build change after `dcb22a5` makes `truth.py` fail until the
   source commit and maps are re-stamped (the rebuild is the normal path).
3. The `AGENTS.md` rule "a map with a different HEAD is stale" is replaced:
   a map is stale when it does not carry the current **source** commit.
4. Hosted CI can run on a records commit; the first push still requires the
   operator (the agent never pushes).
5. The rule is pinned by `tests/release/test_truth_source_commit.py`:
   source-ancestor accepted, docs commit as source rejected, source changed
   after recording rejected, non-ancestor source rejected.

## Alternatives rejected

- **B. Overlay-at-HEAD (current behavior).** Uncommitted head fields are not a
  release state; the CI checkout cannot see them, and the runtime manifest
  digest drifts.
- **C. External provenance record (e.g. GitHub attestation).** Correct in
  principle, but adds infrastructure and does not fix the local gate; the
  source commit is already in git.
- **D. Drop the HEAD fields.** Removes the provenance check instead of making
  it satisfiable.

## References

- `admin-evidence/ci-readiness-20261020/README.md` (Finding A, option A;
  gitignored operator evidence)
- `tools/truth.py`, `tools/rebuild_truth.py`, `tools/create_manifest.py`
- `tests/release/test_truth_source_commit.py`
- `AGENTS.md` (machine-readable truth, current-HEAD snapshot, pre-commit)
- `.github/workflows/ci.yml` (truth gate step)
- `EVIDENCE_INDEX.json` entry `CI-TRUTH-SOURCE-COMMIT` (E2)
