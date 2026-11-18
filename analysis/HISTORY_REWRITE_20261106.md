# History rewrite — 2026-11-06

Status: **applied to the local repository**. The pre-rewrite history is preserved
in an operator archive bundle, and every old→new commit pair is published in
[`commit-map.txt`](history-rewrite-20261106/commit-map.txt).

## 1. Trigger

`git push -u origin codex/o2-etw-context` was rejected by GitHub with
`GH001: Large files detected` (pre-receive hook declined). The branch history
contained 12 blobs larger than 50 MB, 13,792.1 MB in total, all under
`aegis-audit-*/04-scan-*.txt`. The largest was 3,637.4 MB:

```
aegis-audit-20260928-001216/04-scan-aegis_pep_enforce_evaluate_unblock_query_provider.txt
```

Those blobs entered history at old commit `419e9f5` (2026-09-29) and were
ancestors of every later commit. No source or build file was affected; the
paths were bulk scan dumps from an external audit session.

## 2. Backup (created before the rewrite)

| Artifact | Location | Size | Check |
|---|---|---|---|
| Full history bundle (`--all`, all refs) | `D:/AEGIS_archive/aegis-history-20261106.bundle` | 559,235,729 bytes (533.3 MiB) | `git bundle verify` → `records a complete history`, `is okay` |
| Audit scan dumps (16 directories) | `D:/AEGIS_archive/audit-dumps/` | 214 files, 24.25 GiB | byte total matched the working tree before deletion |
| Admin evidence (99 tracked + ignored local files) | `D:/AEGIS_archive/admin-evidence-20261106/` | 2,211 files, 2,353.42 MB | 99/99 tracked files restored locally after the rewrite |

The bundle contains the pre-rewrite branch, tags, and the tool checkpoint refs
that were later removed locally (10 heads total).

## 3. What changed

```text
git filter-repo --force --invert-paths \
  --path-regex '^(aegis-audit-|admin-evidence/)'
```

- `aegis-audit-*` was removed from every commit **and** from the working tree;
  the archive copy above is now the only retained copy.
- `admin-evidence/` was removed from every commit. The 99 tracked files were
  restored into the working tree afterwards and remain **local-only** because
  `.gitignore` already ignores the directory.
- Two `refs/codex/turn-diffs/checkpoints/...` tree refs still pinned the old
  audit trees. They were removed from the local repository (they are in the
  bundle) and `git gc --prune=now` dropped the 13.8 GB of blobs.
- `.gitignore` now also ignores `aegis-audit-*/` so the dumps cannot be
  re-added by accident.
- Four commits that became empty after the path removal were pruned. The branch
  is 602 commits ahead of `origin/main` instead of 605.

No source, build, test, or runtime file was modified by the rewrite. The source
tree is byte-identical to the pre-rewrite build source:

```text
git diff 572ff13 HEAD -- src rust-src nose cmake build.zig build.zig.zon CMakeLists.txt
# empty
```

## 4. Commit mapping (key evidence commits)

| Pre-rewrite | Post-rewrite | Subject |
|---|---|---|
| `d6facf2d69fb4336475bfeee34e66f3ea66bbea2` | `aa388f4dc297e4d212febba864432967f0e85728` | docs(context): mark historical open claims as closed with evidence |
| `fc108b06a3451042ecb615f3f7d994737869a33c` | `572ff132a988c9950fde713696038087a89132b1` | fix(hostnet): annotate the poll sleep step as u32 |
| `f7c626df89bc18b31d0132181d0a4632d6b1e6f3` | `e06fcc3cae0f1f684d5033773169b923721ad054` | wire(xdr): persist frozen advisory assessments as IDS evidence receipts (XDR-RECEIPT-002) |
| `13a9ad10fc0a09ce380482c2ebe2fc0b3bfcb49e` | `db911c8921456a4e65a436bf3d86e93c8ee4d2a0` | docs(truth): rebaseline maps to hostnet build fix 572ff13 |
| `1afde37696e195877900fdf4b30b53768d72d9b9` | `4f76399ef77aabb644708c45b21aee477709e332` | docs(evidence): record the RB-021 preflight pass and the stale lab pin |
| `be2f398d42c24e360e119c622a6d2eee8e1dad28` | `e78ebfd4539b3ae3227563abf023d2c1bb0cc1b5` | docs(evidence): close XDR-005 at E5 with live multi-source receipt/replay |
| `3327c8b1df1e2415e6decf21855aa002e125e12f` | `73247a2d140c3986a64b9a206b771784568884f8` | docs(context): align remaining-closure notes with the XDR-005 E5 closure |
| `7e222ef22abc586c6445ba5a3d349f1a5653a067` | `8b8956a20bd34ae3448910739381ab208c9c30ec` | docs(evidence): record QLOSS observability at E5; repair E5 count |
| `419e9f511038e7905d731dfb756dd7da777c8ffc` | `919c2038ffe50f1e0a417629e8766422c9cdb8dc` | Synchronize unified control center with daemon snapshot |
| `1294da6935e63e8d10cee0351906e0d020f155d4` | `2d193813a43b37143e3baacf3016e7ffe0666ca1` | tools: add safe O2 outbound host proof |

`origin/main` (`daf90885d7def23b899712090cff71835873567f`) is before the
removed paths and keeps its SHA.

The complete 904-line mapping is in
`analysis/history-rewrite-20261106/commit-map.txt`. Four old commits map to the
all-zero SHA because they became empty and were pruned.

## 5. Consequences

- Evidence entries that cite a pre-rewrite SHA remain historical records of
  when the evidence was produced. The commit map resolves each old SHA to the
  equivalent post-rewrite commit.
- `EVIDENCE_INDEX.json` contains 63 entries that cite `admin-evidence/...`
  artifacts. Those files are intentionally **not published**; they are in the
  operator archive. The evidence entries themselves are unchanged.
- Machine maps now carry the post-rewrite build source `572ff13` (previously
  `fc108b0`).
- Published history contains no file larger than 50 MB and no audit dump.

## 6. Recovery

```powershell
# Inspect or restore the pre-rewrite history
git clone D:/AEGIS_archive/aegis-history-20261106.bundle aegis-restored
# or fetch selected old refs into the current repository
git fetch D:/AEGIS_archive/aegis-history-20261106.bundle `
  'refs/heads/*:refs/restored/heads/*'
```

## 7. Verification (post-rewrite, local)

| Check | Command | Result |
|---|---|---|
| Source content unchanged | `git diff 572ff13 HEAD -- src rust-src nose cmake build.zig build.zig.zon CMakeLists.txt` | empty |
| Source ancestry | `git merge-base --is-ancestor 572ff13 HEAD` | rc=0 |
| Tracked tree | `git ls-tree -r -l HEAD` | 1,583 files, 21.6 MB, 0 files >50 MB |
| Pack size | `git count-objects -vH` | 289.09 MiB |
| Truth | `python tools/truth.py verify` | `TRUTH_VALID` — source `572ff13`, ancestor of HEAD, source worktree clean |
| Release digests | `python tools/release_engineering.py --verify` | `OK - 651/651` (source_commit=572ff13) |
| Release tests | `python -m pytest tests/release -q` | 89 passed |
| Inventory | `inventory.json` | 1,481 files (was 1,776; 297 removed paths, 2 added records) |

The rewrite commit itself is `aa388f4`; the build source remains `572ff13`
because no source/build file changed.
