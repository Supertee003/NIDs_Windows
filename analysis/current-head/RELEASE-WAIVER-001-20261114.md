# RELEASE-WAIVER-001 — the owner can ship without the soak, but not by pretending it passed

**Created:** 2026-11-14
**Build source:** `tools/`, `tests/`, `docs/gates/` only — no `RUNTIME_PATHS`
entry, so the running 24 h window is unaffected.
**Level:** E2 for the mechanism (8 pins); the exception itself is a decision, not
evidence.

---

## 1. The decision this records

The owner chose to ship without waiting for the 24 h soak window. That is the
owner's call to make. What the audit must not do is turn that decision into a
green check, because the truth of the matter is:

| Claim | State |
|---|---|
| 24 h continuous window observed for this build | **not observed** (0.4 h of 24.0 h recorded) |
| No dropped rows / restarts / DEGRADED / SCM 7031-7034 | proven for the observed fraction only |
| The 24 h claim reconstructable later from this artifact | **no** — a future window must be run separately |

Writing an artifact that says `PASS at 24.0/24.0 h` would satisfy the gate and
be false; it would also contradict `AGENTS.md` (never claim a higher evidence
level than tested) and the audit's own stated rule that a missing cell is
"reported with its gap, never silently waived".

## 2. What was built instead

An explicit waiver channel:

* `docs/gates/waivers.json` holds owner entries: `gate_id`, `reason`,
  `accepted_by`, `accepted_at`, `not_proven` (non-empty list), optional
  `expires_at`.
* `final_audit.load_waivers()` validates them. An entry with a missing field, an
  unknown gate id, an empty `not_proven` or an unparsable/expired `expires_at` is
  **ignored**, not trusted.
* `apply_waivers()` marks the gate `waived: true` and rewrites its detail to
  `WAIVED by owner (<time>): <reason>`. It **never** sets `ok`.
* `release_verdict()` gains `shippable_with_waiver` (every gate closed or
  explicitly waived), `waived` and `unwaived` alongside the unchanged `shippable`.
* `--release-check` alone still exits 1. `--release-check --accept-waivers` exits
  0 only when nothing is left unwaived, and still prints
  `FAIL: not a full shippable release; shipping with owner waiver on soak_24h (unproven)`.
* Both outputs keep saying `NOT SHIPPABLE (waived by owner: soak_24h, unproven)`,
  and the markdown report lists what is not proven under the gate table.

## 3. Verification

| Check | Result |
|---|---|
| `pytest -q tests/release/test_release_waivers.py` | 8 passed |
| `final_audit.py --release-check` | exit **1**, `soak_24h` shown as `WAIVED` |
| `final_audit.py --release-check --accept-waivers` | exit **0**, same WAIVED row, stderr says "not a full shippable release" |
| a closed gate with a matching waiver | not marked waived |
| expired / malformed / unknown-gate waivers | ignored |

## 4. Limitations

1. **The release is not "100 %".** Five of six gates are closed and proven; the
   sixth is waived by the owner and unproven. `--accept-waivers` is a shipping
   decision, not a measurement.
2. **Waivers are plain JSON in the repository**, editable by anyone with commit
   access. They are governance, not cryptography; the release signature covers
   the release tree, not this file.
3. **Deleting the entry restores the hard gate** — and after 2026-11-15T22:20:15
   a real 24 h run can close it, provided no `RUNTIME_PATHS` commit lands in
   between.
4. **The waiver does not expire**, so it will keep applying to later builds until
   someone removes it. That is deliberate (the owner's exception travels with the
   decision) but it is also a foot-gun: an entry that outlives its reason is
   indistinguishable from an accepted one.
