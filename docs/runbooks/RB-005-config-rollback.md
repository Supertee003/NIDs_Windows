# RB-005: Config Rollback

## Objective

Revert a bad ruleset to the previous one. Lighter than RB-004 (files
only, daemon reloads without reinstall).

## Prerequisites

- Operator shell in `D:\NIDs_Windows`. No elevation for validate;
  reload is daemon-side (no elevation either).

## Steps

1. **Back up the current (broken) file**
   ```bat
   copy configs\Rules.json configs\Rules.json.bak
   ```

2. **Restore the previous file** (your versioned copy or repo HEAD):
   ```bat
   copy configs\Rules.json.v<target> configs\Rules.json
   ```
   - No versioned copy? `git show HEAD:configs/Rules.json` to inspect
     what HEAD holds before overwriting anything.

3. **Validate BEFORE asking for reload**
   ```bat
   python tools\aegisctl.py rules validate
   ```
   - Must pass: non-empty, no duplicate ids, no id 0, within limits.
     Fix the file, never force past this gate.

4. **Reload and confirm**
   ```bat
   python tools\aegisctl.py rules reload
   python tools\aegisctl.py rules list
   python scripts\aegis_open.py status
   ```
   - `list` count must match the restored file; daemon `rules_loaded`
     in status must agree. If the count disagrees, the reload did not
     take: restart the service (admin) and re-check.

5. **Record**: file versions, validate output, before/after counts.

## Verification

- `rules validate` exit 0; `list` count == file count; status green.
- New events flow (nose frames advance).

## Rollback of the rollback

- The `.bak` from step 1 is the way forward again; repeat the
  procedure with it.

## Notes

- Canonical path is `configs/Rules.json` (not `config/`).
- Every event records the active ruleset version at decision time.

## References

- RB-004 (full restore), RB-009 (hot-reload mechanics)
- `tools/config_validator.py --config configs/runtime.json`
  (runtime config sibling check)
