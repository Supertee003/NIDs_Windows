# RB-009: Hot Reload Config (No Restart)

## Objective

Swap `configs/Rules.json` without reinstalling. Same mechanics as
RB-005, written as the forward (deploy-new) direction.

## Prerequisites

- New ruleset file ready, operator shell in repo root.

## Steps

1. **Prepare + validate the new file FIRST (never deploy blind)**
   ```bat
   python tools\aegisctl.py rules validate
   ```
   - Gates: non-empty, no duplicate ids, no id 0, within limits.
     A failing file must never reach step 2.

2. **Back up, then deploy**
   ```bat
   copy configs\Rules.json configs\Rules.json.bak
   copy configs\Rules.new.json configs\Rules.json
   ```
   - Canonical path is `configs/Rules.json` (not `config/`).

3. **Reload and confirm the swap took**
   ```bat
   python tools\aegisctl.py rules reload
   python tools\aegisctl.py rules list
   python scripts\aegis_open.py status
   ```
   - `list` count == new file count; daemon `rules_loaded` agrees.
     Disagreement means the reload did not take: restart the service
     (admin) and re-check. Proven live: reload returns
     `postcondition: ACTIVE`.

4. **Watch post-reload**
   - Status green, DEFCON sane, nose frames advancing,
     `forensic verify` true when run.

5. **Record**: old/new counts, validate + reload output, HEAD.

## Verification

- Validate exit 0 pre-deploy; counts agree post-deploy; flow
  uninterrupted (no service restart needed when it takes).

## Rollback

```bat
copy configs\Rules.json.bak configs\Rules.json
python tools\aegisctl.py rules validate
python tools\aegisctl.py rules reload
```
Then re-confirm step 3. Full procedure: RB-005.

## Notes

- Validation runs BEFORE any swap effect: a bad file cannot take down
  the live ruleset through this path.
- Every event records the active ruleset version at decision time.

## References

- RB-005 (rollback), RB-011 (policy IR mirror, which is
  restart-loaded, unlike rules)
