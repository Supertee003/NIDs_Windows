# CONFIG-VALIDATE-001 — the config validator crashed instead of reporting

**Created:** 2026-11-14
**Build source:** `069356b` (unchanged; this patch touches `tools/` and `tests/`)
**Level:** E2 (31 pins, including three real subprocess runs against the shipped
configs)

---

## 1. What was wrong

Running the shipped validator against the shipped configs:

```
$ python tools/config_validator.py --config configs/aegis.conf --strict
Traceback (most recent call last):
  ...
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)

$ python tools/config_validator.py --config configs/policies.json --strict
Traceback (most recent call last):
  ...
UnicodeEncodeError: 'charmap' codec can't encode character '' in position 1
```

Two defects, both in the *reporting* path rather than the validation:

1. **No error handling.** `load_config` / `load_schema` raised straight through
   `main()`, so a file that is not JSON (`configs/aegis.conf` lives in the same
   directory as the JSON configs and has a `.conf` suffix the loader ignores) or
   a wrong `--schema` path produced a stack trace. An operator learns the file
   name from the traceback's last line; the exit code is Python's, not the
   tool's.
2. **The report could crash on its own text.** `OK:` / `FAIL:` were written as
   `âœ…` / `âŒ` — UTF-8 bytes decoded as cp1252 somewhere in the file's history —
   and printing them to a cp1252 console raises `UnicodeEncodeError`. The
   validator could fail while telling you a config failed, and the failure it
   reported was about printing, not about the config.

## 2. What changed

- `main()` wraps schema and config loading in `try/except (OSError, ValueError)`
  and returns **exit 2** with `ERROR: cannot read config <path> as JSON/TOML: …`
  on stderr; a non-object config (a list, a string) is named as such.
- The status lines are plain ASCII (`OK: config valid: …`, `FAIL: config
  validation failed (n errors):`).
- `--normalize` without `--output` prints the JSON with `ensure_ascii=True`, so
  printing a valid config with a non-ASCII value cannot raise either. File
  output keeps `ensure_ascii=False`.

Behaviour on the real configs after the change:

| Command | Before | After |
|---|---|---|
| `--config configs/runtime.json --strict` | `âœ… Config valid` (mojibake) | `OK: config valid`, exit 0 |
| `--config configs/aegis.conf --strict` | traceback | `ERROR: cannot read config … as JSON/TOML`, exit 2 |
| `--config configs/policies.json --strict` | `UnicodeEncodeError` while printing | 4 `Missing required field` lines, exit 1 |
| `--schema configs/does-not-exist.json` | traceback | `ERROR: cannot read schema …`, exit 2 |

## 3. Pins

`tests/tools/test_config_validator.py`, 31 passed: the valid runtime config
passes; a non-JSON config, a missing schema, and a non-object config each exit 2
with a diagnostic and **no `Traceback`**; a config with a non-ASCII filename still
reports its failures instead of raising `UnicodeEncodeError`; all 24 `configs/**`
JSON files parse; and no `*.before-*` / `*.bak` shadow copy is named by the
bundle payload.

The shadow copy in question, `configs/Rules.json.before-reload-test`, really is
stale — it predates the `rate_mode` / `rate_threshold` / `rate_window_ms` fields
and the tightened `hosts` regex in the live `Rules.json`.
`analysis/current-head/01-build-inventory.md` already called it "an unclassified
file that must not be included in a production package". The pin keeps that true
and fails if the two files ever become identical (same rules twice is its own
hazard) or if the bundle ever names it.

Mutation control: removing the `load_config` try/except fails
`test_a_non_json_config_is_reported_not_traced_back`; restoring returns 31 passed.

## 4. Limitations

1. **E2.** `jsonschema` is not installed in this environment, so validation ran
   with the module's minimal fallback (required-key checks). A schema violation
   that only `jsonschema` would catch was therefore not exercised here.
2. **The stale rules copy still exists.** Deleting a tracked file is a
   disposition decision (it is the record of what the rules looked like before
   the reload test); the pins keep it out of the package and out of the way.
3. **`configs/aegis.conf` is not validated by anything.** It is not JSON, and
   `load_config` only understands `.json` / `.toml`; whether that file is live
   configuration or documentation is unanswered here.
4. **Only `configs/runtime.json` was checked against the schema.** The other 23
   JSON files are pinned as parseable, not as schema-conformant — several are
   test fixtures with a different shape on purpose.
