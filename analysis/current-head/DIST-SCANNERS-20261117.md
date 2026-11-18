# Distribution scanners and installer — local coverage now exists

**Date:** 2026-11-17
**Scope:** the two distribution items that needed tooling, not key material:
`bandit` / `pip-audit` and the NSIS installer build.

## Scanners

Installed into the user site (no system change):

```
python -m pip install --user bandit pip-audit
bandit 1.9.4        pip-audit 2.10.1
```

Commands and results:

| Scan | Command | Result |
|---|---|---|
| bandit | `python -m bandit -r brain tools scripts -f json` | 401 findings: **5 HIGH, 27 MEDIUM, 369 LOW** (exit 1) |
| pip-audit | `python -m pip_audit -r requirements.txt --format json` | **37 dependencies, 0 known vulnerabilities** (exit 0) |

### Bandit triage (honest, not a clean pass)

All five HIGH findings are `B605` on a constant clear-screen call:

```
os.system('cls' if os.name == 'nt' else 'clear')
```

in `scripts/Dashboard.py:101`, `scripts/aegis_console.py:155`,
`scripts/aegis_console_pro.py:50`, and two quarantined legacy files under
`tools/legacy/aegisctl_commands_quarantined/`. There is no user-controlled
string in the command, so these are false positives for injection; they are
recorded, not suppressed.

The 27 MEDIUM findings are triaged by category:

- `B104` bind to `0.0.0.0` in `brain/windows_brain.py` — the brain binds a
  configurable listener; this is a deployment choice, not a hidden default in
  the detection path.
- `B310` `urlopen` in local operator tools and Kali attack scripts — URLs are
  built from local/CLI inputs; no remote scheme is accepted by the shipped
  detector.
- `B108` hardcoded `/tmp` in the Kali canary scripts — the scripts run inside
  the disposable attacker VM.
- `B314` `xml.etree` parsing in `scripts/wfp_s6_cleanup.py` and
  `tools/wfp_filter_audit.py` — the XML is the output of the local `netsh wfp`
  audit, not untrusted network data.

None of the triaged findings is in a production enforcement path; the product
is detection-only and `prevention_gate=closed`.

Artifacts: `admin-evidence/dist-scanners-20261117/bandit.json`,
`bandit.txt`, `pip-audit.json`.

## Installer

`tools/installer.py --package` fails closed only when `makensis` is missing.
NSIS **is** installed on this host at
`C:\Program Files (x86)\NSIS\makensis.exe` (not on PATH, but the tool's
candidate list finds it). The generator was run against the current tree
(commit `7c604d5`) and `makensis` built a complete installer:

```
aegis-installer-5.0.0-current.exe   6,130,207 bytes
```

It was built to a temp output path so no tracked or previously shipped file was
overwritten, and it was **not installed**. The generated script embeds
`AEGIS_COMMIT "7c604d5"`, the product version `5.0.0`, both kernel drivers when
present, and the runtime components.

The backlog's "installer 6.0.0" label is a version decision, not a build
failure: the tool's `APPVERSION` is `5.0.0`. A 6.0.0 installer needs an explicit
product version bump (a source change) and its own evidence cycle.

## What this closes

- scanner coverage is now local, not CI-only: bandit and pip-audit both ran
  against this tree with recorded output;
- the installer toolchain works and produces an installer from the current
  tree, so the distribution gap is a version/signing decision, not missing
  tooling.
