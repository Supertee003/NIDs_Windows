"""CONFIG-VALIDATE-001: the validator must report, not traceback — and every
config in `configs/` must be readable by something.

Two defects were found by running the shipped validator against the shipped
configs:

* `python tools/config_validator.py --config configs/aegis.conf` (a non-JSON
  file in the same directory as the JSON configs) died with an uncaught
  `json.decoder.JSONDecodeError` traceback and exit 1 — the operator saw a stack
  trace instead of "that file is not JSON".
* `--config configs/policies.json` died with `UnicodeEncodeError` while
  *printing* the failure report: the module's own `âœ…` / `âŒ` literals were saved
  through a mis-encoded conversion, and a cp1252 console cannot encode them. The
  report could crash where the config did not.

Also pinned here: every `*.json` file under `configs/` parses, and no shadow copy
(`Rules.json.before-reload-test` and friends) is shipped in the release bundle.
That file is a stale snapshot of the live rules — it lacks the `rate_mode` /
`rate_threshold` fields the current `Rules.json` has — and
`analysis/current-head/01-build-inventory.md` already flagged it as an
unclassified file that must not reach a package.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "configs"
VALIDATOR = ROOT / "tools" / "config_validator.py"
BUNDLE = ROOT / "scripts" / "package_release.ps1"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )


def _json_configs() -> list[Path]:
    return sorted(CONFIGS.rglob("*.json"))


def test_the_shipped_runtime_config_is_valid() -> None:
    proc = _run("--config", "configs/runtime.json", "--strict")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: config valid" in proc.stdout


def test_a_non_json_config_is_reported_not_traced_back() -> None:
    proc = _run("--config", "configs/aegis.conf", "--strict")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    combined = proc.stdout + proc.stderr
    assert "cannot read config" in combined
    assert "Traceback" not in combined, (
        "a non-JSON config must produce a diagnostic, not a stack trace:\n" + combined
    )
    assert "configs/aegis.conf" in combined or "aegis.conf" in combined


def test_a_missing_schema_is_reported_not_traced_back() -> None:
    proc = _run("--config", "configs/runtime.json", "--schema", "configs/does-not-exist.json")
    assert proc.returncode == 2
    combined = proc.stdout + proc.stderr
    assert "cannot read schema" in combined
    assert "Traceback" not in combined


def test_a_failure_report_cannot_crash_on_encoding(tmp_path: Path) -> None:
    """The report ran through cp1252 literals; a config with any non-ASCII name
    must not turn a validation failure into a UnicodeEncodeError."""
    bad = tmp_path / "config-with-ümlaut.json"
    bad.write_text(json.dumps({"version": "5.0"}), encoding="utf-8")  # missing required keys
    proc = _run("--config", str(bad), "--strict")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    combined = proc.stdout + proc.stderr
    assert "Traceback" not in combined
    assert "UnicodeEncodeError" not in combined


def test_a_config_that_is_not_an_object_is_reported(tmp_path: Path) -> None:
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    proc = _run("--config", str(bad), "--strict")
    assert proc.returncode == 2
    assert "not a JSON object" in proc.stdout + proc.stderr


@pytest.mark.parametrize("path", _json_configs(), ids=lambda p: p.name)
def test_every_config_json_parses(path: Path) -> None:
    json.loads(path.read_text(encoding="utf-8-sig"))


def test_no_shadow_copy_of_a_live_config_is_shipped() -> None:
    """`*.before-*` / `*.bak` files are snapshots, never payload."""
    bundle = BUNDLE.read_text(encoding="utf-8")
    shadows = [
        p for p in CONFIGS.rglob("*")
        if p.is_file() and (".before-" in p.name or p.name.endswith((".bak", ".orig")))
    ]
    assert shadows, (
        "the shadow-copy guard has no subject any more; if the stale copy was "
        "removed, delete this test rather than letting it pass vacuously"
    )
    for path in shadows:
        assert path.name not in bundle, (
            f"the bundle copies a shadow copy of a live config: {path.name}"
        )


def test_the_shadow_rule_copy_is_older_than_the_live_one() -> None:
    """A stale copy that disagrees with the live rules must not look current."""
    live = CONFIGS / "Rules.json"
    shadow = CONFIGS / "Rules.json.before-reload-test"
    if not shadow.exists() or not live.exists():
        pytest.skip("shadow copy removed")
    live_rules = json.loads(live.read_text(encoding="utf-8-sig"))
    shadow_rules = json.loads(shadow.read_text(encoding="utf-8-sig"))
    assert live_rules != shadow_rules, (
        "the shadow copy is now identical to the live rules; it is either the "
        "same file twice or the pair drifted back together - decide which one "
        "the runtime loads before shipping either"
    )
    # 01-build-inventory.md calls this file unclassified; the pin keeps it from
    # silently becoming an alternative to the live rules.
    assert bundle_ships_only("Rules.json"), "the bundle must ship Rules.json only"


def bundle_ships_only(name: str) -> bool:
    """True when the bundle payload names that config and no shadow copy."""
    bundle = BUNDLE.read_text(encoding="utf-8")
    target = "configs" + "\\" + name
    return target in bundle and "before-" not in bundle
