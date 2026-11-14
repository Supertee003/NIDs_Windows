"""CLI-LOGS-RESOLVER-001: one resolver for runtime paths, pinned so it cannot drift.

`TEST-HYGIENE-S301` fixed the two candidate-list commands by hand and recorded
the rest as residual: `aegis_core.ndjson`, `canary_last.json` and
`anomalous.json` still built `<repo>/logs/...` inline. That is the same defect
class — a runtime path that no fixture can redirect — so it is closed here
rather than left as a note, and this file makes the invariant structural: the
literal `<repo>/logs` may appear in exactly one place, the resolver's default.

Behavioural half: `canary report` reads a receipt file, so it is the cheapest
end-to-end proof that `AEGIS_LOGS_DIR` redirects a command that actually opens a
path (no daemon, no control plane).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "tools" / "aegisctl.py"
SOURCE = (REPO / "tools" / "aegisctl.py").read_text(encoding="utf-8")

HAND_BUILT = re.compile(r'TOOLS_DIR\.parent\s*/\s*"logs"')


def test_repo_logs_literal_exists_only_in_the_resolver() -> None:
    matches = [m.start() for m in HAND_BUILT.finditer(SOURCE)]
    assert len(matches) == 1, (
        "runtime paths must go through _logs_dir(); found "
        f"{len(matches)} inline `TOOLS_DIR.parent / \"logs\"` sites"
    )
    # And that one site is the resolver's own default, not a command path.
    start = SOURCE.index("def _logs_dir()")
    tail = SOURCE[start:]
    end = tail.find("\ndef ", 1)
    resolver = tail if end == -1 else tail[:end]
    assert 'TOOLS_DIR.parent / "logs"' in resolver, (
        "the single remaining literal must be the production default inside "
        "_logs_dir(), or production state moved without anyone deciding to"
    )


def test_no_command_joins_a_filename_onto_a_bare_logs_path() -> None:
    # Belt and braces: even a differently spelled hand-built path would drift.
    for pattern in ('parent / "logs" / "', 'REPO_ROOT / "logs" /'):
        assert pattern not in SOURCE, f"hand-built logs path survives: {pattern}"


def test_canary_report_reads_the_redirected_directory(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    receipt = {"available": True, "marker": "redirect-proof"}
    (logs / "canary_last.json").write_text(json.dumps(receipt), encoding="utf-8")

    env = dict(os.environ)
    env["AEGIS_LOGS_DIR"] = str(logs)
    proc = subprocess.run(
        [sys.executable, str(CLI), "canary", "report"],
        capture_output=True,
        text=True,
        timeout=90,
        cwd=REPO,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == receipt


def test_canary_report_without_a_receipt_is_honest_and_never_writes(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "empty"
    logs.mkdir()
    env = dict(os.environ)
    env["AEGIS_LOGS_DIR"] = str(logs)
    proc = subprocess.run(
        [sys.executable, str(CLI), "canary", "report"],
        capture_output=True,
        text=True,
        timeout=90,
        cwd=REPO,
        env=env,
    )
    assert proc.returncode == 3
    body = json.loads(proc.stdout)
    assert body["available"] is False
    assert body["reason"] == "no_canary_runs_yet"
    assert list(logs.iterdir()) == [], "a read command must not create files"
