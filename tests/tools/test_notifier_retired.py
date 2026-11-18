"""Herald retired truthfully (EVT-152): the notifier must stay retired.

scripts/aegis_notifier.py was marked "DEPRECATED, use aegisctl events" --
but aegisctl events is view-only (count/tail/follow/stats) and sends
nothing, so the pointer was false and the script sat in limbo: fully
coded transports, zero configuration, zero ownership. EVT-152 decision:
RETIRED, file kept (no deletion), header states the truth. These pins
lock it: header says RETIRED, the component matrix row says retired, and
no launcher/runner references it (resurrection must be deliberate, with
secrets management and lab proof -- never a silent rewire).

Read-only and static: no system touch, no tree writes.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NOTIFIER = REPO / "scripts" / "aegis_notifier.py"
MATRIX = REPO / "docs" / "runtime" / "COMPONENT_MATRIX.md"


def test_notifier_header_states_retired():
    text = NOTIFIER.read_text(encoding="utf-8")
    assert "RETIRED (EVT-152)" in text
    assert "aegisctl.py events" in text and "VIEW-only" in text
    assert "UNOWNED" in text


def test_notifier_has_no_managed_runner():
    # The opener, the bat, and the manifests must not launch it. If a
    # future herald is revived, this pin forces the decision to be
    # explicit (and to bring secrets + lab proof with it).
    for path in (REPO / "scripts" / "aegis_open.py",
                 REPO / "scripts" / "run_aegis.bat",
                 REPO / "runtime_manifest.json"):
        assert "notifier" not in path.read_text(encoding="utf-8").lower(), path.name


def test_component_matrix_marks_notifier_retired():
    lines = MATRIX.read_text(encoding="utf-8").splitlines()
    comp = [ln for ln in lines if ln.startswith("| `notifier`")
            and "`scripts/aegis_notifier.py`" in ln]
    assert len(comp) == 1
    assert "RETIRED (EVT-152" in comp[0]
    ver = [ln for ln in lines if ln.startswith("| `notifier`")
           and "How to query" not in ln and "aegis_notifier.py" not in ln]
    # The versioning table must not offer a --version gate for a retired
    # component; remaining pipe/startup rows are historical context.
    for ln in ver:
        assert "--version" not in ln, ln
