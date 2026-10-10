"""EVT-171 (ps1 follow-up): the wrapper routes to live surfaces only.

scripts/aegis.ps1 used to launch the retired menu consoles, the retired
graph script, and a mislabeled desktop binary as `web`. Now every route
delegates to the opener or aegisctl with arguments passed through.
Static pins (no execution; live proofs run separately and are recorded
in the EVT).
"""
from __future__ import annotations

from pathlib import Path

PS1 = Path(__file__).resolve().parents[2] / "scripts" / "aegis.ps1"


def _text() -> str:
    return PS1.read_text(encoding="utf-8", errors="replace")


def test_retired_entrypoints_unreferenced():
    text = _text()
    for dead in ("aegis_console.py", "aegis_console_pro.py",
                 "scripts/aegis_graph.py"):
        assert dead not in text, dead


def test_routes_delegate_live():
    text = _text()
    assert "aegis_open.py" in text and "displays --tui" in text
    assert "aegisctl console" in text or "$cli console" in text
    assert "displays --web" in text
    assert "aegisctl graph" in text or "$cli graph" in text


def test_gui_has_truthful_name():
    text = _text()
    assert '"gui"' in text
    assert "aegis_dashboard" in text
