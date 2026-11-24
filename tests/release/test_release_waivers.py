"""RELEASE-WAIVER-001: an owner exception must never look like a pass.

The owner can decide to ship without a gate (that is their call), but the audit
must not dress that decision up as evidence. These pins hold the boundary:

* a waiver never sets `ok` on the gate;
* a malformed, unknown-gate or expired waiver is ignored, not trusted;
* `--release-check` alone still fails while a gate is open;
* `--accept-waivers` never becomes a green exit: it prints
  `WAIVED_NOT_SHIPPABLE` and returns 2, while the markdown/JSON keep saying
  the exception is unproven (V&R-08).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import final_audit  # noqa: E402


def _gate(ok: bool = False) -> dict:
    return {"id": "soak_24h", "ok": ok, "owner": "time", "detail": "IN_PROGRESS"}


def _waiver(**overrides) -> dict:
    entry = {
        "gate_id": "soak_24h",
        "reason": "owner ships without the window",
        "accepted_by": "owner",
        "accepted_at": "2026-11-14T22:35:00",
        "not_proven": ["24 h was never observed"],
    }
    entry.update(overrides)
    return entry


def _write(tmp_path: Path, waivers: list[dict]) -> Path:
    path = tmp_path / "waivers.json"
    path.write_text(json.dumps({"waivers": waivers}), encoding="utf-8")
    return path


def test_a_waiver_never_turns_a_gate_into_pass(tmp_path: Path) -> None:
    waivers = final_audit.load_waivers(_write(tmp_path, [_waiver()]))
    gate = final_audit.apply_waivers([_gate()], waivers)[0]
    assert gate["ok"] is False
    assert gate["waived"] is True
    assert gate["waiver"]["not_proven"] == ["24 h was never observed"]
    assert gate["detail"].startswith("WAIVED by owner")


def test_a_closed_gate_is_not_marked_waived(tmp_path: Path) -> None:
    waivers = final_audit.load_waivers(_write(tmp_path, [_waiver()]))
    gate = final_audit.apply_waivers([_gate(ok=True)], waivers)[0]
    assert not gate.get("waived")
    assert "waiver" not in gate


def test_incomplete_waivers_are_ignored(tmp_path: Path) -> None:
    for broken in (
        _waiver(reason=""),
        _waiver(accepted_by=""),
        _waiver(not_proven=[]),
        _waiver(gate_id="not_a_gate"),
        _waiver(not_proven="a string, not a list"),
    ):
        assert final_audit.load_waivers(_write(tmp_path, [broken])) == {}, broken


def test_an_expired_waiver_is_ignored(tmp_path: Path) -> None:
    expired = _waiver(expires_at="2020-01-01T00:00:00")
    assert final_audit.load_waivers(_write(tmp_path, [expired])) == {}


def test_a_future_expiry_is_accepted(tmp_path: Path) -> None:
    live = _waiver(expires_at="2099-01-01T00:00:00")
    assert "soak_24h" in final_audit.load_waivers(_write(tmp_path, [live]))


def test_the_verdict_separates_shippable_from_waived(tmp_path: Path) -> None:
    waivers = final_audit.load_waivers(_write(tmp_path, [_waiver()]))
    gates = final_audit.apply_waivers([_gate(), {"id": "truth_artifacts", "ok": True,
                                                 "owner": "none", "detail": "ok"}], waivers)
    verdict = final_audit.release_verdict(gates)
    assert verdict["shippable"] is False
    assert verdict["shippable_with_waiver"] is True
    assert verdict["waived"] == ["soak_24h"]
    assert verdict["unwaived"] == []


def test_an_unwaived_open_gate_blocks_even_with_the_flag(tmp_path: Path) -> None:
    waivers = final_audit.load_waivers(_write(tmp_path, [_waiver()]))
    gates = final_audit.apply_waivers(
        [_gate(), {"id": "clean_host_e5", "ok": False, "owner": "owner", "detail": "x"}],
        waivers,
    )
    verdict = final_audit.release_verdict(gates)
    assert verdict["shippable_with_waiver"] is False
    assert verdict["unwaived"] == ["clean_host_e5"]


def test_no_waivers_file_means_no_waivers(tmp_path: Path) -> None:
    assert final_audit.load_waivers(tmp_path / "absent.json") == {}


def test_waiver_mode_is_never_a_green_release_exit(tmp_path: Path) -> None:
    waivers = final_audit.load_waivers(_write(tmp_path, [_waiver()]))
    verdict = final_audit.release_verdict(final_audit.apply_waivers([
        _gate(), {"id": "truth_artifacts", "ok": True, "owner": "none", "detail": "ok"},
    ], waivers))
    assert verdict["shippable"] is False
    assert verdict["shippable_with_waiver"] is True

    code, message = final_audit.release_exit(verdict, accept_waivers=False)
    assert code == 1
    assert message and message.startswith("FAIL: release gates open:")

    code, message = final_audit.release_exit(verdict, accept_waivers=True)
    assert code == 2
    assert message and message.startswith("WAIVED_NOT_SHIPPABLE:")
    assert "soak_24h" in message
    assert "never green" in message


def test_full_release_exit_is_green_without_waivers() -> None:
    verdict = final_audit.release_verdict([
        {"id": "soak_24h", "ok": True, "owner": "time", "detail": "PASS"},
    ])
    assert final_audit.release_exit(verdict, accept_waivers=True) == (0, None)
