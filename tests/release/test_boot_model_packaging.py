"""Packaging pins for the boot model and the loss budget (BOOT-RING-LOSS-001,
LOSS-BUDGET-001).

The host was fixed by hand; these tests make the installer carry the same
contract, so a fresh install cannot silently regress to AUTO_START, no loader,
or a daemon that never hears the accepted loss envelope.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_nsis_installer_ships_demand_start_boot_task_and_budget() -> None:
    install = _text("tools/installer.py")
    assert "start= demand" in install
    assert "start= auto" not in install
    # NSIS File directives must ship both scripts.
    assert "scripts\\boot-sequence.ps1" in install
    assert "scripts\\install-boot-task.ps1" in install
    assert "install-boot-task.ps1" in install
    # Uninstall must remove the task it created.
    assert "schtasks /delete /tn AegisBootSequence" in install
    assert "RMDir /r \"$INSTDIR\\scripts\"" in install


def test_bundle_installer_uses_the_same_contract() -> None:
    install = _text("scripts/install_aegis.ps1")
    assert "start= demand" in install
    assert "start= auto" not in install
    assert "install-boot-task.ps1" in install
    assert "AegisBootSequence" in install


def test_boot_task_installs_budget_and_loader() -> None:
    task = _text("scripts/install-boot-task.ps1")
    assert "AEGIS_LOSS_BUDGET=$LossBudget" in task
    assert "AegisBootSequence" in task
    assert "start= demand" in task
    assert "Register-ScheduledTask" in task


def test_boot_sequence_starts_daemon_before_minifilter() -> None:
    boot = _text("scripts/boot-sequence.ps1")
    daemon = boot.index("starting AegisNids")
    minifilter = boot.index("EnsureRunning 'AegisMinifilter'")
    assert daemon < minifilter, "minifilter must start after the daemon so the ring starts empty"
    # The loader must not use the array -match defect.
    assert "| Out-String" in boot
