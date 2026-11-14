"""E2 pins for the post-install preflight gate (PREFLIGHT-001).

The tool exists to answer one question a human cannot be trusted to answer from
memory on a clean host: did this machine come up the way the installer says it
will? Each rule below is a failure mode that already happened on this project, so
the pins are written against the real historical shape, not a happy path:

  * AUTO_START daemon + demand-start drivers -> ring fills with no reader
    (2026-11-11 boot failure, 448/4,012 lost),
  * a hand-fixed lab host whose boot task points at an admin-evidence script
    is not an installed host, so a "PASS" there would be false,
  * a boot task that exits non-zero started nothing, whatever the services say.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "host_preflight", ROOT / "tools" / "host_preflight.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


INSTALL = r"C:\Program Files\AEGIS NIDS"


def installed_facts(**over) -> dict:
    facts = {
        "service": {
            "start_type": "DEMAND_START",
            "binary": INSTALL + r"\runtime\aegis_nids.exe",
            "start_name": "LocalSystem",
        },
        "env": {"raw": "AEGIS_LOSS_BUDGET=3500", "loss_budget": 3500},
        "task": {
            "exists": True,
            "state": "Enabled",
            "run_as": "SYSTEM",
            "last_result": 0,
            "task_to_run": (
                'powershell.exe -NoProfile -File "'
                + INSTALL
                + r'\scripts\boot-sequence.ps1"'
            ),
        },
        "services": {"AegisWfp": "RUNNING", "AegisMinifilter": "RUNNING", "AegisNids": "RUNNING"},
        "health": {
            "state": "RUNNING",
            "degraded": False,
            "data_integrity": {"loss_budget": 3500, "minifilter_ring_dropped": 0},
        },
        "status": {"state": "RUNNING", "uptime_ms": 5 * 60_000},
    }
    facts.update(over)
    return facts


def ids(checks: list[dict]) -> set[str]:
    return {c["id"] for c in checks}


def failed_ids(checks: list[dict]) -> set[str]:
    return {c["id"] for c in checks if not c["ok"]}


def test_a_correct_install_passes_every_check() -> None:
    checks = load_tool().evaluate(installed_facts(), loss_budget=3500)
    assert failed_ids(checks) == set()
    # The rule set is not allowed to shrink silently: every failure mode below
    # must still have a check.
    assert ids(checks) >= {
        "service_start_type",
        "service_loss_budget",
        "boot_task_present",
        "boot_task_system",
        "boot_task_last_result",
        "boot_task_loader_installed",
        "driver_AegisWfp",
        "driver_AegisMinifilter",
        "daemon_health",
        "daemon_loss_budget",
        "minifilter_ring_clean",
        "daemon_uptime",
    }


def test_auto_start_daemon_fails_with_the_reason() -> None:
    facts = installed_facts()
    facts["service"] = dict(facts["service"], start_type="AUTO_START")
    checks = load_tool().evaluate(facts, loss_budget=3500)
    assert "service_start_type" in failed_ids(checks)
    detail = next(c for c in checks if c["id"] == "service_start_type")["detail"]
    assert "AUTO_START" in detail


def test_lab_loader_outside_the_install_dir_fails() -> None:
    """The 2026-11-14 host: hand-fixed via admin-evidence. Not an install."""
    facts = installed_facts()
    facts["task"] = dict(
        facts["task"],
        task_to_run=(
            'powershell.exe -File "D:\\NIDs_Windows\\admin-evidence\\'
            'host-window-003-20261110\\boot-sequence.ps1"'
        ),
    )
    checks = load_tool().evaluate(facts, loss_budget=3500)
    assert failed_ids(checks) == {"boot_task_loader_installed"}


def test_task_that_failed_its_last_run_fails() -> None:
    facts = installed_facts()
    facts["task"] = dict(facts["task"], last_result=1)
    assert "boot_task_last_result" in failed_ids(load_tool().evaluate(facts, loss_budget=3500))


def test_missing_task_fails_closed_on_every_task_rule() -> None:
    facts = installed_facts()
    facts["task"] = {
        "exists": False,
        "state": None,
        "run_as": None,
        "last_result": None,
        "task_to_run": None,
    }
    failed = failed_ids(load_tool().evaluate(facts, loss_budget=3500))
    assert {"boot_task_present", "boot_task_system", "boot_task_last_result",
            "boot_task_loader_installed"} <= failed


def test_stopped_driver_fails() -> None:
    facts = installed_facts()
    facts["services"] = dict(facts["services"], AegisMinifilter="STOPPED")
    assert "driver_AegisMinifilter" in failed_ids(load_tool().evaluate(facts, loss_budget=3500))


def test_unreadable_health_fails_closed() -> None:
    facts = installed_facts()
    facts["health"] = {"error": "control_daemon_query_failed"}
    failed = failed_ids(load_tool().evaluate(facts, loss_budget=3500))
    assert "daemon_health" in failed


def test_ring_loss_fails() -> None:
    facts = installed_facts()
    facts["health"] = dict(
        facts["health"],
        data_integrity={"loss_budget": 3500, "minifilter_ring_dropped": 12},
    )
    assert "minifilter_ring_clean" in failed_ids(load_tool().evaluate(facts, loss_budget=3500))


def test_budget_mismatch_fails_in_both_places() -> None:
    facts = installed_facts()
    facts["env"] = {"raw": "AEGIS_LOSS_BUDGET=0", "loss_budget": 0}
    facts["health"] = dict(
        facts["health"], data_integrity={"loss_budget": 0, "minifilter_ring_dropped": 0}
    )
    failed = failed_ids(load_tool().evaluate(facts, loss_budget=3500))
    assert {"service_loss_budget", "daemon_loss_budget"} <= failed


def test_uptime_floor_is_enforced() -> None:
    checks = load_tool().evaluate(installed_facts(), loss_budget=3500, min_uptime_min=30)
    assert "daemon_uptime" in failed_ids(checks)
