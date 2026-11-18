"""Pins for tools/capture_select.py (E2: pure logic, no host touch).

The tool exists because a capture decision made by hand is a decision nobody
verified: the earlier lab watched Wi-Fi while the attacker sat on VMnet1, and
"0 detections" was read as a detector failure. So the selector resolution, the
EVT-200 disjointness rule, the direct-reader state, and the rendered plan are
pinned here against the real ``aegis-nose.exe --list-devices`` shape.

Nothing in this file opens a device, writes an environment variable, restarts
a service, or writes outside tmp_path.
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

NOSE_WIFI = r"\Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}"
NOSE_VMNET1 = r"\Device\NPF_{CE375996-106D-46F7-A67C-0168EAE8C96F}"


def _module():
    spec = importlib.util.spec_from_file_location(
        "capture_select", REPO / "tools" / "capture_select.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


select = _module()


# Real `aegis-nose.exe --list-devices` shape (this host, 2026-11-18), trimmed
# to the adapters the selection rule actually turns on.
DEVICE_LIST = f"""[NOSE DEVICES] found=8
[NOSE DEVICES] #0 name=\\Device\\NPF_{{AAA}} description="WAN Miniport (IPv6)" addresses=0
[NOSE DEVICES] #1 name=\\Device\\NPF_{{BBB}} description="Hyper-V Virtual Ethernet Adapter" addresses=2
[NOSE DEVICES] #1 address=172.23.224.1 netmask=fffff000
[NOSE DEVICES] #5 name={NOSE_WIFI} description="Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)" addresses=4
[NOSE DEVICES] #5 address=192.168.1.39 netmask=ffffff00
[NOSE DEVICES] #5 address=fe80::28bd:665b:2dd9:2169 netmask=ffffffffffffffff0000000000000000
[NOSE DEVICES] #7 name={NOSE_VMNET1} description="VMware Virtual Ethernet Adapter for VMnet1" addresses=2
[NOSE DEVICES] #7 address=192.168.126.1 netmask=ffffff00
[NOSE DEVICES] #8 name=\\Device\\NPF_{{DDD}} description="Microsoft Wi-Fi Direct Virtual Adapter #3" addresses=2
[NOSE DEVICES] #8 address=169.254.244.130 netmask=ffff0000
[NOSE DEVICES] #10 name=\\Device\\NPF_Loopback description="Adapter for loopback traffic capture" addresses=2
[NOSE DEVICES] #10 address=127.0.0.1 netmask=ff000000
"""


def devices() -> list[dict]:
    return select.parse_list_devices(DEVICE_LIST)


# --------------------------------------------------------------------------
# selector resolution: never guess, never reinterpret a GUID as a substring
# --------------------------------------------------------------------------


def test_exact_canonical_name_wins() -> None:
    device, error = select.resolve_selector(devices(), NOSE_VMNET1)
    assert error == ""
    assert device["description"] == "VMware Virtual Ethernet Adapter for VMnet1"


def test_unique_description_selector_resolves() -> None:
    device, error = select.resolve_selector(devices(), "VMnet1")
    assert error == ""
    assert device["name"] == NOSE_VMNET1


def test_index_selector_resolves_the_listed_device() -> None:
    device, error = select.resolve_selector(devices(), "#5")
    assert error == ""
    assert device["name"] == NOSE_WIFI


def test_ambiguous_selector_is_refused_with_candidates() -> None:
    device, error = select.resolve_selector(devices(), "Wi-Fi")
    assert device is None
    assert "ambiguous" in error
    # Actionable: the message must hand back the names to copy.
    assert NOSE_WIFI in error


def test_unknown_selector_is_refused() -> None:
    device, error = select.resolve_selector(devices(), "VMnet9")
    assert device is None
    assert "matches no Npcap device" in error


def test_empty_selector_is_an_error_not_a_default() -> None:
    device, error = select.resolve_selector(devices(), "   ")
    assert device is None
    assert error == "empty selector"


def test_auto_select_never_picks_a_virtual_adapter() -> None:
    auto = select.select_capture_device(devices())
    assert auto["name"] == NOSE_WIFI


# --------------------------------------------------------------------------
# EVT-200: two readers on one segment duplicate events
# --------------------------------------------------------------------------


def test_overlap_detects_equality_and_containment() -> None:
    assert select.overlaps(NOSE_VMNET1, NOSE_VMNET1) is True
    assert select.overlaps(NOSE_WIFI, NOSE_VMNET1) is False
    assert select.overlaps(NOSE_VMNET1, "") is False
    # "VMnet1" is a description, not part of the NPF path: a string test alone
    # cannot see that the two selectors name one adapter. That is why callers
    # must pass resolved device names (see the evaluate() test below).
    assert select.overlaps("VMnet1", NOSE_VMNET1) is False


def test_direct_capture_needs_two_distinct_resolved_devices() -> None:
    assert select.direct_capture_state("", "")[0] == "disabled"
    assert select.direct_capture_state(NOSE_WIFI, "")[0] == "disabled"
    assert select.direct_capture_state("", NOSE_VMNET1)[0] == "disabled"
    assert select.direct_capture_state(NOSE_WIFI, NOSE_VMNET1)[0] == "enabled"
    assert select.direct_capture_state(NOSE_VMNET1, NOSE_VMNET1)[0] == "disabled"


def test_two_spellings_of_one_adapter_are_not_disjoint() -> None:
    # The exact bug this slice closes: a GUID nose pin and a "VMnet1" lab pin
    # name the same adapter, so the direct reader must stay off.
    state = select.evaluate(
        devices(), {select.NOSE_ENV: NOSE_VMNET1, select.DAEMON_ENV: "VMnet1"}
    )
    assert state["direct_capture"]["state"] == "disabled"
    assert state["direct_capture"]["reason"] == "both selectors resolve to one device"


# --------------------------------------------------------------------------
# the verdict an operator reads before trusting the topology
# --------------------------------------------------------------------------


def test_show_reports_the_attack_target_and_both_roles() -> None:
    state = select.evaluate(
        devices(), {select.NOSE_ENV: NOSE_WIFI, select.DAEMON_ENV: NOSE_VMNET1}
    )
    assert state["verdict"] == "CAPTURE_SELECT_OK"
    assert state["nose"]["target_ipv4"] == ["192.168.1.39"]
    assert state["daemon"]["target_ipv4"] == ["192.168.126.1"]
    assert state["direct_capture"]["state"] == "enabled"
    assert state["effective_nose_source"] == "pin"


def test_show_without_pins_names_the_auto_selected_device() -> None:
    state = select.evaluate(devices(), {})
    assert state["verdict"] == "CAPTURE_SELECT_OK"
    assert state["effective_nose_source"] == "auto-select"
    assert state["effective_nose_device"] == NOSE_WIFI
    assert state["direct_capture"]["state"] == "disabled"


def test_daemon_pin_without_nose_pin_is_reported() -> None:
    state = select.evaluate(devices(), {select.DAEMON_ENV: NOSE_VMNET1})
    assert state["verdict"] == "CAPTURE_SELECT_BLOCKED"
    assert any("direct capture stays disabled" in p for p in state["problems"])


def test_dangling_pin_blocks_the_verdict() -> None:
    state = select.evaluate(devices(), {select.NOSE_ENV: r"\Device\NPF_{GONE}"})
    assert state["verdict"] == "CAPTURE_SELECT_BLOCKED"
    assert state["problems"]


# --------------------------------------------------------------------------
# the plan: canonical names, no writes, explicit restart cost
# --------------------------------------------------------------------------


def test_plan_pins_the_canonical_name_not_the_substring() -> None:
    plan = select.build_plan(devices(), nose="VMnet1")
    assert plan["verdict"] == "CAPTURE_SELECT_PLAN_OK"
    assert plan["resolved"]["nose"] == NOSE_VMNET1
    assert plan["commands"] == [["setx", "/M", select.NOSE_ENV, NOSE_VMNET1]]
    assert plan["restart_required"] is True


def test_plan_refuses_two_readers_on_one_segment() -> None:
    plan = select.build_plan(devices(), nose="VMnet1", daemon="VMnet1")
    assert plan["verdict"] == "CAPTURE_SELECT_BLOCKED"
    assert plan["restart_required"] is False
    assert any("duplicate" in e for e in plan["errors"])


def test_plan_refuses_an_ambiguous_selector() -> None:
    plan = select.build_plan(devices(), nose="Wi-Fi")
    assert plan["verdict"] == "CAPTURE_SELECT_BLOCKED"
    assert any("ambiguous" in e for e in plan["errors"])


def test_plan_clear_removes_the_machine_value() -> None:
    plan = select.build_plan(devices(), clear_role="daemon")
    assert plan["commands"] == [
        ["reg", "delete", select.ENV_KEY, "/V", select.DAEMON_ENV, "/F"]
    ]
    assert plan["resolved"]["daemon"] == ""


def test_plan_text_states_the_restart_cost() -> None:
    text = select.render_plan(select.build_plan(devices(), nose="VMnet1"))
    assert "Restart-Service AegisNids" in text
    assert "soak window" in text


# --------------------------------------------------------------------------
# import hygiene: inspection must not touch the host
# --------------------------------------------------------------------------


def test_import_does_not_run_the_device_probe(monkeypatch) -> None:
    calls: list[tuple] = []

    def explode(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("import touched the host")

    monkeypatch.setattr(subprocess, "run", explode)
    spec = importlib.util.spec_from_file_location(
        "capture_select_reimport", REPO / "tools" / "capture_select.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert calls == []
    assert module.NOSE_ENV == "AEGIS_NOSE_IFACE"
