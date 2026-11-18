"""Pins for tools/lab_attack_window.py (E2: pure logic, no host touch).

The tool's whole value is that its "the sensor is watching X" claim uses the
same selector the shipped Go Nose uses. If the two drift, the tool blesses a
target the NIDS is blind to and the operator reads silence as a detector
failure. So the selector, the device parser, the log-delta reader, and the
verdict rules are pinned here against the exact shapes the host produces.

Nothing in this file talks to the control pipe, starts a service, or writes
outside tmp_path.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _module():
    spec = importlib.util.spec_from_file_location(
        "lab_attack_window", REPO / "tools" / "lab_attack_window.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


law = _module()


# The real `aegis-nose.exe --list-devices` output shape (2026-11-15 host),
# trimmed to the adapters that matter to the selection rule.
DEVICE_LIST = """[NOSE DEVICES] found=6
[NOSE DEVICES] #0 name=\\Device\\NPF_{AAA} description="WAN Miniport (IPv6)" addresses=0
[NOSE DEVICES] #1 name=\\Device\\NPF_{BBB} description="Hyper-V Virtual Ethernet Adapter" addresses=2
[NOSE DEVICES] #1 address=172.27.176.1 netmask=fffff000
[NOSE DEVICES] #2 name=\\Device\\NPF_{CCC} description="Bluetooth Device (Personal Area Network)" addresses=2
[NOSE DEVICES] #2 address=169.254.9.173 netmask=ffff0000
[NOSE DEVICES] #3 name=\\Device\\NPF_{DDD} description="Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)" addresses=4
[NOSE DEVICES] #3 address=192.168.1.39 netmask=ffffff00
[NOSE DEVICES] #3 address=fe80::28bd:665b:2dd9:2169 netmask=ffffffffffffffff0000000000000000
[NOSE DEVICES] #4 name=\\Device\\NPF_{EEE} description="VMware Virtual Ethernet Adapter for VMnet1" addresses=2
[NOSE DEVICES] #4 address=192.168.126.1 netmask=ffffff00
"""


def test_parse_list_devices_keeps_declared_and_seen_addresses():
    devices = law.parse_list_devices(DEVICE_LIST)
    assert [d["index"] for d in devices] == [0, 1, 2, 3, 4]
    wifi = devices[3]
    assert wifi["description"].startswith("Killer(R) Wi-Fi 6")
    assert [a["ip"] for a in wifi["addresses"]] == [
        "192.168.1.39",
        "fe80::28bd:665b:2dd9:2169",
    ]
    # #0 declares addresses=0 and carries none: the Go selector skips it.
    assert devices[0]["addresses"] == []


def test_selector_matches_go_nose_first_up_device():
    devices = law.parse_list_devices(DEVICE_LIST)
    chosen = law.select_capture_device(devices)
    assert chosen is not None
    # Virtual and Bluetooth adapters lose even though they have addresses;
    # the physical Wi-Fi adapter wins because it is the first clean one.
    assert "Wi-Fi" in chosen["description"]
    assert law.usable_ipv4(chosen) == ["192.168.1.39"]


def test_selector_never_blesses_a_vmnet_lab_link():
    # A Kali-on-VMnet1 topology is invisible to this capture path. The tool
    # must not report VMnet1 as the watched device when a physical NIC exists.
    devices = law.parse_list_devices(DEVICE_LIST)
    chosen = law.select_capture_device(devices)
    assert "VMware" not in chosen["description"]


def test_selector_falls_back_to_first_addressed_device():
    only_virtual = [
        {"index": 0, "name": "\\Device\\NPF_{AAA}", "description": "VMware Virtual Ethernet Adapter for VMnet1",
         "addresses": [{"ip": "192.168.126.1", "netmask": "ffffff00"}]},
    ]
    chosen = law.select_capture_device(only_virtual)
    assert chosen is not None and chosen["index"] == 0
    assert law.usable_ipv4(chosen) == ["192.168.126.1"]


def test_usable_ipv4_drops_link_local_and_ipv6():
    device = {
        "addresses": [
            {"ip": "fe80::1", "netmask": "x"},
            {"ip": "169.254.1.1", "netmask": "x"},
            {"ip": "127.0.0.1", "netmask": "x"},
            {"ip": "10.0.0.5", "netmask": "x"},
        ]
    }
    assert law.usable_ipv4(device) == ["10.0.0.5"]


def test_read_rows_since_only_returns_appended_complete_rows(tmp_path):
    log = tmp_path / "aegis_core.ndjson"
    first = {"event": "reg_change", "src_ip": "0.0.0.0"}
    log.write_text(json.dumps(first) + "\n", encoding="utf-8")
    offset = law.log_offset(log)

    second = {"event": "signature_match", "src_ip": "192.168.1.50", "rule": "1745456278"}
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(second) + "\n")
        # A half-written trailing object must not be counted as evidence.
        handle.write('{"event": "signature_match", "src_ip": "192.1')

    rows, _read, next_offset = law.read_rows_since(log, offset)
    assert rows == [second]
    assert next_offset > offset

    # The offset stops at the last complete line, so finishing the write makes
    # exactly one row visible and the earlier row never repeats.
    with log.open("a", encoding="utf-8") as handle:
        handle.write('68.1.50"}\n')
    rows, _read, _next = law.read_rows_since(log, next_offset)
    assert [r["src_ip"] for r in rows] == ["192.168.1.50"]


def test_read_rows_since_handles_missing_and_truncated_log(tmp_path):
    missing = tmp_path / "absent.ndjson"
    rows, read, offset = law.read_rows_since(missing, 0)
    assert (rows, read, offset) == ([], 0, 0)

    log = tmp_path / "rotated.ndjson"
    log.write_text('{"a":1}\n', encoding="utf-8")
    # A rotated (shorter) log must not replay old rows from a stale offset.
    rows, read, offset = law.read_rows_since(log, 10_000)
    assert (rows, read) == ([], 0)


def test_fnv1a32_matches_the_cross_language_golden_table():
    # rule_loader.zig pins the same values; a drift here would label every
    # attributed row with the wrong rule.
    assert law.fnv1a32("R1001") == 3813986375
    assert law.fnv1a32("R9064") == 4194591294
    assert law.fnv1a32("R9006") == 1745456278


def test_rule_names_reads_the_shipped_catalog():
    names = law.rule_names()
    assert names[law.fnv1a32("R9006")]["rule_id"] == "R9006"
    assert names[law.fnv1a32("R9006")]["layer"] == "L4"
    assert "SYN" in names[law.fnv1a32("R9006")]["name"]


def test_describe_rule_keeps_unknown_numerics_visible():
    assert "R0088" in law.describe_rule("4254503461")
    assert "UNKNOWN" in law.describe_rule(12345)


def _bench(packets, detections=10, dropped=0, shed=0, quota=0):
    return {
        "packets_captured": packets,
        "detections": detections,
        "dropped_total": dropped,
        "shed_overload": shed,
        "source_quota_shed": quota,
        "flows_active": 1,
    }


def test_verdict_pass_needs_ingress_and_attribution():
    before = _bench(1000, detections=10)
    after = _bench(1400, detections=14)
    row = {
        "event": "signature_match",
        "src_ip": "192.168.1.50",
        "rule": "1745456278",
        "enforcement_status": "observed",
        "host_effect_confirmed": False,
    }
    result = law.evaluate(before, after, [row], "192.168.1.50")
    assert result["verdict"] == "PASS"
    assert result["exit_code"] == 0
    assert result["rows_attributed"] == 1
    assert result["per_rule"] == {"1745456278": 1}
    assert result["frames_gained"] == 400
    assert result["detections_delta"] == 4


def test_verdict_no_attribution_when_only_ambient_rows_moved():
    before = _bench(1000)
    after = _bench(1400, detections=12)
    ambient = {"event": "reg_change", "src_ip": "0.0.0.0", "rule": "2",
               "enforcement_status": "observed", "host_effect_confirmed": False}
    result = law.evaluate(before, after, [ambient], "192.168.1.50")
    assert result["verdict"] == "NO_ATTRIBUTION"
    assert result["exit_code"] == 2
    assert result["rows_total"] == 1
    assert result["rows_attributed"] == 0


def test_verdict_blind_when_ingress_does_not_move():
    result = law.evaluate(_bench(1000), _bench(1000), [], "192.168.1.50")
    assert result["verdict"] == "BLIND"
    assert result["exit_code"] == 3


def test_verdict_blind_when_counter_goes_backwards():
    # A restart inside the window resets the counter: that is not ingress.
    result = law.evaluate(_bench(5000), _bench(20), [], "192.168.1.50")
    assert result["verdict"] == "BLIND"
    assert law.scored(-4980) is False


def test_verdict_invariant_fails_closed_on_any_host_effect():
    before = _bench(1000)
    after = _bench(1400)
    row = {
        "event": "signature_match",
        "src_ip": "192.168.1.50",
        "rule": "1745456278",
        "enforcement_status": "observed",
        "host_effect_confirmed": True,
    }
    result = law.evaluate(before, after, [row], "192.168.1.50")
    assert result["verdict"] == "INVARIANT"
    assert result["exit_code"] == 5
    assert result["violations_total"] == 1


def test_verdict_invariant_flags_a_non_observed_enforcement_status():
    row = {
        "event": "signature_match",
        "src_ip": "192.168.1.50",
        "rule": "1",
        "enforcement_status": "blocked",
        "host_effect_confirmed": False,
    }
    result = law.evaluate(_bench(1), _bench(2), [row], "192.168.1.50")
    assert result["verdict"] == "INVARIANT"
    assert result["violations"][0]["enforcement_status"] == "blocked"


def test_verdict_reports_queue_cost():
    before = _bench(1000, dropped=100, shed=0, quota=10)
    after = _bench(1400, dropped=160, shed=3, quota=40)
    result = law.evaluate(before, after, [], "192.168.1.50")
    assert result["dropped_delta"] == 60
    assert result["shed_delta"] == 3
    assert result["quota_shed_delta"] == 30


def test_verdict_without_expect_src_scores_on_ingress_only():
    result = law.evaluate(_bench(1000), _bench(1100), [], None)
    assert result["verdict"] == "PASS"
    assert result["expect_src"] is None


def test_markdown_names_the_device_target_and_verdict():
    doc = {
        "label": "wifi-bridged-test",
        "started_at": "2026-11-16T00:00:00Z",
        "finished_at": "2026-11-16T00:04:00Z",
        "seconds": 240,
        "head_sha": "deadbeef",
        "event_log": "C:/Windows/System32/logs/aegis_core.ndjson",
        "preflight": {
            "reason": "wire ingress advancing",
            "frames_gained": 5219,
            "sample_seconds": 5,
            "capture": {
                "selected_name": "\\Device\\NPF_{DDD}",
                "selected_description": "Killer(R) Wi-Fi 6",
                "selected_ipv4": ["192.168.1.39"],
            },
        },
        "before": _bench(1000),
        "after": _bench(1400),
        "result": law.evaluate(_bench(1000), _bench(1400), [], None),
    }
    text = law.render_markdown(doc)
    assert "192.168.1.39" in text
    assert "Killer(R) Wi-Fi 6" in text
    assert "`PASS`" in text
    assert "| packets_captured | 1000 | 1400 | 400 |" in text


def test_cli_help_is_offline_and_exits_zero(capsys):
    # --help must not construct the control client (an offline host still
    # needs the usage text).
    with pytest.raises(SystemExit) as exc:
        law.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--preflight" in out and "--expect-src" in out
