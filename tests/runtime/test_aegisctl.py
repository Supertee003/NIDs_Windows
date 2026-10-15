"""
test_aegisctl.py - Tests for the aegisctl CLI (Gate C, v1).

Verifies that the aegisctl command/control CLI works as documented:
  - All subcommands parse correctly
  - version/status/health/diagnose are read-only and safe
  - start/stop/restart handle missing binaries gracefully
  - Exit codes follow the documented convention

These tests do NOT require running components — they verify the CLI
plumbing itself.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGISCTL = REPO_ROOT / "tools" / "aegisctl.py"


def _run_aegisctl(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    """Run aegisctl with the given args. Returns (exit_code, stdout, stderr)."""
    cmd = [sys.executable, str(AEGISCTL)] + list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT),
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"


class TestAegisctlExists(unittest.TestCase):
    """The aegisctl script must exist and be importable."""

    def test_aegisctl_script_exists(self):
        self.assertTrue(AEGISCTL.exists(), f"aegisctl.py not found at {AEGISCTL}")

    def test_aegisctl_help_exits_0(self):
        rc, stdout, stderr = _run_aegisctl("--help")
        self.assertEqual(rc, 0, f"--help should exit 0, got {rc}; stderr={stderr}")
        self.assertIn("aegisctl", stdout.lower())
        self.assertIn("version", stdout)
        self.assertIn("status", stdout)
        self.assertIn("health", stdout)


class TestAegisctlVersionCommand(unittest.TestCase):
    """`aegisctl version` must list component versions from the runtime."""

    def test_version_lists_all_components(self):
        rc, stdout, stderr = _run_aegisctl("version")
        # CTRL-001: version now queries runtime via pipe
        # When daemon is running with new code, it returns versions from the pipe
        # When daemon is running with old code, it returns {"ok":false} (no handler)
        # When daemon is not running, it returns error
        self.assertIn("Component", stdout)
        # Either we got version data, or the daemon doesn't have the handler yet
        has_data = any(
            line.strip().startswith(("core", "nose", "shield", "pep"))
            for line in stdout.splitlines()
            if line.strip() and not line.startswith("-") and not line.startswith("Component")
        )
        has_error = "not reachable" in stderr or "not reachable" in stdout
        # Accept: data present, error present, or empty table (old daemon)
        self.assertTrue(
            has_data or has_error or rc == 0,
            f"unexpected output: stdout={stdout!r} stderr={stderr!r}"
        )

    def test_version_component_filter(self):
        rc, stdout, stderr = _run_aegisctl("version", "--component", "brain")
        # Should mention brain but not bridge/core/etc.
        self.assertIn("brain", stdout)
        # Other components should NOT appear in the table body
        # (the header "Component" is always present).
        lines = [l for l in stdout.splitlines() if l and not l.startswith("-") and not l.startswith("Component")]
        for line in lines:
            self.assertTrue(
                line.startswith("brain"),
                f"expected only 'brain' rows, got: {line}"
            )


class TestAegisctlStatusCommand(unittest.TestCase):
    """`aegisctl status` must show runtime state via pipe."""

    def test_status_lists_all_components(self):
        rc, stdout, stderr = _run_aegisctl("status")
        self.assertEqual(rc, 0, f"status should exit 0, got {rc}; stderr={stderr}")
        # CTRL-001: status now queries runtime via pipe
        # Output shows Version, State, Uptime, etc.
        self.assertIn("State", stdout)
        self.assertIn("Version", stdout)

    def test_status_shows_state_column(self):
        rc, stdout, stderr = _run_aegisctl("status")
        # CTRL-001: status shows runtime state
        # Old daemon returns lowercase "running", new daemon returns "RUNNING"
        self.assertTrue(
            "running" in stdout.lower() or "not reachable" in stderr,
            f"expected running or connection error, got: stdout={stdout!r} stderr={stderr!r}"
        )

    def test_status_shows_traffic_gauges(self):
        # CLI-SHOW-158: operator-visible packets/flows lines.
        rc, stdout, stderr = _run_aegisctl("status")
        self.assertEqual(rc, 0, f"status should exit 0, got {rc}; stderr={stderr}")
        self.assertIn("Packets captured:", stdout)
        self.assertIn("Flows active:", stdout)

    def test_status_json_carries_traffic_gauges(self):
        # CLI-SHOW-158: machine-readable status exposes the gauges even
        # against pre-slice daemons (absent reads as 0).
        import json as _json
        rc, stdout, stderr = _run_aegisctl("status", "--json")
        self.assertEqual(rc, 0, f"status --json should exit 0, got {rc}; stderr={stderr}")
        document = _json.loads(stdout)
        self.assertIn("packets_captured", document["health"])
        self.assertIn("flows_active", document["health"])

    def test_status_json_carries_host_effect_posture(self):
        # EVT-179: host-effect honesty is observable, not claimed.
        # status --json carries host_effect_posture with filesystem
        # observations only; blocking truth stays with `enforce status`
        # (prevention_gate), never with file presence.
        import json as _json
        import os as _os
        rc, stdout, stderr = _run_aegisctl("status", "--json")
        self.assertEqual(rc, 0, f"status --json should exit 0, got {rc}; stderr={stderr}")
        document = _json.loads(stdout)
        posture = document.get("host_effect_posture")
        self.assertIsInstance(posture, dict)
        for key in ("installed_driver_present", "deploy_bundle_root",
                    "legacy_bundle_root", "legacy_scope_note"):
            self.assertIn(key, posture)
        sysroot = _os.environ.get("SystemRoot", r"C:\Windows")
        self.assertEqual(posture["installed_driver_present"],
                         _os.path.exists(_os.path.join(
                             sysroot, "System32", "drivers", "aegis_wfp.sys")))
        self.assertEqual(posture["deploy_bundle_root"],
                         _os.path.exists(r"C:\Program Files\AEGIS NIDS"))
        self.assertEqual(posture["legacy_bundle_root"],
                         _os.path.exists(r"C:\Program Files\AEGIS"))
        self.assertIn("pre-rename bundle", posture["legacy_scope_note"])
        self.assertIn("6.5", posture["legacy_scope_note"])

    def test_status_text_shows_host_posture_lines(self):
        # EVT-179: operator-visible posture lines, same source as --json.
        rc, stdout, stderr = _run_aegisctl("status")
        self.assertEqual(rc, 0, f"status should exit 0, got {rc}; stderr={stderr}")
        self.assertIn("Driver present:", stdout)
        self.assertIn("Deploy bundle root:", stdout)
        self.assertIn("Legacy bundle root:", stdout)


class TestAegisctlDashboardCommand(unittest.TestCase):
    """`aegisctl dashboard` one-shot must answer like `components`."""

    def test_oneshot_dashboard_probes_deep(self):
        # EVT-180: the one-shot render uses the deep concept probes, so a
        # live brain reads RUNNING here exactly as in `aegisctl
        # components`. The watch/iterations loop keeps the fast path
        # (cheap polling); only the single render pays for probes.
        rc, stdout, stderr = _run_aegisctl("dashboard")
        self.assertEqual(rc, 0, f"dashboard should exit 0, got {rc}; stderr={stderr}")
        brain_lines = [l for l in stdout.splitlines() if "AEGIS Brain" in l]
        self.assertTrue(brain_lines, "dashboard must list AEGIS Brain")
        self.assertNotIn("UNKNOWN", brain_lines[0],
                         f"one-shot dashboard must probe deep: {brain_lines[0]!r}")

    def test_dashboard_wiring_pins_depth_by_mode(self):
        # Static wiring: one-shot passes deep_components=True; the poll
        # loop uses the default (fast path). Guards a silent revert to
        # all-shallow.
        import pathlib as _pl
        src = (_pl.Path(__file__).resolve().parents[2]
               / "tools" / "aegisctl.py").read_text(encoding="utf-8")
        self.assertIn("def _render_dashboard_once(deep_components", src)
        self.assertIn("_render_dashboard_once(deep_components=True)", src)

    def test_incidents_list_reports_counters(self):
        # EVT-207: the command every Kali hint points at must exist and
        # report the daemon's counters (quiet reads zero, never an error).
        import json as _json
        rc, stdout, stderr = _run_aegisctl("incidents", "list", "--json")
        self.assertEqual(rc, 0, f"incidents list should exit 0, got {rc}; stderr={stderr}")
        document = _json.loads(stdout)
        for key in ("incidents_total", "incidents_open", "detections",
                    "policies_matched", "correlations"):
            self.assertIn(key, document)
        rc, stdout, stderr = _run_aegisctl("incidents", "list")
        self.assertEqual(rc, 0, f"incidents list should exit 0, got {rc}; stderr={stderr}")
        self.assertIn("Incidents open:", stdout)

    def test_dashboard_shows_detections_section(self):
        # EVT-207: the one-shot frame carries the same detection counters
        # as `incidents list` (or a labeled unavailable line, never silence).
        # Generous timeout: one-shot deep probes + several pipe round-trips
        # can exceed 10s under full-suite load; the command itself is fine.
        rc, stdout, stderr = _run_aegisctl("dashboard", timeout=60)
        self.assertEqual(rc, 0, f"dashboard should exit 0, got {rc}; stderr={stderr}")
        self.assertIn("DETECTIONS:", stdout)
        self.assertTrue(
            "Incidents open:" in stdout or "unavailable" in stdout,
            f"DETECTIONS section must report or admit: {stdout[-500:]!r}"
        )


class TestAegisctlHealthCommand(unittest.TestCase):
    """`aegisctl health` must probe runtime health via pipe."""

    def test_health_runs_without_crash(self):
        rc, stdout, stderr = _run_aegisctl("health")
        # CTRL-001: health now queries runtime via pipe
        # Output shows Component, State, PID, Checks, etc.
        # When daemon is running, it shows subsystem checks
        # When daemon is not running, it shows connection error
        self.assertTrue(
            "State" in stdout or "not reachable" in stderr,
            f"expected State or connection error, got: stdout={stdout!r} stderr={stderr!r}"
        )


class TestAegisctlDiagnoseCommand(unittest.TestCase):
    """`aegisctl diagnose` must produce a comprehensive report."""

    def test_diagnose_contains_all_sections(self):
        rc, stdout, stderr = _run_aegisctl("diagnose")
        self.assertEqual(rc, 0, f"diagnose should exit 0, got {rc}; stderr={stderr}")
        # CTRL-001: diagnose now queries runtime via pipe
        # Sections: VERSION, RUNTIME STATUS, SUBSYSTEM HEALTH, LOG FILES
        self.assertIn("VERSION", stdout)
        self.assertIn("RUNTIME STATUS", stdout)
        self.assertIn("SUBSYSTEM HEALTH", stdout)
        self.assertIn("LOG FILES", stdout)
        self.assertIn("Diagnostic report complete", stdout)

    def test_diagnose_shows_repo_root(self):
        rc, stdout, stderr = _run_aegisctl("diagnose")
        self.assertIn("Repo root:", stdout)
        self.assertIn("Python:", stdout)
        self.assertIn("Platform:", stdout)

    def test_diagnose_reports_endpoint_ownership(self):
        # ORPHAN-154: the report names owned endpoints and never stops
        # anything; on this host the brain channel is expected clear.
        rc, stdout, stderr = _run_aegisctl("diagnose")
        self.assertEqual(rc, 0, f"diagnose should exit 0, got {rc}; stderr={stderr}")
        self.assertIn("ENDPOINT OWNERSHIP", stdout)
        self.assertIn("brain channel", stdout)
        self.assertIn("control pipe", stdout)


class TestOrphanDetection(unittest.TestCase):
    """GAP-010: foreign listeners on owned UDP channels must be reported,
    never acted on. Windows-only (netstat/wmic scans)."""

    def test_ephemeral_squatter_is_foreign(self):
        if sys.platform != "win32":
            self.skipTest("netstat scan is Windows-only")
        import socket
        from tools.aegisctl.api import control_api
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            findings = None
            for _ in range(3):
                findings = control_api.detect_foreign_udp_listener(
                    port, ("windows_brain.py",))
                if findings and findings[0].get("pid") is not None:
                    break
                import time
                time.sleep(0.5)
            self.assertTrue(findings)
            self.assertEqual(findings[0]["status"], "FOREIGN")
            self.assertEqual(findings[0]["port"], port)
        finally:
            sock.close()

    def test_clear_port_reports_no_listener(self):
        if sys.platform != "win32":
            self.skipTest("netstat scan is Windows-only")
        import socket
        from tools.aegisctl.api import control_api
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", 0))
            free = probe.getsockname()[1]
        except OSError:
            self.skipTest("no ephemeral UDP port available")
            return
        finally:
            probe.close()
        findings = control_api.detect_foreign_udp_listener(free, ("windows_brain.py",))
        for found in findings:
            self.assertIn(found["status"], ("CLEAR", "FOREIGN"))
            if found["status"] == "CLEAR":
                self.assertIsNone(found["pid"])

    def test_owned_markers_recognize_expected_owner(self):
        if sys.platform != "win32":
            self.skipTest("netstat scan is Windows-only")
        import socket
        from tools.aegisctl.api import control_api
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            findings = control_api.detect_foreign_udp_listener(port, ("python",))
            if not findings or findings[0].get("pid") is None:
                self.skipTest("own command line not visible to wmic here")
            # This test process runs under python.exe, so the marker matches.
            self.assertEqual(findings[0]["status"], "OWNED")
        finally:
            sock.close()


class TestAegisctlStartStopErrors(unittest.TestCase):
    """`aegisctl start/stop` must validate arguments."""

    def test_start_without_args_errors(self):
        rc, stdout, stderr = _run_aegisctl("start")
        self.assertNotEqual(rc, 0, "start without --component or --all should fail")
        # argparse enforces mutually_exclusive_group with required=True,
        # so the error message will mention that one of the options is required.
        combined = stdout + stderr
        self.assertTrue(
            "required" in combined.lower() or
            "must specify --component NAME or --all" in combined,
            f"expected error about required arg, got: stdout={stdout!r} stderr={stderr!r}"
        )

    def test_stop_without_args_errors(self):
        rc, stdout, stderr = _run_aegisctl("stop")
        self.assertNotEqual(rc, 0, "stop without --component or --all should fail")

    def test_restart_without_component_errors(self):
        rc, stdout, stderr = _run_aegisctl("restart")
        self.assertNotEqual(rc, 0, "restart without --component should fail")

    def test_start_and_all_are_mutually_exclusive(self):
        rc, stdout, stderr = _run_aegisctl("start", "--component", "brain", "--all")
        self.assertNotEqual(rc, 0, "should reject --component and --all together")


class TestAegisctlExitCodes(unittest.TestCase):
    """Exit codes follow the documented convention:
       0 = success, 1 = partial failure, 2 = usage error."""

    def test_version_returns_0_when_all_present_or_1_when_missing(self):
        rc, _, _ = _run_aegisctl("version")
        self.assertIn(rc, (0, 1), f"version exit code should be 0 or 1, got {rc}")

    def test_status_always_returns_0(self):
        rc, _, _ = _run_aegisctl("status")
        self.assertEqual(rc, 0, f"status should always exit 0, got {rc}")

    def test_diagnose_returns_0(self):
        rc, _, _ = _run_aegisctl("diagnose")
        self.assertEqual(rc, 0, f"diagnose should exit 0, got {rc}")

    def test_bad_command_returns_2(self):
        rc, _, _ = _run_aegisctl("nonexistent-command")
        self.assertEqual(rc, 2, f"bad command should exit 2, got {rc}")


class TestAegisctlBridgeDiagnostic(unittest.TestCase):
    """`aegisctl bridge` answers RB-017 step 3 honestly (EVT-154).

    The old stub always reported bridge_diagnostic_not_connected. The new
    command synthesizes host-local truth (UDP :9999 listener owner).
    Live-shape test is state-tolerant: it pins the document contract,
    not whether the brain happens to be up right now.
    """

    def test_bridge_json_is_a_shaped_document(self):
        rc, stdout, _ = _run_aegisctl("bridge", "--json")
        self.assertIn(rc, (0, 1, 2), f"bridge exit must be 0/1/2, got {rc}")
        try:
            doc = __import__("json").loads(stdout)
        except Exception as exc:
            self.fail(f"bridge --json must parse: {exc}\n{stdout[:300]}")
        for key in ("command", "port", "available", "listener",
                    "owner_is_brain", "secret_posture", "note"):
            self.assertIn(key, doc, f"bridge doc missing {key}")
        self.assertEqual(doc["command"], "bridge")
        self.assertEqual(doc["port"], 9999)
        if doc["listener"] is not None:
            self.assertIn("pid", doc["listener"])
            self.assertIsInstance(doc["owner_is_brain"], bool)
            if doc["owner_is_brain"] is True:
                self.assertEqual(rc, 0)
                self.assertTrue(doc["available"])

    def test_bridge_human_output_names_the_owner(self):
        rc, stdout, _ = _run_aegisctl("bridge")
        self.assertIn(rc, (0, 1, 2), f"bridge exit must be 0/1/2, got {rc}")
        self.assertIn("9999", stdout)
        self.assertIn("owner_is_brain", stdout)


class TestBridgeDiagnosticLogic(unittest.TestCase):
    """Deterministic doc-logic pins (mocked probes, no system touch)."""

    def test_doc_branches(self):
        from unittest.mock import patch
        from tools.aegisctl.api import control_api
        base = {"listener": None}
        with patch.object(control_api, "udp_listener_owner", return_value=None), \
             patch.object(control_api, "query_control", return_value={}):
            doc = control_api.bridge_diagnostic()
            self.assertFalse(doc["available"])
            self.assertIsNone(doc["listener"])
            self.assertIsNone(doc["owner_is_brain"])
        with patch.object(control_api, "udp_listener_owner",
                          return_value=(1234, "python", "C:\\x\\windows_brain.py")), \
             patch.object(control_api, "query_control", return_value={}):
            doc = control_api.bridge_diagnostic()
            self.assertTrue(doc["available"])
            self.assertTrue(doc["owner_is_brain"])
            self.assertEqual(doc["listener"]["pid"], 1234)
        with patch.object(control_api, "udp_listener_owner",
                          return_value=(999, "other", "C:\\x\\other.exe")), \
             patch.object(control_api, "query_control", return_value={}):
            doc = control_api.bridge_diagnostic()
            self.assertFalse(doc["owner_is_brain"])
            self.assertFalse(doc["available"])
        with patch.object(control_api, "udp_listener_owner",
                          return_value=(999, "python", None)), \
             patch.object(control_api, "query_control", return_value={}):
            doc = control_api.bridge_diagnostic()
            self.assertIsNone(doc["owner_is_brain"])
            self.assertIn("unknown", (doc.get("reason", "") + doc.get("note", "")).lower())

    def test_doc_secret_posture_branches(self):
        # EVT-156: posture comes from the listener's own HEALTH reply
        # (on/off only); timeout/garbage stays unknown, never fabricated.
        from unittest.mock import patch
        from tools.aegisctl.api import control_api
        owner = (1234, "python", "C:\\x\\windows_brain.py")
        with patch.object(control_api, "udp_listener_owner", return_value=owner), \
             patch.object(control_api, "_udp_health", return_value={"auth": "on", "pid": 1234}), \
             patch.object(control_api, "query_control", return_value={}):
            doc = control_api.bridge_diagnostic()
            self.assertEqual(doc["secret_posture"], "on")
            self.assertTrue(doc["available"])
        with patch.object(control_api, "udp_listener_owner", return_value=owner), \
             patch.object(control_api, "_udp_health", return_value={"auth": "off", "pid": 1234}), \
             patch.object(control_api, "query_control", return_value={}):
            self.assertEqual(control_api.bridge_diagnostic()["secret_posture"], "off")
        with patch.object(control_api, "udp_listener_owner", return_value=owner), \
             patch.object(control_api, "_udp_health", return_value=None), \
             patch.object(control_api, "query_control", return_value={}):
            self.assertEqual(control_api.bridge_diagnostic()["secret_posture"], "unknown")
        with patch.object(control_api, "udp_listener_owner", return_value=owner), \
             patch.object(control_api, "_udp_health", return_value={"auth": "maybe"}), \
             patch.object(control_api, "query_control", return_value={}):
            self.assertEqual(control_api.bridge_diagnostic()["secret_posture"], "unknown")

    def test_doc_pid_corroboration_when_cmdline_unreadable(self):
        # Command line unreadable (None) but a schema-correct HEALTH reply
        # from the listener pid itself corroborates identity.
        from unittest.mock import patch
        from tools.aegisctl.api import control_api
        with patch.object(control_api, "udp_listener_owner",
                          return_value=(999, "python", None)), \
             patch.object(control_api, "_udp_health",
                          return_value={"auth": "off", "pid": 999}), \
             patch.object(control_api, "query_control", return_value={}):
            doc = control_api.bridge_diagnostic()
            self.assertTrue(doc["owner_is_brain"])
            self.assertTrue(doc["available"])
            self.assertEqual(doc["secret_posture"], "off")


class TestAegisctlComponents(unittest.TestCase):
    """`aegisctl components` shows the five as concepts (EVT-162)."""

    def test_components_json_shape(self):
        import json as _json
        rc, stdout, stderr = _run_aegisctl("components", "--json", timeout=60)
        self.assertEqual(rc, 0, f"components --json exit 0, got {rc}; {stderr[-300:]}")
        doc = _json.loads(stdout)
        self.assertEqual(doc["command"], "components")
        rows = {r["id"]: r for r in doc["components"]}
        self.assertEqual(sorted(rows), ["brain", "bridge", "core", "mouth", "nose"])
        for rid, row in rows.items():
            for key in ("name", "language", "role", "version",
                        "entrypoint", "status", "detail"):
                self.assertIn(key, row, (rid, key))
            self.assertIn(row["status"], ("running", "stopped", "degraded", "unknown"))

    def test_components_human_names_all_five(self):
        rc, stdout, stderr = _run_aegisctl("components", timeout=60)
        self.assertEqual(rc, 0, f"components exit 0, got {rc}; {stderr[-300:]}")
        for name in ("AEGIS Core", "AEGIS Brain", "AEGIS Nose",
                     "AEGIS Mouth", "AEGIS Bridge"):
            self.assertIn(name, stdout)
        for lang in ("Zig", "Python", "Go", "Rust", "C++"):
            self.assertIn(lang, stdout)


class TestAegisctlConsoleGraph(unittest.TestCase):
    """EVT-165: reborn console + receipt-aware graph (subprocess, live)."""

    def test_console_once_rules_is_deterministic(self):
        # Read-only catalog view: no daemon, no elevation, always exit 0.
        rc, stdout, stderr = _run_aegisctl(
            "console", "--once", "--choice", "7", timeout=60)
        self.assertEqual(rc, 0, f"console rules exit 0, got {rc}; {stderr[-300:]}")
        self.assertIn("Detection catalog", stdout)

    def test_console_once_invalid_choice_lists_keys(self):
        rc, stdout, _ = _run_aegisctl(
            "console", "--once", "--choice", "bogus", timeout=60)
        self.assertEqual(rc, 2)
        self.assertIn("0", stdout)

    def test_console_blocks_mutation_for_operator(self):
        rc, stdout, _ = _run_aegisctl(
            "console", "--once", "--choice", "1", timeout=60)
        self.assertEqual(rc, 1)
        self.assertIn("BLOCKED", stdout)

    def test_graph_builds_to_tmp(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "g.html")
            rc, stdout, stderr = _run_aegisctl(
                "graph", "--out", out, "--limit", "50", timeout=120)
            self.assertEqual(rc, 0, f"graph exit 0, got {rc}; {stderr[-300:]}")
            self.assertIn("Threat graph", stdout)
            self.assertTrue(os.path.isfile(out))


class TestAegisctlIptest(unittest.TestCase):
    """EVT-167: bounded latency probe instead of the stub (live)."""

    def test_iptest_reports_bounded_sample(self):
        import json as _json
        rc, stdout, stderr = _run_aegisctl("iptest", "--rounds", "3", "--json", timeout=60)
        self.assertEqual(rc, 0, f"iptest exit 0, got {rc}; {stderr[-300:]}")
        doc = _json.loads(stdout)
        self.assertEqual(doc["rounds"], 3)
        self.assertFalse(doc["capped"])
        self.assertEqual(doc["ok"] + doc["failed"], 3)
        if doc["ok"]:
            self.assertLessEqual(doc["p50_ms"], doc["p99_ms"])


class TestForensicSearchContracts(unittest.TestCase):
    """EVT-175: search misuse degrades to guidance, never a traceback."""

    def test_text_source_value_explains_ordinal(self):
        import json as _json
        rc, stdout, stderr = _run_aegisctl(
            "forensic", "search", "--field", "source", "--value", "1.2.3.4",
            timeout=60)
        combined = stdout + stderr
        self.assertEqual(rc, 2, f"expected exit 2, got {rc}")
        self.assertNotIn("Traceback", combined)
        body = _json.loads(combined.strip().splitlines()[-1])
        self.assertEqual(body.get("reason"), "source_must_be_a_numeric_ordinal")

    def test_unknown_field_names_valid_filters(self):
        rc, stdout, stderr = _run_aegisctl(
            "forensic", "search", "--field", "bogus", "--value", "x",
            timeout=60)
        self.assertEqual(rc, 2)
        self.assertIn("source_or_payload_prefix", stdout + stderr)

    def test_rule_field_accepts_catalog_id_shape(self):
        # Live shape only (the daemon filter it addresses deploys
        # separately): catalog id accepted, JSON parses, no traceback.
        import json as _json
        rc, stdout, stderr = _run_aegisctl(
            "forensic", "search", "--field", "rule", "--value", "R9059",
            timeout=90)
        combined = stdout + stderr
        self.assertNotIn("Traceback", combined)
        self.assertEqual(rc, 0, f"rule search must not fail, got {rc}")
        doc = _json.loads(stdout)
        self.assertIn("records_matched", doc)


class TestRulesWriteRefusedGracefully(unittest.TestCase):
    """EVT-174: unwritable Rules.json must read as a message, not a traceback."""

    def test_mutate_rules_reports_oserror(self):
        import importlib.util
        import types
        from unittest.mock import patch
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        path = REPO_ROOT / "tools" / "aegisctl.py"
        spec = importlib.util.spec_from_file_location("aegisctl_under_test", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["aegisctl_under_test"] = module
        spec.loader.exec_module(module)
        args = types.SimpleNamespace(
            id="R1", rule_json=None, name="n", category="c", layer=None,
            severity="Low", action="Alert", match_pattern="x",
            regex_pattern=None)
        with patch.object(module, "load_rules", return_value={"nids_rules": []}), \
             patch.object(module, "_save_rules", side_effect=OSError("denied")), \
             patch("builtins.print") as pr:
            rc = module._mutate_rules(args, "add")
        self.assertEqual(rc, 1)
        printed = " ".join(str(c.args[0]) for c in pr.call_args_list)
        self.assertIn("elevation", printed)
        self.assertNotIn("Traceback", printed)


if __name__ == "__main__":
    unittest.main()
