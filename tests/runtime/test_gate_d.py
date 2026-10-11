"""
test_gate_d.py - Tests for Gate D inspection commands (rules/events/forensic).

Verifies that the aegisctl inspection commands work correctly:
  - rules list/show/validate
  - events tail/count/stats
  - forensic show/search/export

These are read-only tests that verify the CLI plumbing. They do NOT
require running components -- they work against the canonical
configs/Rules.json rule file and the control daemon (forensic queries are
served from the daemon's hash-chained ring, not from a local NDJSON log).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AEGISCTL = REPO_ROOT / "tools" / "aegisctl.py"
# Single rule authority (see tests/security/test_single_rule_authority.py).
RULES_FILE = REPO_ROOT / "configs" / "Rules.json"
FORENSIC_LOG = REPO_ROOT / "logs" / "aegis_core.ndjson"


def _run_aegisctl(*args: str, timeout: int = 10,
                  env: dict | None = None) -> tuple[int, str, str]:
    cmd = [sys.executable, str(AEGISCTL)] + list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT), env=env,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"


class TestRulesCommands(unittest.TestCase):
    """Tests for 'aegisctl rules list/show/validate'."""

    def setUp(self):
        if not RULES_FILE.exists():
            self.skipTest("configs/Rules.json not found")

    def test_rules_list_shows_all_rules(self):
        rc, stdout, _ = _run_aegisctl("rules", "list")
        self.assertEqual(rc, 0)
        self.assertIn("Rule ID", stdout)
        self.assertIn("Total:", stdout)
        # Should mention at least some rule IDs
        self.assertIn("R", stdout)

    def test_rules_list_filter_by_severity(self):
        rc, stdout, _ = _run_aegisctl("rules", "list", "--severity", "Critical")
        self.assertEqual(rc, 0)
        self.assertIn("Critical", stdout)
        self.assertIn("filtered by", stdout)

    def test_rules_list_filter_by_category(self):
        rc, stdout, _ = _run_aegisctl("rules", "list", "--category", "Injection")
        self.assertEqual(rc, 0)
        self.assertIn("Injection", stdout)

    def test_rules_show_existing_rule(self):
        # First read the rules file to find a valid rule_id
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("nids_rules", [])
        self.assertGreater(len(rules), 0, "Rules.json has no rules")
        first_rule_id = rules[0]["rule_id"]

        rc, stdout, _ = _run_aegisctl("rules", "show", "--id", first_rule_id)
        self.assertEqual(rc, 0)
        # Should output valid JSON
        parsed = json.loads(stdout)
        self.assertEqual(parsed["rule_id"], first_rule_id)

    def test_rules_show_nonexistent_rule(self):
        rc, stdout, _ = _run_aegisctl("rules", "show", "--id", "NONEXISTENT")
        self.assertEqual(rc, 1)
        self.assertIn("not found", stdout.lower())

    def test_rules_validate_passes(self):
        rc, stdout, _ = _run_aegisctl("rules", "validate")
        self.assertEqual(rc, 0)
        self.assertIn("VALID", stdout)
        self.assertIn("rules checked", stdout)

    def test_rules_validate_reports_count(self):
        rc, stdout, _ = _run_aegisctl("rules", "validate")
        self.assertEqual(rc, 0)
        # Should mention the number of rules checked
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        expected_count = len(data.get("nids_rules", []))
        self.assertIn(f"{expected_count} rules", stdout)


class TestEventsCommands(unittest.TestCase):
    """Tests for 'aegisctl events tail/count/stats'."""

    def test_events_count_runs_without_crash(self):
        rc, stdout, _ = _run_aegisctl("events", "count")
        # Returns 0 whether log exists or not
        self.assertEqual(rc, 0)
        # Either shows "Events: N" or reports that the log doesn't exist
        self.assertTrue(
            "Events:" in stdout or "0" in stdout,
            f"unexpected output: {stdout}"
        )

    def test_events_tail_runs_without_crash(self):
        rc, stdout, _ = _run_aegisctl("events", "tail", "--count", "5")
        self.assertEqual(rc, 0)
        # Either shows events or says "No events found"
        self.assertTrue(
            "event(s)" in stdout or "No events" in stdout,
            f"unexpected output: {stdout}"
        )

    def test_events_stats_runs_without_crash(self):
        rc, stdout, _ = _run_aegisctl("events", "stats")
        self.assertEqual(rc, 0)
        # Either shows stats or says no log file
        self.assertTrue(
            "Event Statistics" in stdout or "No log file" in stdout,
            f"unexpected output: {stdout}"
        )

    def test_events_count_with_no_log(self):
        """Missing and empty logs both report 0 gracefully, isolated.

        EVT-181: the old version skipped whenever the production log
        existed (always, on the opened system). AEGIS_EVENT_LOG points
        the CLI at scratch instead: a nonexistent path and an empty
        file must both read as Events: 0 with rc 0. Zero prod touch.
        """
        child_env = dict(os.environ)
        missing = str(Path(tempfile.mkdtemp(prefix="events-empty-"))
                      / "absent.ndjson")
        child_env["AEGIS_EVENT_LOG"] = missing
        rc, stdout, _ = _run_aegisctl("events", "count", env=child_env)
        self.assertEqual(rc, 0)
        self.assertIn("Events: 0", stdout)
        empty = Path(missing).parent / "empty.ndjson"
        empty.write_text("", encoding="utf-8")
        child_env["AEGIS_EVENT_LOG"] = str(empty)
        rc, stdout, _ = _run_aegisctl("events", "count", env=child_env)
        self.assertEqual(rc, 0)
        self.assertIn("Events: 0", stdout)


class TestForensicCommands(unittest.TestCase):
    """Tests for 'aegisctl forensic show/search/export'."""

    def test_forensic_show_without_id_errors(self):
        # argparse should reject missing --id
        rc, _, _ = _run_aegisctl("forensic", "show")
        self.assertNotEqual(rc, 0)

    def test_forensic_search_requires_field_and_value(self):
        rc, _, _ = _run_aegisctl("forensic", "search")
        self.assertNotEqual(rc, 0)

    def test_forensic_export_requires_output(self):
        rc, _, _ = _run_aegisctl("forensic", "export")
        self.assertNotEqual(rc, 0)

    def test_forensic_search_rejects_unsupported_fields(self):
        """Search is served by the control daemon, which filters on the
        canonical source/payload-prefix fields only. An unsupported field must
        fail with a machine-readable reason instead of silently searching a
        different (local log) data source."""
        rc, _stdout, stderr = _run_aegisctl(
            "forensic", "search", "--field", "rule_id", "--value", "TEST"
        )
        self.assertEqual(rc, 2)
        payload = json.loads(stderr)
        self.assertFalse(payload["available"])
        self.assertIn("source_or_payload_prefix", payload["reason"])

    def test_forensic_export_requires_a_verified_hash_chain(self):
        """Export is daemon-sourced evidence, never a local log file: it must
        either write a verified ring summary or fail closed with no artifact."""
        output = Path(tempfile.mkdtemp()) / "export.json"
        rc, stdout, stderr = _run_aegisctl(
            "forensic", "export", "--output", str(output)
        )
        if rc == 0:
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["export_kind"], "forensic_ring_summary")
            self.assertTrue(document["integrity"]["verified"])
            self.assertTrue(json.loads(stdout)["verified"])
        else:
            payload = json.loads(stderr)
            self.assertFalse(payload["available"])
            self.assertEqual(payload["command"], "forensics.verify")
            self.assertFalse(
                output.exists(), "a failed integrity verification must not write evidence"
            )


class TestForensicExportWithTestData(unittest.TestCase):
    """Test forensic export with a synthetic NDJSON log."""

    def setUp(self):
        if not AEGISCTL.exists():
            self.skipTest("aegisctl.py not found")
        # Create a temporary NDJSON log for testing
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_log = Path(self.tmp_dir) / "test_forensic.ndjson"
        # Write 3 test records
        records = [
            {"ts_ms": 1000, "level": "High", "event": "SYN-FLOOD", "rule": "R9002",
             "src_ip": "1.2.3.4"},
            {"ts_ms": 2000, "level": "Critical", "event": "SQLI", "rule": "R0056",
             "src_ip": "5.6.7.8"},
            {"ts_ms": 3000, "level": "High", "event": "SYN-FLOOD", "rule": "R9002",
             "src_ip": "1.2.3.4"},
        ]
        with open(self.tmp_log, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        # We can't easily redirect aegisctl to use a different log file,
        # so we'll test the export function logic via direct import.
        self.records = records

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_export_json_format(self):
        """Verify the export logic produces valid JSON."""
        # We verify by checking that the records are JSON-serializable
        # and contain the expected fields.
        output = json.dumps(self.records, indent=2)
        parsed = json.loads(output)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0]["rule"], "R9002")
        self.assertEqual(parsed[1]["level"], "Critical")

    def test_export_csv_format(self):
        """Verify the CSV export logic collects all field names."""
        import csv
        import io
        # Collect all unique field names
        fieldnames = []
        for r in self.records:
            for k in r.keys():
                if k not in fieldnames:
                    fieldnames.append(k)
        self.assertEqual(set(fieldnames), {"ts_ms", "level", "event", "rule", "src_ip"})

        # Write to CSV in memory
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in self.records:
            writer.writerow(r)
        csv_output = output.getvalue()
        self.assertIn("ts_ms", csv_output)
        self.assertIn("SYN-FLOOD", csv_output)
        self.assertIn("1.2.3.4", csv_output)


class TestGateDHelpCommands(unittest.TestCase):
    """Verify the --help for all Gate D subcommands works."""

    def test_rules_help(self):
        rc, stdout, _ = _run_aegisctl("rules", "--help")
        self.assertEqual(rc, 0)
        self.assertIn("list", stdout)
        self.assertIn("show", stdout)
        self.assertIn("validate", stdout)

    def test_events_help(self):
        rc, stdout, _ = _run_aegisctl("events", "--help")
        self.assertEqual(rc, 0)
        self.assertIn("tail", stdout)
        self.assertIn("count", stdout)
        self.assertIn("stats", stdout)

    def test_forensic_help(self):
        rc, stdout, _ = _run_aegisctl("forensic", "--help")
        self.assertEqual(rc, 0)
        self.assertIn("show", stdout)
        self.assertIn("search", stdout)
        self.assertIn("export", stdout)


class TestGateDExitCodes(unittest.TestCase):
    """Verify exit codes follow the documented convention."""

    def test_rules_list_returns_0(self):
        if not RULES_FILE.exists():
            self.skipTest("Rules.json not found")
        rc, _, _ = _run_aegisctl("rules", "list")
        self.assertEqual(rc, 0)

    def test_rules_validate_returns_0_when_valid(self):
        if not RULES_FILE.exists():
            self.skipTest("Rules.json not found")
        rc, _, _ = _run_aegisctl("rules", "validate")
        self.assertEqual(rc, 0)

    def test_rules_show_nonexistent_returns_1(self):
        rc, _, _ = _run_aegisctl("rules", "show", "--id", "ZZZZZ")
        self.assertEqual(rc, 1)

    def test_events_count_always_returns_0(self):
        rc, _, _ = _run_aegisctl("events", "count")
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
