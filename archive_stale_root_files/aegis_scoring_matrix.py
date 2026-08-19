"""
aegis_scoring_matrix.py — AEGIS NIDS Deterministic Scoring Matrix (Layer 4: Python)

Replaces ML/AI with 100% deterministic rule-based scoring.
Every test case has a defined input → expected output mapping.

Scoring Architecture:
  - Each rule has: condition + score_points + severity_threshold
  - Total threat score = sum of all matching rule scores (capped at 100)
  - Severity = max severity among all matching rules
  - Cross-vector bonuses: Network+Pipe, Network+File, Triple (from Rust)

This guarantees:
  - 100% reproducible results (no randomness)
  - Full control over false positive/negative rates
  - Audit trail: every score decision is traceable to specific rules
"""

import json
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.scoring")

# ─── Severity Levels ───
class Severity(IntEnum):
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

# ─── Event Vector ───
class EventVector(IntEnum):
    NETWORK = 0
    FILE    = 1
    PIPE    = 2

# ─── Scoring Rule ───
@dataclass
class ScoringRule:
    id: int
    name: str
    category: str           # "network", "pipe", "file", "cross_vector", "signature"
    condition_type: str     # "regex", "port", "ip_blacklist", "pipe_name", "cross_vector", "entropy"
    condition_value: str    # The value to match (regex pattern, port number, etc.)
    score: float            # Points added when condition matches [0.0, 100.0]
    severity: Severity      # Minimum severity if this rule matches
    description: str = ""
    enabled: bool = True

# ─── Scoring Result ───
@dataclass
class ScoringResult:
    threat_score: float = 0.0       # [0.0, 100.0]
    severity: Severity = Severity.INFO
    matched_rules: list = field(default_factory=list)  # (rule_id, rule_name, score)
    action: str = "pass"            # "pass", "alert", "alert_preserve", "block_preserve"
    cross_vector_bonus: float = 0.0 # Extra score from cross-vector correlation
    confidence: float = 0.0         # [0.0, 1.0]

# ─── Deterministic Scoring Matrix ───
class ScoringMatrix:
    """
    Deterministic rule-based scoring engine.
    Every packet/event is scored by running through all rules.
    The total score determines the action taken.

    Score Thresholds:
      0-19:   Pass (no alert)
      20-49:  Alert (log + notify)
      50-79:  Alert + Preserve (forensic hash)
      80-100: Block + Preserve (immediate action)
    """

    def __init__(self):
        self.rules: dict[int, ScoringRule] = {}
        self._load_default_rules()

    def _load_default_rules(self):
        """Load built-in deterministic scoring rules."""
        defaults = [
            # ── Network Rules ──
            ScoringRule(101, "SQL Injection", "network", "regex",
                       r"(?i)union\s+(all\s+)?select", 50.0, Severity.CRITICAL,
                       "SQL injection via UNION SELECT"),
            ScoringRule(102, "XSS Script Tag", "network", "regex",
                       r"(?i)<script[^>]*>", 35.0, Severity.HIGH,
                       "Cross-site scripting via script tag"),
            ScoringRule(103, "Path Traversal", "network", "regex",
                       r"\.\./\.\./etc/passwd", 50.0, Severity.CRITICAL,
                       "Path traversal targeting /etc/passwd"),
            ScoringRule(104, "Command Injection", "network", "regex",
                       r"(?i)cmd\.exe|powershell\.exe|bash\s+-c", 50.0, Severity.CRITICAL,
                       "OS command injection"),
            ScoringRule(105, "C2 Beacon Pattern", "network", "regex",
                       r"(?i)POST\s+/(gate|beacon|checkin|submit)", 45.0, Severity.HIGH,
                       "HTTP C2 beacon check-in"),
            ScoringRule(106, "Suspicious Port", "network", "port",
                       "4444,5555,6666,6667,31337", 15.0, Severity.MEDIUM,
                       "Connection to/from known suspicious port"),
            ScoringRule(107, "Blacklisted IP", "network", "ip_blacklist",
                       "", 30.0, Severity.HIGH,
                       "Connection from/to known malicious IP"),

            # ── Named Pipe Rules ──
            ScoringRule(201, "Cobalt Strike Pipe", "pipe", "pipe_name",
                       r"(?i)\\pipe\\(msagent|mserv|postex_|mojo\.|status_)",
                       60.0, Severity.CRITICAL,
                       "Cobalt Strike named pipe detected"),
            ScoringRule(202, "Meterpreter Pipe", "pipe", "pipe_name",
                       r"(?i)\\pipe\\(msf|meterpreter)",
                       55.0, Severity.CRITICAL,
                       "Meterpreter named pipe detected"),
            ScoringRule(203, "Generic Backdoor Pipe", "pipe", "pipe_name",
                       r"(?i)\\pipe\\(backdoor|c2|remote|cmd)",
                       40.0, Severity.HIGH,
                       "Generic backdoor/C2 named pipe"),
            ScoringRule(204, "Cross-Process Pipe", "pipe", "cross_vector",
                       "cross_process_pipe", 25.0, Severity.HIGH,
                       "Different PID connected to pipe vs creator"),

            # ── Cross-Vector Correlation Rules (bonus scores) ──
            ScoringRule(301, "Network + Pipe (Lateral Movement)", "cross_vector", "cross_vector",
                       "network_and_pipe", 60.0, Severity.CRITICAL,
                       "Network anomaly + suspicious pipe = lateral movement"),
            ScoringRule(302, "Network + File (Data Exfil)", "cross_vector", "cross_vector",
                       "network_and_file", 45.0, Severity.HIGH,
                       "Network anomaly + suspicious file = data exfiltration"),
            ScoringRule(303, "Triple Vector (Full Chain)", "cross_vector", "cross_vector",
                       "triple_vector", 85.0, Severity.CRITICAL,
                       "All 3 vectors suspicious = full attack chain"),
            ScoringRule(304, "Cobalt Strike Full Pattern", "cross_vector", "cross_vector",
                       "cobalt_strike_pattern", 90.0, Severity.CRITICAL,
                       "CS pipe + network beacon = confirmed Cobalt Strike"),

            # ── File Rules ──
            ScoringRule(401, "PE Executable Write", "file", "regex",
                       r"\x4d\x5a", 30.0, Severity.HIGH,
                       "PE executable (MZ header) written to disk"),
            ScoringRule(402, "Sensitive File Access", "file", "regex",
                       r"(?i)(sam|ntds\.dit|shadow|passwd|hosts)$", 25.0, Severity.HIGH,
                       "Access to sensitive system files"),
        ]

        for rule in defaults:
            self.rules[rule.id] = rule

    def load_from_file(self, path: Path) -> int:
        """Load additional scoring rules from JSON file."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        count = 0
        for rd in data.get("scoring_rules", []):
            rule = ScoringRule(
                id=rd["id"], name=rd["name"], category=rd["category"],
                condition_type=rd["condition_type"],
                condition_value=rd.get("condition_value", ""),
                score=float(rd.get("score", 10.0)),
                severity=Severity(rd.get("severity", 2)),
                description=rd.get("description", ""),
                enabled=rd.get("enabled", True),
            )
            self.rules[rule.id] = rule
            count += 1
        logger.info(f"Loaded {count} scoring rules from {path}")
        return count

    def score_event(self, event_ctx: dict) -> ScoringResult:
        """
        Score an event against all rules. Deterministic: same input → same output.

        event_ctx keys:
          - vector: EventVector
          - payload: bytes
          - src_ip, dst_ip: int
          - src_port, dst_port: int
          - pipe_name: str (for pipe events)
          - risk_flags: int
          - suspicious_network: bool (from Rust correlation)
          - suspicious_pipe: bool (from Rust correlation)
          - suspicious_file: bool (from Rust correlation)
          - cross_process_pipe: bool (from Rust correlation)
        """
        result = ScoringResult()
        import re

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            matched = False

            if rule.condition_type == "regex":
                payload = event_ctx.get("payload", b"")
                if isinstance(payload, bytes):
                    try:
                        if re.search(rule.condition_value, payload, re.IGNORECASE | re.DOTALL):
                            matched = True
                    except re.error:
                        continue

            elif rule.condition_type == "port":
                suspicious_ports = {int(p) for p in rule.condition_value.split(",") if p.strip()}
                src_port = event_ctx.get("src_port", 0)
                dst_port = event_ctx.get("dst_port", 0)
                if src_port in suspicious_ports or dst_port in suspicious_ports:
                    matched = True

            elif rule.condition_type == "ip_blacklist":
                blacklist = event_ctx.get("ip_blacklist", set())
                src_ip = event_ctx.get("src_ip", 0)
                dst_ip = event_ctx.get("dst_ip", 0)
                if src_ip in blacklist or dst_ip in blacklist:
                    matched = True

            elif rule.condition_type == "pipe_name":
                pipe_name = event_ctx.get("pipe_name", "")
                if pipe_name:
                    try:
                        if re.search(rule.condition_value, pipe_name, re.IGNORECASE):
                            matched = True
                    except re.error:
                        continue

            elif rule.condition_type == "cross_vector":
                cv_key = rule.condition_value
                if cv_key == "cross_process_pipe" and event_ctx.get("cross_process_pipe", False):
                    matched = True
                elif cv_key == "network_and_pipe" and event_ctx.get("suspicious_network", False) and event_ctx.get("suspicious_pipe", False):
                    matched = True
                elif cv_key == "network_and_file" and event_ctx.get("suspicious_network", False) and event_ctx.get("suspicious_file", False):
                    matched = True
                elif cv_key == "triple_vector" and event_ctx.get("suspicious_network", False) and event_ctx.get("suspicious_pipe", False) and event_ctx.get("suspicious_file", False):
                    matched = True
                elif cv_key == "cobalt_strike_pattern" and event_ctx.get("suspicious_pipe", False) and event_ctx.get("suspicious_network", False):
                    matched = True

            if matched:
                result.matched_rules.append((rule.id, rule.name, rule.score))
                result.threat_score += rule.score
                if rule.severity > result.severity:
                    result.severity = rule.severity

        # Cap at 100
        result.threat_score = min(result.threat_score, 100.0)

        # Determine action
        if result.threat_score >= 80.0:
            result.action = "block_preserve"
        elif result.threat_score >= 50.0:
            result.action = "alert_preserve"
        elif result.threat_score >= 20.0:
            result.action = "alert"
        else:
            result.action = "pass"

        # Compute confidence
        if result.matched_rules:
            result.confidence = min(0.5 + len(result.matched_rules) * 0.1, 1.0)
        else:
            result.confidence = 0.1

        return result

    def validate_test_case(self, test_case: dict) -> dict:
        """
        Validate a test case: run scoring and verify expected outcome.

        test_case format:
          {
            "name": "SQL Injection detection",
            "input": { "vector": 0, "payload": "...", ... },
            "expected": {
              "min_score": 40.0,
              "min_severity": 3,
              "action": "alert_preserve",
              "must_match_rule_ids": [101]
            }
          }

        Returns: {"passed": bool, "actual": ScoringResult, "failures": [...]}
        """
        result = self.score_event(test_case["input"])
        expected = test_case["expected"]
        failures = []

        if result.threat_score < expected.get("min_score", 0):
            failures.append(f"Score {result.threat_score} < expected {expected['min_score']}")

        if result.severity < Severity(expected.get("min_severity", 0)):
            failures.append(f"Severity {result.severity} < expected {expected['min_severity']}")

        expected_action = expected.get("action", "pass")
        if result.action != expected_action and expected_action != "any_alert":
            if expected_action == "any_alert" and result.action not in ("alert", "alert_preserve", "block_preserve"):
                failures.append(f"Action {result.action} != expected {expected_action}")

        for rule_id in expected.get("must_match_rule_ids", []):
            matched_ids = {r[0] for r in result.matched_rules}
            if rule_id not in matched_ids:
                failures.append(f"Expected rule {rule_id} not matched")

        return {
            "passed": len(failures) == 0,
            "actual_score": result.threat_score,
            "actual_severity": int(result.severity),
            "actual_action": result.action,
            "matched_rules": result.matched_rules,
            "failures": failures,
        }
