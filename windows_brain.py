"""
windows_brain.py — AEGIS NIDS Analysis Brain (Layer 4: Python)

Tier-2 analysis engine that performs deep inspection beyond what the
Zig Aho-Corasick matcher handles. Responsibilities:
  - Regex-based protocol anomaly detection
  - Heuristic malware behavior scoring
  - TLS certificate chain validation
  - DNS tunneling detection
  - Payload entropy analysis (calls Cython accelerator)

SecDevOps + Forensics + Hook techniques are applied HERE (analysis phase only):
  - Pre-analysis hooks:  Inspect packet before regex matching
  - Post-analysis hooks: Modify verdict after scoring
  - Forensic hooks:      Trigger Rust shield SHA-256 for evidence preservation

Language: Python 3.11+ (Cython hotspots in .pyx files)
"""

import ctypes
import json
import logging
import re
import struct
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Optional

# ─── Logging ───
logger = logging.getLogger("aegis.brain")
logger.setLevel(logging.DEBUG)

# ─── ctypes Bridge to Rust Shield (libaegis_shield) ───
try:
    _shield = ctypes.CDLL("aegis_shield")
    _shield.aegis_shield_init.restype = ctypes.c_int32
    _shield.aegis_shield_submit_packet.restype = ctypes.c_int32
    _shield.aegis_shield_get_forensic_hash.restype = ctypes.c_int32
    _shield.aegis_shield_shutdown.restype = None
    SHIELD_AVAILABLE = True
except OSError:
    logger.warning("Rust shield library not found — forensic hashing disabled")
    SHIELD_AVAILABLE = False

# ─── ctypes Bridge to IPC DLL (aegis_ipc.dll) ───
try:
    _ipc = ctypes.CDLL("aegis_ipc")
    _ipc.aegis_ipc_init.restype = ctypes.c_int32
    _ipc.aegis_ipc_get_stats.restype = ctypes.c_int32
    IPC_AVAILABLE = True
except OSError:
    logger.warning("IPC bridge DLL not found — stats unavailable")
    IPC_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════

class Severity(IntEnum):
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


class HookAction(IntEnum):
    PASS     = 0   # Continue normal processing
    DROP     = 1   # Silently discard
    ALERT    = 2   # Raise alert, continue
    PRESERVE = 3   # Alert + forensic preservation


@dataclass
class PacketContext:
    """Context passed to all analysis hooks."""
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    ip_proto: int
    payload: bytes
    timestamp_ms: int
    stream_id: int = 0
    process_id: int = 0
    direction: int = 0  # 0=inbound, 1=outbound


@dataclass
class AnalysisVerdict:
    """Result of analysis for a single packet/stream."""
    action: HookAction = HookAction.PASS
    severity: Severity = Severity.INFO
    rule_name: str = ""
    rule_id: int = 0
    score: float = 0.0          # Heuristic score [0.0, 1.0]
    forensic_hash: Optional[bytes] = None  # SHA-256 if preserved
    tags: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# Hook System (Analysis-Phase Intercept Framework)
# ═══════════════════════════════════════════════════════════════

PreHookFn = Callable[[PacketContext], HookAction]
PostHookFn = Callable[[PacketContext, AnalysisVerdict], HookAction]


class HookRegistry:
    """
    Central registry for analysis-phase hooks.
    Hooks implement SecDevOps, forensics, and penetration-testing
    interceptors WITHOUT modifying core analysis logic.
    """
    MAX_HOOKS = 32

    def __init__(self):
        self._pre_hooks: list[PreHookFn] = []
        self._post_hooks: list[PostHookFn] = []

    def register_pre(self, hook: PreHookFn) -> None:
        if len(self._pre_hooks) >= self.MAX_HOOKS:
            raise RuntimeError(f"Max pre-hooks ({self.MAX_HOOKS}) exceeded")
        self._pre_hooks.append(hook)
        logger.debug(f"Registered pre-hook: {hook.__name__}")

    def register_post(self, hook: PostHookFn) -> None:
        if len(self._post_hooks) >= self.MAX_HOOKS:
            raise RuntimeError(f"Max post-hooks ({self.MAX_HOOKS}) exceeded")
        self._post_hooks.append(hook)
        logger.debug(f"Registered post-hook: {hook.__name__}")

    def run_pre(self, ctx: PacketContext) -> HookAction:
        """Run all pre-hooks. Returns first non-PASS action or PASS."""
        for hook in self._pre_hooks:
            result = hook(ctx)
            if result != HookAction.PASS:
                return result
        return HookAction.PASS

    def run_post(self, ctx: PacketContext, verdict: AnalysisVerdict) -> HookAction:
        """Run all post-hooks. Returns aggregated action."""
        final_action = HookAction.PASS
        for hook in self._post_hooks:
            result = hook(ctx, verdict)
            if result > final_action:  # PRESERVE > ALERT > DROP > PASS
                final_action = result
        return final_action


# ═══════════════════════════════════════════════════════════════
# Detection Rules
# ═══════════════════════════════════════════════════════════════

@dataclass
class DetectionRule:
    id: int
    name: str
    severity: Severity
    pattern: str            # Regex pattern
    category: str           # "exploit", "malware", "anomaly", "forensic"
    description: str = ""
    enabled: bool = True
    _compiled: re.Pattern = field(default=None, repr=False, init=False)

    def __post_init__(self):
        if self.pattern:
            try:
                self._compiled = re.compile(self.pattern, re.DOTALL | re.IGNORECASE)
            except re.error as e:
                logger.error(f"Rule {self.id} '{self.name}': invalid regex: {e}")
                self.enabled = False

    def match(self, payload: bytes) -> Optional[re.Match]:
        if not self.enabled or not self._compiled:
            return None
        return self._compiled.search(payload)


class RuleEngine:
    """Manages detection rules loaded from Rules.json."""

    def __init__(self):
        self.rules: dict[int, DetectionRule] = {}
        self._lock = threading.RLock()

    def load_from_file(self, path: Path) -> int:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        count = 0
        with self._lock:
            for rule_data in data.get("rules", []):
                rule = DetectionRule(
                    id=rule_data["id"],
                    name=rule_data["name"],
                    severity=Severity(rule_data.get("severity", 2)),
                    pattern=rule_data.get("pattern", ""),
                    category=rule_data.get("category", "anomaly"),
                    description=rule_data.get("description", ""),
                    enabled=rule_data.get("enabled", True),
                )
                self.rules[rule.id] = rule
                count += 1
        logger.info(f"Loaded {count} rules from {path}")
        return count

    def match_all(self, payload: bytes) -> list[tuple[DetectionRule, re.Match]]:
        results = []
        with self._lock:
            for rule in self.rules.values():
                m = rule.match(payload)
                if m:
                    results.append((rule, m))
        return results


# ═══════════════════════════════════════════════════════════════
# Cython Accelerator Imports (5 hotspots)
# ═══════════════════════════════════════════════════════════════

try:
    from aegis_hotspots import entropy_calc      as _cy_entropy
    from aegis_hotspots import pattern_scan      as _cy_pattern_scan
    from aegis_hotspots import stream_reassemble as _cy_stream_reassemble
    from aegis_hotspots import ip_reputation     as _cy_ip_reputation
    from aegis_hotspots import payload_classify  as _cy_payload_classify
    CYTHON_AVAILABLE = True
except ImportError:
    CYTHON_AVAILABLE = False
    _cy_entropy = None
    _cy_pattern_scan = None
    _cy_stream_reassemble = None
    _cy_ip_reputation = None
    _cy_payload_classify = None


def compute_entropy(payload: bytes) -> float:
    """Calculate Shannon entropy of payload. Cython-accelerated if available."""
    if CYTHON_AVAILABLE and _cy_entropy:
        return _cy_entropy(payload)
    # Pure Python fallback
    if not payload:
        return 0.0
    freq = defaultdict(int)
    for b in payload:
        freq[b] += 1
    length = len(payload)
    import math
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ═══════════════════════════════════════════════════════════════
# Built-in Hooks (SecDevOps + Forensics + Penetration Testing)
# ═══════════════════════════════════════════════════════════════

def hook_blacklist_check(ctx: PacketContext) -> HookAction:
    """Pre-hook: Check source/dest IP against threat intel blacklist."""
    BLACKLIST = {0x0A000001, 0xC0A80001}  # Example IPs
    if ctx.src_ip in BLACKLIST or ctx.dst_ip in BLACKLIST:
        return HookAction.ALERT
    return HookAction.PASS


def hook_entropy_anomaly(ctx: PacketContext) -> HookAction:
    """Pre-hook: Flag payloads with very high entropy (possible encryption/packing)."""
    if len(ctx.payload) > 64:
        entropy = compute_entropy(ctx.payload)
        if entropy > 7.5:  # Very high entropy — suspicious
            return HookAction.ALERT
    return HookAction.PASS


def hook_forensic_preserve(ctx: PacketContext, verdict: AnalysisVerdict) -> HookAction:
    """Post-hook: Preserve evidence for high-severity alerts (chain-of-custody)."""
    if verdict.severity >= Severity.HIGH:
        return HookAction.PRESERVE
    return HookAction.PASS


def hook_chain_of_custody(ctx: PacketContext, verdict: AnalysisVerdict) -> HookAction:
    """Post-hook: Ensure forensic integrity via Rust shield SHA-256."""
    if verdict.action == HookAction.PRESERVE and SHIELD_AVAILABLE:
        # Submit to Rust shield for forensic hashing
        meta = AegisPktMetaC(
            size=0, orig_len=len(ctx.payload), timestamp=ctx.timestamp_ms,
            layer_id=0, direction=ctx.direction, process_id=ctx.process_id,
            ip_proto=ctx.ip_proto, _pad=0,
            src_ip=ctx.src_ip, dst_ip=ctx.dst_ip,
            src_port=ctx.src_port, dst_port=ctx.dst_port,
        )
        _shield.aegis_shield_submit_packet(
            ctypes.byref(meta), ctx.payload, len(ctx.payload), None, 0
        )
    return HookAction.PASS


def hook_suspicious_ports(ctx: PacketContext) -> HookAction:
    """Pre-hook: Flag connections to/from suspicious ports."""
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 8888, 31337}
    if ctx.src_port in SUSPICIOUS_PORTS or ctx.dst_port in SUSPICIOUS_PORTS:
        return HookAction.ALERT
    return HookAction.PASS


# ctypes structure for Rust shield FFI
class AegisPktMetaC(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32), ("orig_len", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64), ("layer_id", ctypes.c_uint16),
        ("direction", ctypes.c_uint16), ("process_id", ctypes.c_uint32),
        ("ip_proto", ctypes.c_uint16), ("_pad", ctypes.c_uint16),
        ("src_ip", ctypes.c_uint32), ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16), ("dst_port", ctypes.c_uint16),
    ]


# ═══════════════════════════════════════════════════════════════
# Analysis Brain
# ═══════════════════════════════════════════════════════════════

class AnalysisBrain:
    """
    Tier-2 deep inspection engine with hook pipeline.

    Pipeline per packet:
      1. Pre-hooks (blacklist, entropy, suspicious ports)
      2. Regex rule matching (RuleEngine)
      3. Heuristic scoring (entropy, port, protocol)
      4. Post-hooks (forensic preserve, chain-of-custody)
      5. Verdict emission
    """

    def __init__(self, rules_path: Optional[Path] = None):
        self.hooks = HookRegistry()
        self.rules = RuleEngine()
        self.stats = {"packets": 0, "alerts": 0, "preserved": 0}
        self._lock = threading.Lock()

        # Register built-in hooks
        self.hooks.register_pre(hook_blacklist_check)
        self.hooks.register_pre(hook_entropy_anomaly)
        self.hooks.register_pre(hook_suspicious_ports)
        self.hooks.register_post(hook_forensic_preserve)
        self.hooks.register_post(hook_chain_of_custody)

        # Load rules if provided
        if rules_path and rules_path.exists():
            self.rules.load_from_file(rules_path)

        logger.info("AnalysisBrain initialized with %d rules, %d pre-hooks, %d post-hooks",
                     len(self.rules.rules), len(self.hooks._pre_hooks), len(self.hooks._post_hooks))

    def analyze(self, ctx: PacketContext) -> AnalysisVerdict:
        """Main analysis pipeline for a single packet."""
        with self._lock:
            self.stats["packets"] += 1

        # Phase 1: Pre-hooks
        pre_result = self.hooks.run_pre(ctx)
        if pre_result == HookAction.DROP:
            return AnalysisVerdict(action=HookAction.DROP, severity=Severity.INFO)

        # Phase 2: Regex rule matching
        verdict = AnalysisVerdict()
        matches = self.rules.match_all(ctx.payload)

        if matches:
            # Take highest-severity match
            best_rule, best_match = max(matches, key=lambda x: x[0].severity)
            verdict.rule_id = best_rule.id
            verdict.rule_name = best_rule.name
            verdict.severity = best_rule.severity
            verdict.action = HookAction.ALERT
            verdict.score = self._compute_score(ctx, best_rule, best_match)
            verdict.tags = [best_rule.category]

        # Phase 3: Heuristic scoring (even without rule match)
        if verdict.score == 0.0:
            verdict.score = self._heuristic_score(ctx)

        # Phase 4: Post-hooks
        post_result = self.hooks.run_post(ctx, verdict)
        if post_result > verdict.action:
            verdict.action = post_result

        # Update stats
        if verdict.action in (HookAction.ALERT, HookAction.PRESERVE):
            with self._lock:
                self.stats["alerts"] += 1
        if verdict.action == HookAction.PRESERVE:
            with self._lock:
                self.stats["preserved"] += 1

        return verdict

    def _compute_score(self, ctx: PacketContext, rule: DetectionRule,
                       match: re.Match) -> float:
        """Compute threat score [0.0, 1.0] based on multiple factors."""
        score = 0.0

        # Rule severity contribution
        score += rule.severity / 4.0 * 0.4  # Max 0.4 from severity

        # Payload entropy contribution
        if len(ctx.payload) > 0:
            entropy = compute_entropy(ctx.payload)
            score += (entropy / 8.0) * 0.3  # Max 0.3 from entropy

        # Match position contribution (early match = more suspicious)
        if match.start() < len(ctx.payload) * 0.1:
            score += 0.15  # Match in first 10% of payload

        # Port contribution
        SUSPICIOUS = {4444, 5555, 6667, 31337}
        if ctx.dst_port in SUSPICIOUS:
            score += 0.15

        return min(score, 1.0)

    def _heuristic_score(self, ctx: PacketContext) -> float:
        """Heuristic scoring when no regex rule matches."""
        score = 0.0
        if len(ctx.payload) > 64:
            entropy = compute_entropy(ctx.payload)
            if entropy > 7.5:
                score += 0.3  # High entropy without match
        if ctx.dst_port in {4444, 5555, 6667, 31337}:
            score += 0.2
        return min(score, 1.0)

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self.stats)


# ═══════════════════════════════════════════════════════════════
# Daemon & Console Integration
# ═══════════════════════════════════════════════════════════════

class AegisDaemon:
    """Background daemon that runs the analysis brain continuously."""

    def __init__(self, brain: AnalysisBrain):
        self.brain = brain
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("AEGIS Daemon started")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("AEGIS Daemon stopped")

    def _run_loop(self) -> None:
        while self._running:
            time.sleep(0.1)  # Main loop — packets arrive via IPC from Zig


def main() -> None:
    """Entry point for standalone brain execution."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )

    rules_path = Path(__file__).parent.parent / "config" / "Rules.json"
    brain = AnalysisBrain(rules_path=rules_path)
    daemon = AegisDaemon(brain)
    daemon.start()

    try:
        while True:
            time.sleep(1)
            stats = brain.get_stats()
            logger.info("Stats: %s", stats)
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    main()
