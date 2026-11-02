r"""T10: Host Network + Process telemetry single authoritative source (Step 32).

The T10 acceptance criteria are:
  AC1. A single authoritative Windows host-network source is chosen
       and documented.
  AC2. Host network + process events flow through C++ -> Canonical
       Event -> Zig Flow as one model.
  AC3. No second/incompatible host-network event model exists in the
       runtime.

Current architecture: Go Nose (`nose/`) is the canonical production
acquisition path. It emits length-prefixed CanonicalEvent frames over
`\\.\pipe\aegis_nose` to the Zig reader. Direct Npcap
(`src/capture/npcap_capture.zig`) remains a disjoint, lab-only
full-payload sensor; it is not a second production ingress. Both paths
normalize to the same CanonicalEvent model and feed the same Zig flow
engine.

This file proves the invariants by scanning the repo for
host-network source modules and asserting the architectural
constraints.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# The single authoritative Windows host-network source.
HOST_NETWORK_SOURCE = "src/capture/npcap_capture.zig"

# A "host-network event model" is any code that:
#   - Captures raw packets from a Windows network adapter
#   - Decodes L2/L3/L4 headers (Ethernet, IP, TCP, UDP, etc.)
#   - Produces flow records or events from the captured packets
# These are the responsibilities of the host-network source. There
# should be EXACTLY ONE such module in the runtime.

# Forbidden patterns indicating a SECOND host-network capture path.
# Anything that talks to a network adapter at the L2/L3 layer is a
# candidate for a duplicate.
FORBIDDEN_HOST_NETWORK_PATTERNS = [
    re.compile(r"\bCreateFileW\s*\(\s*L[\"']\\\\DEVICE\\\\NPF_"),  # Npcap device open (forbidden outside npcap_capture)
    re.compile(r"\bWSAStartup\s*\("),  # Winsock startup (could be used for raw capture)
    re.compile(r"\bsocket\s*\(\s*AF_PACKET"),  # Linux raw socket
    re.compile(r"\bsocket\s*\(\s*SOCK_RAW"),
    re.compile(r"\braw_socket\b"),
]

# Source kinds that the canonical_event module defines. A second
# host-network event model would introduce a duplicate source kind.
CANONICAL_HOST_NETWORK_SOURCES = {
    ".wfp_sensor":   "WFP sensor (network flow capture)",
    ".npcap_sensor": "Npcap capture (raw packet path, T10 authoritative host-network source)",
    ".host_telemetry": "Host telemetry (T9 ETW/FIM/Registry)",
    ".process_sensor": "Process sensor (T9 EtwProcessSource)",
}


def test_single_authoritative_host_network_source_exists() -> None:
    """AC1: The single authoritative host-network source exists."""
    p = REPO_ROOT / HOST_NETWORK_SOURCE
    assert p.is_file(), (
        f"authoritative host-network source missing: {HOST_NETWORK_SOURCE}"
    )


def test_no_duplicate_host_network_source() -> None:
    """AC1 (negative): No second/incompatible host-network source
    exists. Scan src/ for modules that import Windows network APIs
    at the L2/L3 layer (other than npcap_capture.zig and the
    well-known exceptions: the C++ bridge, the Zig WFP mirror, the
    cluster federation over loopback)."""
    violations: list[str] = []
    # The C++ bridge adapter may use socket APIs for IPC over loopback;
    # that's not a host-network capture path. Allow `bridge/`.
    # The WFP mirror is a contract test mirror, not a capture path.
    ALLOWED_DIRS = ("src/capture/npcap_capture.zig", "src/capture/npcap_test_live.zig", "src/policy/wfp_")
    # TEST-001: the old `core/` tree was migrated to src/. Scanning a
    # non-existent directory made this negative control pass vacuously.
    for path in (REPO_ROOT / "src").rglob("*.zig"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if any(rel.startswith(a) for a in ALLOWED_DIRS):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in FORBIDDEN_HOST_NETWORK_PATTERNS:
            if pat.search(text):
                # The search is intentionally lenient: a match in a
                # comment or test is not a violation, but a match in
                # actual code is. We just report the file here and
                # let a human inspect. The contract test is
                # "exactly one" -- so the test is conservative and
                # only fails on clearly distinct code paths.
                if "test" in rel or "Test" in rel:
                    continue
                # Only count matches in non-test code
                violations.append(f"{rel}: matches {pat.pattern!r}")
    assert not violations, (
        f"Second host-network source detected (T10 AC1):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_canonical_event_defines_host_network_source_kinds() -> None:
    """AC2 (cross-language): core/canonical_event.zig must define the
    source kinds the host-network source uses, and the Zig Flow
    engine must consume them."""
    text = (REPO_ROOT / "src" / "contract" / "canonical_event.zig").read_text(encoding="utf-8")
    for source, desc in CANONICAL_HOST_NETWORK_SOURCES.items():
        assert source in text, (
            f"canonical_event.zig must define EventSource{source} ({desc})"
        )


def test_zig_flow_engine_consumes_canonical_events() -> None:
    """AC2: Host network events flow into the Zig Flow engine as one
    model. core/flow_engine.zig must consume CanonicalEvent (not
    some parallel event type)."""
    text = (REPO_ROOT / "src" / "capture" / "flow_engine.zig").read_text(encoding="utf-8")
    assert "canonical_event" in text, (
        "core/flow_engine.zig must import canonical_event.zig (single event model)"
    )


def test_process_telemetry_uses_same_canonical_event_model() -> None:
    """AC2: Process telemetry (EtwProcessSource) emits Canonical
    Events too -- one model, two sources (network + process)."""
    # The adapter framework's events flow through core/host_telemetry.zig
    # which produces canonical events. We verify the chain: adapter
    # -> host_telemetry -> cpp_adapter -> canonical_event.
    wa = (REPO_ROOT / "src" / "windows" / "windows_adapters.zig").read_text(encoding="utf-8")
    assert "host_telemetry" in wa, (
        "core/windows_adapters.zig must import host_telemetry.zig (single model chain)"
    )
    ht = (REPO_ROOT / "src" / "windows" / "host_telemetry.zig").read_text(encoding="utf-8")
    # host_telemetry.zig doesn't import canonical_event.zig directly;
    # instead it emits HostEvent which is converted to CanonicalEvent
    # in cpp_adapter.zig. We verify the chain: adapter -> host_telemetry
    # -> cpp_adapter -> canonical_event.
    assert "HostEvent" in ht, (
        "core/host_telemetry.zig must emit HostEvent (single model chain)"
    )
    ca = (REPO_ROOT / "src" / "windows" / "cpp_adapter.zig").read_text(encoding="utf-8")
    # cpp_adapter.zig doesn't emit CanonicalEvent directly; instead it
    # imports canonical_event.zig and uses it for the ABI. The actual
    # emission happens in the C++ bridge (aegis_adapter.cpp).
    assert "canonical_event" in ca, (
        "core/cpp_adapter.zig must import canonical_event.zig (single model chain)"
    )
    # And the source kind .process_sensor is in canonical_event.zig
    canon = (REPO_ROOT / "src" / "contract" / "canonical_event.zig").read_text(encoding="utf-8")
    assert ".process_sensor" in canon, (
        "canonical_event.zig must define .process_sensor for the adapter"
    )


def test_no_alternate_host_network_module() -> None:
    """AC3: No second/incompatible host-network event model. Scan
    src/ for modules that declare host-network data structures
    independent of the canonical event model."""
    # A duplicate model would have its own packet/flow types.
    duplicate_signatures = [
        re.compile(r"struct\s+HostPacket\b"),
        re.compile(r"struct\s+RawFrame\b"),
        re.compile(r"struct\s+NetEvent\b"),
        re.compile(r"struct\s+AdapterFrame\b"),
    ]
    violations: list[str] = []
    for path in (REPO_ROOT / "src").rglob("*.zig"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in duplicate_signatures:
            if pat.search(text):
                rel = path.relative_to(REPO_ROOT).as_posix()
                violations.append(f"{rel}: matches {pat.pattern!r}")
    assert not violations, (
        f"Duplicate host-network event model detected (T10 AC3):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_host_network_and_process_share_event_processor() -> None:
    """AC2 (lock-in): The event processor must consume both network and
    process events through the same pipeline (processEvent, one flow
    construction site). No parallel dispatcher for process events."""
    text = (REPO_ROOT / "src" / "pipeline" / "event_processor.zig").read_text(encoding="utf-8")
    # processEvent handles every event kind through one flow key build —
    # there is no source-kind branch and no second flow construction site.
    # (Unit tests in the same file also call FlowKey.normalize, so the pin
    # matches the production call site, not the bare identifier.)
    assert "fn processEvent" in text, "event_processor.zig must define processEvent"
    assert text.count("const fkey = flow.FlowKey.normalize") == 1, (
        "event_processor must build the flow key at exactly one site (single model)"
    )


def test_manifest_documents_lab_npcap_and_production_nose() -> None:
    """AC1 (manifest): the manifest must state the current split.

    Go Nose is the production acquisition path (REAL, golden path);
    direct Npcap is a disjoint lab-only full-payload sensor.
    """
    import json
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    mod = manifest["modules"].get(HOST_NETWORK_SOURCE)
    assert mod is not None, (
        f"{HOST_NETWORK_SOURCE} must be in runtime_manifest.json (lab sensor record)"
    )
    assert mod.get("status") == "LAB", (
        f"{HOST_NETWORK_SOURCE} must be LAB (direct Npcap is not production ingress); got {mod}"
    )
    assert mod.get("golden_path") is False, (
        f"{HOST_NETWORK_SOURCE} must not be on the production golden path"
    )
    for nose_mod in ("nose/capture.go", "nose/canonical.go", "nose/pipe_writer.go"):
        entry = manifest["modules"].get(nose_mod)
        assert entry is not None, f"{nose_mod} must be in runtime_manifest.json"
        assert entry.get("status") == "REAL", f"{nose_mod} must be REAL; got {entry}"
        assert entry.get("golden_path") is True, f"{nose_mod} must be on the golden path"


def test_authority_invariants_declare_one_host_network_source() -> None:
    """AC1: The authority_invariants section must document the single
    production acquisition source and the lab-only direct-Npcap split.

    This test is read-only. It must never repair tracked state: a missing
    invariant is a source/generator defect, not something a test may write.
    """
    import json
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    invariants = manifest.get("authority_invariants", [])
    matching = [
        line for line in invariants
        if "canonical acquisition path" in line.lower()
        and "direct npcap" in line.lower()
        and "lab-only" in line.lower()
    ]
    assert matching, (
        "authority_invariants must declare Go Nose as the canonical acquisition "
        f"path and direct Npcap as lab-only (T10 AC1); got: {invariants}"
    )
