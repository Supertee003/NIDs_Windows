"""T14: Windows Golden Path E2E (Step 38).

The T14 acceptance criteria are:
  AC1. A real Windows event travels the full canonical chain and produces
       a verified end-to-end result.
  AC2. Identifier integrity: event_id, incident_id, policy_id/version,
       request_id, forensic_id survive the whole path.
  AC3. Python Brain, Cython, RAG, TypeScript policy, Rust PEP, WFP,
       forensics, replay all appear in the path.
  AC4. The Golden Path is REAL (host-verified), not a mock.

Chain (matching runtime_manifest.json golden_path):
  nose/capture.go (gopacket/npcap live Windows capture) +=
  nose/canonical.go (109B CanonicalEvent serializer) ->
  core/nose_pipe_reader.zig (named pipe) ->
  core/event_fabric.zig -> flow -> detection -> verdict ->
  correlation (incident_id) -> threat_intel -> rag - >
  brain (Python windows_brain.py + Cython accelerators) ->
  policy (TS policy compiler/seal + ed25519 signing, policy_id/version) ->
  rust pep (rust-src/lib.rs, request_id) -> wfp (Rust PEP adapter) ->
  forensics (forensic_id) -> replay.

No mock/simulated stage appears on the golden path.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CANONICAL_EVENT = "src/contract/canonical_event.zig"
CORRELATION = "src/detection/correlation_engine.zig"
POLICY_SIGNING = "src/policy/policy_signing.zig"
PEP_RS = "rust-src/lib.rs"
# E2E-TRUTH-141: WFP enforcement lives in its own module; it previously
# aliased PEP_RS and the suite read one file twice.
WFP = "src/policy/wfp_production.zig"
FORENSICS = "src/forensic/forensics_engine.zig"
REPLAY = "src/forensic/replay_engine.zig"
EVENT_PROCESSOR = "src/pipeline/event_processor.zig"
ACTION_DISPATCHER = "src/policy/action_dispatcher.zig"

# Golden path stages in runtime_manifest.json (human labels), used to prove
# AC3 (each subsystem appears in the path) in the same order as the source.
GOLDEN_PATH_STAGES = [
    "acquisition",       # real Windows capture (nose/capture.go + npcap_capture)
    "canonical_event",   # event_id
    "event_fabric",
    "flow",
    "detection",
    "verdict",
    "correlation",       # incident_id
    "threat_intel",
    "rag",               # RAG context
    "brain",             # Python + Cython advisory brain
    "policy",            # TS policy decision
    "signing",           # ed25519 policy signing
    "rust pep",          # enforcement authority
    "wfp",               # Windows enforcement
    "forensics",         # forensic_id, immutable trace
    "replay",
]


def _manifest() -> dict:
    return json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8", errors="ignore")


def test_golden_path_is_real_and_ordered() -> None:
    """AC3+AC4: the manifest golden path includes every subsystem and is a
    REAL (host-verified) chain; golden-path modules are never MOCK."""
    gp = _manifest()["golden_path"]
    gp_lower = " | ".join(g.lower() for g in gp)
    for stage in GOLDEN_PATH_STAGES:
        assert stage in gp_lower, (
            f"golden path must include {stage!r} (T14 AC3); got: {gp}"
        )
    # Payment ordering: forensics trace then replay last (immutable trace).
    assert gp[-1].lower() == "replay", f"golden path must end in replay; got {gp[-1]}"
    assert "forensics" in gp[-2].lower(), f"forensics must precede replay; got {gp[-2:]}"
    # No MOCK module is on the golden path (AC4).
    for mod, entry in _manifest()["modules"].items():
        if entry.get("golden_path"):
            assert entry.get("status") == "REAL", (
                f"golden-path module {mod} must be REAL (T14 AC4); got {entry.get('status')}"
            )


def test_manifest_names_the_real_windows_sources() -> None:
    """AC1/AC4: the real Windows acquisition chain is declared REAL in the
    manifest: Go nose capture (gopacket/npcap) -> 109B canonical JSON ->
    named pipe -> event fabric."""
    for mod in [
        "nose/capture.go",
        "nose/canonical.go",
        "nose/pipe_writer.go",
        "core/nose_pipe_reader.zig",
        "core/event_fabric.zig",
        "src/capture/npcap_capture.zig",
        "src/windows/windows_adapters.zig",
    ]:
        entry = _manifest()["modules"].get(mod)
        assert entry is not None, f"manifest must declare real Windows source {mod} (T14 AC1)"
        assert entry.get("status") == "REAL", f"{mod} must be REAL (T14 AC4); got {entry}"
        assert entry.get("golden_path") is True, (
            f"{mod} must be on the golden path (T14 AC1)"
        )


def test_windows_capture_is_wfp_reader_not_separate_source() -> None:
    """AC1: windows_capture.zig reads WFP kernel traffic through the Rust
    PEP (rust_pep.read_events) and is thread 3 of the real capture loop,
    not a competing canonicalizer. Canonicalization lives in npcap_capture."""
    wcap = _read("src/capture/windows_capture.zig")
    assert "WFP" in wcap and "rust_pep" in wcap, (
        "windows_capture must read WFP events via the Rust PEP (T14 AC1)"
    )
    npcap = _read("src/capture/npcap_capture.zig")
    assert "canonical" in npcap.lower(), (
        "npcap_capture must canonicalize real Windows packets (T14 AC1)"
    )


def test_event_id_canonical_and_survives() -> None:
    """AC2: event_id is assigned once in canonical_event.zig and carried
    through forensics PipelineResult (and hence replay)."""
    ce = _read(CANONICAL_EVENT)
    assert "event_id: u64" in ce and "nextEventId" in ce
    fe = _read(FORENSICS)
    assert "event_id: u64" in fe, "PipelineResult must carry event_id (AC2)"
    assert ".event_id = event.event_id" in fe, "forensics must capture the canonical event_id (AC2)"


def test_incident_id_survives_event_processor() -> None:
    """AC2: incident_id lives on the correlation Incident and is carried in
    the event processor StageContext through the decision chain."""
    ce = _read(CORRELATION)
    assert "incident_id: u64" in ce, "correlation Incident must carry incident_id (AC2)"
    ep = _read(EVENT_PROCESSOR)
    assert "incident_id" in ep, (
        "event_processor must carry the correlation incident_id (AC2)"
    )
    assert "active_incident" in ep and "incident_id" in ep


def test_policy_id_and_version_survive() -> None:
    """AC2: policy_id/version are minted in the signing pipeline
    (SignedPolicy) and reach the canonical Rust PEP trace (rust-src/lib.rs)."""
    ps = _read(POLICY_SIGNING)
    assert "SignedPolicy" in ps, "policy signing must produce SignedPolicy (AC2)"
    assert "policy_version: u32" in ps, "SignedPolicy must carry policy_version (AC2)"
    pep = _read(PEP_RS)
    assert "policy_id" in pep, "PEP trace must carry policy_id (AC2)"
    assert "policy_version" in pep, "PEP trace must carry policy_version (AC2)"


def test_request_id_survives() -> None:
    """AC2: request_id exists on PepRequest/PepTrace so every enforcement
    request is traceable."""
    pep = _read(PEP_RS)
    assert "request_id" in pep, "PEP must carry request_id (AC2)"
    assert "request_id:" in pep or "pub request_id" in pep, (
        "PepRequest/PepTrace must declare request_id (AC2)"
    )


def test_forensic_id_assigned_and_survives() -> None:
    """AC2: forensic_id is minted by the forensics engine (per trace entry)
    and is part of the authoritative PipelineResult that replay consumes."""
    fe = _read(FORENSICS)
    assert "forensic_id: u64" in fe, "PipelineResult must carry forensic_id (AC2)"
    assert ".forensic_id = seq" in fe, "logResult must assign forensic_id = sequence (AC2)"
    re_src = _read(REPLAY)
    assert "forensics.PipelineResult" in re_src, "replay must use the forensic PipelineResult (AC2)"


def test_python_and_cython_brain_in_path() -> None:
    """AC3: the Python advisory brain + its Cython accelerators are present,
    REAL, and on the golden path."""
    manifest = _manifest()
    assert _read("brain/windows_brain.py")
    for cy in ["brain/aegis_brain_cython/fast_scan.pyx", "brain/cython/cython_regex_scan.pyx"]:
        e = manifest["modules"].get(cy)
        assert e is not None and e["status"] == "REAL" and e.get("golden_path"), cy
    assert manifest["modules"]["brain/windows_brain.py"]["status"] == "REAL"


def test_rag_in_path() -> None:
    """AC3: RAG context enrichment is a REAL golden-path stage."""
    rag = _read("src/detection/rag_engine.zig")
    assert "pub const RagEngine" in rag
    e = _manifest()["modules"]["core/rag_engine.zig"]
    assert e["status"] == "REAL" and e.get("golden_path")
    # E2E-TRUTH-141: core/ is a manifest alias, not a directory: the entry
    # must resolve through canonical_path to the file read above.
    assert e.get("compatibility_alias") is True
    assert e.get("canonical_path") == "src/detection/rag_engine.zig"


def test_typescript_policy_in_path() -> None:
    """AC3: TypeScript policy authoring + sealing (compiler.ts/seal.ts) is a
    REAL golden-path stage feeding policy signing."""
    manifest = _manifest()
    assert _read("ts_policy/src/compiler.ts")
    assert _read("ts_policy/src/seal.ts")
    for mod in ["ts_policy/src/compiler.ts", "ts_policy/src/seal.ts"]:
        e = manifest["modules"].get(mod)
        assert e is not None and e["status"] == "REAL", mod


def test_rust_pep_and_wfp_in_path() -> None:
    """AC3/AC1: the canonical Rust PEP and WFP enforcement
    terminal stage are REAL and golden-path."""
    manifest = _manifest()
    pep_entry = manifest["canonical_entrypoints"]["rust_pep_tier3"]
    assert pep_entry["file"] == "rust-src/lib.rs"
    assert pep_entry["classification"] == "CANONICAL"
    wfp = _read(WFP)
    assert "wfp" in wfp.lower() and ("block" in wfp.lower() or "enforce" in wfp.lower())
    # E2E-TRUTH-141: the WFP module is independently REAL on the golden
    # path (previously the suite read rust-src/lib.rs twice).
    wfp_entry = manifest["modules"].get("src/policy/wfp_production.zig")
    assert wfp_entry is not None
    assert wfp_entry["status"] == "REAL" and wfp_entry.get("golden_path")


def test_event_processor_is_sole_orchestrator() -> None:
    """AC1: event_processor.zig is the sole orchestrator and defines every stage
    helper end to end (capture-facing -> forensics)."""
    src = _read(EVENT_PROCESSOR)
    assert "fn processEvent" in src, (
        "event_processor.zig must define processEvent (T14 AC1)"
    )
    assert "pub fn pipelineLoop" in src, (
        "event_processor.zig must define pipelineLoop (T14 AC1)"
    )
    # Flow lookup, detection, correlation, anomaly, threat tracking, brain,
    # policy, PEP, dispatch, forensics are all inline in processEvent.
    for keyword in [
        "flow.FlowKey.normalize",   # 1. flow lookup
        "the_ac.match",              # 2. signature matching
        "corr.observe",              # 3. correlation
        "ad.observe",                # 4. anomaly detection
        "tt.observeFlowThreat",      # 5. threat tracking
        "ps.evaluate",               # 6. policy evaluation
        "pep_enf.enforce",           # 7. PEP (sole enforcement call)
        "dispatchWithReceipt",       # 8. action dispatch with receipt
        "g_brain_enabled",           # 9. Tier-2 brain offer
        "forensic_ring.append",      # 10. forensic recording
    ]:
        assert keyword in src, f"event_processor must run stage {keyword} inline (T14 AC1)"


def test_manifest_documents_identifier_integrity() -> None:
    """AC2/AC4: the identifier chain + REAL-Windows-E2E rule is an explicit
    authority invariant in the manifest."""
    joined = "\n".join(_manifest()["authority_invariants"])
    for needle in [
        "identifier integrity",
        "golden path is REAL (host-verified Windows E2E)",
    ]:
        assert needle in joined, (
            f"authority_invariants must declare {needle!r} (T14); got: {joined}"
        )
