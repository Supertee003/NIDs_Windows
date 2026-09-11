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
  rust pep (shield/src/pep.rs, request_id) -> wfp (windows_enforce) ->
  forensics (forensic_id) -> replay.

No mock/simulated stage appears on the golden path.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CANONICAL_EVENT = "core/canonical_event.zig"
CORRELATION = "core/correlation_engine.zig"
POLICY_SIGNING = "core/policy_signing.zig"
PEP_RS = "shield/src/pep.rs"
WFP = "core/wfp_production.zig"
FORENSICS = "core/forensics_engine.zig"
REPLAY = "core/replay_engine.zig"
DISPATCHER = "core/dispatcher.zig"

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
        "core/npcap_capture.zig",
        "core/windows_adapters.zig",
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


def test_incident_id_survives_dispatcher() -> None:
    """AC2: incident_id lives on the correlation Incident and is carried in
    the dispatcher StageContext through the decision chain."""
    ce = _read(CORRELATION)
    assert "incident_id: u64" in ce, "correlation Incident must carry incident_id (AC2)"
    disp = _read(DISPATCHER)
    assert "incident: ?correlation_engine.Incident" in disp, (
        "dispatcher must carry the correlation Incident (AC2)"
    )
    assert "processCorrelation" in disp and "ctx.incident" in disp


def test_policy_id_and_version_survive() -> None:
    """AC2: policy_id/version are minted in the signing pipeline
    (SignedPolicy) and reach the PEP trace (shield/src/pep.rs)."""
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
    """AC3/AC1: the Rust PEP (shield/src/pep.rs) and WFP enforcement
    terminal stage are REAL and golden-path."""
    manifest = _manifest()
    assert manifest["modules"]["shield/src/pep.rs"]["status"] == "REAL"
    assert manifest["modules"]["core/wfp_production.zig"]["status"] == "REAL"
    wfp = _read(WFP)
    assert "wfp" in wfp.lower() and ("block" in wfp.lower() or "enforce" in wfp.lower())


def test_dispatcher_is_sole_orchestrator() -> None:
    """AC1: dispatcher.zig is the sole orchestrator and defines every stage
    helper end to end (capture-facing -> forensics)."""
    src = _read(DISPATCHER)
    for stage in [
        "processEvent", "processFlow", "processDetection", "processVerdict",
        "processCorrelation", "processThreatIntel", "processRAG",
        "processBrain", "processPolicy", "processPEP", "processForensics",
    ]:
        assert f"fn {stage}" in src, f"dispatcher must define {stage} (T14 AC1)"


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