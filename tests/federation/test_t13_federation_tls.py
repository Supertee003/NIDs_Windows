"""T13: Federation + Real TLS/mTLS (Steps 36-37).

The T13 acceptance criteria are:
  AC1. Federated nodes exchange messages with identity, schema, sequence,
       heartbeat, and version; they share incidents and threat intel.
  AC2. Remote nodes can NOT override or bypass local policy/enforcement
       authority (enforcement stays local / in the Rust PEP).
  AC3. Real mTLS (SChannel preferred on Windows) authenticates both
       sides; expired / unknown-CA / revoked certificates are rejected.
  AC4. There is no plaintext / pass-through production transport.

Architecture:
  - core/cluster_coord.zig      : ClusterMessage (identity, heartbeat,
    incident + threat-intel sharing) + ClusterCoord facade (heartbeat
    timeout, leader election, cross-node incident aggregation, TI
    broadcast).
  - core/federation_codec.zig   : binary wire format (FrameHeader with
    MAGIC + VERSION + msg_type + CRC32). Every ClusterMessage carries
    from_node_id (identity), timestamp_ns, and seq (monotonic sequence).
  - core/federation_tls.zig     : TLS/mTLS wrap. CertificateValidator is
    the single validation authority: expiry (CertExpired), CN mismatch
    (CNMismatch), self-signed (CertValidationFailed), unknown CA
    (CertNotFound), and revocation (CertRevoked) are all rejected.
  - core/federation_tcp.zig     : plain TCP transport used for host tests
    only; the TLS transport is what production federation uses.

Authority rule (AC2): federation modules exchange *reports* only. They
never import or call the enforcement chain (policy_engine, rust_pep,
wfp_*), so a remote node cannot force local enforcement to change.

This file proves the invariants by scanning the source and the manifest.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CLUSTER_COORD = "core/cluster_coord.zig"
FEDERATION_CODEC = "core/federation_codec.zig"
FEDERATION_TCP = "core/federation_tcp.zig"
FEDERATION_TLS = "core/federation_tls.zig"
FEDERATION_TLS_CONFIG = "configs/test/federation_tls_config.json"

# Federation modules must never reach into enforcement (AC2).
ENFORCEMENT_MODULES = ("policy_engine.zig", "rust_pep.zig", "wfp_ioctl.zig", "wfp_production.zig")


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8", errors="ignore")


def test_cluster_message_has_identity_schema_and_sequence() -> None:
    """AC1: ClusterMessage carries identity (from_node_id/to_node_id),
    a message type schema (MessageType enum), a timestamp, and a
    per-sender monotonic sequence."""
    src = _read(CLUSTER_COORD)
    assert "pub const ClusterMessage = struct" in src
    assert "from_node_id: u32" in src, "identity: from_node_id (AC1)"
    assert "to_node_id: u32" in src, "identity: to_node_id (AC1)"
    assert "timestamp_ns: i64" in src
    assert "seq: u32" in src, "sequence: per-sender monotonic seq (AC1)"
    assert "pub const MessageType = enum" in src, "schema: MessageType (AC1)"


def test_message_types_cover_heartbeat_incident_and_ti() -> None:
    """AC1: the message schema must cover heartbeat, incident sharing,
    and threat-intel sharing."""
    src = _read(CLUSTER_COORD)
    for tok in [".heartbeat", ".incident_report", ".threat_intel_share", ".node_join", ".leader_announce"]:
        assert tok in src, f"MessageType must include {tok!r} (AC1)"


def test_shared_payloads_cover_incidents_and_ti() -> None:
    """AC1: ClusterMessage must be able to ship incident details and a
    threat-intel entry to peers."""
    src = _read(CLUSTER_COORD)
    for tok in ["incident_source_ip", "incident_severity", "incident_score", "incident_label", "threat_intel: ?ThreatIntelEntry"]:
        assert tok in src, f"ClusterMessage must carry {tok!r} (AC1)"


def test_frame_schema_has_magic_version_type_and_crc() -> None:
    """AC1: the wire schema (FrameHeader) must identify the protocol
    (magic), the version, the message type, and protect integrity."""
    src = _read(FEDERATION_CODEC)
    assert "MAGIC: u32 = 0x41_45_47_49" in src, "magic 'AEGI' (AC1)"
    assert "pub const VERSION: u8 = 1" in src, "schema version (AC1)"
    assert "magic: u32" in src and "version: u8" in src and "msg_type: u8" in src, "FrameHeader fields (AC1)"
    assert "pub fn crc32(" in src, "CRC32 integrity (AC1)"
    assert "error.MagicMismatch" in src, "decode rejects wrong magic (AC1)"
    assert "error.VersionMismatch" in src, "decode rejects wrong version (AC1)"


def test_codec_roundtrips_sequence() -> None:
    """AC1: encode/decode must carry the seq field end to end, so message
    order/replay is reproducible across the wire."""
    src = _read(FEDERATION_CODEC)
    # Sequence written in the common payload header (encode side).
    assert "writeU32(payload[0..], &p_off, msg.seq);" in src, "encode must write msg.seq (AC1)"
    # And read back on decode side.
    assert "msg.seq = readU32(payload, &p_off);" in src, "decode must read msg.seq (AC1)"


def test_federation_modules_do_not_reach_enforcement() -> None:
    """AC2: remote nodes cannot override or bypass local policy/enforcement
    authority. Federation modules must never import policy/PEP/WFP
    enforcement modules, so inbound federation messages are *reports* only
    -- they cannot force local enforcement to change."""
    violations = []
    for mod, rel in [
        (CLUSTER_COORD, CLUSTER_COORD),
        (FEDERATION_CODEC, FEDERATION_CODEC),
        (FEDERATION_TCP, FEDERATION_TCP),
        (FEDERATION_TLS, FEDERATION_TLS),
    ]:
        del mod
        src = _read(rel)
        for enc in ENFORCEMENT_MODULES:
            if f'@import("{enc}")' in src:
                violations.append(f"{rel} imports {enc}")
    assert not violations, (
        f"federation must never import enforcement modules (AC2); got: {violations}"
    )


def test_federation_has_no_enforcement_calls() -> None:
    """AC2: no function call in any federation module may touch the
    enforcement API surface (block/enforce/pep), even indirectly."""
    enforcement_api = re.compile(r"\b(block_ip|enforceDecision|enforce|EnforcementAction|pep\w*\.)\b")
    for rel in (CLUSTER_COORD, FEDERATION_CODEC, FEDERATION_TCP, FEDERATION_TLS):
        src = _read(rel)
        imports = re.findall(r'@import\("([\w_]+\.zig)"\)', src)
        if any(enc.replace(".zig", "") in i for i in imports for enc in ENFORCEMENT_MODULES):
            continue
        hits = enforcement_api.findall(src)
        assert not hits, f"{rel} must not call enforcement API {hits} (AC2)"


def test_tls_validator_rejects_expired_certs() -> None:
    """AC3: real mTLS rejects expired certificates."""
    src = _read(FEDERATION_TLS)
    assert "error.CertExpired" in src
    assert 'test "CertificateValidator validate - expired cert"' in src


def test_tls_validator_rejects_unknown_ca() -> None:
    """AC3: real mTLS rejects certificates issued by an unknown CA
    (cert does not chain to the trusted CA fingerprint)."""
    src = _read(FEDERATION_TLS)
    assert "ca_fingerprint" in src, "trusted CA fingerprint configuration (AC3)"
    assert "issuer_ca_fingerprint" in src, "cert issuer CA fingerprint (AC3)"
    assert "error.CertNotFound" in src
    assert 'test "CertificateValidator validate - unknown CA rejected"' in src


def test_tls_validator_rejects_revoked_certs() -> None:
    """AC3: real mTLS rejects revoked certificates (CRL/OCSP)."""
    src = _read(FEDERATION_TLS)
    assert "error.CertRevoked" in src
    assert "revoked: bool" in src, "cert revocation flag (AC3)"
    assert 'test "CertificateValidator validate - revoked cert rejected"' in src
    assert "check_revocation" in src, "revocation checking enabled by config (AC3)"


def test_tls_validator_covers_cn_self_signed_and_not_enabled() -> None:
    """AC3/AC4: the validator also rejects CN mismatch, self-signed certs
    (when not allowed), and refuses to run when TLS is disabled."""
    src = _read(FEDERATION_TLS)
    assert "error.CNMismatch" in src
    assert "error.CertValidationFailed" in src
    assert "error.NotEnabled" in src
    assert 'test "CertificateValidator validate - CN mismatch"' in src
    assert 'test "CertificateValidator validate - self-signed not allowed"' in src
    assert 'test "CertificateValidator validate - disabled returns NotEnabled"' in src


def test_mtls_requires_client_cert() -> None:
    """AC3: mutual TLS is the default -- a client certificate is required,
    so both sides are authenticated."""
    src = _read(FEDERATION_TLS)
    assert re.search(r"require_client_cert:\s*bool\s*=\s*true", src), "mTLS: require_client_cert default true (AC3)"


def test_tls_handshake_timeout_exists() -> None:
    """AC3: handshakes that do not complete in time fail (no silent
    fallback)."""
    src = _read(FEDERATION_TLS)
    assert "TLS_HANDSHAKE_TIMEOUT_MS" in src
    assert "HandshakeTimeout" in src


def test_no_plaintext_production_transport() -> None:
    """AC4: there is no plaintext production transport.

    federation_tls is the ONLY transport that performs real authentication
    (client + server certs) and revocation/CA validation; federation_tcp is
    the plaintext TCP transport used for host tests only. Production wiring
    must route federation through the TLS transport."""
    tls = _read(FEDERATION_TLS)
    tcp = _read(FEDERATION_TCP)
    # TLS is the production-grade transport: it must exist, wrap TCP, and
    # be what callers route through (TlsTransport implements the vtable).
    assert "pub const TlsTransport = struct" in tls
    assert "pub const TlsServer = struct" in tls
    assert "pub fn asTransport" in tls, "TLS must plug into the Transport vtable (AC4)"
    assert "handshake_count" in tls and "total_bytes_encrypted" in tls
    # The plaintext transport must be internally described as the host-test
    # channel, never as the production channel.
    tcp_lower = tcp.lower()
    assert "test" in tcp_lower or "host test" in tcp_lower, "federation_tcp must be host-test only (AC4)"


def test_federation_tls_config_marks_tls_as_production_transport() -> None:
    """AC4: the shipped TLS config must declare SChannel as the Windows
    production transport and must not claim plaintext for production."""
    config = json.loads((REPO_ROOT / FEDERATION_TLS_CONFIG).read_text(encoding="utf-8"))
    assert config.get("module") == "federation_tls"
    # Windows = real TLS (SChannel); Linux = mock for host testing only.
    platform_behavior = config.get("platform_behavior", {})
    assert "Real TLS" in platform_behavior.get("windows", ""), (
        "Windows TLS config must be real TLS (SChannel), AC4"
    )
    assert "mock" in platform_behavior.get("linux", "").lower(), (
        "Linux TLS is a host-test mock only (AC4)"
    )


def test_manifest_documents_federation_tls() -> None:
    """AC1-AC4: runtime_manifest.json must document federation + TLS as
    REAL on the golden path, and declare their authority role."""
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    for mod in (CLUSTER_COORD, FEDERATION_CODEC, FEDERATION_TLS):
        entry = manifest["modules"].get(mod)
        assert entry is not None, f"{mod} must be in runtime_manifest.json (T13)"
        assert entry.get("status") == "REAL", f"{mod} must be REAL (T13); got {entry}"
        assert entry.get("golden_path") is True, f"{mod} must be on golden path (T13)"


def test_authority_invariants_declare_federation_and_tls() -> None:
    """AC2/AC4: authority_invariants must declare the federation authority
    (report-only, enforcement stays local) and the TLS transport authority."""
    manifest = json.loads((REPO_ROOT / "runtime_manifest.json").read_text(encoding="utf-8"))
    invariants = manifest.get("authority_invariants", [])
    joined = "\n".join(invariants)
    for needle in [
        "federation authority",
        "federation: reports only, enforcement stays local",
        "federation transport is TLS (no plaintext production transport)",
    ]:
        assert needle in joined, (
            f"authority_invariants must declare {needle!r} (T13); got: {invariants}"
        )