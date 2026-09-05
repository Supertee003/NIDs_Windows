"""
AEGIS Canonical Event Test Vectors (Phase A3)

Golden vectors for validating CanonicalEvent serialization/deserialization
across all languages (Zig, C++, Rust, Go, Python).

Each vector has:
  - name: human-readable identifier
  - description: what this vector tests
  - event: dict representation of CanonicalEvent
  - expected_valid: True if the event should pass validation
  - expected_error: None if valid, else the validation error class
"""

VECTORS = [
    {
        "name": "valid_minimal",
        "description": "Minimal valid event with required fields only",
        "event": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 100,  # approximate sizeof
            "event_id": 1,
            "timestamp_ms": 1700000000000,
            "monotonic_ns": 1000000,
            "source": 0,  # zig_core
            "source_ip": 0,
            "source_port": 0,
            "dest_ip": 0,
            "dest_port": 0,
            "session_id": 0,
            "protocol": 0,
            "direction": 0,
            "layer_id": 0,
            "is_pipe": 0,
            "event_type": 0,
            "severity": 0,
            "rule_id": 0,
            "ruleset_version": 1,
            "payload_length": 0,
            "payload_hash": 0,
            "policy_action": 0,
            "enforcement_status": 0,
            "defcon_impact": 5,
            "context_flags": 0,
            "reserved": b"\x00" * 16,
        },
        "expected_valid": True,
        "expected_error": None,
    },
    {
        "name": "valid_network_event",
        "description": "Typical network event from WFP sensor",
        "event": {
            "magic": 0x41454731,
            "version": 1,
            "struct_size": 100,
            "event_id": 42,
            "timestamp_ms": 1700000001234,
            "monotonic_ns": 5000000,
            "source": 1,  # wfp_sensor
            "source_ip": 0x0A000001,  # 10.0.0.1
            "source_port": 54321,
            "dest_ip": 0x0A000002,  # 10.0.0.2
            "dest_port": 80,
            "session_id": 123456,
            "protocol": 6,  # TCP
            "direction": 0,  # inbound
            "layer_id": 1,  # WFP
            "is_pipe": 0,
            "event_type": 1,  # match
            "severity": 2,  # High
            "rule_id": 0x12345678,
            "ruleset_version": 1,
            "payload_length": 256,
            "payload_hash": 0xDEADBEEFCAFEBABE,
            "policy_action": 1,  # alert
            "enforcement_status": 0,
            "defcon_impact": 3,
            "context_flags": 0x01,  # threat_intel_match
            "reserved": b"\x00" * 16,
        },
        "expected_valid": True,
        "expected_error": None,
    },
    {
        "name": "invalid_magic",
        "description": "Wrong magic number should be rejected",
        "event": {
            "magic": 0xDEADBEEF,  # wrong
            "version": 1,
        },
        "expected_valid": False,
        "expected_error": "INVALID_MAGIC",
    },
    {
        "name": "invalid_version",
        "description": "Future version should be rejected",
        "event": {
            "magic": 0x41454731,
            "version": 99,  # too high
        },
        "expected_valid": False,
        "expected_error": "UNSUPPORTED_VERSION",
    },
    {
        "name": "invalid_severity",
        "description": "Severity out of range [0,3]",
        "event": {
            "magic": 0x41454731,
            "version": 1,
            "severity": 99,
        },
        "expected_valid": False,
        "expected_error": "INVALID_SEVERITY",
    },
    {
        "name": "invalid_reserved",
        "description": "Reserved field must be all zeros",
        "event": {
            "magic": 0x41454731,
            "version": 1,
            "reserved": b"\xFF" * 16,  # non-zero
        },
        "expected_valid": False,
        "expected_error": "INVALID_RESERVED",
    },
    {
        "name": "duplicate_event_id",
        "description": "Event with duplicate ID (replay attempt)",
        "event": {
            "magic": 0x41454731,
            "version": 1,
            "event_id": 1,  # same as valid_minimal
        },
        "expected_valid": False,
        "expected_error": "DUPLICATE_EVENT_ID",
    },
    {
        "name": "replay_event",
        "description": "Event with old timestamp (replay attempt)",
        "event": {
            "magic": 0x41454731,
            "version": 1,
            "event_id": 999,
            "timestamp_ms": 1000,  # very old
            "monotonic_ns": 1000,  # very old
        },
        "expected_valid": False,
        "expected_error": "REPLAY_DETECTED",
    },
]


def get_valid_vectors():
    """Return only the valid event vectors."""
    return [v for v in VECTORS if v["expected_valid"]]


def get_invalid_vectors():
    """Return only the invalid event vectors."""
    return [v for v in VECTORS if not v["expected_valid"]]


def get_vector_by_name(name: str):
    """Return a vector by its name."""
    for v in VECTORS:
        if v["name"] == name:
            return v
    raise KeyError(f"vector {name!r} not found")
