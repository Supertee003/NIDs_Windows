"""CONTRACT-02 (PEP ABI) cross-language layout guard.

The PEP ABI is the boundary between the Zig runtime spine and the Rust
enforcement authority. It is declared three times, in three languages:

  * ``rust-src/lib.rs``                    — ``#[repr(C)]`` structs (owner)
  * ``src/policy/pep_bindings.zig``        — ``extern struct`` + FFI-001 tests
  * ``tests/wfp/test_t11_windows_host.py`` — ``ctypes.Structure`` declarations

Nothing previously asserted that the three declarations agreed. A stale
Python declaration silently drove the enforcement authority with
``requested_action == 0 == ACTION_PASS`` (so every privileged request answered
ALLOW) and wrote ``filter_id`` past the end of the caller's allocation.

This module derives the layout from the Rust source of truth, then verifies
that the Zig `FFI-001` assertions and the Python `ctypes` declarations both
reproduce it. Any drift fails here instead of at runtime on a host where WFP
is installed.
"""
from __future__ import annotations

import ctypes
import importlib.util
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUST_SRC = REPO_ROOT / "rust-src" / "lib.rs"
ZIG_BINDINGS = REPO_ROOT / "src" / "policy" / "pep_bindings.zig"
PYTHON_HOST_TEST = REPO_ROOT / "tests" / "wfp" / "test_t11_windows_host.py"

RUST_TO_CTYPES = {
    "u8": ctypes.c_uint8,
    "u16": ctypes.c_uint16,
    "u32": ctypes.c_uint32,
    "u64": ctypes.c_uint64,
}

# Canonical CONTRACT-02 layout. Sizes and offsets are the contract.
CANONICAL_SIZE = {"PepContext": 24, "PepRequest": 64, "PepResponse": 24}
CANONICAL_OFFSETS: Dict[str, Dict[str, int]] = {
    "PepContext": {
        "caller_pid": 0,
        "caller_capability_mask": 4,
        "request_id": 8,
        "policy_version": 16,
    },
    "PepRequest": {
        "decision_kind": 0,
        "requested_action": 1,
        "flow_id": 8,
        "src_ip": 16,
        "dst_ip": 20,
        "src_port": 24,
        "dst_port": 26,
        "protocol": 28,
        "policy_id": 32,
        "severity": 36,
        "ctx": 40,
    },
    "PepResponse": {
        "decision": 0,
        "reason": 4,
        "quota_remaining": 8,
        "signed_by": 12,
        "filter_id": 16,
    },
}

STRUCT_NAMES = ("PepContext", "PepRequest", "PepResponse")


def _rust_struct_fields(source: str, struct_name: str) -> List[Tuple[str, str]]:
    """Return [(field_name, rust_type)] in declaration order."""
    match = re.search(
        r"pub struct " + struct_name + r"\s*\{(?P<body>.*?)\n\}",
        source,
        re.DOTALL,
    )
    assert match, f"{struct_name} not found in {RUST_SRC}"
    fields: List[Tuple[str, str]] = []
    for line in match.group("body").splitlines():
        line = line.strip()
        if not line.startswith("pub "):
            continue
        field_match = re.match(r"pub\s+(\w+)\s*:\s*(\w+)\s*,", line)
        if field_match:
            fields.append((field_match.group(1), field_match.group(2)))
    return fields


def _build_ctypes_structs(source: str) -> Dict[str, type]:
    """Reconstruct the Rust #[repr(C)] layout using ctypes."""
    built: Dict[str, type] = {}
    for struct_name in STRUCT_NAMES:
        fields = _rust_struct_fields(source, struct_name)
        ctypes_fields = []
        for field_name, rust_type in fields:
            if rust_type in RUST_TO_CTYPES:
                ctypes_fields.append((field_name, RUST_TO_CTYPES[rust_type]))
            elif rust_type in built:
                ctypes_fields.append((field_name, built[rust_type]))
            else:
                pytest.fail(
                    f"{struct_name}.{field_name} has unsupported type {rust_type!r}"
                )
        built[struct_name] = type(struct_name, (ctypes.Structure,), {"_fields_": ctypes_fields})
    return built


@pytest.fixture(scope="module")
def rust_layout() -> Dict[str, type]:
    assert RUST_SRC.is_file(), f"missing {RUST_SRC}"
    return _build_ctypes_structs(RUST_SRC.read_text(encoding="utf-8", errors="ignore"))


def test_rust_repr_c_structure_order_is_canonical(rust_layout: Dict[str, type]) -> None:
    """Field *order* is part of the contract; reordering is an ABI break."""
    source = RUST_SRC.read_text(encoding="utf-8", errors="ignore")
    for struct_name, expected in CANONICAL_OFFSETS.items():
        actual_fields = [name for name, _ in _rust_struct_fields(source, struct_name)]
        assert actual_fields == list(expected.keys()), (
            f"{struct_name} field order drifted from CONTRACT-02: "
            f"{actual_fields} != {list(expected.keys())}"
        )


def test_rust_layout_sizes_and_offsets_match_contract(rust_layout: Dict[str, type]) -> None:
    for struct_name, expected_size in CANONICAL_SIZE.items():
        struct = rust_layout[struct_name]
        assert ctypes.sizeof(struct) == expected_size, (
            f"{struct_name} must be {expected_size} bytes, got {ctypes.sizeof(struct)}"
        )
    for struct_name, expected_offsets in CANONICAL_OFFSETS.items():
        struct = rust_layout[struct_name]
        for field_name, expected_offset in expected_offsets.items():
            assert getattr(struct, field_name).offset == expected_offset, (
                f"{struct_name}.{field_name} offset drifted from CONTRACT-02: "
                f"{getattr(struct, field_name).offset} != {expected_offset}"
            )


def _zig_declared_offsets() -> Dict[str, Dict[str, int]]:
    """Parse the @offsetOf expectations out of the Zig FFI-001 tests."""
    source = ZIG_BINDINGS.read_text(encoding="utf-8", errors="ignore")
    pattern = re.compile(
        r"expectEqual\(@as\(usize,\s*(\d+)\),\s*@offsetOf\((\w+),\s*\"(\w+)\"\)\)"
    )
    declared: Dict[str, Dict[str, int]] = {}
    for expected, struct_name, field_name in pattern.findall(source):
        declared.setdefault(struct_name, {})[field_name] = int(expected)
    return declared


def _zig_declared_sizes() -> Dict[str, int]:
    source = ZIG_BINDINGS.read_text(encoding="utf-8", errors="ignore")
    pattern = re.compile(
        r"expectEqual\(@as\(usize,\s*(\d+)\),\s*@sizeOf\((\w+)\)\)"
    )
    return {struct_name: int(size) for size, struct_name in pattern.findall(source)}


def test_zig_extern_structs_match_rust_layout(rust_layout: Dict[str, type]) -> None:
    zig_offsets = _zig_declared_offsets()
    zig_sizes = _zig_declared_sizes()
    assert zig_offsets, "no @offsetOf assertions found in pep_bindings.zig"
    assert zig_sizes, "no @sizeOf assertions found in pep_bindings.zig"

    for struct_name in STRUCT_NAMES:
        assert struct_name in zig_offsets, f"{struct_name} offsets not pinned in Zig"
        assert struct_name in zig_sizes, f"{struct_name} size not pinned in Zig"

        assert zig_sizes[struct_name] == CANONICAL_SIZE[struct_name], (
            f"Zig {struct_name} size assertion drifted: "
            f"{zig_sizes[struct_name]} != {CANONICAL_SIZE[struct_name]}"
        )
        for field_name, expected_offset in zig_offsets[struct_name].items():
            assert expected_offset == CANONICAL_OFFSETS[struct_name][field_name], (
                f"Zig FFI-001 pins {struct_name}.{field_name} at {expected_offset} "
                f"but CONTRACT-02 says {CANONICAL_OFFSETS[struct_name][field_name]}"
            )

        # Every canonical field must be individually pinned on the Zig side.
        assert set(zig_offsets[struct_name]) == set(CANONICAL_OFFSETS[struct_name]), (
            f"Zig is not pinning every {struct_name} field: "
            f"{set(CANONICAL_OFFSETS[struct_name]) - set(zig_offsets[struct_name])}"
        )


@pytest.fixture(scope="module")
def python_host_layout() -> Dict[str, type]:
    """Import the ctypes declarations used by the Windows host test."""
    assert PYTHON_HOST_TEST.is_file(), f"missing {PYTHON_HOST_TEST}"
    spec = importlib.util.spec_from_file_location("aegis_pep_host_test", PYTHON_HOST_TEST)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return {struct_name: getattr(module, struct_name) for struct_name in STRUCT_NAMES}


def test_python_ctypes_declarations_match_contract(python_host_layout: Dict[str, type]) -> None:
    for struct_name, expected_size in CANONICAL_SIZE.items():
        struct = python_host_layout[struct_name]
        assert ctypes.sizeof(struct) == expected_size, (
            f"Python {struct_name} must be {expected_size} bytes, got "
            f"{ctypes.sizeof(struct)} — a short struct lets the PEP write past "
            f"the caller's allocation"
        )
    for struct_name, expected_offsets in CANONICAL_OFFSETS.items():
        struct = python_host_layout[struct_name]
        actual_fields = [name for name, _ in struct._fields_]
        assert actual_fields == list(expected_offsets.keys()), (
            f"Python {struct_name} field order drifted: "
            f"{actual_fields} != {list(expected_offsets.keys())}"
        )
        for field_name, expected_offset in expected_offsets.items():
            assert getattr(struct, field_name).offset == expected_offset, (
                f"Python {struct_name}.{field_name} offset drifted: "
                f"{getattr(struct, field_name).offset} != {expected_offset}"
            )


def test_python_host_test_targets_a_privileged_action(python_host_layout: Dict[str, type]) -> None:
    """The host test must request a privileged action.

    Sending ACTION_PASS (or leaving the byte zero) makes the PEP answer ALLOW,
    so the test could never verify enforcement even on a WFP-capable host.
    """
    source = PYTHON_HOST_TEST.read_text(encoding="utf-8", errors="ignore")
    assert re.search(r"requested_action\s*=\s*ACTION_BLOCK", source), (
        "the Windows host test must set requested_action=ACTION_BLOCK, otherwise "
        "the PEP correctly answers ALLOW and the test proves nothing"
    )
    assert "ACTION_BLOCK = 4" in source, "ACTION_BLOCK must be pinned to the policy.Action ordinal 4"


def test_policy_action_ordinals_match_pep_constants() -> None:
    """policy.Action ordinals are the values the PEP dispatches on."""
    source = (REPO_ROOT / "src" / "policy" / "policy_ir.zig").read_text(
        encoding="utf-8", errors="ignore"
    )
    match = re.search(r"pub const Action = enum\(u8\)\s*\{(?P<body>.*?)\n\};", source, re.DOTALL)
    assert match, "policy.Action enum not found"
    ordinals = {}
    next_value = 0
    for line in match.group("body").splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith("//"):
            continue
        if "=" in line:
            name, value = (part.strip() for part in line.split("=", 1))
            next_value = int(value)
        else:
            name = line
        ordinals[name] = next_value
        next_value += 1

    assert ordinals == {
        "pass": 0,
        "log": 1,
        "alert": 2,
        "rate_limit": 3,
        "block": 4,
        "quarantine": 5,
        "escalate": 6,
    }, f"policy.Action ordinals drifted: {ordinals}"

    rust = (REPO_ROOT / "rust-src" / "lib.rs").read_text(encoding="utf-8", errors="ignore")
    for rust_name, ordinal in [("ACTION_PASS", 0), ("ACTION_BLOCK", 4), ("ACTION_ESCALATE", 6)]:
        assert re.search(rf"const {rust_name}: u8 = {ordinal};", rust), (
            f"Rust {rust_name} must equal policy.Action ordinal {ordinal}"
        )


def test_rust_rejects_unknown_action_without_allowing() -> None:
    """The unknown-action branch must not leave the default ALLOW decision."""
    source = RUST_SRC.read_text(encoding="utf-8", errors="ignore")
    match = re.search(
        r"\}\s*else\s*\{(?P<body>[^}]*reason = 6;[^}]*)\}",
        source,
        re.DOTALL,
    )
    assert match, "unknown-action branch not found in aegis_pep_enforce"
    body = match.group("body")
    assert "decision = DECISION_ESCALATE;" in body, (
        "an unclassifiable requested_action must fail closed with ESCALATE; "
        "setting only `reason` returns the default DECISION_ALLOW"
    )
