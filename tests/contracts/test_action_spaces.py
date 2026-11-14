"""ACTION-SPACES-001: four action enums, three numberings, one of them swapped.

The repository carries several "action" enums. Reading them side by side found
that five of the six are one space and one had two values transposed:

| Declaration | Ordinals |
|---|---|
| `src/contract/canonical_event.zig` `PolicyAction` | allow0 alert1 block2 quarantine3 rate_limit4 log_only5 |
| `src/forensic/policy_contract.zig` `PolicyAction` | same (its own test pins it) |
| `src/policy/policy_engine.zig` `EnforcementAction` | same |
| `src/tests/proofs/pep_enforcement_proof.zig` `EnforcementAction` | **rate_limit3, quarantine4 — swapped** |
| `src/policy/policy_ir.zig` `Action` | pass0 log1 alert2 rate_limit3 block4 quarantine5 escalate6 |
| `rust-src/lib.rs` `ACTION_*` | same seven as `policy_ir.Action` |

The proof file is a `u8` enum inside structs the proof compares, and its comment
claims to mirror the enforcement vocabulary; `policy_contract.zig` even has a
test called "quarantine and rate_limit are not interchangeable". The proof only
used tag equality, so nothing executed wrongly — but the ordinal space it
declared was wrong, in the file whose output becomes evidence.

The `policy_ir` / Rust pair is a genuinely different space: it is the FFI
`requested_action` ABI, it has `pass` and `escalate`, and its `BLOCK` is 4 while
the frozen space calls 2 `BLOCK`. That space was not declared anywhere; it is now
`pep_request_action_ordinals` in `contracts/operator_contract_v1.json`.

This module is what keeps the four declarations honest against each other.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contracts" / "operator_contract_v1.json"

CANONICAL_SPACE = {
    "src/contract/canonical_event.zig": "PolicyAction",
    "src/forensic/policy_contract.zig": "PolicyAction",
    "src/policy/policy_engine.zig": "EnforcementAction",
    "src/tests/proofs/pep_enforcement_proof.zig": "EnforcementAction",
}


def _zig_enum(rel: str, name: str) -> dict[str, int]:
    text = (ROOT / rel).read_text(encoding="utf-8-sig")
    match = re.search(rf"pub const {name} = enum\(u8\) \{{(.*?)\n\}};", text, re.DOTALL)
    assert match, f"{rel}: no `pub const {name} = enum(u8)` block"
    members = re.findall(r"^\s*(\w+) = (\d+),\s*$", match.group(1), re.MULTILINE)
    assert members, f"{rel}: {name} has no explicit ordinals"
    return {k: int(v) for k, v in members}


def _rust_actions() -> dict[str, int]:
    text = (ROOT / "rust-src" / "lib.rs").read_text(encoding="utf-8-sig")
    found = dict(re.findall(r"const ACTION_(\w+): u8 = (\d+);", text))
    assert len(found) == 7, f"expected seven ACTION_* constants, found {sorted(found)}"
    return {k.lower(): int(v) for k, v in found.items()}


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


@pytest.mark.parametrize("rel,name", sorted(CANONICAL_SPACE.items()))
def test_canonical_action_space_is_identical_everywhere(rel: str, name: str) -> None:
    declared = {k.lower(): v for k, v in _contract()["policy_action_ordinals"].items()}
    assert _zig_enum(rel, name) == declared, (
        f"{rel} {name} does not match policy_action_ordinals; this is the space "
        "where swapping quarantine/rate_limit is a mis-recorded verdict"
    )


def test_the_pep_request_space_matches_rust_and_the_contract() -> None:
    declared = {k.lower(): v for k, v in _contract()["pep_request_action_ordinals"].items()}
    zig = _zig_enum("src/policy/policy_ir.zig", "Action")
    rust = _rust_actions()
    assert zig == declared, f"policy_ir.Action drifted from the contract: {zig}"
    assert rust == declared, f"rust ACTION_* drifted from the contract: {rust}"


def test_the_two_spaces_cannot_be_confused_by_ordinal() -> None:
    """The whole reason the contract exists: BLOCK is 2 in one space, 4 in the other."""
    contract = _contract()
    frozen = contract["policy_action_ordinals"]
    ffi = contract["pep_request_action_ordinals"]
    assert frozen["BLOCK"] != ffi["BLOCK"], (
        "the frozen and FFI spaces now agree on BLOCK; the conversion between them "
        "still must exist, so re-derive both and keep the note truthful"
    )
    assert frozen["QUARANTINE"] != ffi["RATE_LIMIT"] or frozen["RATE_LIMIT"] != ffi["QUARANTINE"], (
        "cross-space values collide in both directions"
    )
    # The concrete collision a cast would cause: frozen 4 is QUARANTINE but FFI 4
    # is BLOCK, and frozen 2 is BLOCK but FFI 2 is ALERT.
    assert ffi["BLOCK"] == frozen["RATE_LIMIT"]
    assert ffi["ALERT"] == frozen["BLOCK"]


def test_no_code_casts_an_action_into_a_canonical_byte() -> None:
    """A `u8` cast between spaces is the bug; a named converter is the fix."""
    banned: list[str] = []
    for path in (ROOT / "src").rglob("*.zig"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if re.search(r"policy_action\s*=\s*@intFromEnum\(", stripped):
                banned.append(f"{path.relative_to(ROOT).as_posix()}:{lineno}")
            if re.search(r"@enumFromInt\([^)]*\.action\b", stripped):
                banned.append(f"{path.relative_to(ROOT).as_posix()}:{lineno}")
    assert not banned, (
        "an action ordinal is being reinterpreted as a canonical policy_action "
        f"byte: {banned} - use the converter in src/policy/policy_contract.zig"
    )


def test_the_named_converter_still_exists() -> None:
    text = (ROOT / "src" / "policy" / "policy_contract.zig").read_text(encoding="utf-8-sig")
    assert "fn fromCanonicalAction(" in text
    assert "fn toCanonicalAction(" in text
    assert "intToEnum(canonical.PolicyAction" in text, (
        "the conversion must go through an enum lookup that can fail, not a cast"
    )
