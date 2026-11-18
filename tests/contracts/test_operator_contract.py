"""CONTRACT-OPERATOR-001: the operator contract had no reader, and one of its
claimants was stale.

`contracts/operator_contract_v1.json` declares the two ordinal spaces an operator
compares (`PolicyAction` and `PepDecision`) and states the rule that makes it
worth writing down:

    "PolicyAction and PepDecision are different namespaces; their BLOCK values
     must not be compared directly."

Nothing in the repository read it. Measured against the code, two things were
wrong:

* `pep_decision_ordinals` listed six values (ALLOW..DROP) while the forensic
  `PepDecision` in `src/forensic/integration_contract.zig` had four: `escalate`
  (4) and `drop` (5) — the two the PEP assessment path actually returns — had no
  member there. The live enum in `src/policy/pep_bindings.zig` and the Rust
  `DECISION_*` constants both have six, so the forensic copy was the odd one out
  and its own inline test passed by checking only the shared four.
* `shared/protocol/protocol_version.json` was also unread; its magic, version,
  header size and max payload are hard-coded in `shared/wire/wire_codec.py`.

This module reads the JSON and compares it to the code in five places, so the
file is a contract again rather than a description.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
OPERATOR = ROOT / "contracts" / "operator_contract_v1.json"
PROTOCOL_VERSION_REL = "shared/protocol/protocol_version.json"
PROTOCOL_VERSION = ROOT / PROTOCOL_VERSION_REL
WIRE_CODEC = ROOT / "shared" / "wire" / "wire_codec.py"


def _operator() -> dict:
    return json.loads(OPERATOR.read_text(encoding="utf-8"))


def _zig_enum(rel: str, name: str) -> dict[str, int]:
    """Parse `pub const <name> = enum(u8) { member = N, ... };` from a Zig file."""
    text = (ROOT / rel).read_text(encoding="utf-8-sig")
    match = re.search(
        rf"pub const {name} = enum\(u8\) \{{(.*?)\}};", text, re.DOTALL
    )
    assert match, f"{rel}: no `pub const {name} = enum(u8)` found"
    members = dict(re.findall(r"(\w+)\s*=\s*(\d+)", match.group(1)))
    assert members, f"{rel}: {name} has no explicit ordinals"
    return {k: int(v) for k, v in members.items()}


def _rust_decisions() -> dict[str, int]:
    text = (ROOT / "rust-src" / "lib.rs").read_text(encoding="utf-8-sig")
    found = dict(re.findall(r"const DECISION_(\w+): u8 = (\d+);", text))
    assert found, "rust-src/lib.rs no longer declares DECISION_* ordinals"
    return {k.lower(): int(v) for k, v in found.items()}


def _json_space(key: str) -> dict[str, int]:
    space = _operator()[key]
    return {k.lower(): int(v) for k, v in space.items()}


def test_policy_actions_match_both_zig_definitions() -> None:
    declared = _json_space("policy_action_ordinals")
    for rel in ("src/contract/canonical_event.zig", "src/forensic/policy_contract.zig"):
        code = _zig_enum(rel, "PolicyAction")
        assert code == declared, (
            f"{rel} PolicyAction ordinals drifted from "
            f"contracts/operator_contract_v1.json: code={code} contract={declared}"
        )


def test_pep_decisions_match_every_implementation() -> None:
    declared = _json_space("pep_decision_ordinals")
    zig_live = _zig_enum("src/policy/pep_bindings.zig", "PepDecision")
    zig_forensic = _zig_enum("src/forensic/integration_contract.zig", "PepDecision")
    rust = _rust_decisions()
    assert zig_live == declared, f"pep_bindings differs from the contract: {zig_live}"
    assert zig_forensic == declared, (
        "the forensic copy of PepDecision differs from the contract "
        f"({zig_forensic} != {declared}); this copy is where escalate/drop went "
        "missing once"
    )
    for name, ordinal in declared.items():
        found = rust.get(name)
        # Rust also declares ACTION_* ordinals, which are a different space; only
        # the DECISION_* names are PepDecision.
        assert found is None or found == ordinal, (
            f"rust-src/lib.rs DECISION_{name.upper()} = {found}, contract says {ordinal}"
        )
    assert {"escalate", "drop"} <= set(rust), (
        "the Rust PEP no longer declares escalate/drop; the assessment path "
        "returns them, so the contract and Zig would both be wrong to keep them"
    )


def test_the_two_namespaces_do_not_share_a_block_ordinal() -> None:
    """The file's own warning, enforced: comparing them by ordinal is a bug."""
    policy = _json_space("policy_action_ordinals")["block"]
    pep = _json_space("pep_decision_ordinals")["block"]
    assert policy != pep, (
        "PolicyAction.BLOCK and PepDecision.BLOCK now share an ordinal, so the "
        "rule in contracts/operator_contract_v1.json no longer protects anything "
        "— rewrite the rule deliberately before removing this pin"
    )


def test_the_enforcement_receipt_requirements_are_still_named() -> None:
    receipt = _operator().get("enforcement_receipt") or {}
    requirements = receipt.get("confirmed_block_requirements") or []
    assert receipt.get("version") == 1
    assert requirements, "the receipt requirements list became empty"
    for text in requirements:
        assert isinstance(text, str) and text.strip()


def test_protocol_version_json_matches_the_wire_codec() -> None:
    version = json.loads(PROTOCOL_VERSION.read_text(encoding="utf-8-sig"))
    source = WIRE_CODEC.read_text(encoding="utf-8-sig")

    def const(name: str) -> int:
        found = re.search(rf"^{name}: int = (0x[0-9a-fA-F]+|\d+)", source, re.MULTILINE)
        assert found, f"{name} missing from shared/wire/wire_codec.py"
        return int(found.group(1), 0)

    assert const("WIRE_VERSION") == version["version"]
    assert const("WIRE_MAGIC") == int(version["magic"], 0)
    assert const("WIRE_HEADER_SIZE") == version["header_size"]
    assert const("WIRE_MAX_PAYLOAD") == version["max_payload"]
    assert const("EVENT_MAGIC") == int(version["canonical_event_magic"], 0)
    assert const("EVENT_VERSION") == version["canonical_event_version"]


@pytest.mark.parametrize("rel", ["contracts/operator_contract_v1.json",
                                 PROTOCOL_VERSION_REL,
                                 "shared/runtime/components.json"])
def test_every_unfixtured_contract_file_is_read_by_something(rel: str) -> None:
    """A contract with no reader is a description. Each of these must be named by
    code or a test, not only by analysis prose.

    The walk is over the working tree, not `git grep`: this test file is itself
    the first reader of some of them, and an uncommitted reader still counts.
    """
    name = Path(rel).name
    scanned = ("src", "tools", "brain", "nose", "go", "ts_policy", "shared",
               "contracts", "tests", "scripts", "installer", "configs")
    suffixes = {".py", ".zig", ".go", ".ts", ".rs", ".nsi", ".ps1"}
    readers: list[str] = []
    for top in scanned:
        base = ROOT / top
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.suffix not in suffixes or not path.is_file():
                continue
            if path == ROOT / rel:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if name in text:
                readers.append(path.relative_to(ROOT).as_posix())
    assert readers, f"{rel} has no reader in code or tests"
