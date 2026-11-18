"""SIGN-RELEASE-001: the signer must satisfy the gate, and must fail closed.

`tools/sign_release.py` exists because nothing in the repository could produce
the artifact the release-signature gate demands. The tests below assert against
the gate's own evaluator (`tools/final_audit.evaluate_signature`), not against a
copy of its rules: a signer that satisfies a restatement of the requirement would
prove nothing.

Fail-closed cases are covered too: a tampered SHA256SUMS, a flipped signature
byte, a missing record and a mismatched algorithm must all be rejected.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import final_audit  # noqa: E402
import sign_release  # noqa: E402

pytest.importorskip("cryptography")


@pytest.fixture()
def release_tree(tmp_path: Path) -> Path:
    tree = tmp_path / "release" / "T99-final" / "deadbee"
    tree.mkdir(parents=True)
    (tree / "SHA256SUMS").write_text("abc123  bin/aegis_nids.exe\n", encoding="utf-8")
    (tree / "signatures.json").write_text(
        json.dumps({"policy": "configs/Rules.json", "commit": "deadbee", "shipped_files": 1}),
        encoding="utf-8",
    )
    return tree


def _key(tmp_path: Path) -> Path:
    key = tmp_path / ".keys" / "release.ed25519"
    assert sign_release.generate_key(key) == 0
    return key


def _gate(tree: Path, repo: Path) -> dict:
    facts = []
    sums = tree / "SHA256SUMS"
    data = json.loads((tree / "signatures.json").read_text(encoding="utf-8"))
    verified = final_audit.verify_detached_signature(
        data, sums.read_bytes(), data.get("public_key")
    )
    facts.append({
        "path": str((tree / "signatures.json").relative_to(repo)),
        "signature": data.get("signature"),
        "public_key": data.get("public_key"),
        "algorithm": data.get("algorithm"),
        "signed_digest": data.get("signed_digest"),
        "actual_digest": final_audit._sha256(sums) if sums.exists() else None,
        "commit": data.get("commit"),
        "signed_at": data.get("signed_at"),
        # This test is about signature bytes, not history: the tree is a tmp
        # fixture whose commit is not a real one, so stand in for what
        # collect_release_facts() would report for a current commit. The
        # history rules have their own pins in test_release_board.py.
        "commit_time": "2026-11-16T00:00:00",
        "commit_in_history": True,
        "commit_contains_runtime": True,
        "runtime_commit": "deadbee",
        **verified,
        "signature_error": verified.get("error"),
    })
    return final_audit.evaluate_signature(facts)


def test_a_signed_tree_passes_the_release_gate(release_tree: Path, tmp_path: Path) -> None:
    key = _key(tmp_path)
    assert sign_release.sign(release_tree, key) == 0
    verdict = _gate(release_tree, tmp_path)
    assert verdict["ok"], verdict["detail"]
    assert "ed25519" in verdict["detail"]


def test_signing_preserves_the_reference_fields(release_tree: Path, tmp_path: Path) -> None:
    key = _key(tmp_path)
    assert sign_release.sign(release_tree, key) == 0
    record = json.loads((release_tree / "signatures.json").read_text(encoding="utf-8"))
    assert record["commit"] == "deadbee"
    assert record["policy"] == "configs/Rules.json"
    assert record["signed_file"] == "SHA256SUMS"
    assert len(base64.b64decode(record["public_key"])) == 32


def test_verify_accepts_a_good_signature(release_tree: Path, tmp_path: Path) -> None:
    key = _key(tmp_path)
    assert sign_release.sign(release_tree, key) == 0
    assert sign_release.verify(release_tree) == 0


def test_verify_rejects_a_tampered_sums_file(release_tree: Path, tmp_path: Path) -> None:
    key = _key(tmp_path)
    assert sign_release.sign(release_tree, key) == 0
    (release_tree / "SHA256SUMS").write_text("tampered  bin/aegis_nids.exe\n", encoding="utf-8")
    assert sign_release.verify(release_tree) == 3
    assert not _gate(release_tree, tmp_path)["ok"]


def test_verify_rejects_a_flipped_signature(release_tree: Path, tmp_path: Path) -> None:
    key = _key(tmp_path)
    assert sign_release.sign(release_tree, key) == 0
    record_path = release_tree / "signatures.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    raw = bytearray(base64.b64decode(record["signature"]))
    raw[0] ^= 0xFF
    record["signature"] = base64.b64encode(bytes(raw)).decode("ascii")
    record_path.write_text(json.dumps(record), encoding="utf-8")
    assert sign_release.verify(release_tree) == 3
    assert not _gate(release_tree, tmp_path)["ok"]


def test_gate_rejects_a_valid_signature_without_owner_trust_anchor(
    release_tree: Path, tmp_path: Path,
) -> None:
    key = _key(tmp_path)
    assert sign_release.sign(release_tree, key) == 0
    data = json.loads((release_tree / "signatures.json").read_text(encoding="utf-8"))
    verified = final_audit.verify_detached_signature(data, (release_tree / "SHA256SUMS").read_bytes())
    assert verified["cryptographic_verified"] is True
    assert verified["trust_anchor_verified"] is False


def test_verify_rejects_an_unsigned_record(release_tree: Path) -> None:
    assert sign_release.verify(release_tree) == 3


def test_the_gate_rejects_the_unsigned_reference_record(release_tree: Path, tmp_path: Path) -> None:
    """The record that shipped in the repository is exactly this shape."""
    verdict = _gate(release_tree, tmp_path)
    assert not verdict["ok"]
    assert "reference record" in verdict["detail"]


def test_generate_key_refuses_to_overwrite(tmp_path: Path) -> None:
    key = _key(tmp_path)
    assert sign_release.generate_key(key) == 2


def test_the_private_key_is_never_printed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = _key(tmp_path)
    printed = capsys.readouterr().out
    secret = key.read_bytes()
    assert secret.hex() not in printed.lower()
    assert base64.b64encode(secret).decode("ascii") not in printed
