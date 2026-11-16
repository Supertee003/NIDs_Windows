"""REL-EOL-DIGEST-001: the signed digest must verify across checkout EOL modes.

The v2.0.0 signature covers the CRLF form of SHA256SUMS; the git blob stores LF.
These pins hold the verifier's contract:

* the shipped tree verifies and says which form matched;
* an LF checkout of byte-identical content verifies as `crlf-normalized`,
  not as a false mismatch;
* a tampered line fails;
* a missing signature fails.

Read-only against the tracked tree; the synthetic trees live in tmp_path.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import verify_release_digest as vrd  # noqa: E402

TREE = ROOT / "release" / "T20-final" / "9ebee9b"


def _synthetic(tmp_path: Path, sums_bytes: bytes) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copy2(TREE / "signatures.json", tree / "signatures.json")
    (tree / "SHA256SUMS").write_bytes(sums_bytes)
    return tree


def test_shipped_tree_verifies_and_names_the_matched_form():
    result = vrd.verify_tree(TREE)
    assert result["ok"] is True, result["error"]
    assert result["matched"] in {"as-stored", "crlf-normalized"}
    sig = json.loads((TREE / "signatures.json").read_text(encoding="utf-8"))
    assert result["signed_digest"] == sig["signed_digest"].upper()


def test_lf_checkout_verifies_as_crlf_normalized(tmp_path):
    raw = (TREE / "SHA256SUMS").read_bytes()
    lf = raw.replace(b"\r\n", b"\n")
    assert lf != raw, "fixture is already LF; the EOL branch would not be exercised"
    result = vrd.verify_tree(_synthetic(tmp_path, lf))
    assert result["ok"] is True, result["error"]
    assert result["matched"] == "crlf-normalized"
    assert result["stored_digest"] != result["signed_digest"]
    assert result["crlf_digest"] == result["signed_digest"]


def test_tampered_line_fails(tmp_path):
    raw = (TREE / "SHA256SUMS").read_bytes()
    tampered = raw + b"0" * 64 + b"  planted\n"
    result = vrd.verify_tree(_synthetic(tmp_path, tampered))
    assert result["ok"] is False
    assert result["matched"] is None
    assert "matches" in result["error"]


def test_missing_signature_is_an_error(tmp_path):
    tree = tmp_path / "bare"
    tree.mkdir()
    (tree / "SHA256SUMS").write_bytes(b"x")
    result = vrd.verify_tree(tree)
    assert result["ok"] is False
    assert "signatures.json" in result["error"]


def test_main_exit_code_reflects_the_verdict(tmp_path):
    assert vrd.main(["--tree", str(TREE), "--json"]) == 0
    raw = (TREE / "SHA256SUMS").read_bytes()
    other = _synthetic(tmp_path, raw + b"junk\n")
    assert vrd.main(["--tree", str(other)]) == 1
