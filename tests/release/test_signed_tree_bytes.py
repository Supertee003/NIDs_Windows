"""SIGNED-TREE-001: a signed release tree must survive git byte-for-byte.

``signatures.json`` signs the bytes of ``SHA256SUMS``, and ``SHA256SUMS`` lists a
digest per shipped file. If git rewrites line endings between the working tree
and the committed blob, the signature verifies on the machine that signed it and
fails on every clone -- which is the only machine that matters for a release.

Two pins:

* every tree carrying ``signatures.json`` stores ``SHA256SUMS`` such that the
  **committed** bytes hash to that record's ``signed_digest``;
* ``.gitattributes`` keeps ``release/**`` out of end-of-line translation.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RELEASE_ROOT = REPO / "release" / "T20-final"


def _git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, check=True
    ).stdout


def _signed_trees() -> list[Path]:
    if not RELEASE_ROOT.is_dir():
        return []
    trees = []
    for tree in sorted(RELEASE_ROOT.iterdir()):
        sig = tree / "signatures.json"
        if not sig.is_file():
            continue
        try:
            record = json.loads(sig.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if record.get("signed_digest"):
            trees.append(tree)
    return trees


@pytest.mark.skipif(not _signed_trees(), reason="no signed release tree in this checkout")
def test_committed_sha256sums_hashes_to_the_signed_digest():
    failures = []
    for tree in _signed_trees():
        record = json.loads((tree / "signatures.json").read_text(encoding="utf-8"))
        rel = f"release/T20-final/{tree.name}/SHA256SUMS"
        try:
            blob = _git("show", f"HEAD:{rel}")
        except subprocess.CalledProcessError:
            blob = _git("show", f":{rel}")
        actual = hashlib.sha256(blob).hexdigest().upper()
        expected = str(record["signed_digest"]).upper()
        if actual != expected:
            failures.append(
                f"{rel}: committed bytes hash to {actual[:16]}..., "
                f"signature names {expected[:16]}..."
            )
    assert not failures, "\n".join(failures)


def test_release_trees_are_stored_verbatim():
    """`-text` is what keeps the digest above true after a fresh clone."""
    attr = subprocess.run(
        ["git", "check-attr", "text", "--", "release/T20-final"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert attr.endswith("text: unset"), (
        "release/** must disable EOL translation or a signed tree changes bytes "
        f"when committed/cloned; git check-attr said {attr!r}"
    )
