#!/usr/bin/env python3
"""Verify a signed SHA256SUMS digest against the bytes in this checkout.

REL-EOL-DIGEST-001 (2026-11-17). The v2.0.0 signature covers the CRLF form of
``release/T20-final/9ebee9b/SHA256SUMS`` (9F87BF36...). Git stores the blob with
LF line endings and hashes to 668C26B1..., so a clean checkout with
``core.autocrlf=false`` computes a different digest for byte-identical content.
This tool accepts either form and prints which one matched, instead of
reporting a false signature failure or a false pass.

Usage:
    python tools/verify_release_digest.py
    python tools/verify_release_digest.py --tree release/T20-final/9ebee9b
    python tools/verify_release_digest.py --json

Exit 0 when the file matches the signed digest as stored or after LF->CRLF
normalisation; exit 1 otherwise. Read-only: nothing is written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_TREE = REPO / "release" / "T20-final" / "9ebee9b"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def lf_to_crlf(data: bytes) -> bytes:
    """Return the CRLF form of text bytes, whatever their current EOL mode."""
    return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


def verify_tree(tree: Path) -> dict:
    """Compare SHA256SUMS with the signed digest. Returns a result dict."""
    sig_path = tree / "signatures.json"
    sums_path = tree / "SHA256SUMS"
    result: dict = {
        "tree": str(tree),
        "signatures": str(sig_path),
        "sha256sums": str(sums_path),
        "ok": False,
        "matched": None,
        "signed_digest": None,
        "stored_digest": None,
        "crlf_digest": None,
        "error": None,
    }
    if not sig_path.is_file():
        result["error"] = f"missing {sig_path}"
        return result
    if not sums_path.is_file():
        result["error"] = f"missing {sums_path}"
        return result
    try:
        sig = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result["error"] = f"cannot read signatures.json: {exc}"
        return result

    signed = str(sig.get("signed_digest") or "").upper()
    result["signed_digest"] = signed or None
    if not signed:
        result["error"] = "signatures.json has no signed_digest"
        return result

    data = sums_path.read_bytes()
    stored = digest(data)
    crlf = digest(lf_to_crlf(data))
    result["stored_digest"] = stored
    result["crlf_digest"] = crlf

    if stored == signed:
        result["ok"] = True
        result["matched"] = "as-stored"
    elif crlf == signed:
        result["ok"] = True
        result["matched"] = "crlf-normalized"
        result["note"] = (
            "checkout has LF line endings; the signed digest covers the CRLF "
            "form. Content matches, only the checkout EOL differs."
        )
    else:
        result["error"] = "neither the stored nor the CRLF-normalised digest matches"
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="verify a signed SHA256SUMS digest")
    ap.add_argument("--tree", default=str(DEFAULT_TREE),
                    help="release tree containing SHA256SUMS and signatures.json")
    ap.add_argument("--json", action="store_true", help="emit the result as JSON")
    args = ap.parse_args(argv)

    result = verify_tree(Path(args.tree))
    if args.json:
        print(json.dumps(result, indent=1, sort_keys=True))
    else:
        print(f"tree: {result['tree']}")
        print(f"signed: {result['signed_digest']}")
        print(f"stored: {result['stored_digest']}")
        print(f"crlf  : {result['crlf_digest']}")
        if result["ok"]:
            print(f"MATCH ({result['matched']})")
            if result.get("note"):
                print(result["note"])
        else:
            print(f"MISMATCH: {result['error']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
