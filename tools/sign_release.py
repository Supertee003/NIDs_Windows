#!/usr/bin/env python3
"""Sign and verify a release tree's SHA256SUMS (release-signature gate).

The release gate (`release_signature` in `tools/final_audit.py`) wants a
`signatures.json` beside a `SHA256SUMS` file, carrying:

  * `signature`      — the detached signature, base64,
  * `public_key`     — base64 of the raw 32-byte ed25519 public key,
  * `signed_digest`  — SHA-256 of the `SHA256SUMS` bytes, uppercase hex,
  * `algorithm`      — `ed25519`.

and it recomputes `actual_digest = sha256(SHA256SUMS)` and requires it to equal
`signed_digest`. This tool produces exactly that, and verifies it.

What the signature covers: the **bytes of the `SHA256SUMS` file**, which is what
the digest names. If that file changes, the digest changes, and the gate says so
before any signature check happens.

Key custody is the owner's:

  * `--generate-key` writes a private key file to a path you choose, with
    restrictive permissions, and prints **only** the public key and the path.
    The private key is never printed, never logged, and never leaves the machine.
  * `--sign` reads that file, uses it, and prints only the public key and the
    digest it signed.
  * Nothing here commits a key. A private key must not be tracked.

Usage:
    python tools/sign_release.py --generate-key .keys/aegis-release.ed25519
    python tools/sign_release.py --sign --dir release/T20-final/<commit> \\
        --key-file .keys/aegis-release.ed25519
    python tools/sign_release.py --verify --dir release/T20-final/<commit>

Exit codes: 0 ok, 2 usage/state error, 3 verification failed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
except ImportError:  # pragma: no cover - reported, not hidden
    print("error: the 'cryptography' package is required for signing", file=sys.stderr)
    raise SystemExit(2)

SUMS_NAME = "SHA256SUMS"
SIGNATURES_NAME = "signatures.json"
ALGORITHM = "ed25519"

# Fields this tool owns. Anything else in signatures.json (policy, commit,
# shipped_files, ...) is preserved untouched.
OWNED = ("signature", "public_key", "algorithm", "signed_digest", "signed_file", "signed_at")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def _public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Accept a PEM key or a raw 32-byte seed written as hex or base64."""
    data = path.read_bytes()
    # `--generate-key` writes the raw 32-byte seed, which is not text at all.
    if len(data) == 32:
        return Ed25519PrivateKey.from_private_bytes(data)
    text = data.decode("ascii", errors="ignore").strip()
    if "BEGIN" in text:
        return serialization.load_pem_private_key(data, password=None)  # type: ignore[return-value]

    raw: bytes | None = None
    decoders = (("hex", bytes.fromhex), ("base64", lambda t: base64.b64decode(t, validate=True)))
    for _name, decoder in decoders:
        try:
            candidate = decoder(text)
        except Exception:  # noqa: BLE001 - try the next encoding
            continue
        if len(candidate) == 32:
            raw = candidate
            break
    if raw is None:
        raise SystemExit(
            f"error: {path} is not a PEM key and not a 32-byte ed25519 seed in hex or base64"
        )
    return Ed25519PrivateKey.from_private_bytes(raw)


def generate_key(path: Path) -> int:
    if path.exists():
        print(f"error: {path} already exists; refusing to overwrite a signing key", file=sys.stderr)
        return 2
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(seed)
    print(f"private key written to {path} (mode 600) - back it up offline, never commit it")
    print(f"public key: {_public_key_b64(key)}")
    return 0


def sign(tree: Path, key_file: Path) -> int:
    sums = tree / SUMS_NAME
    if not sums.is_file():
        print(f"error: {sums} does not exist; assemble the release tree first", file=sys.stderr)
        return 2
    key = load_private_key(key_file)
    data = sums.read_bytes()
    signature = key.sign(data)
    digest = hashlib.sha256(data).hexdigest().upper()

    record_path = tree / SIGNATURES_NAME
    record: dict = {}
    if record_path.is_file():
        record = json.loads(record_path.read_text(encoding="utf-8"))
    for field in OWNED:
        record.pop(field, None)
    record.update({
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": _public_key_b64(key),
        "algorithm": ALGORITHM,
        "signed_digest": digest,
        "signed_file": SUMS_NAME,
        "signed_at": __import__("datetime").datetime.now().astimezone().isoformat(timespec="seconds"),
    })
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(f"signed {sums} -> {record_path}")
    print(f"algorithm : {ALGORITHM}")
    print(f"digest    : {digest}")
    print(f"public key: {record['public_key']}")
    return 0


def verify(tree: Path) -> int:
    sums = tree / SUMS_NAME
    record_path = tree / SIGNATURES_NAME
    for path in (sums, record_path):
        if not path.is_file():
            print(f"error: {path} is missing", file=sys.stderr)
            return 2
    record = json.loads(record_path.read_text(encoding="utf-8"))
    missing = [f for f in ("signature", "public_key", "signed_digest") if not record.get(f)]
    if missing:
        print(f"error: {record_path} lacks {missing}", file=sys.stderr)
        return 3
    if str(record.get("algorithm") or "").lower() != ALGORITHM:
        print(f"error: unsupported algorithm {record.get('algorithm')!r}", file=sys.stderr)
        return 3

    data = sums.read_bytes()
    actual = hashlib.sha256(data).hexdigest().upper()
    if actual != str(record["signed_digest"]).upper():
        print(f"FAIL: SHA256SUMS hashes to {actual[:16]}... but the record signs "
              f"{str(record['signed_digest'])[:16]}...", file=sys.stderr)
        return 3

    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(record["public_key"]))
    try:
        public.verify(base64.b64decode(record["signature"]), data)
    except Exception:  # noqa: BLE001 - any failure is a failed verification
        print("FAIL: the signature does not verify over SHA256SUMS", file=sys.stderr)
        return 3
    print(f"PASS: {SIGNATURES_NAME} signs {SUMS_NAME} ({actual[:16]}...) with an {ALGORITHM} key")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--generate-key", metavar="PATH",
                        help="write a new ed25519 private key to PATH (prints only the public key)")
    parser.add_argument("--sign", action="store_true", help="sign DIR/SHA256SUMS")
    parser.add_argument("--verify", action="store_true", help="verify DIR/signatures.json")
    parser.add_argument("--dir", metavar="PATH", help="release tree directory")
    parser.add_argument("--key-file", metavar="PATH", help="ed25519 private key (PEM, hex or base64)")
    args = parser.parse_args(argv)

    if args.generate_key:
        return generate_key(Path(args.generate_key))
    if args.sign:
        if not args.dir or not args.key_file:
            parser.error("--sign needs --dir and --key-file")
        return sign(Path(args.dir), Path(args.key_file))
    if args.verify:
        if not args.dir:
            parser.error("--verify needs --dir")
        return verify(Path(args.dir))
    parser.error("nothing to do: pass --generate-key, --sign or --verify")
    return 2


if __name__ == "__main__":
    sys.exit(main())
