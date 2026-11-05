"""TAXII 2.1 push for AEGIS STIX bundles (transport only, advisory data).

Sends a STIX 2.1 bundle (for example the file produced by
``tools/stix_export.py``) to a TAXII 2.1 collections objects endpoint
(``POST <base>/collections/<id>/objects/``) and expects ``202 Accepted``.

Fail-closed rules, deliberately strict because this is a new surface:

- Configuration comes only from environment variables (credentials are never
  command-line arguments and never appear in diagnostics).
- Plain ``http://`` targets are refused unless ``--allow-http`` is passed; the
  flag is loopback-only and exists for local integration tests.
- The bundle must be structurally valid before anything is transmitted.
- Any transport failure or non-202 status exits 2 with one diagnostic line;
  the diagnostic never contains credentials or query strings.

TAXII contract notes: the request body is the default interchange envelope
(``{"id": "bundle--...", "objects": [...]}``) with
``Content-Type: application/stix+json;version=2.1`` and
``Accept: application/taxii+json;version=2.1``; the canonical success status
of an add is ``202 Accepted`` (TAXII 2.1, add STIX objects).

Import hygiene: importing this module performs no I/O and binds nothing; the
network happens only inside ``push_bundle``.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import stix_export  # same directory; advisory mapping + loader, no side effects

ENV_URL = "AEGIS_TAXII_URL"
ENV_COLLECTION = "AEGIS_TAXII_COLLECTION"
ENV_USERNAME = "AEGIS_TAXII_USERNAME"
ENV_PASSWORD = "AEGIS_TAXII_PASSWORD"

STIX_CONTENT_TYPE = "application/stix+json;version=2.1"
TAXII_ACCEPT = "application/taxii+json;version=2.1"

ExportError = stix_export.ExportError


class TaxiiError(RuntimeError):
    """Raised when the push cannot proceed or the server misbehaves."""


# ---------------------------------------------------------------------------
# URL + auth construction (pure, unit-testable)
# ---------------------------------------------------------------------------

def objects_url(base_url: str, collection_id: str) -> str:
    """Build `<base>/collections/<id>/objects/` from a TAXII root URL."""
    base = base_url.strip().rstrip("/")
    if not base:
        raise TaxiiError("empty TAXII base URL")
    if "://" not in base:
        raise TaxiiError("TAXII base URL has no scheme")
    collection = (collection_id or "").strip()
    if not collection:
        raise TaxiiError("TAXII collection id is empty")
    if any(c in collection for c in ("/", "?", "#", " ", "&")):
        raise TaxiiError("TAXII collection id contains a URL fragment")
    if "/collections" in base:
        raise TaxiiError("base already includes a collection path; pass the TAXII root")
    return f"{base}/collections/{collection}/objects/"


def basic_auth_header(username: str, password: str) -> str:
    """TAXII 2.1 commonly authenticates with HTTP Basic over TLS."""
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# Validation + transmission
# ---------------------------------------------------------------------------

def validate_bundle_payload(bundle: Dict[str, Any]) -> None:
    """Refuse to transmit anything that is not a structurally valid bundle."""
    if not isinstance(bundle, dict):
        raise TaxiiError("payload is not a JSON object")
    if bundle.get("type") != "bundle":
        raise TaxiiError("payload is not a STIX bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise TaxiiError("payload has no non-empty objects array")
    errors = stix_export.validate_bundle(bundle)
    if errors:
        raise TaxiiError("bundle validation failed: " + "; ".join(errors[:5]))


def _read_bundle_input(file_path: Optional[str], want_daemon: bool) -> Dict[str, Any]:
    """Bundle from a .stix.json file, or from a live read-only xdr.list query."""
    if file_path:
        return stix_export.load_view_file(Path(file_path))
    if want_daemon:
        view = stix_export.load_view_daemon()
        return stix_export.build_bundle(view)
    raise TaxiiError("no input source selected")


def push_bundle(bundle: Dict[str, Any], base_url: str, collection_id: str,
                username: Optional[str] = None, password: Optional[str] = None,
                timeout: float = 30.0) -> Tuple[int, str]:
    """POST the envelope; returns (status, response text).

    Raises TaxiiError on transport failure or any status other than 202.
    Credentials are optional (HTTP Basic only when both are present).
    """
    validate_bundle_payload(bundle)
    url = objects_url(base_url, collection_id)

    headers: Dict[str, str] = {
        "Content-Type": STIX_CONTENT_TYPE,
        "Accept": TAXII_ACCEPT,
    }
    if username and password:
        headers["Authorization"] = basic_auth_header(username, password)

    data = json.dumps({"id": bundle.get("id"), "objects": bundle["objects"]},
                      ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise TaxiiError(f"server rejected the push: HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise TaxiiError(f"transport failure: {exc}") from exc
    if status != 202:
        raise TaxiiError(f"unexpected success status {status}; TAXII 2.1 expects 202")
    return status, body


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Push a STIX 2.1 bundle to a TAXII 2.1 collection (fail-closed).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="STIX bundle .stix.json file")
    src.add_argument("--daemon", action="store_true",
                     help="query xdr.list live and push the mapped bundle")
    ap.add_argument("--allow-http", action="store_true",
                    help="permit plain http:// for a loopback test server only")
    args = ap.parse_args(argv)

    base = os.environ.get(ENV_URL, "")
    collection = os.environ.get(ENV_COLLECTION, "")
    if args.allow_http:
        if "localhost" not in base and "127.0.0.1" not in base:
            print("TAXII_PUSH_ERROR: --allow-http is loopback-only", file=sys.stderr)
            return 2
    elif not base.startswith("https://"):
        print(f"TAXII_PUSH_ERROR: {ENV_URL} must be https:// (unset denies the push)",
              file=sys.stderr)
        return 2

    try:
        bundle = _read_bundle_input(args.file, args.daemon)
        status, _ = push_bundle(bundle, base, collection,
                                username=os.environ.get(ENV_USERNAME),
                                password=os.environ.get(ENV_PASSWORD))
        print(f"PUSHED status={status} objects={len(bundle['objects'])}")
        return 0
    except TaxiiError as exc:
        print(f"TAXII_PUSH_ERROR: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:  # json.JSONDecodeError on a malformed --file
        print(f"TAXII_PUSH_ERROR: malformed bundle file: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
