"""Audit a `netsh wfp show state` dump for AEGIS-owned filters and their actions.

The detection-only claim has a host-side half: the deployed filter set must
contain no AEGIS filter whose action is FWP_ACTION_BLOCK. Reading that from a
dump by eye is not evidence; this tool reduces the dump to counts that can be
recorded and re-derived.

Usage:
    python tools/wfp_filter_audit.py <state.xml> [--json out.json] [--match AEGIS]

Exit codes:
    0  dump parsed and the audit report was produced
    1  dump could not be parsed
    2  --require-no-block given and an AEGIS filter uses FWP_ACTION_BLOCK
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

BLOCK_ACTION = "FWP_ACTION_BLOCK"


def _tag(element: ET.Element) -> str:
    return element.tag.split("}")[-1]


def _child_text(element: ET.Element, *path: str) -> str:
    current = element
    for part in path:
        found = None
        for child in current:
            if _tag(child) == part:
                found = child
                break
        if found is None:
            return ""
        current = found
    return (current.text or "").strip()


def load_dump(path: pathlib.Path) -> ET.Element:
    """Load a netsh state dump.

    `netsh wfp show state file=...` writes several top-level elements, so the
    document is wrapped in a synthetic root before parsing.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"<\?xml[^>]*\?>", "", text)
    return ET.fromstring("<wfp_dump>" + text + "</wfp_dump>")


def collect_filters(root: ET.Element) -> list[dict[str, str]]:
    filters: list[dict[str, str]] = []
    for item in root.iter():
        if _tag(item) != "item":
            continue
        filter_key = _child_text(item, "filterKey")
        if not filter_key:
            continue
        filters.append(
            {
                "filter_key": filter_key,
                "name": _child_text(item, "displayData", "name"),
                "action": _child_text(item, "action", "type"),
                "layer": _child_text(item, "layerKey"),
                "provider": _child_text(item, "providerKey"),
            }
        )
    return filters


def audit(filters: list[dict[str, str]], needle: str = "AEGIS") -> dict:
    needle_upper = needle.upper()
    matched = [f for f in filters if needle_upper in (f["name"] or "").upper()]
    histogram = collections.Counter(f["action"] or "(none)" for f in matched)
    blocking = [f for f in matched if f["action"] == BLOCK_ACTION]
    layers = collections.Counter(f["layer"] for f in matched)
    return {
        "needle": needle,
        "total_filters": len(filters),
        "matched_filters": len(matched),
        "action_histogram": dict(sorted(histogram.items())),
        "layers": dict(sorted(layers.items())),
        "blocking_filters": blocking,
        "blocking_filter_count": len(blocking),
        "verdict": "NO_BLOCK_FILTER" if not blocking else "BLOCK_FILTER_PRESENT",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dump", type=pathlib.Path, help="path to a netsh wfp show state XML dump")
    parser.add_argument("--json", type=pathlib.Path, default=None, help="write the report here")
    parser.add_argument("--match", default="AEGIS", help="case-insensitive filter-name substring")
    parser.add_argument(
        "--require-no-block",
        action="store_true",
        help="exit 2 when a matched filter uses FWP_ACTION_BLOCK",
    )
    args = parser.parse_args(argv)

    try:
        root = load_dump(args.dump)
    except (OSError, ET.ParseError) as exc:
        print(f"could not parse dump: {exc}", file=sys.stderr)
        return 1

    report = audit(collect_filters(root), args.match)
    report["dump"] = args.dump.name

    text = json.dumps(report, indent=2)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8", newline="\n")
    print(text)

    if args.require_no_block and report["blocking_filter_count"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
