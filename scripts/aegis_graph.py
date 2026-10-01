"""Generate or watch a verified AEGIS forensic evidence graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import networkx as nx
from pyvis.network import Network

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "reports" / "forensic_evidence_graph.html"


def query_forensic_records(limit: int = 500) -> dict:
    bounded = max(1, min(int(limit), 1000))
    # The daemon returns byte-budgeted pages; `--all` follows the continuation
    # cursor so the graph sees a complete result set instead of the first page.
    command = [
        sys.executable, str(ROOT / "tools" / "aegisctl.py"),
        "forensics", "list", "--limit", str(bounded), "--all", "--json",
    ]
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"Forensic control query failed: {detail}")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Forensic control query returned invalid JSON: {exc}") from exc
    if document.get("available") is not True:
        raise RuntimeError("Forensic control query unavailable; graph not generated")
    if document.get("integrity") != "ok" or document.get("verified") is not True:
        raise RuntimeError("Forensic evidence is not verified; graph not generated")
    if document.get("truncated") is True:
        raise RuntimeError(
            "Forensic page budget was exhausted before the result set was "
            "complete; refusing to render a partial graph"
        )
    records = document.get("records")
    if not isinstance(records, list):
        raise RuntimeError("Forensic control response has no records array")
    return document


def generate_forensic_graph(output_file: Path, limit: int) -> tuple[int, int, int]:
    document = query_forensic_records(limit)
    records = [
        item for item in document["records"]
        if isinstance(item, dict) and item.get("verified") is True
    ]
    graph = nx.DiGraph()
    graph.add_node(
        "AEGIS_NIDS", label="AEGIS NIDS", color="#22c55e", size=34,
        title="Verified forensic evidence root",
    )
    for item in records:
        seq = item.get("record_seq", "unknown")
        event_id = item.get("event_id", "unknown")
        rule_id = item.get("rule_id", "unknown")
        source = item.get("source", "unknown")
        # The daemon owns the canonical source space and names it; render that
        # name instead of a bare ordinal so the graph, the CLI and the wire
        # contract all name the same sensor.
        source_name = item.get("source_name") or f"source_{source}"
        payload_len = item.get("payload_len", 0)
        source_node = f"source:{source}"
        event_node = f"event:{seq}:{event_id}"
        rule_node = f"rule:{rule_id}"
        record_node = f"record:{seq}"
        graph.add_node(
            source_node, label=f"Source {source_name}", color="#60a5fa", shape="ellipse",
            title=f"source={source} ({item.get('source_space', 'canonical')})",
        )
        graph.add_node(event_node, label=f"Event {event_id}", color="#fbbf24", shape="dot")
        graph.add_node(rule_node, label=f"Rule {rule_id}", color="#fb7185", shape="square")
        graph.add_node(
            record_node, label=f"Record {seq}", color="#a78bfa", shape="box",
            title=f"record_seq={seq}; payload_len={payload_len}; verified=true",
        )
        graph.add_edge(source_node, event_node, label="observed")
        graph.add_edge(event_node, rule_node, label="matched")
        graph.add_edge(rule_node, record_node, label="sealed")
        graph.add_edge(record_node, "AEGIS_NIDS", label="evidence")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    net = Network(height="850px", width="100%", directed=True, heading="AEGIS Forensic Evidence Graph")
    net.from_nx(graph)
    net.set_options("""
    {"interaction":{"hover":true,"navigationButtons":true},
     "physics":{"enabled":true,"stabilization":{"iterations":300}},
     "edges":{"arrows":{"to":{"enabled":true}}}}
    """)
    net.save_graph(str(output_file))
    print(
        f"Graph refreshed: {output_file} | source=control-daemon forensics.list "
        f"integrity={document['integrity']} verified={document['verified']} "
        f"records={len(records)} nodes={graph.number_of_nodes()} edges={graph.number_of_edges()}",
        flush=True,
    )
    return len(records), graph.number_of_nodes(), graph.number_of_edges()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate/watch AEGIS forensic evidence graph from the control daemon"
    )
    parser.add_argument("--limit", type=int, default=500, help="Maximum records; capped at 1000")
    parser.add_argument("--interval", type=float, default=3.0, help="Watch refresh interval in seconds")
    parser.add_argument("--watch", action="store_true", help="Refresh the graph continuously")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--log", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.log is not None:
        parser.error("--log is retired; Graph requires the control-daemon forensic query")
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    try:
        if not args.watch:
            generate_forensic_graph(args.output, args.limit)
            return 0
        print(f"Graph watch started: interval={args.interval:g}s; press Ctrl+C to stop", flush=True)
        while True:
            generate_forensic_graph(args.output, args.limit)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Graph watch stopped", flush=True)
        return 0
    except (OSError, RuntimeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
