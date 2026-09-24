"""Generate an operator threat graph from the canonical AEGIS event log."""
import argparse
import json
from pathlib import Path

import networkx as nx
from pyvis.network import Network

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = ROOT / "logs" / "aegis_core.ndjson"
DEFAULT_OUTPUT = ROOT / "reports" / "threat_graph.html"


def generate_threat_graph(log_file: Path = DEFAULT_LOG, output_file: Path = DEFAULT_OUTPUT) -> Path:
    graph = nx.DiGraph()
    graph.add_node("AEGIS_NIDS", label="AEGIS NIDS", color="#22c55e", size=32, title="Protected host")

    if not log_file.exists():
        raise FileNotFoundError(f"Canonical event log not found: {log_file}")

    parsed = 0
    with log_file.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed += 1
            src_ip = event.get("src_ip") or event.get("source_ip") or "unknown-source"
            rule = event.get("rule") or event.get("rule_id") or "unknown-rule"
            attack = event.get("attack_type") or event.get("event") or "event"
            policy = str(event.get("policy") or event.get("action") or "Alert")
            source_node = f"src:{src_ip}"
            rule_node = f"rule:{rule}"
            graph.add_node(source_node, label=src_ip, color="#ef4444", size=22, title=f"Source: {src_ip}")
            graph.add_node(rule_node, label=rule, color="#f59e0b", size=18, title=f"Rule: {rule} | {attack}")
            graph.add_edge(source_node, rule_node, label=policy, color="#ef4444")
            graph.add_edge(rule_node, "AEGIS_NIDS", label=policy, color="#f59e0b")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    network = Network(height="820px", width="100%", bgcolor="#0b1220", font_color="#e5e7eb", directed=True)
    network.from_nx(graph)
    network.set_options("""
    {"interaction":{"hover":true,"navigationButtons":true},"physics":{"stabilization":{"iterations":180}}}
    """)
    network.save_graph(str(output_file))
    print(f"Threat graph generated: {output_file}")
    print(f"Events parsed: {parsed}; nodes: {graph.number_of_nodes()}; edges: {graph.number_of_edges()}")
    return output_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AEGIS threat graph")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        generate_threat_graph(args.log, args.output)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
