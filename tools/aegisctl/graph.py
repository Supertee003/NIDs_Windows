"""Receipt-aware threat graph (EVT-165).

The old scripts/aegis_graph.py drew src_ip -> rule -> host edges colored
by the record's policy label alone -- an 'enforced' label with no receipt
drew the same green as a confirmed block. This rebuild colors by receipt
evidence and says so in the legend: claim-based colors for triage, with
`forensics verify` the authority (never the graph).

Reads the newest-wins canonical log (same rule as the web console and the
desktop dashboard: service path vs dev-tree path). Writes an interactive
pyvis HTML (reports/ is gitignored, so generation never dirties the tree).
On-demand only: no poll loop may call this (a full-log graph per tick
would be absurd).

networkx/pyvis are optional: import lazily so `aegisctl graph` fails
honestly when they are absent instead of breaking the CLI import.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVICE_LOG = Path(r"C:\Windows\System32\logs\aegis_core.ndjson")
DEV_LOG = REPO_ROOT / "logs" / "aegis_core.ndjson"
DEFAULT_OUT = REPO_ROOT / "reports" / "threat_graph.html"
DEFAULT_LIMIT = 500

# Edge colors by receipt evidence (legend states claim-based).
COLOR_CONFIRMED = "#22c55e"  # BLOCKED_CONFIRMED with receipt fields
COLOR_OBSERVED = "#f59e0b"  # observed/alert, no enforcement claim
COLOR_UNVERIFIED = "#ef4444"  # enforcement claim WITHOUT receipt fields
COLOR_DEFAULT = "#6b7280"  # anything else


def select_log(candidates: List[Path] | None = None) -> Path:
    """Newest existing candidate wins; last candidate is the fallback.

    Same rule as the web console newest-wins feed. Pure over the
    filesystem (tmp-testable, no tree writes).
    """
    cands = candidates if candidates is not None else [SERVICE_LOG, DEV_LOG]
    best: Path | None = None
    best_mtime = -1.0
    for path in cands:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime > best_mtime:
            best_mtime = mtime
            best = path
    return best if best is not None else cands[-1]


def edge_style(record: Dict[str, Any]) -> Tuple[str, str, bool]:
    """Pure: (color, label, dashed) for one record. Never raises.

    Conservative and claim-labeled: green only when the record carries
    the full receipt set (decision block + host_effect_confirmed +
    provider + nonzero filter/request ids); an enforcement claim without
    that set draws red dashed (unverified, possibly a label lie); plain
    observations draw amber. Anything else is gray.
    """
    try:
        status = str(record.get("enforcement_status", "") or "")
        decision = str(record.get("decision", "") or "")
        confirmed = bool(record.get("host_effect_confirmed", False))
        provider = str(record.get("provider", "") or "")
        try:
            filter_id = int(record.get("filter_id", 0) or 0)
            request_id = int(record.get("request_id", 0) or 0)
        except (ValueError, TypeError):
            filter_id, request_id = 0, 0
        receipt = confirmed and bool(provider) and filter_id > 0 and request_id > 0
        is_block = decision == "block" or status in ("enforced", "block", "BLOCKED_CONFIRMED")
        if is_block and receipt:
            return (COLOR_CONFIRMED, "BLOCKED_CONFIRMED (receipt)", False)
        if is_block:
            return (COLOR_UNVERIFIED, "claimed block, NO receipt", True)
        if status == "observed" or decision in ("alert", "allow"):
            return (COLOR_OBSERVED, "observed (no enforcement claim)", False)
    except Exception:
        pass
    return (COLOR_DEFAULT, "other", False)


def read_records(log: Path, limit: int = DEFAULT_LIMIT) -> List[Dict[str, Any]]:
    """Parse up to `limit` records (tail) from the log. Never raises."""
    import json
    try:
        lines = log.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    records: List[Dict[str, Any]] = []
    for line in lines[-limit:] if limit > 0 else lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def build_threat_graph(records: List[Dict[str, Any]], output: Path,
                       limit: int = DEFAULT_LIMIT) -> Tuple[int, int, int]:
    """Render records to interactive HTML. Returns (records, nodes, edges).

    Raises ImportError with a pip hint when networkx/pyvis are absent,
    FileNotFoundError only via the caller's log selection (records may be
    empty -- an empty graph still renders with the legend).
    """
    try:
        import networkx as nx
        from pyvis.network import Network
    except ImportError as exc:
        raise ImportError("pip install networkx pyvis") from exc
    graph = nx.DiGraph()
    graph.add_node("AEGIS_NIDS", label="AEGIS NIDS", color="#22c55e",
                   size=32, title="Protected host")
    for event in records[:limit] if limit > 0 else records:
        src_ip = event.get("src_ip") or event.get("source_ip") or "unknown-source"
        rule = event.get("rule") or event.get("rule_id") or "unknown-rule"
        attack = event.get("attack_type") or event.get("event") or "event"
        color, label, dashed = edge_style(event)
        source_node = "src:%s" % src_ip
        rule_node = "rule:%s" % rule
        if source_node not in graph:
            graph.add_node(source_node, label=str(src_ip), color="#ef4444",
                           size=22, title="Source: %s" % src_ip)
        if rule_node not in graph:
            graph.add_node(rule_node, label=str(rule), color="#f59e0b",
                           size=18, title="Rule: %s | %s" % (rule, attack))
        graph.add_edge(source_node, rule_node, label=label, color=color,
                       dashes=dashed)
        graph.add_edge(rule_node, "AEGIS_NIDS", label=label, color=color,
                       dashes=dashed)
    output.parent.mkdir(parents=True, exist_ok=True)
    network = Network(height="820px", width="100%", bgcolor="#0b1220",
                      font_color="#e5e7eb", directed=True)
    network.from_nx(graph)
    network.set_options(
        '{"interaction":{"hover":true,"navigationButtons":true},'
        '"physics":{"stabilization":{"iterations":180}}}')
    network.save_graph(str(output))
    return (len(records), graph.number_of_nodes(), graph.number_of_edges())
