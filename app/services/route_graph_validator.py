from __future__ import annotations

from typing import Any


def validate_route_graph(route_graph: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(route_graph, dict):
        return False, ["route_graph deve ser um objeto."]
    if not route_graph.get("schema_version"):
        errors.append("schema_version deve existir.")
    if not route_graph.get("graph_uid"):
        errors.append("graph_uid deve existir.")
    nodes = route_graph.get("nodes")
    edges = route_graph.get("edges")
    if not isinstance(nodes, list):
        errors.append("nodes deve ser lista.")
        nodes = []
    if not isinstance(edges, list):
        errors.append("edges deve ser lista.")
        edges = []
    node_ids = {str(node.get("id")) for node in nodes if isinstance(node, dict) and node.get("id")}
    hop_indexes = [node.get("hop_index") for node in nodes if isinstance(node, dict)]
    if any(hop_index is None for hop_index in hop_indexes):
        errors.append("hop_index deve existir em todos os nodes.")
    else:
        try:
            sorted(hop_indexes)
        except TypeError:
            errors.append("hop_index deve ser ordenável.")
    for edge in edges:
        if not isinstance(edge, dict):
            errors.append("edges deve conter objetos válidos.")
            continue
        if edge.get("source") not in node_ids:
            errors.append(f"edge.source inválido: {edge.get('source')}")
        if edge.get("target") not in node_ids:
            errors.append(f"edge.target inválido: {edge.get('target')}")
    return not errors, errors
