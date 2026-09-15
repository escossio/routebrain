from __future__ import annotations

from typing import Any


def route_graph_to_cytoscape(route_graph: dict[str, Any]) -> dict[str, Any]:
    elements: list[dict[str, Any]] = []
    for node in route_graph.get("nodes") or []:
        elements.append(
            {
                "data": {
                    "id": node.get("id"),
                    "label": node.get("label"),
                    "kind": node.get("kind"),
                    "ip": node.get("ip"),
                    "asn": node.get("asn"),
                    "as_name": node.get("as_name"),
                    "bgp_evidence": node.get("bgp_evidence"),
                    "bgp_context": node.get("bgp_context"),
                    "bgp_matched_prefix": (node.get("bgp_evidence") or {}).get("matched_prefix") if isinstance(node.get("bgp_evidence"), dict) else None,
                    "bgp_origin_asn": (node.get("bgp_evidence") or {}).get("origin_asn") if isinstance(node.get("bgp_evidence"), dict) else None,
                    "bgp_source": (node.get("bgp_evidence") or {}).get("source") if isinstance(node.get("bgp_evidence"), dict) else None,
                    "hop_index": node.get("hop_index"),
                    "latency_ms": node.get("latency_ms"),
                    "is_private": node.get("is_private"),
                    "is_silent": node.get("is_silent"),
                    "is_destination": node.get("is_destination"),
                    "confidence": node.get("confidence"),
                    "badges": list(node.get("badges") or []),
                    "evidence_count": len(node.get("evidence") or []),
                }
            }
        )
    for edge in route_graph.get("edges") or []:
        elements.append(
            {
                "data": {
                    "id": edge.get("id"),
                    "source": edge.get("source"),
                    "target": edge.get("target"),
                    "kind": edge.get("kind"),
                }
            }
        )
    return {"elements": elements, "layout": {"name": "breadthfirst", "directed": True}}
