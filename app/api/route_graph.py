from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.adapters.route_graph_cytoscape import route_graph_to_cytoscape
from app.services.route_graph_builder import build_route_graph_v1
from app.services.route_graph_validator import validate_route_graph
from app.services.external_route_inventory import get_external_route_trace_graph

router = APIRouter(prefix="/route-graph", tags=["route-graph"])


def _normalize_target_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        try:
            return str(ipaddress.ip_network(text, strict=False).network_address)
        except ValueError:
            text = text.split("/", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _source_payload_for_run(run_uid: str) -> dict[str, Any]:
    requested_run_uid = str(run_uid).strip()
    graph = None
    if run_uid.isdigit():
        from app.services.traceroute_graph import get_traceroute_graph_by_run

        graph = get_traceroute_graph_by_run(int(run_uid))
    if not graph or not graph.get("available"):
        graph = get_external_route_trace_graph(run_uid)
    if not graph.get("available"):
        raise HTTPException(status_code=404, detail="Run não encontrada.")
    return {
        "run_uid": run_uid,
        "target": graph.get("target") or graph.get("target_host") or graph.get("target_resolved_ip"),
        "session_id": graph.get("request_uid") or graph.get("service_uid"),
        "ip_family": graph.get("ip_family") or graph.get("target_ip_family"),
        "generated_at": graph.get("generated_at") or graph.get("observed_at") or graph.get("completed_at"),
        "hops": graph.get("nodes") or [],
        "warnings": list(graph.get("warnings") or []),
        "edges": graph.get("edges") or [],
    }


@router.get("/runs/{run_uid}")
def route_graph_run(run_uid: str, format: str = Query("routegraph", pattern="^(routegraph|cytoscape)$")) -> dict[str, Any]:
    payload = build_route_graph_v1(_source_payload_for_run(run_uid))
    valid, errors = validate_route_graph(payload)
    if not valid:
        raise HTTPException(status_code=500, detail={"message": "RouteGraph inválido.", "errors": errors})
    if format == "cytoscape":
        return route_graph_to_cytoscape(payload)
    return payload
