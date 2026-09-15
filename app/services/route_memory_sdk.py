from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row

from app.services.route_memory_graph_validator import ValidationResult, validate_route_memory_graph_payload


@dataclass(frozen=True)
class RouteMemoryGraphSnapshot:
    graph_uid: str
    source_node: str
    title: str | None
    graph_type: str
    route_count: int | None
    schema_version: str
    created_at: Any
    payload: dict[str, Any]
    validation: ValidationResult


@dataclass(frozen=True)
class RouteMemorySdkResult:
    snapshot: RouteMemoryGraphSnapshot
    summary: dict[str, Any]
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    divergences: list[dict[str, Any]]
    grafana_summary: dict[str, Any]
    grafana_nodes: list[dict[str, Any]]
    grafana_edges: list[dict[str, Any]]
    grafana_divergences: list[dict[str, Any]]


def _snapshot_from_row(row: dict[str, Any]) -> RouteMemoryGraphSnapshot:
    payload = row.get("payload_json")
    if not isinstance(payload, dict):
        payload = {}
    validation = validate_route_memory_graph_payload(payload)
    return RouteMemoryGraphSnapshot(
        graph_uid=str(row.get("graph_uid") or ""),
        source_node=str(row.get("source_node") or ""),
        title=row.get("title"),
        graph_type=str(row.get("graph_type") or "route_memory_graph"),
        route_count=row.get("route_count"),
        schema_version=str(row.get("schema_version") or ""),
        created_at=row.get("created_at"),
        payload=payload,
        validation=validation,
    )


def load_latest_graph_snapshot(conn: Connection[Any]) -> RouteMemoryGraphSnapshot:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            select graph_uid, source_node, title, graph_type, route_count, schema_version, created_at, payload_json
            from route_memory_graph_snapshots
            order by created_at desc, id desc
            limit 1;
            """
        )
        row = cur.fetchone()
        if row is None:
            raise LookupError("No route memory graph snapshots found.")
        return _snapshot_from_row(dict(row))


def load_graph_snapshot_by_uid(conn: Connection[Any], graph_uid: str) -> RouteMemoryGraphSnapshot:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            select graph_uid, source_node, title, graph_type, route_count, schema_version, created_at, payload_json
            from route_memory_graph_snapshots
            where graph_uid = %s
            limit 1;
            """,
            (graph_uid,),
        )
        row = cur.fetchone()
        if row is None:
            raise LookupError(f"Route memory graph snapshot not found: {graph_uid}")
        return _snapshot_from_row(dict(row))


def _count_items(items: list[dict[str, Any]]) -> int:
    return sum(1 for item in items if isinstance(item, dict))


def build_grafana_summary(snapshot: RouteMemoryGraphSnapshot) -> dict[str, Any]:
    payload = snapshot.payload or {}
    routes = payload.get("routes") or []
    nodes = payload.get("nodes") or []
    edges = payload.get("edges") or []
    segments = payload.get("segments") or []
    divergences = payload.get("divergences") or []
    validation = snapshot.validation
    return {
        "graph_uid": snapshot.graph_uid,
        "source_node": snapshot.source_node,
        "title": snapshot.title,
        "graph_type": snapshot.graph_type,
        "schema_version": snapshot.schema_version,
        "created_at": snapshot.created_at,
        "route_count": snapshot.route_count,
        "routes_count": len(routes),
        "nodes_count": len(nodes),
        "edges_count": len(edges),
        "segments_count": len(segments),
        "divergences_count": len(divergences),
        "shared_nodes_count": sum(1 for node in nodes if isinstance(node, dict) and bool(node.get("shared"))),
        "shared_edges_count": sum(1 for edge in edges if isinstance(edge, dict) and bool(edge.get("shared"))),
        "validation_status": "valid" if validation.is_valid else "invalid",
        "validation_errors_count": len(validation.errors),
        "validation_warnings_count": len(validation.warnings),
    }


def build_sdk_payload(snapshot: RouteMemoryGraphSnapshot) -> dict[str, Any]:
    return {
        "snapshot": {
            "graph_uid": snapshot.graph_uid,
            "source_node": snapshot.source_node,
            "title": snapshot.title,
            "graph_type": snapshot.graph_type,
            "route_count": snapshot.route_count,
            "schema_version": snapshot.schema_version,
            "created_at": snapshot.created_at,
        },
        "summary": build_grafana_summary(snapshot),
        "nodes": build_grafana_node_rows(snapshot),
        "edges": build_grafana_edge_rows(snapshot),
        "divergences": build_grafana_divergence_rows(snapshot),
        "validation": {
            "is_valid": snapshot.validation.is_valid,
            "errors": [issue.__dict__ for issue in snapshot.validation.errors],
            "warnings": [issue.__dict__ for issue in snapshot.validation.warnings],
            "summary": snapshot.validation.summary,
        },
    }


def build_grafana_node_rows(snapshot: RouteMemoryGraphSnapshot) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node in snapshot.payload.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        route_ids = [str(route_id) for route_id in node.get("route_ids") or []]
        row = {
            "id": node.get("node_id"),
            "title": node.get("label") or node.get("canonical_key") or node.get("node_id"),
            "subtitle": node.get("node_type") or node.get("segment_type") or node.get("ip") or node.get("canonical_key"),
            "mainStat": "shared" if node.get("shared") else (node.get("node_type") or node.get("segment_type") or "node"),
            "secondaryStat": f"{len(route_ids)} route(s)",
            "arc__shared": 1 if node.get("shared") else 0,
            "detail__ip": node.get("ip"),
            "detail__asn": node.get("asn"),
            "detail__canonical_key": node.get("canonical_key"),
            "detail__route_ids": route_ids,
            "detail__node_type": node.get("node_type"),
            "detail__segment_type": node.get("segment_type"),
            "detail__shared": bool(node.get("shared")),
            "detail__source_node_ids": node.get("source_node_ids") or [],
        }
        rows.append(row)
    return rows


def build_grafana_edge_rows(snapshot: RouteMemoryGraphSnapshot) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for edge in snapshot.payload.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        route_ids = [str(route_id) for route_id in edge.get("route_ids") or []]
        rows.append(
            {
                "id": edge.get("edge_id"),
                "source": edge.get("source"),
                "target": edge.get("target"),
                "mainStat": "shared" if edge.get("shared") else (edge.get("edge_type") or "edge"),
                "secondaryStat": f"{len(route_ids)} route(s)",
                "detail__route_ids": route_ids,
                "detail__edge_type": edge.get("edge_type"),
                "detail__shared": bool(edge.get("shared")),
                "detail__source_key": edge.get("source_key"),
                "detail__target_key": edge.get("target_key"),
            }
        )
    return rows


def build_grafana_divergence_rows(snapshot: RouteMemoryGraphSnapshot) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for divergence in snapshot.payload.get("divergences") or []:
        if not isinstance(divergence, dict):
            continue
        rows.append(
            {
                "divergence_id": divergence.get("divergence_id") or divergence.get("id"),
                "divergence_type": divergence.get("divergence_type"),
                "severity": divergence.get("severity"),
                "summary": divergence.get("summary"),
                "route_ids": divergence.get("route_ids") or [],
                "at_segment": divergence.get("at_segment"),
                "graph_uid": snapshot.graph_uid,
            }
        )
    return rows
