from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.db.connection import get_connection
from app.services.active_traceroute import get_latest_traceroutes
from app.services.traceroute_graph import get_traceroute_graph_by_run

GRAPH_VERSION = "traceroute-visual-v2"
LAYOUT_ALGORITHM = "deterministic-asn-columns"
VISUALIZATION_NAME = "Visual Traceroute"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_ip(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "*":
        return None
    return text.split("/", 1)[0]


def _safe_json(value: Any, fallback: Any) -> Any:
    return fallback if value is None else value


def _raise_value_error(message: str) -> None:
    raise ValueError(message)


def _validate_minimum_payload(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        _raise_value_error("Payload inválido.")
    if not isinstance(payload.get("payload"), dict):
        _raise_value_error("Campo payload é obrigatório.")
    if not str(payload.get("name") or "").strip():
        _raise_value_error("Nome da visualização é obrigatório.")
    if not str(payload.get("graph_version") or GRAPH_VERSION).strip():
        _raise_value_error("graph_version é obrigatório.")
    if not str(payload.get("layout_algorithm") or LAYOUT_ALGORITHM).strip():
        _raise_value_error("layout_algorithm é obrigatório.")
    if not str(payload.get("selected_view_mode") or "").strip():
        _raise_value_error("selected_view_mode é obrigatório.")


def _classification(node: dict[str, Any]) -> str:
    if node.get("role") == "destination":
        return "destination"
    if node.get("role") == "local_gateway":
        return "origin"
    if not node.get("ip"):
        return "timeout" if node.get("role") == "no_reply" else "unknown"
    if node.get("asn") is not None or node.get("org"):
        return "asn_enriched"
    if str(node.get("ip") or "").startswith(("172.16.", "192.168.", "10.")):
        return "private"
    return "unknown"


def _visual_flags(node: dict[str, Any], *, previous_rtt: float | None) -> dict[str, bool]:
    rtt = node.get("rtt_ms")
    latency_jump = False
    if rtt is not None and previous_rtt is not None:
        latency_jump = float(rtt) - float(previous_rtt) >= 50.0
    return {
        "timeout": not bool(node.get("ip")),
        "unknown": node.get("ip") is None and node.get("role") != "no_reply",
        "destination": node.get("role") == "destination",
        "high_latency": bool(rtt is not None and float(rtt) >= 120.0),
        "latency_jump": latency_jump,
        "loss": float(node.get("packet_loss_percent") or 0.0) > 0.0,
        "inferred": str(node.get("origin")) == "inferred",
        "asn_enriched": bool(node.get("asn") is not None or node.get("org")),
        "asn_missing": not bool(node.get("asn") is not None or node.get("org")),
    }


def _asn_key(node: dict[str, Any]) -> str:
    if node.get("asn") is not None:
        return f"asn:{int(node['asn'])}"
    if node.get("role") == "local_gateway":
        return "asn:local"
    if node.get("role") == "destination":
        return "asn:destination"
    if node.get("ip") and str(node.get("ip")).startswith(("172.16.", "192.168.", "10.")):
        return "asn:private"
    if node.get("org"):
        return f"asn:org:{str(node['org']).lower().replace(' ', '-')}"
    return "asn:unknown"


def _asn_label(node: dict[str, Any]) -> str:
    if node.get("asn") is not None:
        return f"AS{int(node['asn'])}"
    if node.get("role") == "local_gateway":
        return "Local"
    if node.get("role") == "destination":
        return "Destino"
    if node.get("org"):
        return str(node["org"])
    if node.get("ip") and str(node.get("ip")).startswith(("172.16.", "192.168.", "10.")):
        return "Privado"
    return "ASN desconhecido"


def _cluster_kind(cluster_id: str) -> str:
    if cluster_id == "asn:local":
        return "origin"
    if cluster_id == "asn:destination":
        return "destination"
    if cluster_id == "asn:private":
        return "private"
    if cluster_id == "asn:unknown":
        return "unknown"
    return "asn"


def _cluster_color(kind: str) -> str:
    return {
        "origin": "#0f766e",
        "asn": "#1d4ed8",
        "private": "#475569",
        "destination": "#7c3aed",
        "unknown": "#64748b",
    }.get(kind, "#64748b")


def _state_for_node(node: dict[str, Any], *, previous_rtt: float | None) -> dict[str, Any]:
    flags = _visual_flags(node, previous_rtt=previous_rtt)
    classification = _classification(node)
    if classification == "origin":
        status = "origin"
    elif classification == "destination":
        status = "destination"
    elif classification == "timeout":
        status = "timeout"
    elif flags["high_latency"] or flags["latency_jump"]:
        status = "high_latency"
    elif classification == "asn_enriched":
        status = "asn_enriched"
    elif classification == "private":
        status = "private"
    else:
        status = "unknown"
    return {"status": status, "classification": classification, "flags": flags, "source": "real" if node.get("ip") or node.get("role") == "no_reply" else "inferred"}


def _build_det_layout(nodes: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    lane_order: dict[str, int] = {}
    positions: dict[str, dict[str, float]] = {}
    ordered = sorted(nodes, key=lambda item: int(item["hop"]))
    for node in ordered:
        cluster_id = str(node["cluster_id"])
        if cluster_id not in lane_order:
            lane_order[cluster_id] = len(lane_order)
        lane = lane_order[cluster_id]
        x = 150 + (int(node["hop"]) - 1) * 190
        y = 160 + lane * 150
        positions[node["id"]] = {"x": float(x), "y": float(y)}
    return positions


def _aggregate_cluster(cluster: dict[str, Any], nodes: list[dict[str, Any]]) -> dict[str, Any]:
    rtts = [float(node["latency_ms"]) for node in nodes if node.get("latency_ms") is not None]
    losses = [float(node["loss_percent"]) for node in nodes if node.get("loss_percent") is not None]
    return {
        **cluster,
        "hops_count": len(nodes),
        "avg_latency_ms": round(mean(rtts), 3) if rtts else None,
        "max_latency_ms": round(max(rtts), 3) if rtts else None,
        "avg_loss_percent": round(mean(losses), 3) if losses else None,
        "timeout_count": sum(1 for node in nodes if node.get("status") == "timeout"),
        "unknown_count": sum(1 for node in nodes if node.get("status") == "unknown"),
        "inferred_count": sum(1 for node in nodes if node.get("is_inferred")),
        "anomaly_count": sum(1 for node in nodes if node.get("status") in {"high_latency", "timeout"}),
        "has_loss": any(node.get("loss_percent") for node in nodes),
        "has_high_latency": any(node.get("status") == "high_latency" for node in nodes),
        "summary_hops": [f"{node['hop']} {node.get('ip') or 'timeout'}" for node in nodes[:6]],
        "operational_note": "Cluster com timeout ou latência alta; tratar com atenção." if any(node.get("status") in {"timeout", "high_latency"} for node in nodes) else "Cluster estável.",
    }


def _normalize_graph(graph: dict[str, Any], *, source: str, measurement_row: dict[str, Any] | None = None) -> dict[str, Any]:
    ordered_nodes = sorted(graph.get("nodes", []), key=lambda item: int(item.get("hop") or 0))
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    clusters: dict[str, dict[str, Any]] = {}
    node_to_cluster: dict[str, str] = {}
    previous_rtt = None

    for index, raw_node in enumerate(ordered_nodes, start=1):
        node_id = f"node:{index}"
        hop = int(raw_node.get("hop") or index)
        ip = _safe_ip(raw_node.get("ip"))
        cluster_id = _asn_key(raw_node)
        state = _state_for_node(raw_node, previous_rtt=previous_rtt)
        loss_percent = raw_node.get("packet_loss_percent")
        latency_ms = raw_node.get("rtt_ms")
        node = {
            "id": node_id,
            "hop": hop,
            "ip": ip,
            "hostname": raw_node.get("hostname"),
            "asn": raw_node.get("asn"),
            "asn_label": _asn_label(raw_node),
            "org": raw_node.get("org"),
            "latency_ms": float(latency_ms) if latency_ms is not None else None,
            "loss_percent": float(loss_percent) if loss_percent is not None else None,
            "status": state["status"],
            "classification": state["classification"],
            "source": state["source"],
            "cluster_id": cluster_id,
            "cluster_label": _asn_label(raw_node),
            "cluster_kind": _cluster_kind(cluster_id),
            "visual_state": state,
            "raw": raw_node,
            "is_inferred": bool(raw_node.get("origin") == "inferred" or state["source"] == "inferred"),
        }
        nodes.append(node)
        node_to_cluster[node_id] = cluster_id
        previous_rtt = latency_ms if latency_ms is not None else previous_rtt

        cluster = clusters.setdefault(
            cluster_id,
            {
                "id": cluster_id,
                "type": _cluster_kind(cluster_id),
                "name": _asn_label(raw_node),
                "asn": raw_node.get("asn"),
                "organization": raw_node.get("org"),
                "label": _asn_label(raw_node),
                "color": _cluster_color(_cluster_kind(cluster_id)),
                "node_ids": [],
                "nodes": [],
            },
        )
        cluster["node_ids"].append(node_id)
        cluster["nodes"].append(node)

    original_to_normalized = {str(raw.get("id") or f"hop-{idx}"): f"node:{idx}" for idx, raw in enumerate(ordered_nodes, start=1)}
    for edge_index, edge in enumerate(graph.get("edges", []), start=1):
        edges.append(
            {
                "id": f"edge:{edge_index}",
                "source": original_to_normalized.get(str(edge.get("source")), str(edge.get("source"))),
                "target": original_to_normalized.get(str(edge.get("target")), str(edge.get("target"))),
                "latency_jump": bool(edge.get("latency_jump")),
                "rtt_delta_ms": edge.get("rtt_delta_ms"),
                "status": "high_latency" if edge.get("latency_jump") else "normal",
            }
        )

    cluster_list = [_aggregate_cluster(cluster, cluster["nodes"]) for cluster in clusters.values()]
    for cluster in cluster_list:
        cluster["visual_state"] = {
            "status": "destination"
            if cluster["type"] == "destination"
            else "origin"
            if cluster["type"] == "origin"
            else "anomaly"
            if cluster["anomaly_count"]
            else "timeout"
            if cluster["timeout_count"]
            else "inferred"
            if cluster["inferred_count"]
            else "normal",
            "has_anomaly": bool(cluster["anomaly_count"]),
            "has_timeout": bool(cluster["timeout_count"]),
            "has_inferred": bool(cluster["inferred_count"]),
            "has_loss": bool(cluster["has_loss"]),
            "has_high_latency": bool(cluster["has_high_latency"]),
        }

    node_positions = _build_det_layout(nodes)
    measurement = {
        "measurement_id": measurement_row.get("measurement_id") if measurement_row else graph.get("run_id"),
        "target": measurement_row.get("target") if measurement_row else graph.get("target_ip"),
        "target_label": measurement_row.get("target_label") if measurement_row else graph.get("target"),
        "source_label": measurement_row.get("source_label") if measurement_row else None,
        "status": measurement_row.get("status") if measurement_row else graph.get("status"),
        "measured_at": measurement_row.get("measured_at").isoformat() if measurement_row and measurement_row.get("measured_at") else None,
    }
    return {
        "available": True,
        "source": source,
        "metadata": {
            "generated_at": _now(),
            "visualization_name": VISUALIZATION_NAME,
            "measurement_id": measurement["measurement_id"],
            "target": measurement["target"],
            "target_label": measurement["target_label"],
            "graph_version": GRAPH_VERSION,
            "layout_algorithm": LAYOUT_ALGORITHM,
            "measurement": measurement,
            "status": measurement["status"],
            "origin": "real" if source == "real" else "fixture",
        },
        "nodes": nodes,
        "edges": edges,
        "clusters": cluster_list,
        "node_positions": node_positions,
        "node_to_cluster": node_to_cluster,
        "cluster_state": {cluster["id"]: cluster["visual_state"] for cluster in cluster_list},
        "filters": {"show_timeouts": True, "show_unknown": True, "show_high_latency": True, "show_loss": True, "show_inferred": True},
        "selected_view_mode": "operational",
        "notes": "Payload pronto para persistência futura de visualização.",
    }


def build_traceroute_visual_payload() -> dict[str, Any]:
    rows = get_latest_traceroutes(1)
    if rows:
        graph = get_traceroute_graph_by_run(rows[0]["measurement_id"])
        if graph.get("available"):
            return _normalize_graph(graph, source="real", measurement_row=rows[0])
    fixture_graph = {
        "run_id": f"fixture-{_now()}",
        "target": "8.8.8.8",
        "target_ip": "8.8.8.8",
        "status": "ok",
        "nodes": [
            {"hop": 1, "ip": "10.20.0.1", "hostname": "routebrain-lab-gateway-01", "rtt_ms": 0.292, "asn": None, "org": None, "role": "local_gateway"},
            {"hop": 2, "ip": "10.21.0.1", "hostname": None, "rtt_ms": 0.482, "asn": None, "org": None, "role": "unknown"},
            {"hop": 3, "ip": None, "hostname": None, "rtt_ms": None, "asn": None, "org": None, "role": "no_reply"},
            {"hop": 4, "ip": "10.22.0.14", "hostname": None, "rtt_ms": 2.134, "asn": None, "org": "RouteBrain Net", "role": "unknown"},
            {"hop": 5, "ip": "10.22.0.18", "hostname": None, "rtt_ms": 3.201, "asn": None, "org": "RouteBrain Net", "role": "unknown"},
            {"hop": 6, "ip": "10.22.0.19", "hostname": None, "rtt_ms": 3.441, "asn": None, "org": "RouteBrain Net", "role": "unknown"},
            {"hop": 7, "ip": "10.22.0.17", "hostname": None, "rtt_ms": 3.913, "asn": None, "org": "RouteBrain Net", "role": "unknown"},
            {"hop": 8, "ip": None, "hostname": None, "rtt_ms": None, "asn": None, "org": None, "role": "no_reply"},
            {"hop": 9, "ip": "10.22.0.10", "hostname": "routebrain-lab", "rtt_ms": 5.202, "asn": None, "org": "RouteBrain Lab", "role": "unknown"},
            {"hop": 10, "ip": "10.22.0.15", "hostname": "routebrain-lab", "rtt_ms": 8.901, "asn": None, "org": "RouteBrain Lab", "role": "unknown"},
            {"hop": 11, "ip": "10.22.0.16", "hostname": "routebrain-lab", "rtt_ms": 9.544, "asn": None, "org": "RouteBrain Lab", "role": "unknown"},
            {"hop": 12, "ip": "10.22.0.11", "hostname": None, "rtt_ms": 11.996, "asn": None, "org": None, "role": "unknown"},
            {"hop": 13, "ip": "203.0.113.72", "hostname": "google-public-dns-a.google.com", "rtt_ms": 18.103, "asn": 15169, "org": "Google", "role": "asn"},
            {"hop": 14, "ip": "198.51.100.233", "hostname": None, "rtt_ms": 28.454, "asn": 15169, "org": "Google", "role": "asn"},
            {"hop": 15, "ip": "198.51.100.77", "hostname": None, "rtt_ms": 34.522, "asn": 15169, "org": "Google", "role": "asn"},
            {"hop": 16, "ip": "8.8.8.8", "hostname": "dns.google", "rtt_ms": 47.995, "asn": 15169, "org": "Google", "role": "destination"},
        ],
        "edges": [{"source": f"node:{index}", "target": f"node:{index + 1}", "latency_jump": False, "rtt_delta_ms": None} for index in range(1, 16)],
    }
    return _normalize_graph(fixture_graph, source="fixture")


def _sanitize_payload_for_storage(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodes": payload.get("nodes") or [],
        "edges": payload.get("edges") or [],
        "clusters": payload.get("clusters") or [],
        "node_positions": payload.get("node_positions") or {},
        "node_to_cluster": payload.get("node_to_cluster") or {},
        "metadata": payload.get("metadata") or {},
    }


def _serialization_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "visualization_uid": row["visualization_uid"],
        "name": row["name"],
        "description": row.get("description"),
        "measurement_id": row.get("measurement_id"),
        "target": row.get("target"),
        "source_label": row.get("source_label"),
        "graph_version": row["graph_version"],
        "layout_algorithm": row["layout_algorithm"],
        "selected_view_mode": row["selected_view_mode"],
        "payload": row["payload"],
        "node_positions": row["node_positions"],
        "cluster_state": row["cluster_state"],
        "filters": row["filters"],
        "notes": row["notes"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _summary_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "visualization_uid": row["visualization_uid"],
        "name": row["name"],
        "measurement_id": row.get("measurement_id"),
        "target": row.get("target"),
        "selected_view_mode": row["selected_view_mode"],
        "graph_version": row["graph_version"],
        "layout_algorithm": row["layout_algorithm"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_traceroute_visualizations() -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    id,
                    visualization_uid,
                    name,
                    measurement_id,
                    target,
                    selected_view_mode,
                    graph_version,
                    layout_algorithm,
                    created_at,
                    updated_at
                from traceroute_visualizations
                order by updated_at desc, id desc;
                """
            )
            return [_summary_row(dict(row)) for row in cur.fetchall()]


def _fetch_visualization(identifier: str | int) -> dict[str, Any] | None:
    if isinstance(identifier, int) or (isinstance(identifier, str) and identifier.isdigit()):
        sql = """
            select *
            from traceroute_visualizations
            where id = %s::bigint or visualization_uid = %s
            limit 1;
        """
        params: tuple[Any, ...] = (int(identifier), str(identifier))
    else:
        sql = """
            select *
            from traceroute_visualizations
            where visualization_uid = %s
            limit 1;
        """
        params = (str(identifier),)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row is not None else None


def get_traceroute_visualization(visualization_uid: str | int) -> dict[str, Any] | None:
    row = _fetch_visualization(visualization_uid)
    if row is None:
        return None
    return _serialization_row(row)


def create_traceroute_visualization(payload: dict[str, Any]) -> dict[str, Any]:
    _validate_minimum_payload(payload)
    visualization_uid = str(payload.get("visualization_uid") or f"tv-{uuid4().hex[:16]}")
    payload_body = _sanitize_payload_for_storage(payload["payload"])
    values = {
        "visualization_uid": visualization_uid,
        "name": str(payload.get("name")).strip(),
        "description": payload.get("description"),
        "measurement_id": payload.get("measurement_id"),
        "target": payload.get("target"),
        "source_label": payload.get("source_label"),
        "graph_version": str(payload.get("graph_version") or GRAPH_VERSION).strip(),
        "layout_algorithm": str(payload.get("layout_algorithm") or LAYOUT_ALGORITHM).strip(),
        "selected_view_mode": str(payload.get("selected_view_mode")).strip(),
        "payload": Jsonb(payload_body),
        "node_positions": Jsonb(_safe_json(payload.get("node_positions"), {})),
        "cluster_state": Jsonb(_safe_json(payload.get("cluster_state"), {})),
        "filters": Jsonb(_safe_json(payload.get("filters"), {})),
        "notes": Jsonb(_safe_json(payload.get("notes"), {})),
    }
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into traceroute_visualizations (
                    visualization_uid,
                    name,
                    description,
                    measurement_id,
                    target,
                    source_label,
                    graph_version,
                    layout_algorithm,
                    selected_view_mode,
                    payload,
                    node_positions,
                    cluster_state,
                    filters,
                    notes
                )
                values (
                    %(visualization_uid)s,
                    %(name)s,
                    %(description)s,
                    %(measurement_id)s,
                    %(target)s,
                    %(source_label)s,
                    %(graph_version)s,
                    %(layout_algorithm)s,
                    %(selected_view_mode)s,
                    %(payload)s::jsonb,
                    %(node_positions)s::jsonb,
                    %(cluster_state)s::jsonb,
                    %(filters)s::jsonb,
                    %(notes)s::jsonb
                )
                returning *;
                """,
                values,
            )
            conn.commit()
            row = cur.fetchone()
            if row is None:
                _raise_value_error("Falha ao salvar visualização.")
            return _serialization_row(dict(row))


def update_traceroute_visualization(visualization_uid: str | int, payload: dict[str, Any]) -> dict[str, Any]:
    _validate_minimum_payload(payload)
    existing = _fetch_visualization(visualization_uid)
    if existing is None:
        _raise_value_error("Visualização não encontrada.")
    values = {
        "visualization_uid": existing["visualization_uid"],
        "name": str(payload.get("name")).strip(),
        "description": payload.get("description"),
        "measurement_id": payload.get("measurement_id"),
        "target": payload.get("target"),
        "source_label": payload.get("source_label"),
        "graph_version": str(payload.get("graph_version") or GRAPH_VERSION).strip(),
        "layout_algorithm": str(payload.get("layout_algorithm") or LAYOUT_ALGORITHM).strip(),
        "selected_view_mode": str(payload.get("selected_view_mode")).strip(),
        "payload": Jsonb(_sanitize_payload_for_storage(payload["payload"])),
        "node_positions": Jsonb(_safe_json(payload.get("node_positions"), {})),
        "cluster_state": Jsonb(_safe_json(payload.get("cluster_state"), {})),
        "filters": Jsonb(_safe_json(payload.get("filters"), {})),
        "notes": Jsonb(_safe_json(payload.get("notes"), {})),
    }
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                update traceroute_visualizations
                set
                    name = %(name)s,
                    description = %(description)s,
                    measurement_id = %(measurement_id)s,
                    target = %(target)s,
                    source_label = %(source_label)s,
                    graph_version = %(graph_version)s,
                    layout_algorithm = %(layout_algorithm)s,
                    selected_view_mode = %(selected_view_mode)s,
                    payload = %(payload)s::jsonb,
                    node_positions = %(node_positions)s::jsonb,
                    cluster_state = %(cluster_state)s::jsonb,
                    filters = %(filters)s::jsonb,
                    notes = %(notes)s::jsonb,
                    updated_at = now()
                where visualization_uid = %(visualization_uid)s
                returning *;
                """,
                values,
            )
            conn.commit()
            row = cur.fetchone()
            if row is None:
                _raise_value_error("Falha ao atualizar visualização.")
            return _serialization_row(dict(row))
