from __future__ import annotations

import ipaddress
import re
from decimal import Decimal
from statistics import mean
from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.db.connection import get_connection

DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."
RTT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms")


def _fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
                return dict(row) if row is not None else None
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def classify_hop_role(hop: dict[str, Any], *, is_first: bool = False, is_last: bool = False) -> str:
    if not hop.get("responded", True) or not hop.get("hop_ip"):
        return "no_reply"
    if is_first:
        return "local_gateway"
    if is_last:
        return "destination"
    classification = str(hop.get("hop_classification") or "").lower()
    router_role = str(hop.get("router_role") or "").lower()
    ip_scope = str(hop.get("ip_scope") or "").lower()
    if "ix" in classification or "ixp" in classification:
        return "ix"
    if "cdn" in classification or "edge" in classification:
        return "cdn_edge"
    if "international" in classification:
        return "international_transit"
    if "transit" in classification:
        return "transit"
    if "operator" in classification or "router" in router_role or "edge" in router_role:
        return "operator"
    if ip_scope in {"private", "cgnat", "link_local"}:
        return "local_network"
    if hop.get("inventory_match_status") == "MATCHED_INTERFACE":
        return "operator"
    return "unknown"


def _node_from_hop(hop: dict[str, Any], *, index: int, total: int) -> dict[str, Any]:
    hop_number = int(hop.get("hop_number") or hop.get("hop") or index)
    ip = hop.get("hop_ip") or hop.get("ip")
    responded = bool(hop.get("responded", ip is not None))
    role = classify_hop_role(hop, is_first=hop_number == 1, is_last=hop_number == total)
    hostname = hop.get("router_hostname") or hop.get("hostname")
    rtt_ms = hop.get("rtt_avg_ms") if hop.get("rtt_avg_ms") is not None else hop.get("rtt_ms")
    if rtt_ms is None and hop.get("raw_line"):
        values = [float(match.group(1)) for match in RTT_RE.finditer(str(hop.get("raw_line")))]
        if values:
            rtt_ms = mean(values)
    return {
        "id": f"hop-{hop_number}",
        "hop": hop_number,
        "ip": str(ip) if ip else None,
        "hostname": hostname,
        "rtt_ms": float(rtt_ms) if rtt_ms is not None else None,
        "asn": hop.get("asn"),
        "org": hop.get("classification_owner") or hop.get("classification_provider"),
        "country": hop.get("country"),
        "role": role,
        "confidence": hop.get("classification_confidence") or ("confirmed" if responded and ip else "unknown"),
        "evidence_source": "traceroute_measurement",
        "raw_line": hop.get("raw_line"),
    }


def compute_latency_jumps(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    for node in nodes:
        if previous is not None:
            previous_rtt = previous.get("rtt_ms")
            current_rtt = node.get("rtt_ms")
            delta = None
            if previous_rtt is not None and current_rtt is not None:
                delta = round(float(current_rtt) - float(previous_rtt), 3)
            edges.append(
                {
                    "source": previous["id"],
                    "target": node["id"],
                    "rtt_delta_ms": delta,
                    "latency_jump": bool(delta is not None and delta >= 50.0),
                }
            )
        previous = node
    return edges


def build_rtt_series(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "hop": node["hop"],
            "label": str(node["hop"]),
            "rtt_ms": node.get("rtt_ms"),
            "ip": node.get("ip"),
        }
        for node in nodes
    ]


def _summary(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    rtts = [float(node["rtt_ms"]) for node in nodes if node.get("rtt_ms") is not None]
    responding = [node for node in nodes if node.get("ip")]
    largest = None
    jumps = [edge for edge in edges if edge.get("rtt_delta_ms") is not None]
    if jumps:
        edge = max(jumps, key=lambda item: float(item.get("rtt_delta_ms") or 0.0))
        largest = {
            "from_hop": int(str(edge["source"]).replace("hop-", "")),
            "to_hop": int(str(edge["target"]).replace("hop-", "")),
            "delta_ms": edge.get("rtt_delta_ms"),
        }
    max_rtt = max(rtts) if rtts else None
    classification = "no_reply" if not responding else "international_high_latency" if max_rtt and max_rtt >= 150 else "ok"
    return {
        "total_hops": len(nodes),
        "last_responding_hop": max((int(node["hop"]) for node in responding), default=None),
        "avg_rtt_ms": round(mean(rtts), 3) if rtts else None,
        "max_rtt_ms": round(max_rtt, 3) if max_rtt is not None else None,
        "largest_latency_jump": largest,
        "classification": classification,
    }


def _build_graph(
    *,
    run_id: str | int | None,
    request_uid: str | None,
    target: str | None,
    target_ip: str | None,
    status: str | None,
    hops: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered = sorted(hops, key=lambda item: int(item.get("hop_number") or item.get("hop") or 0))
    total = len(ordered)
    nodes = [_node_from_hop(hop, index=index + 1, total=total) for index, hop in enumerate(ordered)]
    edges = compute_latency_jumps(nodes)
    return _json_safe(
        {
            "available": bool(nodes),
            "run_id": str(run_id) if run_id is not None else None,
            "request_uid": request_uid,
            "target": target,
            "target_ip": target_ip or target,
            "status": status or "ok",
            "nodes": nodes,
            "edges": edges,
            "rtt_series": build_rtt_series(nodes),
            "summary": _summary(nodes, edges),
        }
    )


def get_traceroute_graph_by_run(run_id: str | int) -> dict[str, Any]:
    measurement = _fetch_one(
        """
        select
          id,
          target::text as target,
          target_label,
          source_label,
          status,
          hop_count,
          responded_hop_count,
          measured_at
        from active_traceroute_measurements
        where id = %s
        limit 1;
        """,
        (run_id,),
    )
    if measurement is None:
        return {"available": False, "reason": "no_traceroute_evidence"}
    hops = _fetch_all(
        """
        select
          measurement_id,
          target::text as target,
          target_label,
          measured_at,
          hop_number,
          hop_ip::text as hop_ip,
          responded,
          rtt_avg_ms,
          raw_line,
          ip_scope,
          is_private,
          is_public,
          inventory_match_status,
          router_hostname,
          router_role,
          interface_name,
          interface_description,
          site_name,
          hop_classification,
          classification_confidence,
          classification_owner,
          classification_provider,
          classification_notes
        from v_active_traceroute_latest_hops_with_classification
        where measurement_id = %s
        order by hop_number;
        """,
        (run_id,),
    )
    if not hops:
        hops = _fetch_all(
            """
            select
              measurement_id,
              target::text as target,
              hop_number,
              hop_ip::text as hop_ip,
              responded,
              rtt_avg_ms,
              raw_line
            from active_traceroute_hops
            where measurement_id = %s
            order by hop_number;
            """,
            (run_id,),
        )
    return _build_graph(
        run_id=measurement.get("id"),
        request_uid=None,
        target=measurement.get("target_label") or measurement.get("target"),
        target_ip=measurement.get("target"),
        status=measurement.get("status"),
        hops=hops,
    )


def _graph_from_learning_evidence(request_uid: str) -> dict[str, Any] | None:
    evidence = _fetch_one(
        """
        select
          e.id,
          e.entity_value,
          e.source_ref,
          e.summary,
          e.data,
          r.request_uid
        from learning_evidence e
        join learning_requests r on r.id = e.request_id
        where r.request_uid = %s
          and e.evidence_type = 'traceroute_measurement'
        order by e.created_at desc, e.id desc
        limit 1;
        """,
        (request_uid,),
    )
    if evidence is None:
        return None
    data = evidence.get("data") if isinstance(evidence.get("data"), dict) else {}
    hops = data.get("hops") if isinstance(data.get("hops"), list) else []
    if not hops:
        return None
    return _build_graph(
        run_id=f"learning-evidence-{evidence.get('id')}",
        request_uid=request_uid,
        target=data.get("target") or evidence.get("entity_value"),
        target_ip=data.get("ip") or evidence.get("entity_value") or evidence.get("source_ref"),
        status=data.get("status"),
        hops=hops,
    )


def _graph_from_learning_memory(request_uid: str) -> dict[str, Any] | None:
    row = _fetch_one(
        """
        select raw_context
        from learning_requests
        where request_uid = %s
        limit 1;
        """,
        (request_uid,),
    )
    if row is None:
        return None
    raw_context = row.get("raw_context") if isinstance(row.get("raw_context"), dict) else {}
    memory = raw_context.get("learning_memory") if isinstance(raw_context.get("learning_memory"), dict) else {}
    for item in memory.get("ips") or []:
        if not isinstance(item, dict):
            continue
        latest = ((item.get("traceroute") or {}).get("latest") or {})
        if not isinstance(latest, dict):
            continue
        data = latest.get("data") if isinstance(latest.get("data"), dict) else {}
        hops = data.get("hops") if isinstance(data.get("hops"), list) else []
        if hops:
            return _build_graph(
                run_id=f"learning-memory-evidence-{latest.get('id')}",
                request_uid=request_uid,
                target=data.get("target") or latest.get("entity_value") or item.get("ip"),
                target_ip=data.get("ip") or latest.get("entity_value") or item.get("ip"),
                status=data.get("status"),
                hops=hops,
            )
    return None


def _latest_target_graph_for_request(request_uid: str) -> dict[str, Any] | None:
    row = _fetch_one(
        """
        select e.entity_value
        from learning_evidence e
        join learning_requests r on r.id = e.request_id
        where r.request_uid = %s
          and e.entity_type = 'ip'
          and e.entity_value is not null
        order by e.created_at desc, e.id desc
        limit 1;
        """,
        (request_uid,),
    )
    if row is None:
        return None
    target = str(row.get("entity_value") or "").strip()
    if not target:
        return None
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return None
    measurement = _fetch_one(
        """
        select id
        from active_traceroute_measurements
        where target = %s::inet
        order by measured_at desc, id desc
        limit 1;
        """,
        (target,),
    )
    if measurement is None:
        return None
    graph = get_traceroute_graph_by_run(measurement["id"])
    graph["request_uid"] = request_uid
    return graph


def get_traceroute_graph_for_learning_request(request_uid: str) -> dict[str, Any]:
    graph = _graph_from_learning_evidence(request_uid) or _graph_from_learning_memory(request_uid) or _latest_target_graph_for_request(request_uid)
    if graph is None:
        return {"available": False, "reason": "no_traceroute_evidence", "request_uid": request_uid}
    return graph


def get_traceroute_summary_for_learning_request(request_uid: str) -> dict[str, Any]:
    graph = get_traceroute_graph_for_learning_request(request_uid)
    if not graph.get("available"):
        return {"available": False, "reason": graph.get("reason") or "no_traceroute_evidence"}
    return {
        "available": True,
        "graph_url": f"/questions/{request_uid}/traceroute-graph",
        "target": graph.get("target"),
        "target_ip": graph.get("target_ip"),
        "summary": graph.get("summary"),
    }
