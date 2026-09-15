from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.db.connection import get_connection
from app.services.external_route_inventory import get_external_hop_context

_DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."
_MAX_LIMIT = 500

_LOCAL_NETS = (
    ipaddress.ip_network("10.20.0.0/24"),
    ipaddress.ip_network("10.21.0.0/24"),
)
_CDN_HINTS = (
    "google",
    "cloudflare",
    "meta",
    "facebook",
    "instagram",
    "netflix",
    "akamai",
    "fastly",
    "amazon",
    "microsoft",
)
_PTT_HINTS = ("ixp", "ix.br", "ptt", "peering", "route server", "route-server")
_CLUSTER_LABELS: dict[str, dict[str, str]] = {
    "local": {
        "label": "Local",
        "description": "Hops privados da rede local conhecida, antes da borda de acesso.",
    },
    "cpe_onu": {
        "label": "CPE/ONU",
        "description": "Primeiro ou segundo hop privado após a origem local.",
    },
    "provider_private": {
        "label": "Operadora privada",
        "description": "Hops privados observados após CPE/ONU e antes da borda pública.",
    },
    "provider_public_edge": {
        "label": "Borda pública",
        "description": "Primeiro hop público depois de uma sequência privada.",
    },
    "transit": {
        "label": "Transit",
        "description": "Hop público sem sinal forte de CDN, IX/PTT ou destino.",
    },
    "cdn_cloud": {
        "label": "CDN/Cloud",
        "description": "Hop associado a CDN, provedor cloud ou edge conhecido.",
    },
    "ptt_ix": {
        "label": "PTT/IX",
        "description": "Hop com sinal de IX/PTT em nome, organização ou contexto.",
    },
    "destination": {
        "label": "Destino",
        "description": "Hop final do serviço conhecido ou target resolvido.",
    },
    "unknown": {
        "label": "Desconhecido",
        "description": "Hop sem evidência suficiente para classificação mais forte.",
    },
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    return value


def _fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(_DB_ERROR_MESSAGE) from exc


def _fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    rows = _fetch_all(sql, params)
    return rows[0] if rows else None


def _normalize_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def _normalize_ip(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _ip_scope(ip_value: str | None) -> str:
    if not ip_value:
        return "unknown"
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return "unknown"
    if address.is_private or address.is_loopback or address.is_link_local:
        return "private"
    if address.is_reserved or address.is_multicast or address.is_unspecified:
        return "reserved"
    return "public"


def _is_public(ip_value: str | None) -> bool:
    return _ip_scope(ip_value) == "public"


def _service_row(service_slug: str) -> dict[str, Any] | None:
    return _fetch_one(
        """
        select id, service_slug, display_name, category, description, is_ptt, enabled, created_at, updated_at
        from external_route_services
        where service_slug = %s
        limit 1;
        """,
        (service_slug,),
    )


def _service_targets(service_slug: str) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          t.id,
          s.service_slug,
          t.target_host,
          t.target_kind,
          t.target_label,
          t.notes,
          t.created_at,
          t.updated_at
        from external_route_targets t
        join external_route_services s on s.id = t.service_id
        where s.service_slug = %s
        order by t.target_host;
        """,
        (service_slug,),
    )


def _service_runs(service_slug: str) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          run_uid,
          service_uid,
          target_uid,
          target_host,
          target_resolved_ip::text as target_resolved_ip,
          target_source,
          target_selection_reason,
          status,
          max_hops,
          hop_count,
          unknown_count,
          edge_count,
          graph_available,
          graph_url,
          requested_by_role,
          requested_by_username,
          observed_at,
          completed_at,
          metadata
        from external_route_traceroute_runs
        where service_uid = %s
        order by observed_at desc, completed_at desc nulls last, run_uid desc;
        """,
        (service_slug,),
    )


def _service_hop_summary(service_slug: str) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          s.service_slug,
          s.display_name,
          s.category as service_category,
          h.id as hop_id,
          h.hop_ip::text as hop_ip,
          h.reverse_dns,
          h.asn,
          h.organization,
          h.country,
          h.category,
          h.role,
          h.confidence,
          h.confidence_rank,
          h.source_priority,
          h.observation_count,
          h.first_seen_at,
          h.last_seen_at,
          h.metadata,
          hs.occurrence_count,
          hs.target_count,
          hs.min_hop_number,
          hs.max_hop_number,
          hs.target_hosts,
          hs.updated_at
        from external_route_service_hop_summary hs
        join external_route_services s on s.id = hs.service_id
        join external_route_hops h on h.id = hs.hop_id
        where s.service_slug = %s
        order by hs.occurrence_count desc, hs.last_seen_at desc, h.hop_ip asc;
        """,
        (service_slug,),
    )


def _all_hop_rows() -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          h.id as hop_id,
          h.hop_ip::text as hop_ip,
          h.reverse_dns,
          h.asn,
          h.organization,
          h.country,
          h.category,
          h.role,
          h.confidence,
          h.confidence_rank,
          h.source_priority,
          h.evidence_sources,
          h.observation_count,
          h.first_seen_at,
          h.last_seen_at,
          h.metadata,
          count(distinct hs.service_id)::bigint as service_count,
          array_agg(distinct s.service_slug order by s.service_slug) filter (where s.service_slug is not null) as services_seen,
          coalesce(sum(hs.occurrence_count), 0)::bigint as service_observation_count,
          min(hs.min_hop_number) as min_hop_number,
          max(hs.max_hop_number) as max_hop_number,
          count(distinct o.target_id)::bigint as target_count
        from external_route_hops h
        left join external_route_service_hop_summary hs on hs.hop_id = h.id
        left join external_route_services s on s.id = hs.service_id
        left join external_route_observations o on o.hop_id = h.id
        group by h.id
        order by h.last_seen_at desc, h.hop_ip asc;
        """
    )


def _all_edge_rows() -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          edge_uid,
          service_uid,
          target_uid,
          traceroute_run_ref,
          observed_at,
          from_hop_ip::text as from_hop_ip,
          from_hop_index,
          to_hop_ip::text as to_hop_ip,
          to_hop_index,
          from_ip_type,
          to_ip_type,
          rtt_delta_ms,
          transition_type,
          confidence,
          metadata
        from external_route_hop_edges
        order by observed_at desc, edge_uid asc;
        """
    )


def _destination_ips() -> set[str]:
    ips: set[str] = set()
    rows = _fetch_all(
        """
        select distinct target_resolved_ip::text as target_resolved_ip
        from external_route_traceroute_runs
        where target_resolved_ip is not null;
        """
    )
    for row in rows:
        ip_value = _normalize_ip(row.get("target_resolved_ip"))
        if ip_value:
            ips.add(ip_value)
    rows = _fetch_all(
        """
        select distinct t.target_host
        from external_route_targets t
        join external_route_services s on s.id = t.service_id
        where t.target_kind = 'ip';
        """
    )
    for row in rows:
        ip_value = _normalize_ip(row.get("target_host"))
        if ip_value:
            ips.add(ip_value)
    return ips


def _cluster_meta(cluster: str) -> dict[str, str]:
    return _CLUSTER_LABELS.get(cluster, _CLUSTER_LABELS["unknown"])


def _cluster_role(cluster: str) -> str:
    return {
        "local": "local_gateway",
        "cpe_onu": "cpe_or_onu",
        "provider_private": "provider_internal_transit_candidate",
        "provider_public_edge": "provider_public_edge",
        "transit": "transit",
        "cdn_cloud": "cdn_edge",
        "ptt_ix": "ptt_ix",
        "destination": "destination",
        "unknown": "unknown",
    }.get(cluster, "unknown")


def _cluster_category(cluster: str, ip_type: str) -> str:
    if cluster in {"local", "cpe_onu", "provider_private"}:
        return "private"
    if cluster == "unknown":
        return "unknown"
    return "public" if ip_type == "public" else "private"


def _confidence_for_cluster(cluster: str) -> float:
    return {
        "local": 0.8,
        "cpe_onu": 0.75,
        "provider_private": 0.7,
        "provider_public_edge": 0.6,
        "transit": 0.55,
        "cdn_cloud": 0.85,
        "ptt_ix": 0.6,
        "destination": 0.92,
        "unknown": 0.25,
    }.get(cluster, 0.4)


def _normalize_reason_list(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        if value and value not in cleaned:
            cleaned.append(value)
    return cleaned


def _cluster_for_node(
    row: dict[str, Any],
    *,
    destination_ips: set[str],
    source_min_hop: int | None,
) -> tuple[str, list[str]]:
    hop_ip = _normalize_ip(row.get("hop_ip"))
    ip_scope = _ip_scope(hop_ip)
    category = str(row.get("category") or "").lower()
    role = str(row.get("role") or "").lower()
    organization = str(row.get("organization") or "").lower()
    reverse_dns = str(row.get("reverse_dns") or "").lower()
    reasons: list[str] = []

    if hop_ip and hop_ip in destination_ips:
        return "destination", ["destination_target_match"]

    if any(hint in organization or hint in reverse_dns for hint in _CDN_HINTS):
        reasons.append("cdn_org_match")
        return "cdn_cloud", reasons

    if any(hint in organization or hint in reverse_dns for hint in _PTT_HINTS):
        reasons.append("ptt_hint")
        return "ptt_ix", reasons

    if ip_scope == "private":
        if hop_ip and any(hop_ip.startswith(str(network.network_address).rsplit(".", 1)[0]) for network in _LOCAL_NETS):
            # 10.20.0.0/24 is treated as the local segment, 10.21.0.0/24 as CPE/ONU.
            if hop_ip.startswith("192.168.88."):
                reasons.append("local_prefix")
                return "local", reasons
            if hop_ip.startswith("192.168.0."):
                reasons.append("cpe_prefix")
                return "cpe_onu", reasons
        if source_min_hop is not None and source_min_hop <= 1:
            reasons.append("local_path")
            return "local", reasons
        if source_min_hop is not None and source_min_hop <= 2:
            reasons.append("cpe_path")
            return "cpe_onu", reasons
        reasons.append("private_path")
        return "provider_private", reasons

    if category == "cloud" or role == "provider_edge":
        reasons.append("cloud_edge")
        return "cdn_cloud", reasons

    if category == "transit" or role == "transit":
        if source_min_hop is not None and source_min_hop <= 3:
            reasons.append("public_edge")
            return "provider_public_edge", reasons
        reasons.append("transit_path")
        return "transit", reasons

    if category == "unknown" or role == "unknown":
        reasons.append("unknown_no_evidence")
        return "unknown", reasons

    if source_min_hop is not None and source_min_hop <= 3:
        reasons.append("public_edge")
        return "provider_public_edge", reasons

    reasons.append("transit_path")
    return "transit", reasons


def _node_from_row(
    row: dict[str, Any],
    *,
    destination_ips: set[str],
    service_hop_summary: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    hop_ip = _normalize_ip(row.get("hop_ip"))
    hop_id = f"hop:{hop_ip}" if hop_ip else f"hop:{row.get('hop_id')}"
    services_seen = [str(value) for value in (row.get("services_seen") or []) if value]
    service_count = int(row.get("service_count") or 0)
    source_min_hop = row.get("min_hop_number")
    if isinstance(service_hop_summary, dict) and hop_ip:
        service_row = service_hop_summary.get(hop_ip)
        if service_row and service_row.get("min_hop_number") is not None:
            source_min_hop = service_row.get("min_hop_number")

    cluster, reasons = _cluster_for_node(row, destination_ips=destination_ips, source_min_hop=int(source_min_hop) if source_min_hop is not None else None)
    ip_type = _ip_scope(hop_ip)
    node_confidence = _confidence_for_cluster(cluster)
    observations_count = int(row.get("observation_count") or 0)
    if service_hop_summary and hop_ip and hop_ip in service_hop_summary:
        observations_count = int(service_hop_summary[hop_ip].get("occurrence_count") or observations_count)

    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    safe_metadata = {
        "ip_scope": metadata.get("ip_scope"),
        "responded": metadata.get("responded"),
        "hop_number": metadata.get("hop_number"),
        "rtt_avg_ms": metadata.get("rtt_avg_ms"),
        "source_kind": metadata.get("source_kind"),
    }
    safe_metadata = {key: _safe_json(value) for key, value in safe_metadata.items() if value is not None}

    return {
        "id": hop_id,
        "label": hop_ip or str(row.get("hop_id")),
        "node_type": "hop",
        "ip": hop_ip,
        "ip_type": ip_type,
        "cluster": cluster,
        "category": _cluster_category(cluster, ip_type),
        "role": _cluster_role(cluster),
        "asn": row.get("asn"),
        "organization": row.get("organization"),
        "reverse_dns": row.get("reverse_dns"),
        "country": row.get("country"),
        "confidence": round(float(node_confidence), 3),
        "confidence_reason": _normalize_reason_list(
            [
                *reasons,
                "common_hop" if service_count > 1 or observations_count > 1 else "",
            ]
        ),
        "services_seen": services_seen,
        "observations_count": observations_count,
        "avg_rtt_ms": _safe_json(row.get("avg_rtt_ms")),
        "first_seen_at": row.get("first_seen_at"),
        "last_seen_at": row.get("last_seen_at"),
        "is_private": ip_type == "private",
        "is_unknown": cluster == "unknown",
        "is_ptt_candidate": cluster == "ptt_ix",
        "is_common_hop": service_count > 1 or observations_count > 1,
        "metadata": safe_metadata,
    }


def _edge_confidence(value: Any) -> float:
    confidence = str(value or "").lower()
    if confidence == "confirmed":
        return 0.9
    if confidence == "probable":
        return 0.8
    if confidence == "suggested":
        return 0.7
    return 0.4


def _edge_signature(from_ip: str | None, to_ip: str | None, transition_type: str) -> str:
    return f"{from_ip or 'missing-source'}->{to_ip or 'missing-target'}:{transition_type}"


def _raw_edges(
    rows: list[dict[str, Any]],
    *,
    allowed_services: set[str] | None = None,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for row in rows:
        service_uid = str(row.get("service_uid") or "")
        if allowed_services is not None and service_uid not in allowed_services:
            continue
        from_ip = _normalize_ip(row.get("from_hop_ip"))
        to_ip = _normalize_ip(row.get("to_hop_ip"))
        transition_type = str(row.get("transition_type") or "unknown_transition")
        observed_at = row.get("observed_at")
        edge_uid = str(row.get("edge_uid") or _edge_signature(from_ip, to_ip, transition_type))
        metadata = {
            "service_uid": service_uid or None,
            "target_uid": row.get("target_uid"),
            "traceroute_run_ref": row.get("traceroute_run_ref"),
            "from_hop_index": row.get("from_hop_index"),
            "to_hop_index": row.get("to_hop_index"),
            "from_ip_type": row.get("from_ip_type"),
            "to_ip_type": row.get("to_ip_type"),
            "relation_key": _edge_signature(from_ip, to_ip, transition_type),
        }
        edges.append(
            {
                "id": f"edge:{edge_uid}",
                "source": f"hop:{from_ip}" if from_ip else None,
                "target": f"hop:{to_ip}" if to_ip else None,
                "transition_type": transition_type,
                "services": [service_uid] if service_uid else [],
                "observations_count": 1,
                "rtt_delta_ms": _safe_json(row.get("rtt_delta_ms")),
                "confidence": round(_edge_confidence(row.get("confidence")), 3),
                "first_seen_at": observed_at,
                "last_seen_at": observed_at,
                "metadata": {key: _safe_json(value) for key, value in metadata.items() if value is not None},
            }
        )
    edges.sort(key=lambda item: (item["last_seen_at"] or datetime.min.replace(tzinfo=timezone.utc), item["id"]))
    return edges


def _build_global_node_map(
    *,
    service_hop_summary: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    destination_ips = _destination_ips()
    rows = _all_hop_rows()
    nodes: dict[str, dict[str, Any]] = {}
    for row in rows:
        node = _node_from_row(row, destination_ips=destination_ips, service_hop_summary=service_hop_summary)
        if node["ip"]:
            nodes[node["ip"]] = node
    return nodes, rows


def _service_hop_summary_map(service_slug: str) -> dict[str, dict[str, Any]]:
    rows = _service_hop_summary(service_slug)
    return {
        str(_normalize_ip(row.get("hop_ip"))): row
        for row in rows
        if _normalize_ip(row.get("hop_ip"))
    }


def _cluster_summary(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = Counter(str(node.get("cluster") or "unknown") for node in nodes)
    summary: list[dict[str, Any]] = []
    for cluster in [
        "local",
        "cpe_onu",
        "provider_private",
        "provider_public_edge",
        "transit",
        "cdn_cloud",
        "ptt_ix",
        "destination",
        "unknown",
    ]:
        meta = _cluster_meta(cluster)
        summary.append(
            {
                "id": cluster,
                "label": meta["label"],
                "type": "inferred_cluster",
                "node_count": int(counts.get(cluster, 0)),
                "description": meta["description"],
                "confidence": "inferred",
                "collapsed_by_default": False,
            }
        )
    return summary


def _global_summary(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    hop_rows = _fetch_one(
        """
        select
          count(*)::bigint as nodes_count,
          count(*) filter (where category = 'private' or strpos(role, 'private') > 0)::bigint as private_hops_count,
          count(*) filter (where category = 'unknown' or confidence = 'unknown')::bigint as unknown_hops_count,
          count(distinct asn)::bigint as asn_count
        from external_route_hops;
        """
    ) or {}
    return {
        "services_count": int((_fetch_one("select count(*)::bigint as value from external_route_services;") or {}).get("value") or 0),
        "targets_count": int((_fetch_one("select count(*)::bigint as value from external_route_targets;") or {}).get("value") or 0),
        "nodes_count": int(hop_rows.get("nodes_count") or len(nodes)),
        "edges_count": int(len(edges)),
        "observations_count": int((_fetch_one("select count(*)::bigint as value from external_route_observations;") or {}).get("value") or 0),
        "private_hops_count": int(hop_rows.get("private_hops_count") or 0),
        "unknown_hops_count": int(hop_rows.get("unknown_hops_count") or 0),
        "asn_count": int(hop_rows.get("asn_count") or 0),
    }


def _limitations_for_global(summary: dict[str, Any], *, service_rows: list[dict[str, Any]] | None = None) -> list[str]:
    limitations: list[str] = []
    if not summary.get("asn_count"):
        limitations.append("asn_org_data_missing_for_most_hops")
    if summary.get("unknown_hops_count"):
        limitations.append("unknown_hops_remain_heuristic")
    if service_rows is not None and any(not row.get("hop_count") for row in service_rows):
        limitations.append("some_services_have_no_route_evidence")
    limitations.append("cluster_derivation_is_heuristic")
    return limitations


def _graph_payload(
    *,
    graph_uid: str,
    scope: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    summary: dict[str, Any],
    clusters: list[dict[str, Any]] | None = None,
    filters: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "graph_uid": graph_uid,
        "scope": scope,
        "generated_at": _now().isoformat(),
        "summary": summary,
        "clusters": clusters or [],
        "nodes": nodes,
        "edges": edges,
        "filters": filters or {},
        "limitations": limitations or [],
    }
    if extra:
        payload.update(extra)
    return payload


def build_global_route_graph() -> dict[str, Any]:
    service_rows = _fetch_all(
        """
        select
          s.service_slug,
          s.display_name,
          s.category,
          s.is_ptt,
          count(distinct hs.hop_id)::bigint as hop_count,
          count(distinct t.id)::bigint as target_count,
          count(distinct o.id)::bigint as observation_count,
          count(distinct e.edge_uid)::bigint as edge_count
        from external_route_services s
        left join external_route_targets t on t.service_id = s.id
        left join external_route_observations o on o.service_id = s.id
        left join external_route_service_hop_summary hs on hs.service_id = s.id
        left join external_route_hop_edges e on e.service_uid = s.service_slug
        group by s.service_slug, s.display_name, s.category, s.is_ptt
        order by s.service_slug;
        """
    )
    service_hop_summary: dict[str, dict[str, Any]] = {}
    # The global node builder only needs min_hop_number per hop; reuse the first service-specific map where available.
    for service in [str(row["service_slug"]) for row in service_rows]:
        for hop_ip, summary_row in _service_hop_summary_map(service).items():
            if hop_ip not in service_hop_summary or (
                summary_row.get("min_hop_number") is not None
                and (
                    service_hop_summary[hop_ip].get("min_hop_number") is None
                    or int(summary_row.get("min_hop_number") or 0) < int(service_hop_summary[hop_ip].get("min_hop_number") or 0)
                )
            ):
                service_hop_summary[hop_ip] = summary_row

    nodes_by_ip, _ = _build_global_node_map(service_hop_summary=service_hop_summary)
    nodes = list(nodes_by_ip.values())
    edges = _raw_edges(_all_edge_rows())
    summary = _global_summary(nodes, edges)
    clusters = _cluster_summary(nodes)
    limitations = _limitations_for_global(summary, service_rows=service_rows)
    return _graph_payload(
        graph_uid="global",
        scope="global",
        nodes=nodes,
        edges=edges,
        summary=summary,
        clusters=clusters,
        filters={},
        limitations=limitations,
    )


def build_service_route_graph(service: str) -> dict[str, Any]:
    service_slug = _normalize_slug(service)
    service_row = _service_row(service_slug)
    if service_row is None:
        raise ValueError("Serviço não encontrado.")

    global_nodes, _ = _build_global_node_map(service_hop_summary=_service_hop_summary_map(service_slug))
    service_summary_map = _service_hop_summary_map(service_slug)
    nodes = [
        {
            **node,
            "observations_count": int(service_summary_map[node["ip"]].get("occurrence_count") or node["observations_count"]),
            "confidence_reason": _normalize_reason_list(
                [*node["confidence_reason"], "service_route_scope", "common_hop" if node["is_common_hop"] else ""]
            ),
        }
        for node in global_nodes.values()
        if node.get("ip") and node["ip"] in service_summary_map
    ]
    edges = _raw_edges(_all_edge_rows(), allowed_services={service_slug})
    service_runs = _service_runs(service_slug)
    service_targets = _service_targets(service_slug)
    service_hops = list(service_summary_map.values())
    observations_count = int((_fetch_one(
        """
        select count(*)::bigint as value
        from external_route_observations o
        join external_route_services s on s.id = o.service_id
        where s.service_slug = %s;
        """,
        (service_slug,),
    ) or {}).get("value") or 0)
    distinct_asn_count = len({row.get("asn") for row in service_hops if row.get("asn") is not None})
    unknown_hop_count = sum(1 for row in service_hops if row.get("category") == "unknown" or row.get("confidence") == "unknown")
    summary = {
        "service_slug": service_slug,
        "display_name": service_row.get("display_name"),
        "category": service_row.get("category"),
        "is_ptt": service_row.get("is_ptt"),
        "target_count": len(service_targets),
        "hop_count": len(nodes),
        "edge_count": len(edges),
        "observation_count": observations_count,
        "distinct_asn_count": distinct_asn_count,
        "unknown_hop_count": unknown_hop_count,
        "graph_available": bool(nodes or edges),
        "last_seen_at": max((node.get("last_seen_at") for node in nodes if node.get("last_seen_at")), default=None),
    }
    limitations = [] if nodes or edges else ["no_route_evidence_for_service"]
    if not nodes and not edges:
        limitations.append("service_seed_only")
    clusters = _cluster_summary(nodes)
    return _graph_payload(
        graph_uid=f"service:{service_slug}",
        scope="service",
        nodes=nodes,
        edges=edges,
        summary=summary,
        clusters=clusters,
        filters={"service": service_slug},
        limitations=limitations,
        extra={"service": service_row, "targets": service_targets, "runs": service_runs},
    )


def get_route_graph_hop_context(ip: str) -> dict[str, Any]:
    normalized = _normalize_ip(ip)
    if normalized is None:
        raise ValueError("IP inválido.")
    graph = build_global_route_graph()
    hop = next((node for node in graph["nodes"] if node.get("ip") == normalized), None)
    if hop is None:
        return {
            "hop": None,
            "previous_hops": [],
            "next_hops": [],
            "edges_in": [],
            "edges_out": [],
            "services_seen": [],
            "sample_paths": [],
            "classification": {},
            "limitations": ["hop_not_found"],
        }
    edges_in = [edge for edge in graph["edges"] if edge.get("target") == hop["id"]]
    edges_out = [edge for edge in graph["edges"] if edge.get("source") == hop["id"]]
    previous_hops = sorted({str(edge.get("source")).removeprefix("hop:") for edge in edges_in if edge.get("source")})
    next_hops = sorted({str(edge.get("target")).removeprefix("hop:") for edge in edges_out if edge.get("target")})
    try:
        external_context = get_external_hop_context(normalized)
    except ValueError:
        external_context = {}
    sample_paths = external_context.get("sample_paths", []) if isinstance(external_context, dict) else []
    limitations = []
    if not sample_paths:
        limitations.append("no_traceroute_evidence_for_hop")
    return {
        "hop": hop,
        "previous_hops": previous_hops,
        "next_hops": next_hops,
        "edges_in": edges_in,
        "edges_out": edges_out,
        "services_seen": hop.get("services_seen", []),
        "sample_paths": sample_paths,
        "classification": {
            "cluster": hop.get("cluster"),
            "category": hop.get("category"),
            "role": hop.get("role"),
            "confidence": hop.get("confidence"),
            "confidence_reason": hop.get("confidence_reason", []),
            "is_private": hop.get("is_private"),
            "is_unknown": hop.get("is_unknown"),
            "is_ptt_candidate": hop.get("is_ptt_candidate"),
            "is_common_hop": hop.get("is_common_hop"),
        },
        "limitations": limitations,
    }


def compare_route_graph_services(service_a: str, service_b: str) -> dict[str, Any]:
    a_graph = build_service_route_graph(service_a)
    b_graph = build_service_route_graph(service_b)
    a_nodes = {str(node.get("id")): node for node in a_graph["nodes"]}
    b_nodes = {str(node.get("id")): node for node in b_graph["nodes"]}
    def edge_key(edge: dict[str, Any]) -> str:
        metadata = edge.get("metadata") if isinstance(edge.get("metadata"), dict) else {}
        relation_key = metadata.get("relation_key")
        if relation_key:
            return str(relation_key)
        return _edge_signature(
            str(edge.get("source") or "").removeprefix("hop:") or None,
            str(edge.get("target") or "").removeprefix("hop:") or None,
            str(edge.get("transition_type") or "unknown_transition"),
        )

    a_edges = {edge_key(edge): edge for edge in a_graph["edges"]}
    b_edges = {edge_key(edge): edge for edge in b_graph["edges"]}
    common_nodes = sorted(set(a_nodes) & set(b_nodes))
    common_edges = sorted(set(a_edges) & set(b_edges))
    only_a_nodes = sorted(set(a_nodes) - set(b_nodes))
    only_b_nodes = sorted(set(b_nodes) - set(a_nodes))

    divergence_points: list[dict[str, Any]] = []
    for node_id in common_nodes:
        a_node = a_nodes[node_id]
        b_node = b_nodes[node_id]
        if a_node.get("cluster") != b_node.get("cluster") or a_node.get("role") != b_node.get("role"):
            divergence_points.append(
                {
                    "node_id": node_id,
                    "service_a_cluster": a_node.get("cluster"),
                    "service_b_cluster": b_node.get("cluster"),
                    "service_a_role": a_node.get("role"),
                    "service_b_role": b_node.get("role"),
                }
            )
    if not divergence_points:
        a_path = [node["id"] for node in sorted(a_graph["nodes"], key=lambda item: item.get("observations_count", 0), reverse=True)]
        b_path = [node["id"] for node in sorted(b_graph["nodes"], key=lambda item: item.get("observations_count", 0), reverse=True)]
        for index, (a_node_id, b_node_id) in enumerate(zip(a_path, b_path)):
            if a_node_id != b_node_id:
                divergence_points.append(
                    {
                        "index": index,
                        "service_a_node": a_nodes.get(a_node_id),
                        "service_b_node": b_nodes.get(b_node_id),
                        "reason": "path_divergence",
                    }
                )
                break

    summary = {
        "service_a": service_a,
        "service_b": service_b,
        "common_nodes_count": len(common_nodes),
        "common_edges_count": len(common_edges),
        "only_a_nodes_count": len(only_a_nodes),
        "only_b_nodes_count": len(only_b_nodes),
        "divergence_points_count": len(divergence_points),
        "shared_node_ratio_a": round(len(common_nodes) / len(a_nodes), 3) if a_nodes else 0.0,
        "shared_node_ratio_b": round(len(common_nodes) / len(b_nodes), 3) if b_nodes else 0.0,
    }
    return {
        "service_a": service_a,
        "service_b": service_b,
        "common_nodes": [a_nodes[node_id] for node_id in common_nodes],
        "common_edges": [a_edges[edge_id] for edge_id in common_edges],
        "only_a_nodes": [a_nodes[node_id] for node_id in only_a_nodes],
        "only_b_nodes": [b_nodes[node_id] for node_id in only_b_nodes],
        "divergence_points": divergence_points,
        "summary": summary,
        "limitations": [],
    }


def list_route_graph_clusters() -> dict[str, Any]:
    graph = build_global_route_graph()
    return {
        "graph_uid": "clusters",
        "scope": "clusters",
        "generated_at": _now().isoformat(),
        "summary": graph["summary"],
        "clusters": graph["clusters"],
        "filters": {},
        "limitations": graph["limitations"],
    }


def list_unknown_route_graph_hops() -> dict[str, Any]:
    graph = build_global_route_graph()
    nodes = [node for node in graph["nodes"] if node.get("is_unknown")]
    node_ids = {node["id"] for node in nodes}
    edges = [edge for edge in graph["edges"] if edge.get("source") in node_ids or edge.get("target") in node_ids]
    summary = {
        "nodes_count": len(nodes),
        "edges_count": len(edges),
        "unknown_hops_count": len(nodes),
    }
    return _graph_payload(
        graph_uid="unknown",
        scope="unknown",
        nodes=nodes,
        edges=edges,
        summary=summary,
        clusters=[cluster for cluster in graph["clusters"] if cluster["id"] == "unknown"],
        filters={"cluster": "unknown"},
        limitations=["unknown_hops_only"],
    )


def build_private_path_graph() -> dict[str, Any]:
    graph = build_global_route_graph()
    clusters = {"local", "cpe_onu", "provider_private", "provider_public_edge"}
    nodes = [node for node in graph["nodes"] if node.get("cluster") in clusters]
    node_ids = {node["id"] for node in nodes}
    edges = [edge for edge in graph["edges"] if edge.get("source") in node_ids and edge.get("target") in node_ids]
    summary = {
        "nodes_count": len(nodes),
        "edges_count": len(edges),
        "private_hops_count": sum(1 for node in nodes if node.get("is_private")),
    }
    return _graph_payload(
        graph_uid="private-path",
        scope="private_path",
        nodes=nodes,
        edges=edges,
        summary=summary,
        clusters=[cluster for cluster in graph["clusters"] if cluster["id"] in clusters],
        filters={"clusters": sorted(clusters)},
        limitations=["derived_from_private_path_heuristics"],
    )
