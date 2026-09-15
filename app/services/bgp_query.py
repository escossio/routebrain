from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from app.db.connection import get_connection


def _build_current_filter(prefix_or_search: str) -> tuple[str, list[Any]]:
    try:
        network = ip_network(prefix_or_search, strict=False)
    except ValueError:
        return "prefix::text like %s", [f"{prefix_or_search}%"]
    return "prefix = %s", [str(network)]


def _build_raw_filter(prefix_or_search: str) -> tuple[str, list[Any]]:
    try:
        network = ip_network(prefix_or_search, strict=False)
    except ValueError:
        return "prefix::text like %s", [f"{prefix_or_search}%"]
    return "prefix = %s", [str(network)]


def query_current_by_prefix(prefix_or_search: str, limit: int = 50) -> list[dict[str, Any]]:
    where_sql, params = _build_current_filter(prefix_or_search)
    sql = f"""
        select source, collector, peer_ip, peer_asn, prefix, next_hop, as_path,
               origin_asn, origin_type, first_seen, last_seen
          from bgp_current_routes
         where {where_sql}
         order by last_seen desc nulls last, first_seen desc nulls last, prefix asc
         limit %s
    """
    params = [*params, limit]

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

    return [
        {
            "source": row[0],
            "collector": row[1],
            "peer_ip": row[2],
            "peer_asn": row[3],
            "prefix": row[4],
            "next_hop": row[5],
            "as_path": row[6],
            "origin_asn": row[7],
            "origin_type": row[8],
            "first_seen": row[9],
            "last_seen": row[10],
        }
        for row in rows
    ]


def summarize_prefix(prefix_or_search: str) -> dict[str, Any]:
    where_sql, params = _build_current_filter(prefix_or_search)
    sql = f"""
        select
            count(*) as total_current_routes,
            count(distinct peer_ip) as total_peers,
            count(distinct peer_asn) as total_peer_asns,
            count(distinct origin_asn) as total_origin_asns,
            count(distinct as_path) as total_as_paths,
            min(first_seen) as first_seen_min,
            max(last_seen) as last_seen_max
          from bgp_current_routes
         where {where_sql}
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()

    return {
        "total_current_routes": row[0],
        "total_peers": row[1],
        "total_peer_asns": row[2],
        "total_origin_asns": row[3],
        "total_as_paths": row[4],
        "first_seen_min": row[5],
        "last_seen_max": row[6],
    }


def query_raw_by_prefix(prefix_or_search: str, limit: int = 20) -> list[dict[str, Any]]:
    where_sql, params = _build_raw_filter(prefix_or_search)
    sql = f"""
        select id, collector, collected_at, peer_ip, peer_asn, prefix, next_hop, as_path,
               origin_asn, origin_type, med, local_pref, communities
          from bgp_raw_routes
         where {where_sql}
         order by collected_at desc nulls last, id desc
         limit %s
    """
    params = [*params, limit]

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

    return [
        {
            "id": row[0],
            "collector": row[1],
            "collected_at": row[2],
            "peer_ip": row[3],
            "peer_asn": row[4],
            "prefix": row[5],
            "next_hop": row[6],
            "as_path": row[7],
            "origin_asn": row[8],
            "origin_type": row[9],
            "med": row[10],
            "local_pref": row[11],
            "communities": row[12],
        }
        for row in rows
    ]
