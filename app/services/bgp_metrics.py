from __future__ import annotations

from typing import Any

from app.db.connection import get_connection


def _fetch_all(sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or [])
            rows = cur.fetchall()
            columns = [desc.name for desc in cur.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def _fetch_one(sql: str, params: list[Any] | None = None) -> dict[str, Any]:
    rows = _fetch_all(sql, params)
    return rows[0] if rows else {}


def get_route_change_summary() -> dict[str, Any]:
    sql = """
        select
            count(*) as total_changes,
            count(distinct prefix) as total_prefixes_changed,
            count(distinct peer_ip) as total_peers_affected,
            count(distinct collector) as total_collectors,
            min(detected_at) as first_change_at,
            max(detected_at) as last_change_at
          from bgp_route_changes
    """
    return _fetch_one(sql)


def get_changes_by_type() -> list[dict[str, Any]]:
    sql = """
        select change_type, count(*) as total_changes
          from bgp_route_changes
         group by change_type
         order by total_changes desc, change_type asc
    """
    return _fetch_all(sql)


def get_top_changed_prefixes(limit: int = 10) -> list[dict[str, Any]]:
    sql = """
        select
            prefix,
            count(*) as total_changes,
            min(detected_at) as first_change_at,
            max(detected_at) as last_change_at
          from bgp_route_changes
         group by prefix
         order by total_changes desc, last_change_at desc, prefix asc
         limit %s
    """
    return _fetch_all(sql, [limit])


def get_top_changed_origin_asns(limit: int = 10) -> list[dict[str, Any]]:
    sql = """
        select
            coalesce(new_origin_asn, old_origin_asn) as origin_asn,
            count(*) as total_changes
          from bgp_route_changes
         group by coalesce(new_origin_asn, old_origin_asn)
         order by total_changes desc, origin_asn asc
         limit %s
    """
    return _fetch_all(sql, [limit])


def get_top_changed_peers(limit: int = 10) -> list[dict[str, Any]]:
    sql = """
        select
            peer_ip,
            peer_asn,
            count(*) as total_changes
          from bgp_route_changes
         group by peer_ip, peer_asn
         order by total_changes desc, peer_ip asc, peer_asn asc
         limit %s
    """
    return _fetch_all(sql, [limit])


def get_latest_changes(limit: int = 20) -> list[dict[str, Any]]:
    sql = """
        select
            id,
            detected_at,
            source,
            collector,
            peer_ip,
            peer_asn,
            prefix,
            change_type,
            old_next_hop,
            new_next_hop,
            old_as_path,
            new_as_path,
            old_origin_asn,
            new_origin_asn
          from bgp_route_changes
         order by detected_at desc, id desc
         limit %s
    """
    return _fetch_all(sql, [limit])


def get_current_routes_summary() -> dict[str, Any]:
    sql = """
        select
            count(*) as total_current_routes,
            count(distinct prefix) as total_prefixes,
            count(distinct peer_ip) as total_peers,
            count(distinct peer_asn) as total_peer_asns,
            count(distinct origin_asn) as total_origin_asns,
            count(distinct collector) as total_collectors,
            min(first_seen) as first_seen_min,
            max(last_seen) as last_seen_max
          from bgp_current_routes
    """
    return _fetch_one(sql)
