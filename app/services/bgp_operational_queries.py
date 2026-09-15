from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.db.connection import get_connection

MAX_LIMIT = 1000
DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."


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


def _fetch_scalar(sql: str, params: tuple[Any, ...] = ()) -> Any:
    row = _fetch_one(sql, params)
    if not row:
        return None
    return next(iter(row.values()))


def _clamp_limit(limit: int) -> int:
    if limit < 1:
        raise ValueError("Limite inválido.")
    return min(limit, MAX_LIMIT)


def _normalize_prefix(prefix: str) -> str:
    if "/" not in prefix:
        raise ValueError("Prefixo CIDR obrigatório.")
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError as exc:
        raise ValueError("Prefixo inválido.") from exc
    return str(network)


def _normalize_asn(value: int | str) -> int:
    try:
        asn = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("ASN inválido.") from exc
    if asn < 0:
        raise ValueError("ASN inválido.")
    return asn


def _normalize_peer(value: str) -> tuple[str | None, int | None]:
    text = str(value).strip()
    if not text:
        raise ValueError("Peer inválido.")
    try:
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        return None, _normalize_asn(text)


def _change_filters(change_type: str | None = None, since_hours: int | None = None) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if change_type:
        clauses.append("change_type = %s")
        params.append(change_type)
    if since_hours is not None:
        if since_hours < 1:
            raise ValueError("Janela temporal inválida.")
        clauses.append("detected_at >= now() - (%s * interval '1 hour')")
        params.append(since_hours)
    if not clauses:
        return "", params
    return " where " + " and ".join(clauses), params


@lru_cache(maxsize=None)
def _summary_table_exists(table_name: str) -> bool:
    exists = _fetch_scalar("select to_regclass(%s) is not null as exists;", (f"public.{table_name}",))
    return bool(exists)


def _current_prefix_summary(prefix: str) -> dict[str, Any] | None:
    return _fetch_one(
        """
        select
          count(*)::bigint as total_current_routes,
          count(distinct peer_ip)::bigint as total_peers,
          count(distinct peer_asn)::bigint as total_peer_asns,
          count(distinct origin_asn)::bigint as total_origin_asns,
          count(distinct collector)::bigint as total_collectors,
          min(first_seen) as first_seen_min,
          max(last_seen) as last_seen_max
        from bgp_current_routes
        where prefix = %s::cidr;
        """,
        (prefix,),
    )


def _current_peer_summary_from_table(peer_ip: str) -> dict[str, Any] | None:
    if not _summary_table_exists("bgp_summary_current_by_peer"):
        return None
    return _fetch_one(
        """
        select
          peer_ip::text as peer_ip,
          peer_asn,
          route_count,
          prefix_count,
          origin_asn_count,
          collector_count,
          updated_at
        from bgp_summary_current_by_peer
        where peer_ip = %s::inet
        limit 1;
        """,
        (peer_ip,),
    )


def _current_origin_asn_summary_from_table(origin_asn: int) -> dict[str, Any] | None:
    if not _summary_table_exists("bgp_summary_current_by_origin_asn"):
        return None
    return _fetch_one(
        """
        select
          origin_asn,
          route_count,
          prefix_count,
          peer_count,
          collector_count,
          updated_at
        from bgp_summary_current_by_origin_asn
        where origin_asn = %s
        limit 1;
        """,
        (origin_asn,),
    )


def _current_peer_summary_rows(limit: int) -> list[dict[str, Any]] | None:
    if not _summary_table_exists("bgp_summary_current_by_peer"):
        return None
    return _fetch_all(
        """
        select
          peer_ip::text as peer_ip,
          peer_asn,
          route_count,
          prefix_count,
          origin_asn_count,
          collector_count,
          updated_at
        from bgp_summary_current_by_peer
        order by route_count desc, prefix_count desc, peer_ip asc, peer_asn asc
        limit %s;
        """,
        (limit,),
    )


def _current_origin_asn_summary_rows(limit: int) -> list[dict[str, Any]] | None:
    if not _summary_table_exists("bgp_summary_current_by_origin_asn"):
        return None
    return _fetch_all(
        """
        select
          origin_asn,
          route_count,
          prefix_count,
          peer_count,
          collector_count,
          updated_at
        from bgp_summary_current_by_origin_asn
        order by route_count desc, prefix_count desc, origin_asn asc
        limit %s;
        """,
        (limit,),
    )


def _changes_by_prefix_summary(limit: int) -> list[dict[str, Any]] | None:
    if not _summary_table_exists("bgp_summary_changes_by_prefix"):
        return None
    rows = _fetch_all(
        """
        select
          prefix::text as prefix,
          total_changes,
          new_route_count,
          as_path_changed_count,
          origin_type_changed_count,
          first_change_at,
          last_change_at,
          updated_at
        from bgp_summary_changes_by_prefix
        order by total_changes desc, last_change_at desc nulls last, prefix asc
        limit %s;
        """,
        (limit,),
    )
    return rows


def _changes_by_origin_asn_summary(limit: int) -> list[dict[str, Any]] | None:
    if not _summary_table_exists("bgp_summary_changes_by_origin_asn"):
        return None
    rows = _fetch_all(
        """
        select
          origin_asn,
          total_changes,
          new_route_count,
          as_path_changed_count,
          origin_type_changed_count,
          updated_at
        from bgp_summary_changes_by_origin_asn
        order by total_changes desc, origin_asn asc
        limit %s;
        """,
        (limit,),
    )
    return rows


def _changes_by_peer_summary(limit: int) -> list[dict[str, Any]] | None:
    if not _summary_table_exists("bgp_summary_changes_by_peer"):
        return None
    rows = _fetch_all(
        """
        select
          peer_ip::text as peer_ip,
          peer_asn,
          total_changes,
          new_route_count,
          as_path_changed_count,
          origin_type_changed_count,
          updated_at
        from bgp_summary_changes_by_peer
        order by total_changes desc, peer_ip asc, peer_asn asc
        limit %s;
        """,
        (limit,),
    )
    return rows


def _current_asn_summary(asn: int) -> dict[str, Any] | None:
    return _fetch_one(
        """
        select
          count(*)::bigint as total_current_routes,
          count(distinct prefix)::bigint as total_prefixes,
          count(distinct peer_ip)::bigint as total_peers,
          count(distinct peer_asn)::bigint as total_peer_asns,
          count(distinct collector)::bigint as total_collectors,
          min(first_seen) as first_seen_min,
          max(last_seen) as last_seen_max
        from bgp_current_routes
        where origin_asn = %s;
        """,
        (asn,),
    )


def _peer_current_summary_by_ip(peer_ip: str) -> dict[str, Any] | None:
    return _fetch_one(
        """
        select
          count(*)::bigint as total_current_routes,
          count(distinct prefix)::bigint as total_prefixes,
          count(distinct origin_asn)::bigint as total_origin_asns,
          count(distinct collector)::bigint as total_collectors,
          min(first_seen) as first_seen_min,
          max(last_seen) as last_seen_max
        from bgp_current_routes
        where peer_ip = %s::inet;
        """,
        (peer_ip,),
    )


def _peer_current_summary_by_asn(peer_asn: int) -> dict[str, Any] | None:
    return _fetch_one(
        """
        select
          count(*)::bigint as total_current_routes,
          count(distinct prefix)::bigint as total_prefixes,
          count(distinct origin_asn)::bigint as total_origin_asns,
          count(distinct peer_ip)::bigint as total_peer_ips,
          count(distinct collector)::bigint as total_collectors,
          min(first_seen) as first_seen_min,
          max(last_seen) as last_seen_max
        from bgp_current_routes
        where peer_asn = %s;
        """,
        (peer_asn,),
    )


def _prefix_peer_counts(prefix: str, limit: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          peer_ip::text as peer_ip,
          peer_asn,
          count(*)::bigint as total_routes,
          min(first_seen) as first_seen_min,
          max(last_seen) as last_seen_max
        from bgp_current_routes
        where prefix = %s::cidr
        group by peer_ip, peer_asn
        order by total_routes desc, peer_ip asc, peer_asn asc
        limit %s;
        """,
        (prefix, limit),
    )


def _prefix_current_routes(prefix: str, limit: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          next_hop::text as next_hop,
          as_path,
          origin_asn,
          origin_type,
          first_seen,
          last_seen,
          inventory_peer_name,
          inventory_connection_type,
          inventory_peer_status,
          router_hostname,
          router_role,
          interface_name,
          interface_description,
          ixp_name,
          site_name,
          enrichment_status,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          ping_measured_at
        from v_bgp_current_routes_with_ping
        where prefix = %s::cidr
        order by peer_ip, collector
        limit %s;
        """,
        (prefix, limit),
    )


def _prefix_recent_changes(prefix: str, limit: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          detected_at,
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          change_type,
          old_as_path,
          new_as_path,
          old_next_hop::text as old_next_hop,
          new_next_hop::text as new_next_hop,
          old_origin_asn,
          new_origin_asn,
          inventory_peer_name,
          inventory_connection_type,
          ixp_name,
          router_hostname,
          enrichment_status,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          ping_measured_at
        from v_bgp_route_changes_with_ping
        where prefix = %s::cidr
        order by detected_at desc, id desc
        limit %s;
        """,
        (prefix, limit),
    )


def _asn_prefixes(asn: int, limit: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          prefix::text as prefix,
          count(*)::bigint as total_routes,
          count(distinct peer_ip)::bigint as total_peers,
          count(distinct peer_asn)::bigint as total_peer_asns,
          min(first_seen) as first_seen_min,
          max(last_seen) as last_seen_max
        from bgp_current_routes
        where origin_asn = %s
        group by prefix
        order by total_routes desc, prefix asc
        limit %s;
        """,
        (asn, limit),
    )


def _asn_top_peers(asn: int, limit: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          peer_ip::text as peer_ip,
          peer_asn,
          count(*)::bigint as total_routes,
          count(distinct prefix)::bigint as total_prefixes,
          min(first_seen) as first_seen_min,
          max(last_seen) as last_seen_max
        from bgp_current_routes
        where origin_asn = %s
        group by peer_ip, peer_asn
        order by total_routes desc, peer_ip asc, peer_asn asc
        limit %s;
        """,
        (asn, limit),
    )


def _asn_current_routes(asn: int, limit: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          next_hop::text as next_hop,
          as_path,
          origin_asn,
          origin_type,
          first_seen,
          last_seen
        from bgp_current_routes
        where origin_asn = %s
        order by prefix::text, peer_ip::text, collector
        limit %s;
        """,
        (asn, limit),
    )


def _asn_recent_changes(asn: int, limit: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          detected_at,
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          change_type,
          old_as_path,
          new_as_path,
          old_next_hop::text as old_next_hop,
          new_next_hop::text as new_next_hop,
          old_origin_asn,
          new_origin_asn
        from bgp_route_changes
        where old_origin_asn = %s or new_origin_asn = %s
        order by detected_at desc, id desc
        limit %s;
        """,
        (asn, asn, limit),
    )


def _asn_change_distribution(asn: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          change_type,
          count(*)::bigint as total_changes
        from bgp_route_changes
        where old_origin_asn = %s or new_origin_asn = %s
        group by change_type
        order by total_changes desc, change_type asc;
        """,
        (asn, asn),
    )


def _peer_inventory_rows(peer_ip: str | None, peer_asn: int | None, limit: int) -> list[dict[str, Any]]:
    if peer_ip is not None:
        return _fetch_all(
            """
            select
              observed_peer_ip::text as observed_peer_ip,
              observed_peer_asn,
              observed_routes,
              observed_prefixes,
              inventory_peer_name,
              inventory_connection_type,
              inventory_status,
              router_hostname,
              router_role,
              interface_name,
              interface_description,
              ixp_name,
              site_name,
              match_status,
              ping_status,
              packets_sent,
              packets_received,
              packet_loss_percent,
              rtt_min_ms,
              rtt_avg_ms,
              rtt_max_ms,
              rtt_mdev_ms,
              ping_measured_at
            from v_bgp_peer_with_latest_ping
            where observed_peer_ip = %s::inet
            limit %s;
            """,
            (peer_ip, limit),
        )
    return _fetch_all(
        """
        select
          observed_peer_ip::text as observed_peer_ip,
          observed_peer_asn,
          observed_routes,
          observed_prefixes,
          inventory_peer_name,
          inventory_connection_type,
          inventory_status,
          router_hostname,
          router_role,
          interface_name,
          interface_description,
          ixp_name,
          site_name,
          match_status,
          ping_status,
          packets_sent,
          packets_received,
          packet_loss_percent,
          rtt_min_ms,
          rtt_avg_ms,
          rtt_max_ms,
          rtt_mdev_ms,
          ping_measured_at
        from v_bgp_peer_with_latest_ping
        where observed_peer_asn = %s
        order by observed_routes desc, observed_peer_ip
        limit %s;
        """,
        (peer_asn, limit),
    )


def _peer_current_routes(peer_ip: str | None, peer_asn: int | None, limit: int) -> list[dict[str, Any]]:
    if peer_ip is not None:
        return _fetch_all(
            """
            select
              source,
              collector,
              peer_ip::text as peer_ip,
              peer_asn,
              prefix::text as prefix,
              next_hop::text as next_hop,
              as_path,
              origin_asn,
              origin_type,
              first_seen,
              last_seen
            from bgp_current_routes
            where peer_ip = %s::inet
            order by prefix, collector
            limit %s;
            """,
            (peer_ip, limit),
        )
    return _fetch_all(
        """
        select
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          next_hop::text as next_hop,
          as_path,
          origin_asn,
          origin_type,
          first_seen,
          last_seen
        from bgp_current_routes
        where peer_asn = %s
        order by prefix, peer_ip, collector
        limit %s;
        """,
        (peer_asn, limit),
    )


def _peer_recent_changes(peer_ip: str | None, peer_asn: int | None, limit: int) -> list[dict[str, Any]]:
    if peer_ip is not None:
        return _fetch_all(
            """
            select
              detected_at,
              source,
              collector,
              peer_ip::text as peer_ip,
              peer_asn,
              prefix::text as prefix,
              change_type,
              old_as_path,
              new_as_path,
              old_next_hop::text as old_next_hop,
              new_next_hop::text as new_next_hop,
              old_origin_asn,
              new_origin_asn
            from bgp_route_changes
            where peer_ip = %s::inet
            order by detected_at desc, id desc
            limit %s;
            """,
            (peer_ip, limit),
        )
    return _fetch_all(
        """
        select
          detected_at,
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          change_type,
          old_as_path,
          new_as_path,
          old_next_hop::text as old_next_hop,
          new_next_hop::text as new_next_hop,
          old_origin_asn,
          new_origin_asn
        from bgp_route_changes
        where peer_asn = %s
        order by detected_at desc, id desc
        limit %s;
        """,
        (peer_asn, limit),
    )


def _peer_change_distribution(peer_ip: str | None, peer_asn: int | None) -> list[dict[str, Any]]:
    if peer_ip is not None:
        return _fetch_all(
            """
            select change_type, count(*)::bigint as total_changes
            from bgp_route_changes
            where peer_ip = %s::inet
            group by change_type
            order by total_changes desc, change_type asc;
            """,
            (peer_ip,),
        )
    return _fetch_all(
        """
        select change_type, count(*)::bigint as total_changes
        from bgp_route_changes
        where peer_asn = %s
        group by change_type
        order by total_changes desc, change_type asc;
        """,
        (peer_asn,),
    )


def _peer_change_totals(peer_ip: str | None, peer_asn: int | None) -> dict[str, Any] | None:
    if peer_ip is not None:
        return _fetch_one(
            """
            select
              count(*)::bigint as total_changes,
              count(distinct prefix)::bigint as total_prefixes_changed,
              count(distinct old_origin_asn)::bigint as total_old_origin_asns,
              count(distinct new_origin_asn)::bigint as total_new_origin_asns
            from bgp_route_changes
            where peer_ip = %s::inet;
            """,
            (peer_ip,),
        )
    return _fetch_one(
        """
        select
          count(*)::bigint as total_changes,
          count(distinct prefix)::bigint as total_prefixes_changed,
          count(distinct old_origin_asn)::bigint as total_old_origin_asns,
          count(distinct new_origin_asn)::bigint as total_new_origin_asns
        from bgp_route_changes
        where peer_asn = %s;
        """,
        (peer_asn,),
    )


def get_prefix_lookup(prefix: str, limit: int = 20) -> dict[str, Any] | None:
    normalized_prefix = _normalize_prefix(prefix)
    limit = _clamp_limit(limit)
    current_summary = _current_prefix_summary(normalized_prefix) or {}
    current_routes = _prefix_current_routes(normalized_prefix, limit)
    peer_counts = _prefix_peer_counts(normalized_prefix, limit)
    recent_changes = _prefix_recent_changes(normalized_prefix, limit)
    total_current_routes = int(current_summary.get("total_current_routes") or 0)
    if total_current_routes == 0 and not current_routes and not recent_changes:
        return None
    return {
        "query": {"prefix": normalized_prefix, "type": "prefix"},
        "summary": current_summary,
        "peer_counts": peer_counts,
        "current_routes": current_routes,
        "recent_changes": recent_changes,
    }


def lookup_bgp_by_ip(ip_address: str, limit_peers: int = 20) -> dict[str, Any] | None:
    normalized_ip = str(ipaddress.ip_address(str(ip_address).strip()))
    limit = _clamp_limit(limit_peers)
    match_row = _fetch_one(
        """
        select
          prefix::text as prefix,
          origin_asn,
          origin_type
        from bgp_current_routes
        where family(prefix) = family(%s::inet)
          and prefix >>= %s::inet
        order by masklen(prefix) desc, last_seen desc nulls last, prefix asc, origin_asn asc
        limit 1;
        """,
        (normalized_ip, normalized_ip),
    )
    if match_row is None:
        return None

    matched_prefix = str(match_row.get("prefix") or "")
    prefix_lookup = get_prefix_lookup(matched_prefix, limit=limit) or {}
    summary = prefix_lookup.get("summary") or {}
    current_routes = prefix_lookup.get("current_routes") or []
    peer_counts = prefix_lookup.get("peer_counts") or []
    sample_peers = [str(row.get("peer_ip")) for row in peer_counts[:5] if row.get("peer_ip")]
    if not sample_peers:
        sample_peers = [str(row.get("peer_ip")) for row in current_routes[:5] if row.get("peer_ip")]
    sample_as_paths: list[str] = []
    seen_paths: set[str] = set()
    for route in current_routes:
        as_path = str(route.get("as_path") or "").strip()
        if not as_path or as_path in seen_paths:
            continue
        seen_paths.add(as_path)
        sample_as_paths.append(as_path)
        if len(sample_as_paths) >= 5:
            break

    total_routes = int(summary.get("total_current_routes") or len(current_routes) or 0)
    peer_count = int(summary.get("total_peers") or len(peer_counts) or 0)
    collector_count = int(summary.get("total_collectors") or 0)
    output = {
        "query": {"ip": normalized_ip, "type": "ip"},
        "ip": normalized_ip,
        "family": "ipv6" if ipaddress.ip_address(normalized_ip).version == 6 else "ipv4",
        "matched_prefix": matched_prefix,
        "origin_asn": match_row.get("origin_asn"),
        "origin_type": match_row.get("origin_type"),
        "match_route_count": total_routes,
        "peer_count": peer_count,
        "collector_count": collector_count,
        "sample_peers": sample_peers,
        "sample_as_paths": sample_as_paths,
        "summary": summary,
        "current_routes": current_routes[:limit],
        "peer_counts": peer_counts[:limit],
    }
    return output


def get_asn_lookup(asn: int | str, limit: int = 20) -> dict[str, Any] | None:
    normalized_asn = _normalize_asn(asn)
    limit = _clamp_limit(limit)
    current_summary = _current_origin_asn_summary_from_table(normalized_asn) or _current_asn_summary(normalized_asn) or {}
    prefixes = _asn_prefixes(normalized_asn, limit)
    top_peers = _asn_top_peers(normalized_asn, limit)
    current_routes = _asn_current_routes(normalized_asn, limit)
    recent_changes = _asn_recent_changes(normalized_asn, limit)
    change_distribution = _asn_change_distribution(normalized_asn)
    total_current_routes = int(current_summary.get("total_current_routes") or 0)
    if total_current_routes == 0 and not prefixes and not recent_changes:
        return None
    return {
        "query": {"asn": normalized_asn, "type": "asn"},
        "summary": current_summary,
        "prefixes": prefixes,
        "top_peers": top_peers,
        "current_routes": current_routes,
        "recent_changes": recent_changes,
        "change_distribution": change_distribution,
    }


def get_peer_lookup(peer: str, limit: int = 20) -> dict[str, Any] | None:
    peer_ip, peer_asn = _normalize_peer(peer)
    limit = _clamp_limit(limit)
    observations: list[dict[str, Any]] = []
    if peer_ip is not None:
        current_summary = _current_peer_summary_from_table(peer_ip) or _peer_current_summary_by_ip(peer_ip)
        if current_summary:
            observations = [
                {
                    "observed_peer_ip": current_summary.get("peer_ip"),
                    "observed_peer_asn": current_summary.get("peer_asn"),
                    "observed_routes": current_summary.get("route_count"),
                    "observed_prefixes": current_summary.get("prefix_count"),
                    "inventory_peer_name": None,
                    "inventory_connection_type": None,
                    "inventory_status": None,
                    "router_hostname": None,
                    "router_role": None,
                    "interface_name": None,
                    "interface_description": None,
                    "ixp_name": None,
                    "site_name": None,
                    "match_status": "SUMMARY",
                }
            ]
    else:
        current_summary = _peer_current_summary_by_asn(peer_asn or 0)

    current_routes = _peer_current_routes(peer_ip, peer_asn, limit)
    recent_changes = _peer_recent_changes(peer_ip, peer_asn, limit)
    change_distribution: list[dict[str, Any]] = []
    change_totals: dict[str, Any] | None = None
    ping_detail = None
    total_current_routes = int((current_summary or {}).get("total_current_routes") or (current_summary or {}).get("route_count") or 0)
    if total_current_routes == 0 and not observations and not current_routes and not recent_changes:
        return None
    return {
        "query": {"peer": peer_ip or peer_asn, "type": "peer_ip" if peer_ip is not None else "peer_asn"},
        "summary": current_summary,
        "observations": observations,
        "ping_detail": ping_detail,
        "current_routes": current_routes,
        "recent_changes": recent_changes,
        "change_distribution": change_distribution,
        "change_totals": change_totals,
    }


def get_top_prefixes(limit: int = 20, change_type: str | None = None, since_hours: int | None = None) -> dict[str, Any] | None:
    limit = _clamp_limit(limit)
    if change_type is None and since_hours is None:
        summary_rows = _changes_by_prefix_summary(limit)
        if summary_rows:
            return {
                "filters": {"change_type": change_type, "since_hours": since_hours},
                "items": summary_rows,
            }
    where_sql, params = _change_filters(change_type=change_type, since_hours=since_hours)
    rows = _fetch_all(
        f"""
        select
          prefix::text as prefix,
          count(*)::bigint as total_changes,
          min(detected_at) as first_change_at,
          max(detected_at) as last_change_at
        from bgp_route_changes
        {where_sql}
        group by prefix
        order by total_changes desc, last_change_at desc, prefix asc
        limit %s;
        """,
        tuple(params + [limit]),
    )
    if not rows:
        return None
    return {
        "filters": {"change_type": change_type, "since_hours": since_hours},
        "items": rows,
    }


def get_top_origin_asns(limit: int = 20, change_type: str | None = None, since_hours: int | None = None) -> dict[str, Any] | None:
    limit = _clamp_limit(limit)
    if change_type is None and since_hours is None:
        summary_rows = _current_origin_asn_summary_rows(limit)
        if summary_rows:
            return {
                "filters": {"change_type": change_type, "since_hours": since_hours},
                "items": summary_rows,
            }
        rows = _fetch_all(
            """
            select
              origin_asn,
              count(*)::bigint as route_count,
              count(distinct prefix)::bigint as prefix_count,
              count(distinct peer_ip)::bigint as peer_count,
              count(distinct collector)::bigint as collector_count,
              max(last_seen) as updated_at
            from bgp_current_routes
            group by origin_asn
            order by route_count desc, origin_asn asc
            limit %s;
            """,
            (limit,),
        )
        if not rows:
            return None
        return {
            "filters": {"change_type": change_type, "since_hours": since_hours},
            "items": rows,
        }
    where_sql, params = _change_filters(change_type=change_type, since_hours=since_hours)
    rows = _fetch_all(
        f"""
        select
          coalesce(new_origin_asn, old_origin_asn) as origin_asn,
          count(*)::bigint as total_changes,
          min(detected_at) as first_change_at,
          max(detected_at) as last_change_at
        from bgp_route_changes
        {where_sql}
        group by coalesce(new_origin_asn, old_origin_asn)
        order by total_changes desc, origin_asn asc
        limit %s;
        """,
        tuple(params + [limit]),
    )
    if not rows:
        return None
    return {
        "filters": {"change_type": change_type, "since_hours": since_hours},
        "items": rows,
    }


def get_top_peers(limit: int = 20, change_type: str | None = None, since_hours: int | None = None) -> dict[str, Any] | None:
    limit = _clamp_limit(limit)
    if change_type is None and since_hours is None:
        summary_rows = _current_peer_summary_rows(limit)
        if summary_rows:
            return {
                "filters": {"change_type": change_type, "since_hours": since_hours},
                "items": summary_rows,
            }
        rows = _fetch_all(
            """
            select
              peer_ip::text as peer_ip,
              peer_asn,
              count(*)::bigint as route_count,
              count(distinct prefix)::bigint as prefix_count,
              count(distinct origin_asn)::bigint as origin_asn_count,
              count(distinct collector)::bigint as collector_count,
              max(last_seen) as updated_at
            from bgp_current_routes
            group by peer_ip, peer_asn
            order by route_count desc, peer_ip asc, peer_asn asc
            limit %s;
            """,
            (limit,),
        )
        if not rows:
            return None
        return {
            "filters": {"change_type": change_type, "since_hours": since_hours},
            "items": rows,
        }
    where_sql, params = _change_filters(change_type=change_type, since_hours=since_hours)
    rows = _fetch_all(
        f"""
        select
          peer_ip::text as peer_ip,
          peer_asn,
          count(*)::bigint as total_changes,
          min(detected_at) as first_change_at,
          max(detected_at) as last_change_at
        from bgp_route_changes
        {where_sql}
        group by peer_ip, peer_asn
        order by total_changes desc, peer_ip asc, peer_asn asc
        limit %s;
        """,
        tuple(params + [limit]),
    )
    if not rows:
        return None
    return {
        "filters": {"change_type": change_type, "since_hours": since_hours},
        "items": rows,
    }


def get_top_changes(limit: int = 20, change_type: str | None = None, since_hours: int | None = None) -> dict[str, Any] | None:
    limit = _clamp_limit(limit)
    where_sql, params = _change_filters(change_type=change_type, since_hours=since_hours)
    change_distribution = _fetch_all(
        f"""
        select change_type, count(*)::bigint as total_changes
        from bgp_route_changes
        {where_sql}
        group by change_type
        order by total_changes desc, change_type asc;
        """,
        tuple(params),
    )
    if change_type is None and since_hours is None:
        top_prefixes = _changes_by_prefix_summary(limit) or _fetch_all(
            """
            select
              prefix::text as prefix,
              count(*)::bigint as total_changes,
              count(*) filter (where change_type = 'NEW_ROUTE')::bigint as new_route_count,
              count(*) filter (where change_type = 'AS_PATH_CHANGED')::bigint as as_path_changed_count,
              count(*) filter (where change_type = 'ORIGIN_TYPE_CHANGED')::bigint as origin_type_changed_count,
              min(detected_at) as first_change_at,
              max(detected_at) as last_change_at,
              max(detected_at) as updated_at
            from bgp_route_changes
            group by prefix
            order by total_changes desc, last_change_at desc, prefix asc
            limit %s;
            """,
            (limit,),
        )
        top_origin_asns = _changes_by_origin_asn_summary(limit) or _fetch_all(
            """
            select
              coalesce(new_origin_asn, old_origin_asn) as origin_asn,
              count(*)::bigint as total_changes,
              count(*) filter (where change_type = 'NEW_ROUTE')::bigint as new_route_count,
              count(*) filter (where change_type = 'AS_PATH_CHANGED')::bigint as as_path_changed_count,
              count(*) filter (where change_type = 'ORIGIN_TYPE_CHANGED')::bigint as origin_type_changed_count,
              max(detected_at) as updated_at
            from bgp_route_changes
            group by coalesce(new_origin_asn, old_origin_asn)
            order by total_changes desc, origin_asn asc
            limit %s;
            """,
            (limit,),
        )
        top_peers = _changes_by_peer_summary(limit) or _fetch_all(
            """
            select
              peer_ip::text as peer_ip,
              peer_asn,
              count(*)::bigint as total_changes,
              count(*) filter (where change_type = 'NEW_ROUTE')::bigint as new_route_count,
              count(*) filter (where change_type = 'AS_PATH_CHANGED')::bigint as as_path_changed_count,
              count(*) filter (where change_type = 'ORIGIN_TYPE_CHANGED')::bigint as origin_type_changed_count,
              max(detected_at) as updated_at
            from bgp_route_changes
            group by peer_ip, peer_asn
            order by total_changes desc, peer_ip asc, peer_asn asc
            limit %s;
            """,
            (limit,),
        )
    else:
        top_prefixes = get_top_prefixes(limit=limit, change_type=change_type, since_hours=since_hours)
        top_origin_asns = get_top_origin_asns(limit=limit, change_type=change_type, since_hours=since_hours)
        top_peers = get_top_peers(limit=limit, change_type=change_type, since_hours=since_hours)
    if not change_distribution and not top_prefixes and not top_origin_asns and not top_peers:
        return None

    def _items(result: Any) -> list[dict[str, Any]]:
        if not result:
            return []
        if isinstance(result, dict):
            return result.get("items", [])
        return result

    return {
        "filters": {"change_type": change_type, "since_hours": since_hours, "limit": limit},
        "change_distribution": change_distribution,
        "top_prefixes": _items(top_prefixes),
        "top_origin_asns": _items(top_origin_asns),
        "top_peers": _items(top_peers),
    }
