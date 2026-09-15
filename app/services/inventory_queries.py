from __future__ import annotations

import ipaddress
from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.db.connection import get_connection

MAX_LIMIT = 500
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


def _clamp_limit(limit: int) -> int:
    if limit < 1:
        raise ValueError("Limite inválido.")
    return min(limit, MAX_LIMIT)


def _normalize_peer_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("IP de peer inválido.") from exc


def _normalize_asn(value: int | str | None) -> int | None:
    if value is None:
        return None
    try:
        asn = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("ASN inválido.") from exc
    if asn < 0:
        raise ValueError("ASN inválido.")
    return asn


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def list_sites() -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          s.id,
          s.site_code,
          s.name,
          s.site_type,
          s.city,
          s.state,
          s.country,
          s.facility,
          s.notes,
          s.created_at,
          s.updated_at,
          coalesce(host_stats.host_count, 0)::bigint as host_count,
          coalesce(interface_stats.interface_count, 0)::bigint as interface_count,
          coalesce(link_stats.peer_link_count, 0)::bigint as peer_link_count
        from inventory_sites s
        left join lateral (
            select count(*)::bigint as host_count
            from inventory_hosts h
            where h.site_id = s.id
        ) host_stats on true
        left join lateral (
            select count(*)::bigint as interface_count
            from inventory_interfaces i
            join inventory_hosts h on h.id = i.host_id
            where h.site_id = s.id
        ) interface_stats on true
        left join lateral (
            select count(*)::bigint as peer_link_count
            from inventory_peer_links pl
            where pl.site_id = s.id
        ) link_stats on true
        order by s.site_code asc;
        """,
    )


def get_site(site_code: str) -> dict[str, Any] | None:
    site_code = _normalize_text(site_code)
    if not site_code:
        raise ValueError("site_code inválido.")
    return _fetch_one(
        """
        select
          s.id,
          s.site_code,
          s.name,
          s.site_type,
          s.city,
          s.state,
          s.country,
          s.facility,
          s.notes,
          s.created_at,
          s.updated_at,
          coalesce(host_stats.host_count, 0)::bigint as host_count,
          coalesce(interface_stats.interface_count, 0)::bigint as interface_count,
          coalesce(link_stats.peer_link_count, 0)::bigint as peer_link_count
        from inventory_sites s
        left join lateral (
            select count(*)::bigint as host_count
            from inventory_hosts h
            where h.site_id = s.id
        ) host_stats on true
        left join lateral (
            select count(*)::bigint as interface_count
            from inventory_interfaces i
            join inventory_hosts h on h.id = i.host_id
            where h.site_id = s.id
        ) interface_stats on true
        left join lateral (
            select count(*)::bigint as peer_link_count
            from inventory_peer_links pl
            where pl.site_id = s.id
        ) link_stats on true
        where s.site_code = %s
        limit 1;
        """,
        (site_code,),
    )


def list_hosts(
    site_code: str | None = None,
    role: str | None = None,
    tag: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit)
    clauses = ["1 = 1"]
    params: list[Any] = []

    site_code = _normalize_text(site_code)
    role = _normalize_text(role)
    tag = _normalize_text(tag)

    if site_code is not None:
        clauses.append("s.site_code = %s")
        params.append(site_code)
    if role is not None:
        clauses.append("h.role = %s")
        params.append(role)
    if tag is not None:
        clauses.append(
            """
            exists (
                select 1
                from inventory_host_tags ht
                join inventory_tags t on t.id = ht.tag_id
                where ht.host_id = h.id
                  and t.tag ilike %s
            )
            """
        )
        params.append(f"%{tag}%")

    sql = f"""
        select
          h.id,
          h.hostname,
          h.mgmt_ip::text as mgmt_ip,
          s.site_code,
          s.name as site_name,
          h.role,
          h.vendor,
          h.model,
          h.os_name,
          h.status,
          h.notes,
          h.created_at,
          h.updated_at,
          coalesce(interface_stats.interface_count, 0)::bigint as interface_count,
          coalesce(link_stats.peer_link_count, 0)::bigint as peer_link_count,
          coalesce(tag_stats.tag_count, 0)::bigint as tag_count
        from inventory_hosts h
        left join inventory_sites s on s.id = h.site_id
        left join lateral (
            select count(*)::bigint as interface_count
            from inventory_interfaces i
            where i.host_id = h.id
        ) interface_stats on true
        left join lateral (
            select count(*)::bigint as peer_link_count
            from inventory_peer_links pl
            where pl.host_id = h.id
        ) link_stats on true
        left join lateral (
            select count(*)::bigint as tag_count
            from inventory_host_tags ht
            where ht.host_id = h.id
        ) tag_stats on true
        where {' and '.join(clauses)}
        order by h.hostname asc
        limit %s;
    """
    params.append(limit)
    return _fetch_all(sql, tuple(params))


def get_host(hostname: str) -> dict[str, Any] | None:
    hostname = _normalize_text(hostname)
    if not hostname:
        raise ValueError("hostname inválido.")
    host = _fetch_one(
        """
        select
          h.id,
          h.hostname,
          h.mgmt_ip::text as mgmt_ip,
          s.site_code,
          s.name as site_name,
          h.role,
          h.vendor,
          h.model,
          h.os_name,
          h.status,
          h.notes,
          h.created_at,
          h.updated_at,
          coalesce(interface_stats.interface_count, 0)::bigint as interface_count,
          coalesce(link_stats.peer_link_count, 0)::bigint as peer_link_count,
          coalesce(tag_stats.tag_count, 0)::bigint as tag_count
        from inventory_hosts h
        left join inventory_sites s on s.id = h.site_id
        left join lateral (
            select count(*)::bigint as interface_count
            from inventory_interfaces i
            where i.host_id = h.id
        ) interface_stats on true
        left join lateral (
            select count(*)::bigint as peer_link_count
            from inventory_peer_links pl
            where pl.host_id = h.id
        ) link_stats on true
        left join lateral (
            select count(*)::bigint as tag_count
            from inventory_host_tags ht
            where ht.host_id = h.id
        ) tag_stats on true
        where lower(h.hostname) = lower(%s)
        limit 1;
        """,
        (hostname,),
    )
    if host is None:
        return None

    host_id = int(host["id"])
    host["tags"] = _fetch_all(
        """
        select
          t.tag,
          t.description
        from inventory_host_tags ht
        join inventory_tags t on t.id = ht.tag_id
        where ht.host_id = %s
        order by t.tag asc;
        """,
        (host_id,),
    )
    host["interfaces"] = _fetch_all(
        """
        select
          i.id,
          i.interface_name,
          i.interface_ip::text as interface_ip,
          i.description,
          i.speed_mbps,
          i.vlan,
          i.circuit_ref,
          i.peer_ip::text as peer_ip,
          i.peer_asn,
          i.status,
          i.notes,
          i.created_at,
          i.updated_at
        from inventory_interfaces i
        where i.host_id = %s
        order by i.interface_name asc;
        """,
        (host_id,),
    )
    host["peer_links"] = _fetch_all(
        """
        select
          pl.id,
          pl.peer_ip::text as peer_ip,
          pl.peer_asn,
          pl.relation_type,
          pl.confidence,
          pl.source,
          pl.notes,
          pl.created_at,
          pl.updated_at,
          pl.host_id,
          pl.interface_id,
          pl.site_id,
          i.interface_name,
          i.interface_ip::text as interface_ip,
          s.site_code,
          s.name as site_name
        from inventory_peer_links pl
        left join inventory_interfaces i on i.id = pl.interface_id
        left join inventory_sites s on s.id = pl.site_id
        where pl.host_id = %s
        order by pl.peer_ip::text asc, pl.id asc;
        """,
        (host_id,),
    )
    host["observations"] = _fetch_all(
        """
        select
          id,
          observation_type,
          observation,
          source,
          created_at
        from inventory_host_observations
        where host_id = %s
        order by created_at desc, id desc;
        """,
        (host_id,),
    )
    return host


def search_hosts(query: str, limit: int = 50) -> list[dict[str, Any]]:
    query = _normalize_text(query)
    if not query:
        raise ValueError("Busca vazia.")
    limit = _clamp_limit(limit)
    like = f"%{query}%"
    return _fetch_all(
        """
        with matches as (
            select distinct h.id
            from inventory_hosts h
            left join inventory_sites s on s.id = h.site_id
            left join inventory_interfaces i on i.host_id = h.id
            left join inventory_host_tags ht on ht.host_id = h.id
            left join inventory_tags t on t.id = ht.tag_id
            where h.hostname ilike %s
               or coalesce(h.notes, '') ilike %s
               or coalesce(h.role, '') ilike %s
               or coalesce(s.site_code, '') ilike %s
               or coalesce(s.name, '') ilike %s
               or coalesce(t.tag, '') ilike %s
               or coalesce(i.description, '') ilike %s
        )
        select
          h.id,
          h.hostname,
          h.mgmt_ip::text as mgmt_ip,
          s.site_code,
          s.name as site_name,
          h.role,
          h.status,
          h.notes,
          h.updated_at,
          coalesce(interface_stats.interface_count, 0)::bigint as interface_count,
          coalesce(link_stats.peer_link_count, 0)::bigint as peer_link_count,
          coalesce(tag_stats.tag_count, 0)::bigint as tag_count
        from inventory_hosts h
        join matches m on m.id = h.id
        left join inventory_sites s on s.id = h.site_id
        left join lateral (
            select count(*)::bigint as interface_count
            from inventory_interfaces i
            where i.host_id = h.id
        ) interface_stats on true
        left join lateral (
            select count(*)::bigint as peer_link_count
            from inventory_peer_links pl
            where pl.host_id = h.id
        ) link_stats on true
        left join lateral (
            select count(*)::bigint as tag_count
            from inventory_host_tags ht
            where ht.host_id = h.id
        ) tag_stats on true
        order by h.hostname asc
        limit %s;
        """,
        (like, like, like, like, like, like, like, limit),
    )


def list_hosts_by_site(
    site_code: str,
    include_interfaces: bool = True,
    include_peers: bool = True,
) -> dict[str, Any] | None:
    site = get_site(site_code)
    if site is None:
        return None

    hosts = list_hosts(site_code=site_code, limit=MAX_LIMIT)
    host_ids = [int(host["id"]) for host in hosts]

    interfaces_by_host: dict[int, list[dict[str, Any]]] = {host_id: [] for host_id in host_ids}
    peer_links_by_host: dict[int, list[dict[str, Any]]] = {host_id: [] for host_id in host_ids}

    if include_interfaces and host_ids:
        interface_rows = _fetch_all(
            f"""
            select
              i.id,
              i.host_id,
              i.interface_name,
              i.interface_ip::text as interface_ip,
              i.description,
              i.speed_mbps,
              i.vlan,
              i.circuit_ref,
              i.peer_ip::text as peer_ip,
              i.peer_asn,
              i.status,
              i.notes,
              i.created_at,
              i.updated_at
            from inventory_interfaces i
            where i.host_id = any(%s)
            order by i.host_id, i.interface_name;
            """,
            (host_ids,),
        )
        for row in interface_rows:
            interfaces_by_host.setdefault(int(row["host_id"]), []).append(row)

    if include_peers and host_ids:
        peer_rows = _fetch_all(
            f"""
            select
              pl.id,
              pl.host_id,
              pl.peer_ip::text as peer_ip,
              pl.peer_asn,
              pl.relation_type,
              pl.confidence,
              pl.source,
              pl.notes,
              pl.created_at,
              pl.updated_at,
              pl.interface_id,
              i.interface_name,
              i.interface_ip::text as interface_ip
            from inventory_peer_links pl
            left join inventory_interfaces i on i.id = pl.interface_id
            where pl.host_id = any(%s)
            order by pl.host_id, pl.peer_ip::text, pl.id;
            """,
            (host_ids,),
        )
        for row in peer_rows:
            peer_links_by_host.setdefault(int(row["host_id"]), []).append(row)

    confirmed_hosts: list[dict[str, Any]] = []
    for host in hosts:
        host_id = int(host["id"])
        host["interfaces"] = interfaces_by_host.get(host_id, []) if include_interfaces else []
        host["peer_links"] = peer_links_by_host.get(host_id, []) if include_peers else []
        confirmed_hosts.append(host)

    peer_links = _fetch_all(
        """
        select
          pl.id,
          pl.peer_ip::text as peer_ip,
          pl.peer_asn,
          pl.relation_type,
          pl.confidence,
          pl.source,
          pl.notes,
          pl.created_at,
          pl.updated_at,
          pl.host_id,
          h.hostname,
          pl.interface_id,
          i.interface_name,
          i.interface_ip::text as interface_ip
        from inventory_peer_links pl
        left join inventory_hosts h on h.id = pl.host_id
        left join inventory_interfaces i on i.id = pl.interface_id
        left join inventory_sites s on s.id = coalesce(pl.site_id, h.site_id)
        where s.site_code = %s or h.site_id = (select id from inventory_sites where site_code = %s limit 1)
        order by pl.peer_ip::text, pl.id;
        """,
        (site_code, site_code),
    )

    note = "Nenhum host confirmado no site ainda. Cadastre hosts ou vínculos para responder com precisão."
    if confirmed_hosts:
        note = "Hosts confirmados encontrados para este site."

    return {
        "site_code": site["site_code"],
        "site": site,
        "confirmed_hosts_count": len(confirmed_hosts),
        "confirmed_hosts": confirmed_hosts,
        "suggested_hosts_count": 0,
        "suggested_hosts": [],
        "peer_links_count": len(peer_links),
        "peer_links": peer_links,
        "summary": {
            "host_count": site.get("host_count"),
            "interface_count": site.get("interface_count"),
            "peer_link_count": site.get("peer_link_count"),
        },
        "note": note if not confirmed_hosts else "Hosts confirmados cadastrados para este site.",
    }


def list_peer_links(
    site_code: str | None = None,
    peer_ip: str | None = None,
    peer_asn: int | str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit)
    clauses = ["1 = 1"]
    params: list[Any] = []

    site_code = _normalize_text(site_code)
    peer_ip = _normalize_text(peer_ip)
    peer_asn_value = _normalize_asn(peer_asn)

    if site_code is not None:
        clauses.append("(s.site_code = %s or h.site_id = (select id from inventory_sites where site_code = %s limit 1))")
        params.extend([site_code, site_code])
    if peer_ip is not None:
        clauses.append("pl.peer_ip = %s::inet")
        params.append(_normalize_peer_ip(peer_ip))
    if peer_asn_value is not None:
        clauses.append("pl.peer_asn = %s")
        params.append(peer_asn_value)

    sql = f"""
        select
          pl.id,
          pl.peer_ip::text as peer_ip,
          pl.peer_asn,
          pl.relation_type,
          pl.confidence,
          pl.source,
          pl.notes,
          pl.created_at,
          pl.updated_at,
          h.hostname,
          h.role,
          s.site_code,
          s.name as site_name,
          i.interface_name,
          i.interface_ip::text as interface_ip,
          i.description as interface_description
        from inventory_peer_links pl
        left join inventory_hosts h on h.id = pl.host_id
        left join inventory_interfaces i on i.id = pl.interface_id
        left join inventory_sites s on s.id = coalesce(pl.site_id, h.site_id)
        where {' and '.join(clauses)}
        order by pl.peer_ip::text asc, coalesce(h.hostname, '') asc, pl.id asc
        limit %s;
    """
    params.append(limit)
    return _fetch_all(sql, tuple(params))


def list_unmatched_bgp_peers(limit: int = 20) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit)
    return _fetch_all(
        """
        with observed_peers as (
            select
              peer_ip,
              peer_asn,
              count(*)::bigint as observed_routes,
              count(distinct prefix)::bigint as observed_prefixes,
              count(distinct collector)::bigint as collector_count
            from bgp_current_routes
            group by peer_ip, peer_asn
        )
        select
          op.peer_ip::text as peer_ip,
          op.peer_asn,
          op.observed_routes,
          op.observed_prefixes,
          op.collector_count,
          'UNMATCHED' as match_status
        from observed_peers op
        where not exists (
            select 1
            from inventory_peer_links pl
            where pl.peer_ip = op.peer_ip
        )
        order by op.observed_routes desc, op.peer_ip::text asc
        limit %s;
        """,
        (limit,),
    )


def list_sites_with_hosts_summary(site_code: str) -> dict[str, Any] | None:
    return list_hosts_by_site(site_code)
