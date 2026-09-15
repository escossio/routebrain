from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.db.connection import get_connection
from app.services.inventory_queries import get_site, list_hosts, list_unmatched_bgp_peers

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


def _normalize_locality_code(value: str | None) -> str:
    if value is None:
        raise ValueError("locality_code inválido.")
    text = str(value).strip().upper()
    if not text:
        raise ValueError("locality_code inválido.")
    return text


def _table_exists(table_name: str) -> bool:
    row = _fetch_one("select to_regclass(%s) is not null as exists;", (f"public.{table_name}",))
    return bool(row and row.get("exists"))


def _participant_summary_rows(locality_code: str, limit: int) -> list[dict[str, Any]]:
    if not _table_exists("bgp_summary_current_by_origin_asn"):
        return []
    return _fetch_all(
        """
        select
          p.locality_code,
          p.asn,
          p.participant_name,
          p.participant_url,
          p.participation_type,
          p.atm_v4,
          p.atm_v6,
          p.transport_l2,
          p.cix,
          p.raw_row,
          p.source_url,
          p.fetched_at,
          p.created_at,
          p.updated_at,
          coalesce(s.route_count, 0)::bigint as route_count,
          coalesce(s.prefix_count, 0)::bigint as prefix_count,
          coalesce(s.peer_count, 0)::bigint as peer_count,
          coalesce(s.collector_count, 0)::bigint as collector_count,
          s.updated_at as bgp_updated_at,
          (s.origin_asn is not null) as seen_as_origin
        from ixbr_participants p
        left join bgp_summary_current_by_origin_asn s
          on s.origin_asn = p.asn
        where p.locality_code = %s
        order by p.asn asc
        limit %s;
        """,
        (locality_code, limit),
    )


def list_ixbr_locations() -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          l.id,
          l.locality_code,
          l.name,
          l.city,
          l.state,
          l.country,
          l.source_url,
          l.fetched_at,
          l.raw_metadata,
          l.created_at,
          l.updated_at,
          coalesce(p.participants_count, 0)::bigint as participants_count,
          coalesce(o.route_server_observations_count, 0)::bigint as route_server_observations_count,
          coalesce(r.discovery_runs_count, 0)::bigint as discovery_runs_count
        from ixbr_locations l
        left join lateral (
            select count(*)::bigint as participants_count
            from ixbr_participants p
            where p.locality_code = l.locality_code
        ) p on true
        left join lateral (
            select count(*)::bigint as route_server_observations_count
            from ixbr_route_server_observations r
            where r.locality_code = l.locality_code
        ) o on true
        left join lateral (
            select count(*)::bigint as discovery_runs_count
            from ixbr_discovery_runs d
            where d.locality_code = l.locality_code
        ) r on true
        order by l.locality_code asc;
        """,
    )


def list_ixbr_participants(locality_code: str = "CE", limit: int = 100) -> list[dict[str, Any]]:
    locality_code = _normalize_locality_code(locality_code)
    return _participant_summary_rows(locality_code, _clamp_limit(limit))


def get_ixbr_participant(locality_code: str, asn: int) -> dict[str, Any] | None:
    locality_code = _normalize_locality_code(locality_code)
    rows = _fetch_all(
        """
        select
          p.locality_code,
          p.asn,
          p.participant_name,
          p.participant_url,
          p.participation_type,
          p.atm_v4,
          p.atm_v6,
          p.transport_l2,
          p.cix,
          p.raw_row,
          p.source_url,
          p.fetched_at,
          p.created_at,
          p.updated_at,
          coalesce(s.route_count, 0)::bigint as route_count,
          coalesce(s.prefix_count, 0)::bigint as prefix_count,
          coalesce(s.peer_count, 0)::bigint as peer_count,
          coalesce(s.collector_count, 0)::bigint as collector_count,
          s.updated_at as bgp_updated_at,
          (s.origin_asn is not null) as seen_as_origin
        from ixbr_participants p
        left join bgp_summary_current_by_origin_asn s
          on s.origin_asn = p.asn
        where p.locality_code = %s
          and p.asn = %s
        limit 1;
        """,
        (locality_code, asn),
    )
    return rows[0] if rows else None


def list_ixbr_asns_seen_as_origin(locality_code: str = "CE", limit: int = 100) -> list[dict[str, Any]]:
    locality_code = _normalize_locality_code(locality_code)
    limit = _clamp_limit(limit)
    return _fetch_all(
        """
        select
          p.locality_code,
          p.asn,
          p.participant_name,
          p.participant_url,
          p.participation_type,
          p.atm_v4,
          p.atm_v6,
          p.transport_l2,
          p.cix,
          p.source_url,
          p.fetched_at,
          coalesce(s.route_count, 0)::bigint as route_count,
          coalesce(s.prefix_count, 0)::bigint as prefix_count,
          coalesce(s.peer_count, 0)::bigint as peer_count,
          coalesce(s.collector_count, 0)::bigint as collector_count,
          s.updated_at as bgp_updated_at
        from ixbr_participants p
        join bgp_summary_current_by_origin_asn s
          on s.origin_asn = p.asn
        where p.locality_code = %s
          and coalesce(s.route_count, 0) > 0
        order by s.route_count desc, s.prefix_count desc, p.asn asc
        limit %s;
        """,
        (locality_code, limit),
    )


def list_ixbr_participants_without_bgp_origin(locality_code: str = "CE", limit: int = 100) -> list[dict[str, Any]]:
    locality_code = _normalize_locality_code(locality_code)
    limit = _clamp_limit(limit)
    return _fetch_all(
        """
        select
          p.locality_code,
          p.asn,
          p.participant_name,
          p.participant_url,
          p.participation_type,
          p.atm_v4,
          p.atm_v6,
          p.transport_l2,
          p.cix,
          p.source_url,
          p.fetched_at,
          p.raw_row
        from ixbr_participants p
        left join bgp_summary_current_by_origin_asn s
          on s.origin_asn = p.asn
        where p.locality_code = %s
          and s.origin_asn is null
        order by p.asn asc
        limit %s;
        """,
        (locality_code, limit),
    )


def list_bgp_origin_asns_not_in_ixbr(locality_code: str = "CE", limit: int = 100) -> list[dict[str, Any]]:
    locality_code = _normalize_locality_code(locality_code)
    limit = _clamp_limit(limit)
    return _fetch_all(
        """
        select
          s.origin_asn,
          s.route_count,
          s.prefix_count,
          s.peer_count,
          s.collector_count,
          s.updated_at
        from bgp_summary_current_by_origin_asn s
        where not exists (
            select 1
            from ixbr_participants p
            where p.locality_code = %s
              and p.asn = s.origin_asn
        )
        order by s.route_count desc, s.prefix_count desc, s.origin_asn asc
        limit %s;
        """,
        (locality_code, limit),
    )


def summarize_ixbr_vs_bgp(locality_code: str = "CE") -> dict[str, Any]:
    locality_code = _normalize_locality_code(locality_code)
    summary_row = _fetch_one(
        """
        select
          count(*)::bigint as total_participants,
          count(*) filter (where s.origin_asn is not null)::bigint as participants_seen_as_origin,
          count(*) filter (where s.origin_asn is null)::bigint as participants_not_seen_as_origin,
          max(p.fetched_at) as participants_fetched_at,
          max(s.updated_at) as bgp_summary_updated_at
        from ixbr_participants p
        left join bgp_summary_current_by_origin_asn s
          on s.origin_asn = p.asn
        where p.locality_code = %s;
        """,
        (locality_code,),
    ) or {}
    top_current_routes = list_ixbr_asns_seen_as_origin(locality_code=locality_code, limit=20)
    if _table_exists("bgp_summary_changes_by_origin_asn"):
        top_changes = _fetch_all(
            """
            select
              p.locality_code,
              p.asn,
              p.participant_name,
              p.participant_url,
              p.participation_type,
              coalesce(c.total_changes, 0)::bigint as total_changes,
              coalesce(c.new_route_count, 0)::bigint as new_route_count,
              coalesce(c.as_path_changed_count, 0)::bigint as as_path_changed_count,
              coalesce(c.origin_type_changed_count, 0)::bigint as origin_type_changed_count,
              c.updated_at as bgp_changes_updated_at
            from ixbr_participants p
            left join bgp_summary_changes_by_origin_asn c
              on c.origin_asn = p.asn
            where p.locality_code = %s
              and coalesce(c.total_changes, 0) > 0
            order by c.total_changes desc, c.new_route_count desc, p.asn asc
            limit 20;
            """,
            (locality_code,),
        )
    else:
        top_changes = []
    return {
        "locality_code": locality_code,
        "total_participants": int(summary_row.get("total_participants") or 0),
        "participants_seen_as_origin": int(summary_row.get("participants_seen_as_origin") or 0),
        "participants_not_seen_as_origin": int(summary_row.get("participants_not_seen_as_origin") or 0),
        "participants_fetched_at": summary_row.get("participants_fetched_at"),
        "bgp_summary_updated_at": summary_row.get("bgp_summary_updated_at"),
        "top_participants_by_current_routes": top_current_routes,
        "top_participants_by_changes": top_changes,
    }


def get_inventory_public_context(
    site_code: str = "PTT-CE",
    locality_code: str = "CE",
    limit: int = 20,
    *,
    include_unmatched_bgp_peers: bool = True,
) -> dict[str, Any] | None:
    site_code = str(site_code).strip()
    locality_code = _normalize_locality_code(locality_code)
    limit = _clamp_limit(limit)
    site = get_site(site_code)
    if site is None:
        return None
    confirmed_hosts = list_hosts(site_code=site_code, limit=limit)
    public_participants = list_ixbr_participants(locality_code=locality_code, limit=limit)
    bgp_summary = summarize_ixbr_vs_bgp(locality_code=locality_code)
    seen_as_origin = list_ixbr_asns_seen_as_origin(locality_code=locality_code, limit=limit)
    unmatched_participants = list_ixbr_participants_without_bgp_origin(locality_code=locality_code, limit=limit)
    bgp_origin_asns_not_in_ixbr = list_bgp_origin_asns_not_in_ixbr(locality_code=locality_code, limit=limit)
    unmatched_bgp_peers = list_unmatched_bgp_peers(limit=limit) if include_unmatched_bgp_peers else []
    suggestions = [
        {
            "asn": row.get("asn"),
            "participant_name": row.get("participant_name"),
            "route_count": row.get("route_count"),
            "prefix_count": row.get("prefix_count"),
            "reason": "Participante público do IX.br visto como origin ASN na base BGP atual.",
        }
        for row in seen_as_origin
    ]
    return {
        "site": site,
        "confirmed_hosts": confirmed_hosts,
        "confirmed_hosts_count": len(confirmed_hosts),
        "public_participants": public_participants,
        "public_participants_count": int(bgp_summary.get("total_participants") or len(public_participants)),
        "bgp_summary": bgp_summary,
        "public_participants_seen_as_origin": seen_as_origin,
        "public_participants_seen_as_origin_count": int(bgp_summary.get("participants_seen_as_origin") or len(seen_as_origin)),
        "public_participants_not_seen_as_origin": unmatched_participants,
        "public_participants_not_seen_as_origin_count": int(bgp_summary.get("participants_not_seen_as_origin") or len(unmatched_participants)),
        "bgp_origin_asns_not_in_ixbr": bgp_origin_asns_not_in_ixbr,
        "bgp_origin_asns_not_in_ixbr_count": len(bgp_origin_asns_not_in_ixbr),
        "unmatched_bgp_peers": unmatched_bgp_peers,
        "unmatched_bgp_peers_count": len(unmatched_bgp_peers),
        "suggestions": suggestions,
        "note": (
            "Dados IX.br indicam participantes públicos do PTT-CE. "
            "Isso não confirma hosts internos. Cadastre hosts/interfaces/peer_links para transformar sugestão em inventário confirmado."
        ),
    }
