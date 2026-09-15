from __future__ import annotations

from typing import Any

from psycopg.types.json import Jsonb

from app.db.connection import get_connection


def build_current_route_payload(
    source: str,
    collector: str,
    collected_at: Any,
    peer_ip: Any,
    peer_asn: Any,
    prefix: Any,
    next_hop: Any,
    as_path: Any,
    origin_asn: Any,
    origin_type: Any,
    raw_record: Any,
) -> dict[str, Any]:
    return {
        "source": source,
        "collector": collector,
        "peer_ip": peer_ip,
        "prefix": prefix,
        "peer_asn": peer_asn,
        "next_hop": next_hop,
        "as_path": as_path,
        "origin_asn": origin_asn,
        "origin_type": origin_type,
        "first_seen": collected_at,
        "last_seen": collected_at,
        "raw_record": Jsonb(raw_record) if raw_record is not None else None,
    }


def _count_current_routes() -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select count(*) from bgp_current_routes;")
            return int(cur.fetchone()[0])


def build_current_routes(limit: int | None = None) -> dict[str, int]:
    current_count_before = _count_current_routes()
    processed = 0

    select_sql = """
        select source, collector, collected_at, peer_ip, peer_asn, prefix, next_hop, as_path,
               origin_asn, origin_type, raw_record
          from bgp_raw_routes
         order by collected_at asc nulls last, id asc
    """
    if limit is not None:
        select_sql += " limit %s"

    upsert_sql = """
        insert into bgp_current_routes (
            source,
            collector,
            peer_ip,
            prefix,
            peer_asn,
            next_hop,
            as_path,
            origin_asn,
            origin_type,
            first_seen,
            last_seen,
            raw_record
        ) values (
            %(source)s,
            %(collector)s,
            %(peer_ip)s,
            %(prefix)s,
            %(peer_asn)s,
            %(next_hop)s,
            %(as_path)s,
            %(origin_asn)s,
            %(origin_type)s,
            %(first_seen)s,
            %(last_seen)s,
            %(raw_record)s
        )
        on conflict (source, collector, peer_ip, prefix) do update set
            peer_asn = excluded.peer_asn,
            next_hop = excluded.next_hop,
            as_path = excluded.as_path,
            origin_asn = excluded.origin_asn,
            origin_type = excluded.origin_type,
            first_seen = case
                when bgp_current_routes.first_seen is null then excluded.first_seen
                when excluded.first_seen is null then bgp_current_routes.first_seen
                when bgp_current_routes.first_seen < excluded.first_seen then bgp_current_routes.first_seen
                else excluded.first_seen
            end,
            last_seen = case
                when bgp_current_routes.last_seen is null then excluded.last_seen
                when excluded.last_seen is null then bgp_current_routes.last_seen
                when bgp_current_routes.last_seen > excluded.last_seen then bgp_current_routes.last_seen
                else excluded.last_seen
            end,
            raw_record = excluded.raw_record
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            params: list[Any] = []
            if limit is not None:
                params = [limit]
            cur.execute(select_sql, params)
            rows = cur.fetchall()

            for source, collector, collected_at, peer_ip, peer_asn, prefix, next_hop, as_path, origin_asn, origin_type, raw_record in rows:
                upsert_row = build_current_route_payload(
                    source,
                    collector,
                    collected_at,
                    peer_ip,
                    peer_asn,
                    prefix,
                    next_hop,
                    as_path,
                    origin_asn,
                    origin_type,
                    raw_record,
                )
                cur.execute(upsert_sql, upsert_row)
                processed += 1

        conn.commit()

    current_count_after = _count_current_routes()
    return {
        "processed": processed,
        "current_count_before": current_count_before,
        "current_count_after": current_count_after,
    }
