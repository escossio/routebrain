from __future__ import annotations

from typing import Any

from app.db.connection import get_connection
from app.services.bgp_current_builder import build_current_route_payload


def _count_rows(table_name: str) -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from {table_name};")
            return int(cur.fetchone()[0])


def _fetch_raw_rows(from_id: int | None, to_id: int | None, limit: int) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    if from_id is not None:
        clauses.append("id >= %s")
        params.append(from_id)
    if to_id is not None:
        clauses.append("id <= %s")
        params.append(to_id)

    where_sql = f"where {' and '.join(clauses)}" if clauses else ""
    sql = f"""
        select id, source, collector, collected_at, peer_ip, peer_asn, prefix, next_hop,
               as_path, origin_asn, origin_type, raw_record
          from bgp_raw_routes
          {where_sql}
         order by id asc
         limit %s
    """
    params.append(limit)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

    return [
        {
            "id": row[0],
            "source": row[1],
            "collector": row[2],
            "collected_at": row[3],
            "peer_ip": row[4],
            "peer_asn": row[5],
            "prefix": row[6],
            "next_hop": row[7],
            "as_path": row[8],
            "origin_asn": row[9],
            "origin_type": row[10],
            "raw_record": row[11],
        }
        for row in rows
    ]


def _lookup_current(cur, raw_route: dict[str, Any]) -> dict[str, Any] | None:
    sql = """
        select source, collector, peer_ip, peer_asn, prefix, next_hop, as_path, origin_asn,
               origin_type, raw_record
          from bgp_current_routes
         where source = %s
           and collector = %s
           and peer_ip = %s
           and prefix = %s
         limit 1
    """
    cur.execute(sql, [raw_route["source"], raw_route["collector"], raw_route["peer_ip"], raw_route["prefix"]])
    row = cur.fetchone()
    if row is None:
        return None
    return {
        "source": row[0],
        "collector": row[1],
        "peer_ip": row[2],
        "peer_asn": row[3],
        "prefix": row[4],
        "next_hop": row[5],
        "as_path": row[6],
        "origin_asn": row[7],
        "origin_type": row[8],
        "raw_record": row[9],
    }


def _build_change(raw_route: dict[str, Any], current_route: dict[str, Any] | None) -> dict[str, Any] | None:
    if current_route is None:
        return {
            "change_type": "NEW_ROUTE",
            "source": raw_route["source"],
            "collector": raw_route["collector"],
            "peer_ip": raw_route["peer_ip"],
            "peer_asn": raw_route.get("peer_asn"),
            "prefix": raw_route["prefix"],
            "old_next_hop": None,
            "new_next_hop": raw_route.get("next_hop"),
            "old_as_path": None,
            "new_as_path": raw_route.get("as_path"),
            "old_origin_asn": None,
            "new_origin_asn": raw_route.get("origin_asn"),
            "old_origin_type": None,
            "new_origin_type": raw_route.get("origin_type"),
            "old_peer_asn": None,
            "new_peer_asn": raw_route.get("peer_asn"),
            "raw_route_id": raw_route["id"],
            "raw_before": None,
            "raw_after": raw_route.get("raw_record"),
        }

    if raw_route.get("peer_asn") != current_route.get("peer_asn"):
        change_type = "PEER_ASN_CHANGED"
    elif raw_route.get("next_hop") != current_route.get("next_hop"):
        change_type = "NEXT_HOP_CHANGED"
    elif raw_route.get("as_path") != current_route.get("as_path"):
        change_type = "AS_PATH_CHANGED"
    elif raw_route.get("origin_asn") != current_route.get("origin_asn"):
        change_type = "ORIGIN_AS_CHANGED"
    elif raw_route.get("origin_type") != current_route.get("origin_type"):
        change_type = "ORIGIN_TYPE_CHANGED"
    else:
        return None

    return {
        "change_type": change_type,
        "source": raw_route["source"],
        "collector": raw_route["collector"],
        "peer_ip": raw_route["peer_ip"],
        "peer_asn": raw_route.get("peer_asn"),
        "prefix": raw_route["prefix"],
        "old_next_hop": current_route.get("next_hop"),
        "new_next_hop": raw_route.get("next_hop"),
        "old_as_path": current_route.get("as_path"),
        "new_as_path": raw_route.get("as_path"),
        "old_origin_asn": current_route.get("origin_asn"),
        "new_origin_asn": raw_route.get("origin_asn"),
        "old_origin_type": current_route.get("origin_type"),
        "new_origin_type": raw_route.get("origin_type"),
        "old_peer_asn": current_route.get("peer_asn"),
        "new_peer_asn": raw_route.get("peer_asn"),
        "raw_route_id": raw_route["id"],
        "raw_before": current_route.get("raw_record"),
        "raw_after": raw_route.get("raw_record"),
    }


def _change_exists(cur, change: dict[str, Any]) -> bool:
    sql = """
        select 1
          from bgp_route_changes
         where source = %s
           and collector = %s
           and peer_ip is not distinct from %s
           and prefix is not distinct from %s
           and change_type = %s
           and old_next_hop is not distinct from %s
           and new_next_hop is not distinct from %s
           and old_as_path is not distinct from %s
           and new_as_path is not distinct from %s
           and old_origin_asn is not distinct from %s
           and new_origin_asn is not distinct from %s
         limit 1
    """
    cur.execute(
        sql,
        [
            change["source"],
            change["collector"],
            change["peer_ip"],
            change["prefix"],
            change["change_type"],
            change.get("old_next_hop"),
            change.get("new_next_hop"),
            change.get("old_as_path"),
            change.get("new_as_path"),
            change.get("old_origin_asn"),
            change.get("new_origin_asn"),
        ],
    )
    return cur.fetchone() is not None


def _insert_change(cur, change: dict[str, Any]) -> None:
    sql = """
        insert into bgp_route_changes (
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
            new_origin_asn,
            raw_before,
            raw_after
        ) values (
            %(source)s,
            %(collector)s,
            %(peer_ip)s,
            %(peer_asn)s,
            %(prefix)s,
            %(change_type)s,
            %(old_next_hop)s,
            %(new_next_hop)s,
            %(old_as_path)s,
            %(new_as_path)s,
            %(old_origin_asn)s,
            %(new_origin_asn)s,
            %(raw_before)s,
            %(raw_after)s
        )
    """
    payload = {
        "source": change["source"],
        "collector": change["collector"],
        "peer_ip": change["peer_ip"],
        "peer_asn": change.get("new_peer_asn"),
        "prefix": change["prefix"],
        "change_type": change["change_type"],
        "old_next_hop": change.get("old_next_hop"),
        "new_next_hop": change.get("new_next_hop"),
        "old_as_path": change.get("old_as_path"),
        "new_as_path": change.get("new_as_path"),
        "old_origin_asn": change.get("old_origin_asn"),
        "new_origin_asn": change.get("new_origin_asn"),
        "raw_before": Jsonb(change.get("raw_before")) if change.get("raw_before") is not None else None,
        "raw_after": Jsonb(change.get("raw_after")) if change.get("raw_after") is not None else None,
    }
    cur.execute(sql, payload)


def _upsert_current(cur, raw_route: dict[str, Any]) -> None:
    sql = """
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

    payload = build_current_route_payload(
        raw_route["source"],
        raw_route["collector"],
        raw_route.get("collected_at"),
        raw_route["peer_ip"],
        raw_route.get("peer_asn"),
        raw_route["prefix"],
        raw_route.get("next_hop"),
        raw_route.get("as_path"),
        raw_route.get("origin_asn"),
        raw_route.get("origin_type"),
        raw_route.get("raw_record"),
    )
    cur.execute(sql, payload)


def process_raw_routes_incremental(
    from_id: int | None = None,
    to_id: int | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    raw_rows = _fetch_raw_rows(from_id=from_id, to_id=to_id, limit=limit)
    processed = 0
    detected_changes = 0
    inserted_changes = 0
    skipped_duplicates = 0
    current_upserts = 0
    min_id_processed: int | None = None
    max_id_processed: int | None = None

    with get_connection() as conn:
        with conn.cursor() as cur:
            for raw_route in raw_rows:
                processed += 1
                raw_id = raw_route["id"]
                min_id_processed = raw_id if min_id_processed is None else min(min_id_processed, raw_id)
                max_id_processed = raw_id if max_id_processed is None else max(max_id_processed, raw_id)

                current_route = _lookup_current(cur, raw_route)
                change = _build_change(raw_route, current_route)

                if change is not None:
                    detected_changes += 1
                    if _change_exists(cur, change):
                        skipped_duplicates += 1
                    else:
                        _insert_change(cur, change)
                        inserted_changes += 1

                _upsert_current(cur, raw_route)
                current_upserts += 1

        conn.commit()

    return {
        "processed": processed,
        "detected_changes": detected_changes,
        "inserted_changes": inserted_changes,
        "skipped_duplicates": skipped_duplicates,
        "current_upserts": current_upserts,
        "min_id_processed": min_id_processed,
        "max_id_processed": max_id_processed,
        "raw_count_after": _count_rows("bgp_raw_routes"),
        "current_count_after": _count_rows("bgp_current_routes"),
        "route_changes_after": _count_rows("bgp_route_changes"),
    }
