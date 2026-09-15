from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.db.connection import get_connection


def _fetch_raw_candidates(limit: int, offset: int) -> list[dict[str, Any]]:
    sql = """
        select id, source, collector, collected_at, peer_ip, peer_asn, prefix, next_hop,
               as_path, origin_asn, origin_type, raw_record
          from bgp_raw_routes
         order by id asc
         limit %s offset %s
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, [limit, offset])
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


def _lookup_current(route: dict[str, Any]) -> dict[str, Any] | None:
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

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, [route["source"], route["collector"], route["peer_ip"], route["prefix"]])
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


def _mutate_for_simulation(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mutated = deepcopy(routes)
    if mutated:
        mutated[0]["next_hop"] = "203.0.113.1"
    if len(mutated) > 1:
        as_path = mutated[1].get("as_path") or ""
        mutated[1]["as_path"] = f"{as_path} 65000".strip()
    if len(mutated) > 2:
        mutated[2]["origin_asn"] = 65000
    return mutated


def _build_change(
    change_type: str,
    raw_route: dict[str, Any],
    current_route: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "change_type": change_type,
        "source": raw_route["source"],
        "collector": raw_route["collector"],
        "peer_ip": raw_route["peer_ip"],
        "peer_asn": raw_route.get("peer_asn"),
        "prefix": raw_route["prefix"],
        "old_next_hop": None if current_route is None else current_route.get("next_hop"),
        "new_next_hop": raw_route.get("next_hop"),
        "old_as_path": None if current_route is None else current_route.get("as_path"),
        "new_as_path": raw_route.get("as_path"),
        "old_origin_asn": None if current_route is None else current_route.get("origin_asn"),
        "new_origin_asn": raw_route.get("origin_asn"),
        "old_origin_type": None if current_route is None else current_route.get("origin_type"),
        "new_origin_type": raw_route.get("origin_type"),
        "old_peer_asn": None if current_route is None else current_route.get("peer_asn"),
        "new_peer_asn": raw_route.get("peer_asn"),
        "raw_route_id": raw_route["id"],
        "raw_before": None if current_route is None else current_route.get("raw_record"),
        "raw_after": raw_route.get("raw_record"),
    }


def detect_changes_from_raw(
    limit: int = 100,
    offset: int = 0,
    simulate: bool = False,
) -> list[dict[str, Any]]:
    candidates = _fetch_raw_candidates(limit=limit, offset=offset)
    if simulate:
        candidates = _mutate_for_simulation(candidates)

    changes: list[dict[str, Any]] = []
    for raw_route in candidates:
        current_route = _lookup_current(raw_route)
        if current_route is None:
            changes.append(_build_change("NEW_ROUTE", raw_route, None))
            continue

        if raw_route.get("peer_asn") != current_route.get("peer_asn"):
            changes.append(_build_change("PEER_ASN_CHANGED", raw_route, current_route))
            continue
        if raw_route.get("next_hop") != current_route.get("next_hop"):
            changes.append(_build_change("NEXT_HOP_CHANGED", raw_route, current_route))
            continue
        if raw_route.get("as_path") != current_route.get("as_path"):
            changes.append(_build_change("AS_PATH_CHANGED", raw_route, current_route))
            continue
        if raw_route.get("origin_asn") != current_route.get("origin_asn"):
            changes.append(_build_change("ORIGIN_AS_CHANGED", raw_route, current_route))
            continue
        if raw_route.get("origin_type") != current_route.get("origin_type"):
            changes.append(_build_change("ORIGIN_TYPE_CHANGED", raw_route, current_route))
            continue

    return changes
