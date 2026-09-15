from __future__ import annotations

from typing import Any

from psycopg.rows import dict_row

from app.db.connection import get_connection


def _build_target_label(observed_peer_ip: str, observed_peer_asn: int | None, inventory_peer_name: str | None) -> str:
    asn_part = f"AS{observed_peer_asn}" if observed_peer_asn is not None else "AS?"
    if inventory_peer_name:
        return f"{inventory_peer_name} / {asn_part}"
    return f"BGP peer {observed_peer_ip} / {asn_part}"


def _fetch_peers(
    limit: int,
    *,
    only_without_ping: bool = False,
    only_matched: bool = False,
    only_unmatched: bool = False,
) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []

    if only_without_ping:
        conditions.append("ping_status is null")
    if only_matched:
        conditions.append("match_status = 'MATCHED'")
    if only_unmatched:
        conditions.append("match_status = 'UNMATCHED'")

    where_clause = f"where {' and '.join(conditions)}" if conditions else ""

    sql = f"""
        select
            observed_peer_ip,
            observed_peer_asn,
            observed_routes,
            observed_prefixes,
            inventory_peer_name,
            match_status,
            ixp_name,
            ping_status
        from v_bgp_peer_with_latest_ping
        {where_clause}
        order by observed_routes desc, observed_peer_ip
        limit %s;
    """
    params.append(limit)

    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()

    peers: list[dict[str, Any]] = []
    for row in rows:
        peer = dict(row)
        peer["target"] = peer.get("observed_peer_ip")
        peer["target_label"] = _build_target_label(
            peer.get("observed_peer_ip") or "",
            peer.get("observed_peer_asn"),
            peer.get("inventory_peer_name"),
        )
        peers.append(peer)
    return peers


def get_top_observed_peers(
    limit: int = 10,
    only_without_ping: bool = False,
    only_matched: bool = False,
    only_unmatched: bool = False,
) -> list[dict[str, Any]]:
    return _fetch_peers(
        limit,
        only_without_ping=only_without_ping,
        only_matched=only_matched,
        only_unmatched=only_unmatched,
    )


def get_peers_missing_ping(limit: int = 10) -> list[dict[str, Any]]:
    return get_top_observed_peers(limit=limit, only_without_ping=True)


def get_matched_peers_for_ping(limit: int = 10) -> list[dict[str, Any]]:
    return get_top_observed_peers(limit=limit, only_matched=True)
