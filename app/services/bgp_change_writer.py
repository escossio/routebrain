from __future__ import annotations

from typing import Any

from psycopg.types.json import Jsonb

from app.db.connection import get_connection
from app.services.bgp_change_detector import detect_changes_from_raw


def _count_route_changes() -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select count(*) from bgp_route_changes;")
            return int(cur.fetchone()[0])


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


def write_detected_changes(limit: int = 100, offset: int = 0) -> dict[str, int]:
    changes = detect_changes_from_raw(limit=limit, offset=offset, simulate=False)
    detected = len(changes)
    inserted = 0
    skipped_duplicates = 0

    insert_sql = """
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

    with get_connection() as conn:
        with conn.cursor() as cur:
            for change in changes:
                if _change_exists(cur, change):
                    skipped_duplicates += 1
                    continue

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
                cur.execute(insert_sql, payload)
                inserted += 1

        conn.commit()

    return {
        "detected": detected,
        "inserted": inserted,
        "skipped_duplicates": skipped_duplicates,
    }
