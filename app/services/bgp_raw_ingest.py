from __future__ import annotations

from typing import Any, Iterable

from psycopg.types.json import Jsonb

from app.db.connection import get_connection


def build_raw_route_payload(record: dict[str, Any]) -> dict[str, Any]:
    row = dict(record)
    row["raw_record"] = Jsonb(row.get("raw_record"))
    return row


def insert_raw_routes(records: Iterable[dict[str, Any]]) -> dict[str, int | None]:
    inserted = 0
    first_id: int | None = None
    last_id: int | None = None
    sql = """
        INSERT INTO bgp_raw_routes (
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
            med,
            local_pref,
            communities,
            raw_record
        ) VALUES (
            %(source)s,
            %(collector)s,
            %(collected_at)s,
            %(peer_ip)s,
            %(peer_asn)s,
            %(prefix)s,
            %(next_hop)s,
            %(as_path)s,
            %(origin_asn)s,
            %(origin_type)s,
            %(med)s,
            %(local_pref)s,
            %(communities)s,
            %(raw_record)s
        )
        RETURNING id
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            for record in records:
                row = build_raw_route_payload(record)
                cur.execute(sql, row)
                inserted_id = int(cur.fetchone()[0])
                if first_id is None:
                    first_id = inserted_id
                last_id = inserted_id
                inserted += 1
        conn.commit()

    return {
        "inserted": inserted,
        "first_id": first_id,
        "last_id": last_id,
    }
