from __future__ import annotations

from typing import Any

from app.db.connection import get_connection


def get_pipeline_state(pipeline_name: str) -> dict[str, Any] | None:
    sql = """
        select pipeline_name, last_raw_route_id, updated_at
          from bgp_pipeline_state
         where pipeline_name = %s
         limit 1
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, [pipeline_name])
            row = cur.fetchone()

    if row is None:
        return None

    return {
        "pipeline_name": row[0],
        "last_raw_route_id": row[1],
        "updated_at": row[2],
    }


def ensure_pipeline_state(pipeline_name: str) -> dict[str, Any]:
    sql = """
        insert into bgp_pipeline_state (pipeline_name, last_raw_route_id)
        values (%s, 0)
        on conflict (pipeline_name) do nothing
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, [pipeline_name])
        conn.commit()
    state = get_pipeline_state(pipeline_name)
    if state is None:
        raise RuntimeError(f"Não foi possível garantir pipeline_state para {pipeline_name}")
    return state


def update_pipeline_state(pipeline_name: str, last_raw_route_id: int) -> None:
    sql = """
        update bgp_pipeline_state
           set last_raw_route_id = %s,
               updated_at = now()
         where pipeline_name = %s
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, [last_raw_route_id, pipeline_name])
        conn.commit()
