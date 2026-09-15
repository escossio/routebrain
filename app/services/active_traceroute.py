from __future__ import annotations

from decimal import Decimal
from typing import Any

from psycopg.rows import dict_row

from app.db.connection import get_connection
from app.services.active_traceroute_lab import run_traceroute, validate_target


def _to_decimal_array(values: list[float]) -> list[Decimal]:
    return [Decimal(str(value)) for value in values]


def run_and_store_traceroute(
    target: str,
    mode: str = "icmp",
    max_hops: int = 30,
    timeout: int = 3,
    probes: int = 3,
    target_label: str | None = None,
    source_label: str = "local",
) -> dict[str, Any]:
    normalized_target = validate_target(target)
    result = run_traceroute(
        normalized_target,
        mode=mode,
        max_hops=max_hops,
        timeout=timeout,
        probes=probes,
    )

    hops = list(result.get("hops", []))
    hop_count = len(hops)
    responded_hop_count = sum(1 for hop in hops if hop.get("responded"))

    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                INSERT INTO active_traceroute_measurements (
                    target,
                    target_label,
                    source_label,
                    mode,
                    max_hops,
                    timeout_seconds,
                    probes,
                    command,
                    returncode,
                    status,
                    hop_count,
                    responded_hop_count,
                    raw_output,
                    error_output,
                    measured_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                RETURNING
                    id,
                    target,
                    target_label,
                    source_label,
                    mode,
                    max_hops,
                    timeout_seconds,
                    probes,
                    command,
                    returncode,
                    status,
                    hop_count,
                    responded_hop_count,
                    raw_output,
                    error_output,
                    measured_at,
                    created_at;
                """,
                (
                    normalized_target,
                    target_label,
                    source_label,
                    result.get("mode"),
                    max_hops,
                    timeout,
                    probes,
                    result.get("command"),
                    result.get("returncode"),
                    result.get("status"),
                    hop_count,
                    responded_hop_count,
                    result.get("raw_output"),
                    result.get("error_output"),
                    result.get("measured_at"),
                ),
            )
            measurement_row = cur.fetchone()
            if measurement_row is None:
                raise RuntimeError("Falha ao gravar medição de traceroute.")

            measurement_id = measurement_row["id"]
            hop_rows: list[dict[str, Any]] = []
            for hop in hops:
                rtt_values = hop.get("rtt_ms_values") or []
                cur.execute(
                    """
                    INSERT INTO active_traceroute_hops (
                        measurement_id,
                        target,
                        hop_number,
                        hop_ip,
                        responded,
                        rtt_ms_values,
                        rtt_avg_ms,
                        raw_line
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING
                        id,
                        measurement_id,
                        target,
                        hop_number,
                        hop_ip,
                        responded,
                        rtt_ms_values,
                        rtt_avg_ms,
                        raw_line,
                        created_at;
                    """,
                    (
                        measurement_id,
                        normalized_target,
                        hop.get("hop_number"),
                        hop.get("hop_ip"),
                        bool(hop.get("responded")),
                        _to_decimal_array(rtt_values),
                        Decimal(str(hop["rtt_avg_ms"])) if hop.get("rtt_avg_ms") is not None else None,
                        hop.get("raw_line"),
                    ),
                )
                hop_row = cur.fetchone()
                if hop_row is not None:
                    hop_rows.append(dict(hop_row))
        conn.commit()

    return {
        "measurement_id": measurement_row["id"],
        "target": normalized_target,
        "status": measurement_row["status"],
        "hop_count": hop_count,
        "responded_hop_count": responded_hop_count,
        "measured_at": measurement_row["measured_at"],
        "hops": hop_rows,
    }


def get_latest_traceroutes(limit: int = 20) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    measurement_id,
                    target::text as target,
                    target_label,
                    source_label,
                    mode,
                    status,
                    hop_count,
                    responded_hop_count,
                    measured_at,
                    command
                from v_active_traceroute_latest
                order by measured_at desc, target::text
                limit %s;
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [dict(row) for row in rows]


def get_traceroute_history(target: str, limit: int = 20) -> list[dict[str, Any]]:
    normalized_target = validate_target(target)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    id,
                    target::text as target,
                    target_label,
                    source_label,
                    mode,
                    max_hops,
                    timeout_seconds,
                    probes,
                    command,
                    returncode,
                    status,
                    hop_count,
                    responded_hop_count,
                    raw_output,
                    error_output,
                    measured_at,
                    created_at
                from active_traceroute_measurements
                where target = %s::inet
                order by measured_at desc, id desc
                limit %s;
                """,
                (normalized_target, limit),
            )
            rows = cur.fetchall()
    return [dict(row) for row in rows]


def get_traceroute_hops(measurement_id: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    id,
                    measurement_id,
                    target::text as target,
                    hop_number,
                    hop_ip::text as hop_ip,
                    responded,
                    rtt_ms_values,
                    rtt_avg_ms,
                    raw_line,
                    created_at
                from active_traceroute_hops
                where measurement_id = %s
                order by hop_number, id;
                """,
                (measurement_id,),
            )
            rows = cur.fetchall()
    return [dict(row) for row in rows]


def get_latest_traceroute_hops_for_target(target: str) -> list[dict[str, Any]]:
    normalized_target = validate_target(target)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    measurement_id,
                    target::text as target,
                    target_label,
                    mode,
                    measured_at,
                    hop_number,
                    hop_ip::text as hop_ip,
                    responded,
                    rtt_avg_ms,
                    raw_line
                from v_active_traceroute_latest_hops
                where target = %s::inet
                order by hop_number, measurement_id desc;
                """,
                (normalized_target,),
            )
            rows = cur.fetchall()
    return [dict(row) for row in rows]


def get_private_hops(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    measurement_id,
                    target::text as target,
                    hop_number,
                    hop_ip::text as hop_ip,
                    rtt_avg_ms,
                    measured_at,
                    raw_line
                from v_active_traceroute_private_hops
                order by measured_at desc, target::text, hop_number
                limit %s;
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [dict(row) for row in rows]
