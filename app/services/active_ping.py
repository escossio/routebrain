from __future__ import annotations

import ipaddress
import re
import subprocess
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from psycopg.rows import dict_row

from app.db.connection import get_connection

_PING_STATS_RE = re.compile(
    r"(?P<sent>\d+)\s+packets transmitted,\s+"
    r"(?P<received>\d+)\s+(?:packets\s+)?received,\s+"
    r"(?P<loss>[\d.]+)%\s+packet loss"
)
_PING_RTT_RE = re.compile(
    r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
    r"(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)\s+ms"
)


def _parse_decimal(value: str | None) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(value)
    except Exception:
        return None


def _parse_ping_output(raw_output: str) -> dict[str, Any]:
    packets_sent = 0
    packets_received = 0
    packet_loss_percent: Decimal | None = None
    rtt_min_ms: Decimal | None = None
    rtt_avg_ms: Decimal | None = None
    rtt_max_ms: Decimal | None = None
    rtt_mdev_ms: Decimal | None = None

    stats_match = _PING_STATS_RE.search(raw_output)
    if stats_match:
        packets_sent = int(stats_match.group("sent"))
        packets_received = int(stats_match.group("received"))
        packet_loss_percent = _parse_decimal(stats_match.group("loss"))

    rtt_match = _PING_RTT_RE.search(raw_output)
    if rtt_match:
        rtt_min_ms = _parse_decimal(rtt_match.group("min"))
        rtt_avg_ms = _parse_decimal(rtt_match.group("avg"))
        rtt_max_ms = _parse_decimal(rtt_match.group("max"))
        rtt_mdev_ms = _parse_decimal(rtt_match.group("mdev"))

    return {
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "packet_loss_percent": packet_loss_percent,
        "rtt_min_ms": rtt_min_ms,
        "rtt_avg_ms": rtt_avg_ms,
        "rtt_max_ms": rtt_max_ms,
        "rtt_mdev_ms": rtt_mdev_ms,
    }


def _ping_command(target: str, count: int, timeout: int) -> list[str]:
    return ["ping", "-c", str(count), "-W", str(timeout), target]


def _insert_measurement(payload: dict[str, Any]) -> dict[str, Any]:
    columns = (
        "target",
        "target_label",
        "source_label",
        "packets_sent",
        "packets_received",
        "packet_loss_percent",
        "rtt_min_ms",
        "rtt_avg_ms",
        "rtt_max_ms",
        "rtt_mdev_ms",
        "command",
        "raw_output",
        "status",
        "measured_at",
    )
    values = tuple(payload[column] for column in columns)
    placeholders = ", ".join(["%s"] * len(columns))
    sql = f"""
        INSERT INTO active_ping_measurements (
            target,
            target_label,
            source_label,
            packets_sent,
            packets_received,
            packet_loss_percent,
            rtt_min_ms,
            rtt_avg_ms,
            rtt_max_ms,
            rtt_mdev_ms,
            command,
            raw_output,
            status,
            measured_at
        ) VALUES ({placeholders})
        RETURNING
            id,
            target,
            target_label,
            source_label,
            packets_sent,
            packets_received,
            packet_loss_percent,
            rtt_min_ms,
            rtt_avg_ms,
            rtt_max_ms,
            rtt_mdev_ms,
            command,
            raw_output,
            status,
            measured_at,
            created_at;
    """
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, values)
            row = cur.fetchone()
        conn.commit()
    return dict(row) if row is not None else {}


def run_ping(
    target: str,
    count: int = 5,
    timeout: int = 5,
    target_label: str | None = None,
    source_label: str | None = None,
) -> dict[str, Any]:
    ipaddress.ip_address(target)

    command = _ping_command(target, count, timeout)
    measured_at = datetime.now(timezone.utc)
    raw_output_parts: list[str] = []
    status = "FAILED"
    packets_sent = count
    packets_received = 0
    packet_loss_percent: Decimal | None = None
    rtt_min_ms: Decimal | None = None
    rtt_avg_ms: Decimal | None = None
    rtt_max_ms: Decimal | None = None
    rtt_mdev_ms: Decimal | None = None

    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.stdout:
            raw_output_parts.append(completed.stdout)
        if completed.stderr:
            raw_output_parts.append(completed.stderr)
        raw_output = "\n".join(part.strip() for part in raw_output_parts if part.strip())
        parsed = _parse_ping_output(raw_output)
        packets_sent = int(parsed["packets_sent"] or count)
        packets_received = int(parsed["packets_received"] or 0)
        packet_loss_percent = parsed["packet_loss_percent"]
        rtt_min_ms = parsed["rtt_min_ms"]
        rtt_avg_ms = parsed["rtt_avg_ms"]
        rtt_max_ms = parsed["rtt_max_ms"]
        rtt_mdev_ms = parsed["rtt_mdev_ms"]
        if packets_received > 0:
            status = "SUCCESS"
        else:
            status = "FAILED"
    except FileNotFoundError as exc:
        raw_output = str(exc)
        status = "FAILED"
    except Exception as exc:
        raw_output = str(exc)
        status = "FAILED"
    else:
        if not raw_output_parts:
            raw_output = ""

    payload = {
        "target": ipaddress.ip_address(target),
        "target_label": target_label,
        "source_label": source_label,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "packet_loss_percent": packet_loss_percent,
        "rtt_min_ms": rtt_min_ms,
        "rtt_avg_ms": rtt_avg_ms,
        "rtt_max_ms": rtt_max_ms,
        "rtt_mdev_ms": rtt_mdev_ms,
        "command": " ".join(command),
        "raw_output": raw_output,
        "status": status,
        "measured_at": measured_at,
    }
    return _insert_measurement(payload)


def get_latest_ping_measurements(limit: int = 20) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    target::text as target,
                    target_label,
                    source_label,
                    packets_sent,
                    packets_received,
                    packet_loss_percent,
                    rtt_min_ms,
                    rtt_avg_ms,
                    rtt_max_ms,
                    rtt_mdev_ms,
                    status,
                    measured_at
                from v_active_ping_latest
                order by measured_at desc, target::text
                limit %s;
                """,
                (limit,),
            )
            rows = cur.fetchall()
    return [dict(row) for row in rows]


def get_ping_history(target: str, limit: int = 50) -> list[dict[str, Any]]:
    normalized_target = str(ipaddress.ip_address(target))
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    id,
                    target::text as target,
                    target_label,
                    source_label,
                    packets_sent,
                    packets_received,
                    packet_loss_percent,
                    rtt_min_ms,
                    rtt_avg_ms,
                    rtt_max_ms,
                    rtt_mdev_ms,
                    command,
                    raw_output,
                    status,
                    measured_at,
                    created_at
                from active_ping_measurements
                where target = %s::inet
                order by measured_at desc, id desc
                limit %s;
                """,
                (normalized_target, limit),
            )
            rows = cur.fetchall()
    return [dict(row) for row in rows]
