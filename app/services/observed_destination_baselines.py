from __future__ import annotations

import json
from typing import Any
from datetime import datetime, timezone
from uuid import uuid4

from psycopg.rows import dict_row

from app.db.connection import get_connection
from app.services.active_ping import run_ping
from app.services.active_traceroute import run_and_store_traceroute
from app.services.observed_destinations import build_observed_destination_baseline_snapshot, get_observed_destination_baseline, is_public_destination
from app.services.traceroute_graph import get_traceroute_graph_by_run


def _json_safe(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _insert_measurement(payload: dict[str, Any]) -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into observed_destination_baseline_measurements (
                    measurement_uid, baseline_uid, destination_ip, measurement_type, status, started_at,
                    finished_at, ping_summary, traceroute_summary, traceroute_run_id, graph_available, errors, metadata
                ) values (
                    %s, %s, %s::inet, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s::jsonb, %s::jsonb
                )
                returning *
                """,
                (
                    payload["measurement_uid"],
                    payload["baseline_uid"],
                    payload["destination_ip"],
                    payload["measurement_type"],
                    payload["status"],
                    payload["started_at"],
                    payload.get("finished_at"),
                    json.dumps(payload.get("ping_summary") or {}, default=str),
                    json.dumps(payload.get("traceroute_summary") or {}, default=str),
                    payload.get("traceroute_run_id"),
                    bool(payload.get("graph_available")),
                    json.dumps(payload.get("errors") or [], default=str),
                    json.dumps(payload.get("metadata") or {}, default=str),
                ),
            )
            row = cur.fetchone()
        conn.commit()
    return dict(row) if row is not None else payload


def execute_baseline_active_measurement(
    ip: str,
    confirm: bool = False,
    include_ping: bool = True,
    include_traceroute: bool = True,
) -> dict[str, Any]:
    if not confirm:
        return {"status": "error", "detail": "Medição ativa da baseline exige confirm=true."}
    baseline = get_observed_destination_baseline(ip)
    if baseline is None:
        return {"status": "error", "detail": "Destino ainda não foi promovido para baseline.", "code": 404}
    if not is_public_destination(ip):
        return {"status": "error", "detail": "IP bloqueado pela política ativa: apenas destino público permitido.", "code": 400}

    measurement_uid = f"obm_{uuid4().hex}"
    started_at = datetime.now(timezone.utc)
    ping_summary: dict[str, Any] = {}
    traceroute_summary: dict[str, Any] = {}
    traceroute_run_id: str | None = None
    graph_available = False
    errors: list[dict[str, Any]] = []

    if include_ping:
        try:
            ping_row = run_ping(ip, count=5, timeout=5, target_label=f"baseline:{ip}", source_label="routebrain-baseline")
            ping_summary = _json_safe(ping_row)
        except Exception as exc:
            errors.append({"stage": "ping", "error": str(exc)})

    if include_traceroute:
        try:
            traceroute_row = run_and_store_traceroute(
                ip,
                mode="icmp",
                max_hops=30,
                timeout=3,
                probes=3,
                target_label=f"baseline:{ip}",
                source_label="routebrain-baseline",
            )
            traceroute_summary = _json_safe(traceroute_row)
            traceroute_run_id = str(traceroute_row.get("measurement_id")) if traceroute_row.get("measurement_id") is not None else None
            graph_available = traceroute_run_id is not None
        except Exception as exc:
            errors.append({"stage": "traceroute", "error": str(exc)})

    status = "ok" if not errors else "partial" if (ping_summary or traceroute_summary) else "failed"
    record = _insert_measurement(
        {
            "measurement_uid": measurement_uid,
            "baseline_uid": baseline.get("baseline_uid"),
            "destination_ip": ip,
            "measurement_type": "active_measurement",
            "status": status,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc),
            "ping_summary": ping_summary,
            "traceroute_summary": traceroute_summary,
            "traceroute_run_id": traceroute_run_id,
            "graph_available": graph_available,
            "errors": errors,
            "metadata": {
                "confirm": True,
                "include_ping": include_ping,
                "include_traceroute": include_traceroute,
                "active_measurement": True,
                "privacy": {
                    "source_profiling": False,
                    "payload_collected": False,
                    "url_collected": False,
                    "query_string_collected": False,
                },
            },
        }
    )
    active_snapshot = {
        "measurement_uid": measurement_uid,
        "baseline_uid": baseline.get("baseline_uid"),
        "destination_ip": ip,
        "measurement_type": "active_measurement",
        "status": status,
        "ping_summary": ping_summary,
        "traceroute_summary": traceroute_summary,
        "traceroute_run_id": traceroute_run_id,
        "graph_available": graph_available,
        "errors": errors,
    }
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update observed_destination_baselines
                set updated_at = now(),
                    last_seen = greatest(coalesce(last_seen, now()), now()),
                    baseline_snapshot = baseline_snapshot || %s::jsonb
                where baseline_uid = %s
                """,
                (json.dumps({"last_active_measurement": active_snapshot}, default=str), baseline.get("baseline_uid")),
            )
            cur.execute(
                """
                insert into observed_destination_baseline_snapshots (
                    baseline_uid, destination_ip, snapshot_type, summary
                ) values (%s, %s::inet, 'active_measurement', %s::jsonb)
                """,
                (baseline.get("baseline_uid"), ip, json.dumps(active_snapshot, default=str)),
            )
        conn.commit()
    graph_url = f"/observed-destinations/baselines/{ip}/traceroute-graph" if graph_available else None
    if traceroute_run_id is not None:
        graph = get_traceroute_graph_by_run(traceroute_run_id)
        graph_available = bool(graph.get("available"))
        graph_url = f"/observed-destinations/baselines/{ip}/traceroute-graph" if graph_available else None
    snapshot = build_observed_destination_baseline_snapshot(baseline if isinstance(baseline, dict) else {})
    return {
        "status": "ok" if status == "ok" else "partial" if status == "partial" else "failed",
        "measurement_uid": measurement_uid,
        "baseline_uid": baseline.get("baseline_uid"),
        "destination_ip": ip,
        "ping_summary": ping_summary,
        "traceroute_summary": traceroute_summary,
        "graph_available": graph_available,
        "graph_url": graph_url,
        "errors": errors,
        "baseline_snapshot": snapshot,
        "measurement_record": record,
    }


def get_latest_baseline_measurement(ip: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select *
                from observed_destination_baseline_measurements
                where destination_ip = %s::inet
                order by started_at desc, id desc
                limit 1
                """,
                (ip,),
            )
            row = cur.fetchone()
            return dict(row) if row is not None else None


def get_baseline_measurements(ip: str, limit: int = 20) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select *
                from observed_destination_baseline_measurements
                where destination_ip = %s::inet
                order by started_at desc, id desc
                limit %s
                """,
                (ip, limit),
            )
            return [dict(row) for row in cur.fetchall()]


def get_baseline_traceroute_graph(ip: str) -> dict[str, Any]:
    latest = get_latest_baseline_measurement(ip)
    if latest is None or not latest.get("traceroute_run_id"):
        return {"available": False, "reason": "no_traceroute_evidence"}
    return get_traceroute_graph_by_run(latest["traceroute_run_id"])
