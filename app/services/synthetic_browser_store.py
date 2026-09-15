from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from psycopg.rows import dict_row

from app.db.connection import get_connection


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return None


def _normalize_inet_list(values: Any) -> list[str] | None:
    if not values:
        return None
    normalized: list[str] = []
    for value in values:
        if value is None:
            continue
        normalized.append(str(value))
    return normalized or None


def _compact_traceroute(traceroute: dict[str, Any] | None) -> dict[str, Any] | None:
    if not traceroute:
        return None
    hops = []
    for hop in traceroute.get("hops", []) or []:
        hops.append(
            {
                "hop_number": hop.get("hop_number"),
                "hop_ip": hop.get("hop_ip"),
                "responded": hop.get("responded"),
                "rtt_avg_ms": hop.get("rtt_avg_ms"),
                "raw_line": hop.get("raw_line"),
            }
        )
    return {
        "status": traceroute.get("status"),
        "command": traceroute.get("command"),
        "returncode": traceroute.get("returncode"),
        "hop_count": len(hops),
        "responded_hop_count": sum(1 for hop in hops if hop.get("responded")),
        "hops": hops,
    }


def store_synthetic_active_analysis(path: str | Path) -> dict[str, Any]:
    analysis_path = Path(path)
    payload = json.loads(analysis_path.read_text())

    run_columns = (
        "source_json_path",
        "url",
        "final_url",
        "title",
        "label",
        "total_requests",
        "total_hosts",
        "total_ipv4",
        "total_ipv6",
        "total_ips_measured",
        "total_ping_success",
        "total_ping_failed",
        "total_traceroutes_run",
        "total_ips_with_bgp_match",
        "parameters",
        "summary",
        "started_at",
        "finished_at",
        "analyzed_at",
    )
    run_values = {
        "source_json_path": payload.get("source_json"),
        "url": payload.get("url"),
        "final_url": payload.get("final_url"),
        "title": payload.get("title"),
        "label": payload.get("label"),
        "total_requests": payload.get("total_requests"),
        "total_hosts": payload.get("summary", {}).get("total_hosts"),
        "total_ipv4": payload.get("summary", {}).get("total_ipv4"),
        "total_ipv6": payload.get("summary", {}).get("total_ipv6"),
        "total_ips_measured": payload.get("summary", {}).get("total_ips_measured"),
        "total_ping_success": payload.get("summary", {}).get("total_ping_success"),
        "total_ping_failed": payload.get("summary", {}).get("total_ping_failed"),
        "total_traceroutes_run": payload.get("summary", {}).get("total_traceroutes_run"),
        "total_ips_with_bgp_match": payload.get("summary", {}).get("total_ips_with_bgp_match"),
        "parameters": json.dumps(payload.get("parameters") or {}),
        "summary": json.dumps(payload.get("summary") or {}),
        "started_at": _parse_datetime(payload.get("summary", {}).get("started_at") or payload.get("started_at")),
        "finished_at": _parse_datetime(payload.get("summary", {}).get("finished_at") or payload.get("finished_at")),
        "analyzed_at": _parse_datetime(payload.get("analyzed_at")),
    }

    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                INSERT INTO synthetic_browser_runs (
                    source_json_path,
                    url,
                    final_url,
                    title,
                    label,
                    total_requests,
                    total_hosts,
                    total_ipv4,
                    total_ipv6,
                    total_ips_measured,
                    total_ping_success,
                    total_ping_failed,
                    total_traceroutes_run,
                    total_ips_with_bgp_match,
                    parameters,
                    summary,
                    started_at,
                    finished_at,
                    analyzed_at
                ) VALUES (
                    %(source_json_path)s,
                    %(url)s,
                    %(final_url)s,
                    %(title)s,
                    %(label)s,
                    %(total_requests)s,
                    %(total_hosts)s,
                    %(total_ipv4)s,
                    %(total_ipv6)s,
                    %(total_ips_measured)s,
                    %(total_ping_success)s,
                    %(total_ping_failed)s,
                    %(total_traceroutes_run)s,
                    %(total_ips_with_bgp_match)s,
                    %(parameters)s::jsonb,
                    %(summary)s::jsonb,
                    %(started_at)s,
                    %(finished_at)s,
                    %(analyzed_at)s
                )
                RETURNING id;
                """,
                run_values,
            )
            run_id = int(cur.fetchone()["id"])

            hosts_inserted = 0
            measurements_inserted = 0

            for host in payload.get("hosts", []):
                request_count = len(host.get("measurements", []) or [])
                cur.execute(
                    """
                    INSERT INTO synthetic_browser_hosts (
                        run_id,
                        hostname,
                        dns_error,
                        ipv4_addresses,
                        ipv6_addresses,
                        selected_ipv4_addresses,
                        request_count
                    ) VALUES (
                        %s,
                        %s,
                        %s,
                        %s::inet[],
                        %s::inet[],
                        %s::inet[],
                        %s
                    )
                    RETURNING id;
                    """,
                    [
                        run_id,
                        host.get("hostname"),
                        host.get("dns_error"),
                        _normalize_inet_list(host.get("ipv4_addresses")),
                        _normalize_inet_list(host.get("ipv6_addresses")),
                        _normalize_inet_list(host.get("selected_ipv4_addresses")),
                        request_count,
                    ],
                )
                host_id = int(cur.fetchone()["id"])
                hosts_inserted += 1

                for measurement in host.get("measurements", []):
                    ping = measurement.get("ping") or {}
                    traceroute = measurement.get("traceroute") or None
                    compact_traceroute = _compact_traceroute(traceroute)
                    cur.execute(
                        """
                        INSERT INTO synthetic_browser_ip_measurements (
                            run_id,
                            host_id,
                            hostname,
                            ip,
                            bgp_route_count,
                            bgp_routes,
                            ping_status,
                            packet_loss_percent,
                            rtt_min_ms,
                            rtt_avg_ms,
                            rtt_max_ms,
                            rtt_mdev_ms,
                            traceroute_status,
                            traceroute_hop_count,
                            traceroute_responded_hop_count,
                            traceroute,
                            measured_at
                        ) VALUES (
                            %s,
                            %s,
                            %s,
                            %s::inet,
                            %s,
                            %s::jsonb,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s::jsonb,
                            %s
                        );
                        """,
                        [
                            run_id,
                            host_id,
                            host.get("hostname"),
                            measurement.get("ip"),
                            measurement.get("bgp_route_count", 0),
                            json.dumps(measurement.get("bgp_routes") or [], default=str),
                            ping.get("status"),
                            ping.get("packet_loss_percent"),
                            ping.get("rtt_min_ms"),
                            ping.get("rtt_avg_ms"),
                            ping.get("rtt_max_ms"),
                            ping.get("rtt_mdev_ms"),
                            compact_traceroute.get("status") if compact_traceroute else None,
                            compact_traceroute.get("hop_count") if compact_traceroute else None,
                            compact_traceroute.get("responded_hop_count") if compact_traceroute else None,
                            json.dumps(compact_traceroute, default=str) if compact_traceroute else None,
                            _parse_datetime(ping.get("measured_at")) or _parse_datetime(compact_traceroute.get("measured_at") if compact_traceroute else None),
                        ],
                    )
                    measurements_inserted += 1

        conn.commit()

    return {
        "run_id": run_id,
        "hosts_inserted": hosts_inserted,
        "measurements_inserted": measurements_inserted,
    }
