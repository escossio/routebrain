from __future__ import annotations

import json
import socket
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from psycopg.rows import dict_row

from app.db.connection import get_connection

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_BROWSER_DIR = PROJECT_ROOT / "data" / "processed" / "synthetic_browser_lab"
SYNTHETIC_BROWSER_ANALYSIS_DIR = SYNTHETIC_BROWSER_DIR / "analysis"


def load_synthetic_browser_json(path: str | Path) -> dict[str, Any]:
    json_path = Path(path)
    return json.loads(json_path.read_text())


def extract_hosts(browser_data: dict[str, Any]) -> list[str]:
    hosts: set[str] = set()

    summary_hosts = browser_data.get("summary", {}).get("hosts", [])
    if isinstance(summary_hosts, list):
        for host in summary_hosts:
            if host:
                hosts.add(str(host).strip())

    requests = browser_data.get("requests", [])
    if isinstance(requests, list):
        for request in requests:
            hostname = request.get("hostname") if isinstance(request, dict) else None
            if hostname:
                hosts.add(str(hostname).strip())

    return sorted(host for host in hosts if host)


def resolve_hostname(hostname: str) -> dict[str, Any]:
    resolved_at = datetime.now(timezone.utc)
    ipv4_addresses: list[str] = []
    ipv6_addresses: list[str] = []
    error: str | None = None

    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            family = info[0]
            address = info[4][0]
            if family == socket.AF_INET:
                ipv4_addresses.append(address)
            elif family == socket.AF_INET6:
                ipv6_addresses.append(address)
    except Exception as exc:  # pragma: no cover - ambiente externo
        error = str(exc)

    return {
        "hostname": hostname,
        "resolved_at": resolved_at,
        "ipv4_addresses": sorted(set(ipv4_addresses)),
        "ipv6_addresses": sorted(set(ipv6_addresses)),
        "error": error,
    }


def _normalize_route(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": row.get("source"),
        "collector": row.get("collector"),
        "peer_ip": row.get("peer_ip"),
        "peer_asn": row.get("peer_asn"),
        "prefix": str(row.get("prefix")) if row.get("prefix") is not None else None,
        "next_hop": row.get("next_hop"),
        "as_path": row.get("as_path"),
        "origin_asn": row.get("origin_asn"),
        "origin_type": row.get("origin_type"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    }


def find_bgp_routes_for_ip(ip: str, limit: int = 20) -> list[dict[str, Any]]:
    sql = """
        select
            source,
            collector,
            peer_ip,
            peer_asn,
            prefix,
            next_hop,
            as_path,
            origin_asn,
            origin_type,
            first_seen,
            last_seen
          from bgp_current_routes
         where prefix >>= %s::inet
         order by masklen(prefix) desc, peer_asn
         limit %s
    """

    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, [ip, limit])
            rows = cur.fetchall()

    return [_normalize_route(dict(row)) for row in rows]


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)


def analyze_synthetic_browser_bgp(
    path: str | Path,
    max_ips_per_host: int = 5,
) -> dict[str, Any]:
    source_path = Path(path)
    browser_data = load_synthetic_browser_json(source_path)
    hosts = extract_hosts(browser_data)
    analyzed_at = datetime.now(timezone.utc)

    hosts_payload: list[dict[str, Any]] = []
    total_ipv4 = 0
    total_ipv6 = 0
    total_dns_errors = 0
    total_ips_with_bgp_match = 0

    for hostname in hosts:
        resolved = resolve_hostname(hostname)
        ipv4_addresses = resolved["ipv4_addresses"]
        ipv6_addresses = resolved["ipv6_addresses"]
        dns_error = resolved["error"]

        if dns_error:
            total_dns_errors += 1

        bgp_matches: list[dict[str, Any]] = []
        for ip in ipv4_addresses[:max_ips_per_host]:
            routes = find_bgp_routes_for_ip(ip)
            if routes:
                total_ips_with_bgp_match += 1
            bgp_matches.append(
                {
                    "ip": ip,
                    "route_count": len(routes),
                    "routes": routes,
                }
            )

        total_ipv4 += len(ipv4_addresses)
        total_ipv6 += len(ipv6_addresses)

        hosts_payload.append(
            {
                "hostname": hostname,
                "ipv4_addresses": ipv4_addresses,
                "ipv6_addresses": ipv6_addresses,
                "dns_error": dns_error,
                "bgp_matches": bgp_matches,
            }
        )

    analysis = {
        "source_json": str(source_path),
        "url": browser_data.get("url"),
        "final_url": browser_data.get("final_url"),
        "title": browser_data.get("title"),
        "total_requests": browser_data.get("summary", {}).get("total_requests", 0),
        "total_hosts": len(hosts),
        "analyzed_at": analyzed_at.isoformat(),
        "hosts": hosts_payload,
        "summary": {
            "hosts_resolved": len(hosts),
            "total_ipv4": total_ipv4,
            "total_ipv6": total_ipv6,
            "total_dns_errors": total_dns_errors,
            "total_ips_with_bgp_match": total_ips_with_bgp_match,
        },
    }

    SYNTHETIC_BROWSER_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = analyzed_at.strftime("%Y%m%dT%H%M%S%fZ")
    safe_host = _safe_name(Path(source_path).stem)
    output_path = SYNTHETIC_BROWSER_ANALYSIS_DIR / f"synthetic_bgp_analysis_{safe_host}_{timestamp}.json"
    output_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False, default=str))
    analysis["json_path"] = str(output_path)
    return analysis
