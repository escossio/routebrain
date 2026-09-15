from __future__ import annotations

import json
import ipaddress
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.active_traceroute_lab import run_traceroute
from app.services.synthetic_dns_bgp_lab import (
    extract_hosts,
    find_bgp_routes_for_ip,
    load_synthetic_browser_json,
    resolve_hostname,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_BROWSER_DIR = PROJECT_ROOT / "data" / "processed" / "synthetic_browser_lab"
SYNTHETIC_BROWSER_ACTIVE_DIR = SYNTHETIC_BROWSER_DIR / "active_analysis"

_PING_STATS_RE = re.compile(
    r"(?P<sent>\d+)\s+packets transmitted,\s+"
    r"(?P<received>\d+)\s+(?:packets\s+)?received,\s+"
    r"(?P<loss>[\d.]+)%\s+packet loss"
)
_PING_RTT_RE = re.compile(
    r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
    r"(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)\s+ms"
)


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)


def _parse_ping_output(raw_output: str) -> dict[str, Any]:
    packets_sent = 0
    packets_received = 0
    packet_loss_percent = None
    rtt_min_ms = None
    rtt_avg_ms = None
    rtt_max_ms = None
    rtt_mdev_ms = None

    stats_match = _PING_STATS_RE.search(raw_output)
    if stats_match:
        packets_sent = int(stats_match.group("sent"))
        packets_received = int(stats_match.group("received"))
        packet_loss_percent = float(stats_match.group("loss"))

    rtt_match = _PING_RTT_RE.search(raw_output)
    if rtt_match:
        rtt_min_ms = float(rtt_match.group("min"))
        rtt_avg_ms = float(rtt_match.group("avg"))
        rtt_max_ms = float(rtt_match.group("max"))
        rtt_mdev_ms = float(rtt_match.group("mdev"))

    return {
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "packet_loss_percent": packet_loss_percent,
        "rtt_min_ms": rtt_min_ms,
        "rtt_avg_ms": rtt_avg_ms,
        "rtt_max_ms": rtt_max_ms,
        "rtt_mdev_ms": rtt_mdev_ms,
    }


def run_ping_probe_no_store(ip: str, count: int = 3, timeout: int = 2) -> dict[str, Any]:
    normalized_ip = str(ipaddress.ip_address(ip))
    command = ["ping", "-c", str(count), "-W", str(timeout), normalized_ip]
    measured_at = datetime.now(timezone.utc)

    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        raw_output = (completed.stdout or "") + (("\n" + completed.stderr) if completed.stderr else "")
        raw_output = raw_output.strip()
        parsed = _parse_ping_output(raw_output)
        packets_received = int(parsed["packets_received"] or 0)
        status = "SUCCESS" if packets_received >= 1 else "FAILED"
        returncode = completed.returncode
        error_output = completed.stderr or ""
    except FileNotFoundError as exc:
        raw_output = ""
        error_output = str(exc)
        parsed = {
            "packets_sent": count,
            "packets_received": 0,
            "packet_loss_percent": None,
            "rtt_min_ms": None,
            "rtt_avg_ms": None,
            "rtt_max_ms": None,
            "rtt_mdev_ms": None,
        }
        status = "FAILED"
        returncode = 127
    except Exception as exc:  # pragma: no cover - ambiente externo
        raw_output = ""
        error_output = str(exc)
        parsed = {
            "packets_sent": count,
            "packets_received": 0,
            "packet_loss_percent": None,
            "rtt_min_ms": None,
            "rtt_avg_ms": None,
            "rtt_max_ms": None,
            "rtt_mdev_ms": None,
        }
        status = "FAILED"
        returncode = 1

    return {
        "ip": normalized_ip,
        "command": " ".join(command),
        "returncode": returncode,
        "status": status,
        "packets_sent": parsed["packets_sent"],
        "packets_received": parsed["packets_received"],
        "packet_loss_percent": parsed["packet_loss_percent"],
        "rtt_min_ms": parsed["rtt_min_ms"],
        "rtt_avg_ms": parsed["rtt_avg_ms"],
        "rtt_max_ms": parsed["rtt_max_ms"],
        "rtt_mdev_ms": parsed["rtt_mdev_ms"],
        "raw_output": raw_output,
        "error_output": error_output,
        "measured_at": measured_at,
    }


def analyze_synthetic_with_active_measurements(
    browser_json_path: str | Path,
    max_hosts: int = 5,
    max_ips_per_host: int = 2,
    ping_count: int = 3,
    ping_timeout: int = 2,
    traceroute: bool = False,
    traceroute_max_hops: int = 15,
    traceroute_timeout: int = 2,
    traceroute_probes: int = 1,
) -> dict[str, Any]:
    source_path = Path(browser_json_path)
    browser_data = load_synthetic_browser_json(source_path)
    hosts = extract_hosts(browser_data)[:max_hosts]
    analyzed_at = datetime.now(timezone.utc)

    hosts_payload: list[dict[str, Any]] = []
    total_ipv4 = 0
    total_ipv6 = 0
    total_ips_measured = 0
    total_ping_success = 0
    total_ping_failed = 0
    total_ips_with_bgp_match = 0
    total_traceroutes_run = 0

    for hostname in hosts:
        resolved = resolve_hostname(hostname)
        ipv4_addresses = resolved["ipv4_addresses"]
        ipv6_addresses = resolved["ipv6_addresses"]
        dns_error = resolved["error"]
        selected_ipv4_addresses = ipv4_addresses[:max_ips_per_host]

        measurements: list[dict[str, Any]] = []
        for ip in selected_ipv4_addresses:
            total_ips_measured += 1
            bgp_routes = find_bgp_routes_for_ip(ip)
            if bgp_routes:
                total_ips_with_bgp_match += 1

            ping_result = run_ping_probe_no_store(ip, count=ping_count, timeout=ping_timeout)
            if ping_result["status"] == "SUCCESS":
                total_ping_success += 1
            else:
                total_ping_failed += 1

            measurement: dict[str, Any] = {
                "ip": ip,
                "bgp_route_count": len(bgp_routes),
                "bgp_routes": bgp_routes,
                "ping": ping_result,
            }

            if traceroute:
                traceroute_result = run_traceroute(
                    ip,
                    mode="icmp",
                    max_hops=traceroute_max_hops,
                    timeout=traceroute_timeout,
                    probes=traceroute_probes,
                )
                total_traceroutes_run += 1
                measurement["traceroute"] = traceroute_result

            measurements.append(measurement)

        total_ipv4 += len(ipv4_addresses)
        total_ipv6 += len(ipv6_addresses)

        hosts_payload.append(
            {
                "hostname": hostname,
                "ipv4_addresses": ipv4_addresses,
                "ipv6_addresses": ipv6_addresses,
                "dns_error": dns_error,
                "selected_ipv4_addresses": selected_ipv4_addresses,
                "measurements": measurements,
            }
        )

    analysis = {
        "source_json": str(source_path),
        "url": browser_data.get("url"),
        "final_url": browser_data.get("final_url"),
        "title": browser_data.get("title"),
        "total_requests": browser_data.get("summary", {}).get("total_requests", 0),
        "analyzed_at": analyzed_at.isoformat(),
        "parameters": {
            "max_hosts": max_hosts,
            "max_ips_per_host": max_ips_per_host,
            "ping_count": ping_count,
            "ping_timeout": ping_timeout,
            "traceroute": traceroute,
            "traceroute_max_hops": traceroute_max_hops,
            "traceroute_timeout": traceroute_timeout,
            "traceroute_probes": traceroute_probes,
        },
        "hosts": hosts_payload,
        "summary": {
            "total_hosts": len(hosts),
            "hosts_resolved": len(hosts),
            "total_ipv4": total_ipv4,
            "total_ipv6": total_ipv6,
            "total_ips_measured": total_ips_measured,
            "total_ping_success": total_ping_success,
            "total_ping_failed": total_ping_failed,
            "total_ips_with_bgp_match": total_ips_with_bgp_match,
            "total_traceroutes_run": total_traceroutes_run,
        },
    }

    SYNTHETIC_BROWSER_ACTIVE_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = analyzed_at.strftime("%Y%m%dT%H%M%S%fZ")
    safe_source = _safe_name(source_path.stem)
    output_path = SYNTHETIC_BROWSER_ACTIVE_DIR / f"synthetic_active_analysis_{safe_source}_{timestamp}.json"
    output_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False, default=str))
    analysis["json_path"] = str(output_path)
    return analysis
