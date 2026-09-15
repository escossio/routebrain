from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import mean
from typing import Any


_HOP_RE = re.compile(r"^\s*(?P<hop>\d+)\s+(?P<body>.*)$")
_IP_RE = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_RTT_RE = re.compile(r"(?P<value>[\d.]+)\s*ms")


def validate_target(target: str) -> str:
    return str(ipaddress.ip_address(target))


def _build_command(target: str, mode: str, max_hops: int, timeout: int, probes: int) -> list[str]:
    command = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), "-q", str(probes)]
    if mode == "icmp":
        command.insert(1, "-I")
    command.append(target)
    return command


def _parse_hop_line(line: str) -> dict[str, Any]:
    match = _HOP_RE.match(line)
    if not match:
        return {}

    hop_number = int(match.group("hop"))
    body = match.group("body").strip()
    if body == "* * *":
        return {
            "hop_number": hop_number,
            "hop_ip": None,
            "probes_raw": ["*", "*", "*"],
            "rtt_ms_values": [],
            "rtt_avg_ms": None,
            "responded": False,
            "raw_line": line,
        }

    hop_ip_match = _IP_RE.search(body)
    hop_ip = hop_ip_match.group("ip") if hop_ip_match else None
    probes_raw = body.split()
    rtt_ms_values = [float(value) for value in _RTT_RE.findall(body)]
    return {
        "hop_number": hop_number,
        "hop_ip": hop_ip,
        "probes_raw": probes_raw,
        "rtt_ms_values": rtt_ms_values,
        "rtt_avg_ms": round(mean(rtt_ms_values), 3) if rtt_ms_values else None,
        "responded": bool(rtt_ms_values or hop_ip),
        "raw_line": line,
    }


def _parse_traceroute_output(raw_output: str) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        parsed = _parse_hop_line(line)
        if parsed:
            hops.append(parsed)
    return hops


def run_traceroute(
    target: str,
    mode: str = "icmp",
    max_hops: int = 30,
    timeout: int = 3,
    probes: int = 3,
) -> dict[str, Any]:
    normalized_target = validate_target(target)
    if mode not in {"icmp", "udp"}:
        raise ValueError("mode deve ser 'icmp' ou 'udp'.")

    command = _build_command(normalized_target, mode, max_hops, timeout, probes)
    measured_at = datetime.now(timezone.utc)

    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        raw_output = completed.stdout or ""
        error_output = completed.stderr or ""
        returncode = completed.returncode
    except FileNotFoundError as exc:
        raw_output = ""
        error_output = str(exc)
        returncode = 127
    except Exception as exc:
        raw_output = ""
        error_output = str(exc)
        returncode = 1

    hops = _parse_traceroute_output(raw_output)
    status = "SUCCESS" if any(hop.get("responded") for hop in hops) else "FAILED"
    if returncode != 0 and status == "SUCCESS":
        status = "SUCCESS"
    elif returncode != 0 and not hops:
        status = "FAILED"

    return {
        "target": normalized_target,
        "mode": mode,
        "command": " ".join(command),
        "returncode": returncode,
        "status": status,
        "hops": hops,
        "raw_output": raw_output,
        "error_output": error_output,
        "measured_at": measured_at,
    }
