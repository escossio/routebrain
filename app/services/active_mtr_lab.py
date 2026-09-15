from __future__ import annotations

import ipaddress
import json
import subprocess
from datetime import datetime, timezone
from typing import Any


def validate_target(target: str) -> str:
    return str(ipaddress.ip_address(target))


def run_mtr_report(target: str, count: int = 5) -> dict[str, Any]:
    normalized_target = validate_target(target)

    command_json = ["mtr", "-r", "-c", str(count), "-n", "--json", normalized_target]
    measured_at = datetime.now(timezone.utc)
    json_supported = True
    parsed: Any = None

    try:
        completed = subprocess.run(command_json, capture_output=True, text=True, check=False)
        raw_output = completed.stdout or ""
        error_output = completed.stderr or ""
        returncode = completed.returncode
        if raw_output.strip():
            try:
                parsed = json.loads(raw_output)
            except Exception:
                parsed = None
    except FileNotFoundError as exc:
        return {
            "target": normalized_target,
            "command": " ".join(command_json),
            "returncode": 127,
            "json_supported": json_supported,
            "parsed": None,
            "raw_output": "",
            "error_output": str(exc),
            "measured_at": measured_at,
        }

    if parsed is None:
        command_plain = ["mtr", "-r", "-c", str(count), "-n", normalized_target]
        try:
            completed = subprocess.run(command_plain, capture_output=True, text=True, check=False)
            raw_output = completed.stdout or ""
            error_output = completed.stderr or ""
            returncode = completed.returncode
            json_supported = False
            parsed = None
            command = command_plain
        except Exception as exc:
            return {
                "target": normalized_target,
                "command": " ".join(command_json),
                "returncode": 1,
                "json_supported": json_supported,
                "parsed": None,
                "raw_output": "",
                "error_output": str(exc),
                "measured_at": measured_at,
            }
    else:
        command = command_json

    return {
        "target": normalized_target,
        "command": " ".join(command),
        "returncode": returncode,
        "json_supported": json_supported,
        "parsed": parsed,
        "raw_output": raw_output,
        "error_output": error_output,
        "measured_at": measured_at,
    }
