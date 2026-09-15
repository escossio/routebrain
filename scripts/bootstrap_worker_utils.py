from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKER_ROOT = Path(os.getenv("ROUTEBRAIN_WORKER_ROOT", "./worker"))
DEFAULT_OUTPUT_FORMAT = os.getenv("ROUTEBRAIN_OUTPUT_FORMAT", "csv").lower()
DEFAULT_BOOTSTRAP_BATCH_SIZE = int(os.getenv("ROUTEBRAIN_BOOTSTRAP_BATCH_SIZE", "100000"))
DEFAULT_MAX_WORKERS = int(os.getenv("ROUTEBRAIN_MAX_WORKERS", "8"))

WORKER_SUBDIRS = [
    "data/raw/routeviews",
    "data/raw/ris",
    "data/processed/bootstrap",
    "data/processed/reports",
    "data/tmp",
    "logs",
    "scripts",
    "config",
    "manifests",
]

BOOTSTRAP_MANIFEST_DIR = PROJECT_ROOT / "data" / "processed" / "bootstrap_worker_manifests"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp_slug(moment: datetime | None = None) -> str:
    moment = moment or utc_now()
    return moment.strftime("%Y%m%dT%H%M%SZ")


def ensure_worker_layout(worker_root: Path) -> list[Path]:
    created: list[Path] = []
    for relative in WORKER_SUBDIRS:
        path = worker_root / relative
        path.mkdir(parents=True, exist_ok=True)
        created.append(path)
    return created


def ensure_project_manifest_layout() -> Path:
    BOOTSTRAP_MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    return BOOTSTRAP_MANIFEST_DIR


def normalize_output_format(value: str | None) -> str:
    normalized = (value or DEFAULT_OUTPUT_FORMAT).strip().lower()
    if normalized not in {"csv", "jsonl", "parquet"}:
        raise ValueError("Formato inválido. Use csv, jsonl ou parquet.")
    return normalized


def command_output(command: str) -> str:
    try:
        return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as exc:
        output = exc.output.strip()
        return f"ERROR: {output}" if output else f"ERROR: returncode={exc.returncode}"


def collect_system_snapshot(worker_root: Path | None = None) -> dict[str, Any]:
    worker_root = worker_root or DEFAULT_WORKER_ROOT
    snapshot: dict[str, Any] = {}

    snapshot["timestamp"] = utc_now().isoformat()
    snapshot["hostname"] = command_output("hostname -f 2>/dev/null || hostname")
    snapshot["user"] = command_output("whoami")
    snapshot["pwd"] = command_output("pwd")
    snapshot["kernel"] = platform.release()
    snapshot["os"] = command_output(". /etc/os-release; printf '%s' \"$PRETTY_NAME\"")
    snapshot["python"] = sys.version.splitlines()[0]
    snapshot["pip"] = command_output("pip3 --version")
    snapshot["git"] = command_output("command -v git || true")
    snapshot["rsync"] = command_output("command -v rsync || true")
    snapshot["ssh"] = command_output("command -v ssh || true")
    snapshot["scp"] = command_output("command -v scp || true")
    snapshot["psql"] = command_output("command -v psql || true")
    snapshot["cpu_logical"] = os.cpu_count()
    snapshot["cpu_model"] = command_output("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'")
    snapshot["cpu_sockets"] = command_output("lscpu | awk -F: '/Socket\\\\(s\\\\)/{gsub(/^ +/, \"\", $2); print $2; exit}'")
    snapshot["cpu_cores_per_socket"] = command_output(
        "lscpu | awk -F: '/Core\\\\(s\\\\) per socket/{gsub(/^ +/, \"\", $2); print $2; exit}'"
    )
    snapshot["cpu_threads_per_core"] = command_output(
        "lscpu | awk -F: '/Thread\\\\(s\\\\) per core/{gsub(/^ +/, \"\", $2); print $2; exit}'"
    )

    meminfo: dict[str, str] = {}
    with open("/proc/meminfo", encoding="utf-8") as handle:
        for line in handle:
            key, value = line.split(":", 1)
            meminfo[key] = value.strip()
    snapshot["mem_total_kb"] = meminfo.get("MemTotal")
    snapshot["mem_free_kb"] = meminfo.get("MemFree")
    snapshot["mem_available_kb"] = meminfo.get("MemAvailable")
    snapshot["swap_total_kb"] = meminfo.get("SwapTotal")
    snapshot["swap_free_kb"] = meminfo.get("SwapFree")

    for mount, key in (("/", "root"), ("/home", "home")):
        try:
            usage = shutil.disk_usage(mount)
            snapshot[f"disk_{key}_free_gb"] = round(usage.free / (1024**3), 2)
            snapshot[f"disk_{key}_total_gb"] = round(usage.total / (1024**3), 2)
        except FileNotFoundError:
            snapshot[f"disk_{key}_error"] = f"mount_not_found:{mount}"

    snapshot["default_route"] = command_output("ip route show default | head -n1")
    default_iface = command_output("ip route show default | awk '{print $5; exit}'")
    snapshot["local_interface"] = default_iface if default_iface and not default_iface.startswith("ERROR:") else None
    snapshot["local_ip"] = (
        command_output(
            f"ip -4 -o addr show dev {default_iface} scope global | awk '{{print $4; exit}}' | cut -d/ -f1"
        )
        if default_iface and not default_iface.startswith("ERROR:") and default_iface != ""
        else command_output("hostname -I | awk '{print $1}'")
    )
    snapshot["filesystem_root"] = command_output("findmnt -no SOURCE,FSTYPE,TARGET /")
    snapshot["filesystem_home"] = command_output("findmnt -no SOURCE,FSTYPE,TARGET /home 2>/dev/null || true")
    snapshot["dns_github"] = "ok" if _dns_resolves("github.com") else "fail"
    snapshot["http_test"] = _http_test("https://example.com")
    snapshot["worker_root"] = str(worker_root)
    snapshot["worker_root_exists"] = worker_root.exists()
    return snapshot


def _dns_resolves(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, 443)
        return True
    except OSError:
        return False


def _http_test(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            return f"ok {response.status}"
    except Exception as exc:  # pragma: no cover - network dependent
        return f"fail {type(exc).__name__}: {exc}"


def json_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            rows.append(json.loads(text))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False))
            handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _stringify_csv_value(row.get(key)) for key in fieldnames})


def _stringify_csv_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def try_import_pyarrow() -> Any | None:
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.csv as pacsv  # type: ignore
        import pyarrow.json as pajson  # type: ignore
        import pyarrow.parquet as pq  # type: ignore

        return {"pa": pa, "csv": pacsv, "json": pajson, "parquet": pq}
    except Exception:
        return None


def dependency_status(packages: list[str]) -> dict[str, bool]:
    status: dict[str, bool] = {}
    for package in packages:
        try:
            __import__(package)
            status[package] = True
        except Exception:
            status[package] = False
    return status


@dataclass(frozen=True)
class BootstrapStats:
    total_rows: int
    distinct_collectors: int
    distinct_peers: int
    distinct_prefixes: int
    distinct_origin_asns: int
    duplicate_rows: int
