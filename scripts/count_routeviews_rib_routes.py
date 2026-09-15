#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.parsers.routeviews_mrt_parser import parse_rib_records  # noqa: E402

DEFAULT_COLLECTOR = "route-views2"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "processed" / f"routeviews_latest_rib_{DEFAULT_COLLECTOR}.json"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "rib_counts"


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def _resolve_rib_path(args: argparse.Namespace) -> tuple[str, Path]:
    collector = args.collector or DEFAULT_COLLECTOR
    if args.rib_path is not None:
        return collector, args.rib_path

    manifest_path = PROJECT_ROOT / "data" / "processed" / f"routeviews_latest_rib_{collector}.json"
    if not manifest_path.exists():
        raise SystemExit(f"Manifesto do RIB não encontrado: {manifest_path}")

    manifest = _load_manifest(manifest_path)
    manifest_collector = manifest.get("collector")
    if isinstance(manifest_collector, str) and manifest_collector:
        collector = manifest_collector

    output_path = manifest.get("output_path")
    if not isinstance(output_path, str) or not output_path:
        raise SystemExit(f"Manifesto inválido, output_path ausente: {manifest_path}")

    rib_path = Path(output_path)
    return collector, rib_path


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return value


def _write_manifest(
    *,
    collector: str,
    rib_path: Path,
    rib_size_bytes: int,
    total_routes_counted: int,
    unique_prefixes: int | None,
    unique_peers: int | None,
    unique_origin_asns: int | None,
    first_record_sample: dict[str, Any] | None,
    last_record_sample: dict[str, Any] | None,
    started_at: datetime,
    finished_at: datetime,
    elapsed_seconds: float,
) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = finished_at.strftime("%Y%m%dT%H%M%SZ")
    manifest_name = f"routeviews_rib_count_{collector}_{rib_path.name}_{timestamp}.json"
    manifest_path = OUTPUT_DIR / manifest_name
    payload = {
        "collector": collector,
        "rib_path": str(rib_path),
        "rib_size_bytes": rib_size_bytes,
        "total_routes_counted": total_routes_counted,
        "unique_prefixes": unique_prefixes,
        "unique_peers": unique_peers,
        "unique_origin_asns": unique_origin_asns,
        "first_record_sample": _jsonable(first_record_sample),
        "last_record_sample": _jsonable(last_record_sample),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "counted_at": finished_at.isoformat(),
        "elapsed_seconds": round(elapsed_seconds, 6),
    }
    manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Count useful RouteViews RIB entries without inserting into PostgreSQL.")
    parser.add_argument("--rib-path", type=Path, default=None, help="Path to the RIB .bz2 file")
    parser.add_argument("--collector", default=DEFAULT_COLLECTOR)
    parser.add_argument("--progress-every", type=int, default=100000)
    parser.add_argument("--limit", type=int, default=None, help="Optional count limit for quick tests")
    parser.add_argument("--no-unique", action="store_true", help="Skip unique prefix/peer/origin tracking")
    args = parser.parse_args()

    console = Console()
    collector, rib_path = _resolve_rib_path(args)
    if not rib_path.exists():
        raise SystemExit(f"RIB não encontrado: {rib_path}")

    rib_size_bytes = rib_path.stat().st_size
    started_at = datetime.now(timezone.utc)
    start = time.perf_counter()

    total_routes_counted = 0
    unique_prefixes: set[str] | None = set() if not args.no_unique else None
    unique_peers: set[str] | None = set() if not args.no_unique else None
    unique_origin_asns: set[Any] | None = set() if not args.no_unique else None
    first_record_sample: dict[str, Any] | None = None
    last_record_sample: dict[str, Any] | None = None

    for route in parse_rib_records(rib_path, collector):
        total_routes_counted += 1
        if first_record_sample is None:
            first_record_sample = route
        last_record_sample = route

        if unique_prefixes is not None:
            prefix = route.get("prefix")
            if prefix:
                unique_prefixes.add(str(prefix))
            peer_ip = route.get("peer_ip")
            if peer_ip:
                unique_peers.add(str(peer_ip))
            origin_asn = route.get("origin_asn")
            if origin_asn is not None:
                unique_origin_asns.add(origin_asn)

        if args.progress_every > 0 and total_routes_counted % args.progress_every == 0:
            elapsed = time.perf_counter() - start
            console.print(
                f"[cyan]Progress[/cyan]: counted={total_routes_counted} elapsed={elapsed:.1f}s "
                f"prefixes={len(unique_prefixes) if unique_prefixes is not None else 'n/a'}"
            )

        if args.limit is not None and total_routes_counted >= args.limit:
            break

    elapsed_seconds = time.perf_counter() - start
    finished_at = datetime.now(timezone.utc)

    manifest_path = _write_manifest(
        collector=collector,
        rib_path=rib_path,
        rib_size_bytes=rib_size_bytes,
        total_routes_counted=total_routes_counted,
        unique_prefixes=len(unique_prefixes) if unique_prefixes is not None else None,
        unique_peers=len(unique_peers) if unique_peers is not None else None,
        unique_origin_asns=len(unique_origin_asns) if unique_origin_asns is not None else None,
        first_record_sample=first_record_sample,
        last_record_sample=last_record_sample,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_seconds=elapsed_seconds,
    )

    table = Table(title="RouteViews RIB count")
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("Collector", collector)
    table.add_row("RIB path", str(rib_path))
    table.add_row("RIB size bytes", str(rib_size_bytes))
    table.add_row("Total routes counted", str(total_routes_counted))
    table.add_row("Unique prefixes", str(len(unique_prefixes) if unique_prefixes is not None else "n/a"))
    table.add_row("Unique peers", str(len(unique_peers) if unique_peers is not None else "n/a"))
    table.add_row("Unique origin ASNs", str(len(unique_origin_asns) if unique_origin_asns is not None else "n/a"))
    table.add_row("Elapsed sec", f"{elapsed_seconds:.2f}")
    table.add_row("Counted at", finished_at.isoformat())
    table.add_row("Manifest", str(manifest_path))

    console.print(table)

    samples = Table(title="Route samples")
    samples.add_column("Tipo")
    samples.add_column("Valor", overflow="fold")
    samples.add_row("First", json.dumps(_jsonable(first_record_sample), ensure_ascii=False, default=str) if first_record_sample else "-")
    samples.add_row("Last", json.dumps(_jsonable(last_record_sample), ensure_ascii=False, default=str) if last_record_sample else "-")
    console.print(samples)
    console.print(Panel.fit(f"Manifest salvo em {manifest_path}", title="Count summary"))


if __name__ == "__main__":
    main()
