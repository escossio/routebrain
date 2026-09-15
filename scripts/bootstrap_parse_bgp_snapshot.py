from __future__ import annotations

import argparse
from collections import defaultdict
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.parsers.routeviews_mrt_parser import parse_rib_records

from scripts.bootstrap_worker_utils import (
    DEFAULT_BOOTSTRAP_BATCH_SIZE,
    DEFAULT_MAX_WORKERS,
    DEFAULT_WORKER_ROOT,
    ensure_project_manifest_layout,
    ensure_worker_layout,
    json_write,
    normalize_output_format,
    timestamp_slug,
    utc_now,
    write_csv,
    write_jsonl,
    try_import_pyarrow,
)


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    collected_at = normalized.get("collected_at")
    if hasattr(collected_at, "isoformat"):
        normalized["collected_at"] = collected_at.isoformat()
    return normalized


def _dedupe_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return (
        record.get("collector"),
        record.get("peer_ip"),
        record.get("prefix"),
        record.get("as_path"),
        record.get("next_hop"),
        record.get("origin_asn"),
        record.get("origin_type"),
    )


def _write_output(output_path: Path, output_format: str, rows: list[dict[str, Any]]) -> None:
    if output_format == "csv":
        write_csv(output_path, rows)
        return
    if output_format == "jsonl":
        write_jsonl(output_path, rows)
        return
    if output_format == "parquet":
        pyarrow_bundle = try_import_pyarrow()
        if pyarrow_bundle is None:
            raise SystemExit("pyarrow não está disponível para gerar parquet.")
        pa = pyarrow_bundle["pa"]
        pq = pyarrow_bundle["parquet"]
        table = pa.Table.from_pylist(rows)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(table, output_path)
        return
    raise SystemExit(f"Formato não suportado: {output_format}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parseia um snapshot BGP/MRT local em arquivo normalizado para bootstrap offline."
    )
    parser.add_argument("--input", required=True, type=Path, help="Arquivo MRT/RIB local.")
    parser.add_argument("--output", required=True, type=Path, help="Arquivo normalizado de saída.")
    parser.add_argument("--collector", default=None, help="Nome do collector RouteViews/RIPE.")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Mantido para compatibilidade.")
    parser.add_argument("--limit", type=int, default=DEFAULT_BOOTSTRAP_BATCH_SIZE, help="Limite de registros parseados.")
    parser.add_argument("--start-record", type=int, default=0, help="Offset lógico para parsing parcial.")
    parser.add_argument("--format", default="csv", help="csv, jsonl ou parquet.")
    parser.add_argument("--manifest", type=Path, default=None, help="Arquivo JSON de manifesto opcional.")
    args = parser.parse_args()

    worker_root = DEFAULT_WORKER_ROOT
    ensure_worker_layout(worker_root)
    ensure_project_manifest_layout()
    output_format = normalize_output_format(args.format)
    collector = args.collector or "route-views2"

    parsed_rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    duplicate_rows = 0
    total_seen = 0

    for record in parse_rib_records(args.input, collector, start_record=args.start_record, limit=args.limit):
        total_seen += 1
        normalized = _normalize_record(record)
        key = _dedupe_key(normalized)
        if key in seen:
            duplicate_rows += 1
            continue
        seen.add(key)
        parsed_rows.append(normalized)

    _write_output(args.output, output_format, parsed_rows)

    manifest = {
        "timestamp": utc_now().isoformat(),
        "input": str(args.input),
        "output": str(args.output),
        "collector": collector,
        "format": output_format,
        "workers": args.workers,
        "limit": args.limit,
        "start_record": args.start_record,
        "parsed_rows": total_seen,
        "emitted_rows": len(parsed_rows),
        "duplicate_rows": duplicate_rows,
        "distinct_peers": len({row.get("peer_ip") for row in parsed_rows if row.get("peer_ip")}),
        "distinct_prefixes": len({row.get("prefix") for row in parsed_rows if row.get("prefix")}),
        "distinct_origin_asns": len({row.get("origin_asn") for row in parsed_rows if row.get("origin_asn") is not None}),
        "worker_root": str(worker_root),
        "status": "DRY_RUN_READY",
    }

    if args.manifest is not None:
        json_write(args.manifest, manifest)
    else:
        default_manifest = ensure_project_manifest_layout() / f"bootstrap_parse_{timestamp_slug()}.json"
        json_write(default_manifest, manifest)

    print(f"input={args.input}")
    print(f"output={args.output}")
    print(f"format={output_format}")
    print(f"parsed_rows={total_seen}")
    print(f"emitted_rows={len(parsed_rows)}")
    print(f"duplicate_rows={duplicate_rows}")


if __name__ == "__main__":
    main()
