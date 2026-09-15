from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import get_connection  # noqa: E402

REPORT_DIR = PROJECT_ROOT / "data" / "processed" / "reports"


@dataclass(frozen=True)
class SummarySpec:
    key: str
    table_name: str
    columns: list[str]
    source_sql: str
    sample_order_by: str
    sample_columns: list[str]


SUMMARY_SPECS = {
    "current-by-peer": SummarySpec(
        key="current-by-peer",
        table_name="bgp_summary_current_by_peer",
        columns=[
            "peer_ip",
            "peer_asn",
            "route_count",
            "prefix_count",
            "origin_asn_count",
            "collector_count",
        ],
        source_sql="""
            select
              peer_ip,
              max(peer_asn) as peer_asn,
              count(*)::bigint as route_count,
              count(distinct prefix)::bigint as prefix_count,
              count(distinct origin_asn)::bigint as origin_asn_count,
              count(distinct collector)::bigint as collector_count
            from bgp_current_routes
            group by peer_ip
        """,
        sample_order_by="route_count desc, peer_ip asc",
        sample_columns=[
            "peer_ip",
            "peer_asn",
            "route_count",
            "prefix_count",
            "origin_asn_count",
            "collector_count",
            "updated_at",
        ],
    ),
    "current-by-origin-asn": SummarySpec(
        key="current-by-origin-asn",
        table_name="bgp_summary_current_by_origin_asn",
        columns=[
            "origin_asn",
            "route_count",
            "prefix_count",
            "peer_count",
            "collector_count",
        ],
        source_sql="""
            select
              origin_asn,
              count(*)::bigint as route_count,
              count(distinct prefix)::bigint as prefix_count,
              count(distinct peer_ip)::bigint as peer_count,
              count(distinct collector)::bigint as collector_count
            from bgp_current_routes
            group by origin_asn
        """,
        sample_order_by="route_count desc, origin_asn asc",
        sample_columns=[
            "origin_asn",
            "route_count",
            "prefix_count",
            "peer_count",
            "collector_count",
            "updated_at",
        ],
    ),
    "changes-by-prefix": SummarySpec(
        key="changes-by-prefix",
        table_name="bgp_summary_changes_by_prefix",
        columns=[
            "prefix",
            "total_changes",
            "new_route_count",
            "as_path_changed_count",
            "origin_type_changed_count",
            "first_change_at",
            "last_change_at",
        ],
        source_sql="""
            select
              prefix,
              count(*)::bigint as total_changes,
              count(*) filter (where change_type = 'NEW_ROUTE')::bigint as new_route_count,
              count(*) filter (where change_type = 'AS_PATH_CHANGED')::bigint as as_path_changed_count,
              count(*) filter (where change_type = 'ORIGIN_TYPE_CHANGED')::bigint as origin_type_changed_count,
              min(detected_at) as first_change_at,
              max(detected_at) as last_change_at
            from bgp_route_changes
            where prefix is not null
            group by prefix
        """,
        sample_order_by="total_changes desc, last_change_at desc nulls last, prefix asc",
        sample_columns=[
            "prefix",
            "total_changes",
            "new_route_count",
            "as_path_changed_count",
            "origin_type_changed_count",
            "first_change_at",
            "last_change_at",
            "updated_at",
        ],
    ),
    "changes-by-origin-asn": SummarySpec(
        key="changes-by-origin-asn",
        table_name="bgp_summary_changes_by_origin_asn",
        columns=[
            "origin_asn",
            "total_changes",
            "new_route_count",
            "as_path_changed_count",
            "origin_type_changed_count",
        ],
        source_sql="""
            select
              coalesce(new_origin_asn, old_origin_asn) as origin_asn,
              count(*)::bigint as total_changes,
              count(*) filter (where change_type = 'NEW_ROUTE')::bigint as new_route_count,
              count(*) filter (where change_type = 'AS_PATH_CHANGED')::bigint as as_path_changed_count,
              count(*) filter (where change_type = 'ORIGIN_TYPE_CHANGED')::bigint as origin_type_changed_count
            from bgp_route_changes
            where coalesce(new_origin_asn, old_origin_asn) is not null
            group by coalesce(new_origin_asn, old_origin_asn)
        """,
        sample_order_by="total_changes desc, origin_asn asc",
        sample_columns=[
            "origin_asn",
            "total_changes",
            "new_route_count",
            "as_path_changed_count",
            "origin_type_changed_count",
            "updated_at",
        ],
    ),
    "changes-by-peer": SummarySpec(
        key="changes-by-peer",
        table_name="bgp_summary_changes_by_peer",
        columns=[
            "peer_ip",
            "peer_asn",
            "total_changes",
            "new_route_count",
            "as_path_changed_count",
            "origin_type_changed_count",
        ],
        source_sql="""
            select
              peer_ip,
              peer_asn,
              count(*)::bigint as total_changes,
              count(*) filter (where change_type = 'NEW_ROUTE')::bigint as new_route_count,
              count(*) filter (where change_type = 'AS_PATH_CHANGED')::bigint as as_path_changed_count,
              count(*) filter (where change_type = 'ORIGIN_TYPE_CHANGED')::bigint as origin_type_changed_count
            from bgp_route_changes
            group by peer_ip, peer_asn
        """,
        sample_order_by="total_changes desc, peer_ip asc, peer_asn asc",
        sample_columns=[
            "peer_ip",
            "peer_asn",
            "total_changes",
            "new_route_count",
            "as_path_changed_count",
            "origin_type_changed_count",
            "updated_at",
        ],
    ),
}


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _selected_specs(args: argparse.Namespace) -> list[SummarySpec]:
    if args.all or not args.only:
        return list(SUMMARY_SPECS.values())
    return [SUMMARY_SPECS[name] for name in args.only]


def _ensure_report_dir() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _query_rows(conn, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        columns = [desc.name for desc in cur.description]
        return [dict(zip(columns, row, strict=False)) for row in cur.fetchall()]


def _query_one(conn, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        columns = [desc.name for desc in cur.description]
        return dict(zip(columns, row, strict=False))


def _refresh_one(conn, spec: SummarySpec, dry_run: bool) -> dict[str, Any]:
    started_at = time.perf_counter()
    if dry_run:
        row_count_row = _query_one(conn, f"select count(*)::bigint as row_count from ({spec.source_sql}) as summary;")
        row_count = int(row_count_row["row_count"]) if row_count_row else 0
        sample_rows = _query_rows(
            conn,
            f"select * from ({spec.source_sql}) as summary order by {spec.sample_order_by} limit 10;",
        )
        elapsed = time.perf_counter() - started_at
        return {
            "key": spec.key,
            "table_name": spec.table_name,
            "dry_run": True,
            "row_count": row_count,
            "elapsed_seconds": round(elapsed, 6),
            "sample_rows": sample_rows,
            "status": "dry_run",
        }

    with conn.transaction():
        with conn.cursor() as cur:
            temp_table = f"tmp_{spec.table_name}"
            cur.execute(f"create temp table {temp_table} (like {spec.table_name} including defaults including constraints) on commit drop;")
            cur.execute(
                f"insert into {temp_table} ({', '.join(spec.columns)}) {spec.source_sql};"
            )
            cur.execute(f"select count(*)::bigint as row_count from {temp_table};")
            row_count = int(cur.fetchone()[0])
            cur.execute(f"truncate table {spec.table_name};")
            cur.execute(
                f"insert into {spec.table_name} ({', '.join(spec.columns)}) select {', '.join(spec.columns)} from {temp_table};"
            )

    sample_rows = _query_rows(
        conn,
        f"select {', '.join(spec.sample_columns)} from {spec.table_name} order by {spec.sample_order_by} limit 10;",
    )
    elapsed = time.perf_counter() - started_at
    return {
        "key": spec.key,
        "table_name": spec.table_name,
        "dry_run": False,
        "row_count": row_count,
        "elapsed_seconds": round(elapsed, 6),
        "sample_rows": sample_rows,
        "status": "refreshed",
    }


def _render_report(results: list[dict[str, Any]], dry_run: bool, total_elapsed: float) -> str:
    console = Console(record=True, width=140)
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"dry_run: {dry_run}",
                    f"total_elapsed_seconds: {round(total_elapsed, 6)}",
                    f"summaries: {len(results)}",
                ]
            ),
            title="BGP Operational Summaries Refresh",
        )
    )
    for result in results:
        table = Table(title=f"{result['key']} ({result['table_name']})")
        table.add_column("metric", style="bold")
        table.add_column("value", overflow="fold")
        table.add_row("status", str(result["status"]))
        table.add_row("row_count", str(result["row_count"]))
        table.add_row("elapsed_seconds", str(result["elapsed_seconds"]))
        table.add_row("dry_run", str(result["dry_run"]))
        console.print(table)
        sample_rows = result.get("sample_rows") or []
        if sample_rows:
            sample_table = Table(title=f"Top 10 - {result['key']}")
            for column in sample_rows[0].keys():
                sample_table.add_column(column, overflow="fold")
            for row in sample_rows:
                sample_table.add_row(*[str(row.get(column, "")) for column in sample_rows[0].keys()])
            console.print(sample_table)
    console.print(Panel.fit(f"total_elapsed_seconds: {round(total_elapsed, 6)}", title="Refresh Total"))
    return console.export_text()


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh summaries operacionais BGP")
    parser.add_argument(
        "--only",
        action="append",
        choices=sorted(SUMMARY_SPECS.keys()),
        help="Executa apenas uma summary. Pode ser repetido.",
    )
    parser.add_argument("--all", action="store_true", help="Executa todas as summaries")
    parser.add_argument("--dry-run", action="store_true", help="Não altera as tabelas de summary")
    args = parser.parse_args()

    selected = _selected_specs(args)
    _ensure_report_dir()
    timestamp = _timestamp_slug()
    report_json = REPORT_DIR / f"routebrain_summary_refresh_{timestamp}.json"
    report_txt = REPORT_DIR / f"routebrain_summary_refresh_{timestamp}.txt"

    started_at = time.perf_counter()
    results: list[dict[str, Any]] = []

    with get_connection() as conn:
        for spec in selected:
            results.append(_refresh_one(conn, spec, args.dry_run))

    total_elapsed = time.perf_counter() - started_at
    payload = {
        "timestamp": timestamp,
        "dry_run": args.dry_run,
        "selected": [spec.key for spec in selected],
        "total_elapsed_seconds": round(total_elapsed, 6),
        "results": results,
    }
    _write_json(report_json, payload)
    _write_text(report_txt, _render_report(results, args.dry_run, total_elapsed))

    print(f"report_json={report_json}")
    print(f"report_text={report_txt}")


if __name__ == "__main__":
    main()
