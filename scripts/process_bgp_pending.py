from __future__ import annotations

import time
import sys
from argparse import ArgumentParser
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import get_connection  # noqa: E402
from app.services.bgp_incremental_processor import process_raw_routes_incremental  # noqa: E402
from app.services.bgp_pipeline_state import (  # noqa: E402
    ensure_pipeline_state,
    get_pipeline_state,
    update_pipeline_state,
)
from app.services.pipeline_lock import try_advisory_lock  # noqa: E402

PIPELINE_NAME = "routeviews_raw_to_current"
LOCK_NAME = "routebrain:routeviews_raw_to_current"


def _count_rows(table_name: str) -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from {table_name};")
            return int(cur.fetchone()[0])


def _max_raw_id() -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select coalesce(max(id), 0) from bgp_raw_routes;")
            return int(cur.fetchone()[0])


def main() -> None:
    parser = ArgumentParser(description="Process pending RouteViews raw routes.")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--sleep-before-finish", type=int, default=0)
    args = parser.parse_args()

    console = Console()
    with get_connection() as lock_conn:
        if not try_advisory_lock(lock_conn, LOCK_NAME):
            console.print(
                Panel.fit(
                    "Outro processamento do pipeline já está em execução. Saindo sem processar.",
                    title="Pending processor",
                )
            )
            return

        state = ensure_pipeline_state(PIPELINE_NAME)
        last_raw_route_id = int(state["last_raw_route_id"])
        max_raw_route_id = _max_raw_id()
        pending_count = max(0, max_raw_route_id - last_raw_route_id)

        if max_raw_route_id <= last_raw_route_id:
            console.print(
                Panel.fit(
                    f"Pipeline {PIPELINE_NAME}: não há registros pendentes. last_raw_route_id={last_raw_route_id}, max_raw_route_id={max_raw_route_id}",
                    title="Pending processor",
                )
            )
            if args.sleep_before_finish > 0:
                time.sleep(args.sleep_before_finish)
            return

        result = process_raw_routes_incremental(
            from_id=last_raw_route_id + 1,
            to_id=max_raw_route_id,
            limit=args.limit,
        )

        if result["processed"] > 0 and result["max_id_processed"] is not None:
            update_pipeline_state(PIPELINE_NAME, int(result["max_id_processed"]))
            new_state = get_pipeline_state(PIPELINE_NAME)
            new_last_raw_route_id = int(new_state["last_raw_route_id"]) if new_state else last_raw_route_id
        else:
            new_last_raw_route_id = last_raw_route_id

        table = Table(title="Pending processor")
        table.add_column("Campo", style="cyan", no_wrap=True)
        table.add_column("Valor", style="white")
        table.add_row("Pipeline", PIPELINE_NAME)
        table.add_row("last_raw_route_id anterior", str(last_raw_route_id))
        table.add_row("max_raw_route_id atual", str(max_raw_route_id))
        table.add_row("pending_count aprox.", str(pending_count))
        table.add_row("processed", str(result["processed"]))
        table.add_row("detected_changes", str(result["detected_changes"]))
        table.add_row("inserted_changes", str(result["inserted_changes"]))
        table.add_row("skipped_duplicates", str(result["skipped_duplicates"]))
        table.add_row("current_upserts", str(result["current_upserts"]))
        table.add_row("min_id_processed", str(result["min_id_processed"]))
        table.add_row("max_id_processed", str(result["max_id_processed"]))
        table.add_row("novo last_raw_route_id salvo", str(new_last_raw_route_id))
        table.add_row("bgp_raw_routes total", str(_count_rows("bgp_raw_routes")))
        table.add_row("bgp_current_routes total", str(_count_rows("bgp_current_routes")))
        table.add_row("bgp_route_changes total", str(_count_rows("bgp_route_changes")))

        console.print(table)
        if args.sleep_before_finish > 0:
            time.sleep(args.sleep_before_finish)


if __name__ == "__main__":
    main()
