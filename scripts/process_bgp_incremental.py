from __future__ import annotations

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


def _count_rows(table_name: str) -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from {table_name};")
            return int(cur.fetchone()[0])


def main() -> None:
    parser = ArgumentParser(description="Process RouteBrain raw routes incrementally.")
    parser.add_argument("--from-id", type=int, default=None)
    parser.add_argument("--to-id", type=int, default=None)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    console = Console()
    result = process_raw_routes_incremental(from_id=args.from_id, to_id=args.to_id, limit=args.limit)

    table = Table(title="Incremental processing")
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("Processed", str(result["processed"]))
    table.add_row("Detected changes", str(result["detected_changes"]))
    table.add_row("Inserted changes", str(result["inserted_changes"]))
    table.add_row("Skipped duplicates", str(result["skipped_duplicates"]))
    table.add_row("Current upserts", str(result["current_upserts"]))
    table.add_row("Min id processed", str(result["min_id_processed"]))
    table.add_row("Max id processed", str(result["max_id_processed"]))
    table.add_row("bgp_route_changes total", str(_count_rows("bgp_route_changes")))
    table.add_row("bgp_current_routes total", str(_count_rows("bgp_current_routes")))

    console.print(table)
    console.print(Panel.fit("Incremental processing completed.", title="Incremental summary"))


if __name__ == "__main__":
    main()
