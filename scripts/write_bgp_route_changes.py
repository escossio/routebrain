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
from app.services.bgp_change_writer import write_detected_changes  # noqa: E402


def _count_changes() -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select count(*) from bgp_route_changes;")
            return int(cur.fetchone()[0])


def main() -> None:
    parser = ArgumentParser(description="Persist detected BGP route changes.")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args()

    console = Console()
    result = write_detected_changes(limit=args.limit, offset=args.offset)
    total = _count_changes()

    table = Table(title="bgp_route_changes write")
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("Detected", str(result["detected"]))
    table.add_row("Inserted", str(result["inserted"]))
    table.add_row("Skipped duplicates", str(result["skipped_duplicates"]))
    table.add_row("Total route_changes", str(total))
    table.add_row("Limit", str(args.limit))
    table.add_row("Offset", str(args.offset))

    console.print(table)
    console.print(Panel.fit("Detected changes persisted with duplicate protection.", title="Write summary"))


if __name__ == "__main__":
    main()
