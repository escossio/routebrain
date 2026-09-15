from __future__ import annotations

import os
import sys
from argparse import ArgumentParser
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.bgp_current_builder import build_current_routes  # noqa: E402


def _resolve_limit(arg_limit: int | None) -> int | None:
    if arg_limit is not None:
        return arg_limit

    env_limit = os.getenv("ROUTEBRAIN_CURRENT_LIMIT")
    if env_limit:
        return int(env_limit)

    return None


def main() -> None:
    parser = ArgumentParser(description="Build bgp_current_routes from bgp_raw_routes.")
    parser.add_argument("--limit", type=int, default=None, help="Optional max number of raw routes to process.")
    args = parser.parse_args()

    console = Console()
    limit = _resolve_limit(args.limit)
    result = build_current_routes(limit=limit)

    table = Table(title="bgp_current_routes build")
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("Processed", str(result["processed"]))
    table.add_row("Count before", str(result["current_count_before"]))
    table.add_row("Count after", str(result["current_count_after"]))
    table.add_row("Limit", str(limit) if limit is not None else "None")

    console.print(table)
    console.print(Panel.fit("Current routes populated from bgp_raw_routes.", title="Build summary"))


if __name__ == "__main__":
    main()
