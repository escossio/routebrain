from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collectors.routeviews_metadata import (  # noqa: E402
    RouteViewsMetadataError,
    fetch_routeviews_metadata,
)


def main() -> None:
    console = Console()
    output_dir = PROJECT_ROOT / "data" / "processed"
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        metadata = fetch_routeviews_metadata()
    except RouteViewsMetadataError as exc:
        console.print(Panel.fit(str(exc), title="RouteViews metadata", style="red"))
        raise SystemExit(1) from exc

    collector = metadata["collector"]
    output_path = output_dir / f"routeviews_metadata_{collector}.json"
    output_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    table = Table(title="RouteViews metadata")
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("Collector", str(metadata.get("collector")))
    table.add_row("Project", str(metadata.get("project")))
    table.add_row("Base URL", str(metadata.get("baseURL")))
    table.add_row("RIB latestDumpTime", str(metadata["ribs"].get("latestDumpTime")))
    table.add_row("RIB latestDumpFile", str(metadata["ribs"].get("latestDumpFile")))
    table.add_row("UPDATE latestDumpTime", str(metadata["updates"].get("latestDumpTime")))
    table.add_row("UPDATE latestDumpFile", str(metadata["updates"].get("latestDumpFile")))

    console.print(table)
    console.print(f"JSON salvo em: {output_path}")


if __name__ == "__main__":
    main()
