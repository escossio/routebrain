from __future__ import annotations

import json
from datetime import datetime, timezone
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.collectors.routeviews_update_downloader import (  # noqa: E402
    RouteViewsUpdateDownloadError,
    download_latest_update,
)


def main() -> None:
    console = Console()
    processed_dir = PROJECT_ROOT / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = download_latest_update()
    except RouteViewsUpdateDownloadError as exc:
        console.print(Panel.fit(str(exc), title="RouteViews UPDATE download", style="red"))
        raise SystemExit(1) from exc

    created_at = datetime.now(timezone.utc).isoformat()
    manifest = {
        **result,
        "created_at": created_at,
    }

    collector = result["collector"]
    manifest_path = processed_dir / f"routeviews_latest_update_{collector}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    table = Table(title="RouteViews latest UPDATE")
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("Collector", str(result["collector"]))
    table.add_row("URL", str(result["url"]))
    table.add_row("Filename", str(result["filename"]))
    table.add_row("Output", str(result["output_path"]))
    table.add_row("Downloaded", str(result["downloaded"]))
    table.add_row("Size bytes", str(result["size_bytes"]))
    table.add_row("Manifest", str(manifest_path))

    console.print(table)
    console.print(f"Manifesto salvo em: {manifest_path}")


if __name__ == "__main__":
    main()
