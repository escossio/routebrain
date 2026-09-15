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

from app.db.connection import get_connection  # noqa: E402


def _count_raw_routes() -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select count(*) from bgp_raw_routes;")
            return int(cur.fetchone()[0])


def _max_raw_id() -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select coalesce(max(id), 0) from bgp_raw_routes;")
            return int(cur.fetchone()[0])


def _load_manifests() -> list[tuple[Path, dict[str, object]]]:
    ingest_dir = PROJECT_ROOT / "data" / "processed" / "ingest_runs"
    if not ingest_dir.exists():
        return []
    manifests: list[tuple[Path, dict[str, object]]] = []
    for path in sorted(ingest_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict):
            manifests.append((path, payload))
    return manifests


def main() -> None:
    console = Console()
    raw_count = _count_raw_routes()
    max_id = _max_raw_id()
    manifests = _load_manifests()

    table = Table(title="RouteViews ingest plan")
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    table.add_row("bgp_raw_routes total", str(raw_count))
    table.add_row("max(id)", str(max_id))
    table.add_row("manifests encontrados", str(len(manifests)))

    console.print(table)

    if manifests:
        recent = Table(title="Last 5 ingest manifests")
        recent.add_column("Arquivo", overflow="fold")
        recent.add_column("Collector")
        recent.add_column("Start")
        recent.add_column("Limit")
        recent.add_column("Inserted")
        recent.add_column("Count after")
        next_start = 0
        for path, payload in manifests[:5]:
            start_record = int(payload.get("start_record", 0) or 0)
            limit = int(payload.get("limit", 0) or 0)
            inserted = int(payload.get("inserted", 0) or 0)
            count_after = int(payload.get("count_after", 0) or 0)
            next_start = max(next_start, start_record + limit)
            recent.add_row(
                path.name,
                str(payload.get("collector", "")),
                str(start_record),
                str(limit),
                str(inserted),
                str(count_after),
            )
        console.print(recent)
    else:
        next_start = 0
        console.print(Panel.fit("Nenhum manifesto de ingestão encontrado. Próximo start-record sugerido: 0", title="Plan"))

    suggested_command = (
        ". .venv/bin/activate && "
        f"python3 scripts/ingest_routeviews_rib_sample.py --limit 500 --start-record {next_start}"
    )
    console.print(Panel.fit(suggested_command, title="Suggested command"))


if __name__ == "__main__":
    main()
