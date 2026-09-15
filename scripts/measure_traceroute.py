#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.active_traceroute import run_and_store_traceroute  # noqa: E402

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="measure_traceroute", description="Executa traceroute e salva medição no PostgreSQL")
    parser.add_argument("target", help="Destino IP")
    parser.add_argument("--mode", choices=["icmp", "udp"], default="icmp")
    parser.add_argument("--max-hops", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--probes", type=int, default=3)
    parser.add_argument("--label")
    parser.add_argument("--source-label", default="local")
    return parser


def _print_hops(rows: list[dict[str, object]]) -> None:
    table = Table(title="Traceroute Hops")
    for column in ["hop", "ip", "responded", "rtt_avg_ms", "raw_line"]:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row.get("hop_number", "")),
            str(row.get("hop_ip", "")),
            str(row.get("responded", "")),
            str(row.get("rtt_avg_ms", "")),
            str(row.get("raw_line", "")),
        )
    console.print(table)


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    result = run_and_store_traceroute(
        args.target,
        mode=args.mode,
        max_hops=args.max_hops,
        timeout=args.timeout,
        probes=args.probes,
        target_label=args.label,
        source_label=args.source_label,
    )

    console.print(f"measurement_id: {result.get('measurement_id')}")
    console.print(f"target: {result.get('target')}")
    console.print(f"status: {result.get('status')}")
    console.print(f"hop_count: {result.get('hop_count')}")
    console.print(f"responded_hop_count: {result.get('responded_hop_count')}")
    console.print(f"measured_at: {result.get('measured_at')}")
    _print_hops(result.get("hops", []))


if __name__ == "__main__":
    main()
