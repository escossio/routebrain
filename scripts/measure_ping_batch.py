#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import get_connection  # noqa: E402
from app.services.active_ping import run_ping  # noqa: E402
from app.services.active_ping_targets import (  # noqa: E402
    get_matched_peers_for_ping,
    get_peers_missing_ping,
    get_top_observed_peers,
)
from app.services.pipeline_lock import try_advisory_lock  # noqa: E402

console = Console()
LOCK_NAME = "routebrain:active_ping_batch"


def _print_targets(rows: list[dict[str, object]], title: str) -> None:
    table = Table(title=title)
    for column in ["target", "target_label", "observed_routes", "match_status", "ixp_name"]:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row.get("target", "")),
            str(row.get("target_label", "")),
            str(row.get("observed_routes", "")),
            str(row.get("match_status", "")),
            str(row.get("ixp_name", "")),
        )
    console.print(table)


def _print_results(rows: list[dict[str, object]]) -> None:
    table = Table(title="Ping Batch Results")
    for column in [
        "target",
        "label",
        "status",
        "sent/received",
        "loss",
        "rtt_avg_ms",
        "measured_at",
        "error",
    ]:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row.get("target", "")),
            str(row.get("label", "")),
            str(row.get("status", "")),
            str(row.get("sent/received", "")),
            str(row.get("loss", "")),
            str(row.get("rtt_avg_ms", "")),
            str(row.get("measured_at", "")),
            str(row.get("error", "")),
        )
    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="measure_ping_batch", description="Executa ping em lote para peers BGP observados")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--missing-only", action="store_true")
    parser.add_argument("--matched-only", action="store_true")
    parser.add_argument("--unmatched-only", action="store_true")
    parser.add_argument("--sleep", type=float, default=0.2)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--source-label", default="routebrain-batch")
    parser.add_argument("--sleep-before-finish", type=float, default=0.0)
    return parser


def _select_targets(args: argparse.Namespace) -> list[dict[str, object]]:
    if args.matched_only and args.unmatched_only:
        raise SystemExit("Use apenas um dos filtros: --matched-only ou --unmatched-only.")

    if args.missing_only:
        return get_peers_missing_ping(limit=args.limit)
    if args.matched_only:
        return get_matched_peers_for_ping(limit=args.limit)
    if args.unmatched_only:
        return get_top_observed_peers(limit=args.limit, only_unmatched=True)
    return get_top_observed_peers(limit=args.limit)


def _run_batch(targets: list[dict[str, object]], args: argparse.Namespace) -> tuple[list[dict[str, object]], dict[str, object]]:
    started_at = time.monotonic()
    results: list[dict[str, object]] = []
    measured = 0
    success = 0
    failed = 0

    for index, target in enumerate(targets, start=1):
        try:
            result = run_ping(
                str(target.get("observed_peer_ip", "")).split("/")[0],
                count=args.count,
                timeout=args.timeout,
                target_label=str(target.get("target_label", "")) or None,
                source_label=args.source_label,
            )
            measured += 1
            status = str(result.get("status", "FAILED"))
            if status == "SUCCESS":
                success += 1
            else:
                failed += 1
            results.append(
                {
                    "target": result.get("target"),
                    "label": result.get("target_label"),
                    "status": status,
                    "sent/received": f"{result.get('packets_sent')}/{result.get('packets_received')}",
                    "loss": result.get("packet_loss_percent"),
                    "rtt_avg_ms": result.get("rtt_avg_ms"),
                    "measured_at": result.get("measured_at"),
                    "error": "",
                }
            )
        except Exception as exc:
            failed += 1
            measured += 1
            results.append(
                {
                    "target": target.get("observed_peer_ip"),
                    "label": target.get("target_label"),
                    "status": "FAILED",
                    "sent/received": "",
                    "loss": "",
                    "rtt_avg_ms": "",
                    "measured_at": "",
                    "error": str(exc),
                }
            )

        if index < len(targets):
            time.sleep(args.sleep)

    if args.sleep_before_finish > 0:
        time.sleep(args.sleep_before_finish)

    elapsed_seconds = round(time.monotonic() - started_at, 3)
    summary = {
        "targets_selected": len(targets),
        "measured": measured,
        "success": success,
        "failed": failed,
        "elapsed_seconds": elapsed_seconds,
    }
    return results, summary


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dry_run:
        targets = _select_targets(args)
        if not targets:
            console.print("Nenhum target encontrado.")
            return
        _print_targets(targets, "Selected Ping Targets")
        console.print(Panel.fit(f"Dry-run concluído. Alvos selecionados: {len(targets)}", title="Ping Batch"))
        return

    with get_connection() as conn:
        if not try_advisory_lock(conn, LOCK_NAME):
            console.print("Outra medição ativa em lote já está em execução. Saindo sem medir.")
            return

        targets = _select_targets(args)
        if not targets:
            console.print("Nenhum target encontrado.")
            return

        _print_targets(targets, "Selected Ping Targets")
        results, summary = _run_batch(targets, args)

    _print_results(results)
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"targets_selected: {summary['targets_selected']}",
                    f"measured: {summary['measured']}",
                    f"success: {summary['success']}",
                    f"failed: {summary['failed']}",
                    f"elapsed_seconds: {summary['elapsed_seconds']}",
                ]
            ),
            title="Ping Batch Summary",
        )
    )


if __name__ == "__main__":
    main()
