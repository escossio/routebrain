#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from decimal import Decimal
import sys
from typing import Any

os.environ.setdefault("PSYCOPG_IMPL", "python")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import get_connection
from app.services.embedding_provider import embedding_dim, embedding_model, is_available, provider_name
from app.services.semantic_memory import (
    learning_search,
    list_semantic_documents,
    rebuild_semantic_documents,
    semantic_search,
)

REPORT_DIR = PROJECT_ROOT / "data" / "processed" / "reports"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp() -> str:
    return _now().strftime("%Y%m%dT%H%M%SZ")


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    return value


def _query_pgvector_status() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  (select exists(select 1 from pg_available_extensions where name = 'vector')) as available,
                  (select exists(select 1 from pg_extension where extname = 'vector')) as installed;
                """
            )
            row = cur.fetchone() or (False, False)
            return {"available": bool(row[0]), "installed": bool(row[1])}


def _document_counts() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select object_type, count(*)::bigint as count
                from semantic_documents
                group by object_type
                order by object_type asc;
                """
            )
            by_object_type = {str(row[0]): int(row[1]) for row in cur.fetchall()}
            cur.execute(
                """
                select coalesce(embedding_status, 'text_only') as embedding_status, count(*)::bigint as count
                from semantic_documents
                group by coalesce(embedding_status, 'text_only')
                order by embedding_status asc;
                """
            )
            embedding_status_counts = {str(row[0]): int(row[1]) for row in cur.fetchall()}
            cur.execute("select count(*)::bigint from semantic_documents;")
            total_documents = int(cur.fetchone()[0])
    return {
        "total_documents": total_documents,
        "by_object_type": by_object_type,
        "embedding_status_counts": embedding_status_counts,
    }


def _scenario_search(label: str, query: str, *, limit: int = 5, object_type: str | None = None) -> dict[str, Any]:
    if label.startswith("learning:"):
        payload = learning_search(query, limit=limit)
    else:
        payload = semantic_search(query, limit=limit, object_type=object_type)
    return {
        "label": label,
        "query": query,
        "search_mode": payload.get("search_mode"),
        "results_count": payload.get("results_count"),
        "results": [
            {
                "document_uid": row.get("document_uid"),
                "object_type": row.get("object_type"),
                "object_ref": row.get("object_ref"),
                "title": row.get("title"),
                "score": row.get("score"),
                "confidence": row.get("confidence"),
                "reason": row.get("reason"),
                "snippet": row.get("snippet"),
            }
            for row in payload.get("results", [])[:limit]
        ],
    }


def _build_report(rebuild_result: dict[str, Any]) -> dict[str, Any]:
    counts = _document_counts()
    pgvector = _query_pgvector_status()
    scenarios = [
        _scenario_search("ptt-ce", "quais hosts pertencem ao PTT-CE"),
        _scenario_search("cloudflare", "o que aprendemos sobre cloudflare"),
        _scenario_search("baidu", "destinos com alta latência internacional"),
        _scenario_search("example-worker", "máquina que processou o BGP pesado"),
        _scenario_search("learning:high-latency", "alta latência internacional"),
    ]
    sample_documents = _safe_json(list_semantic_documents(limit=20))
    return {
        "generated_at": _now().isoformat(),
        "rebuild": _safe_json(rebuild_result),
        "pgvector": pgvector,
        "embedding_provider": {
            "provider": provider_name(),
            "model": embedding_model(),
            "dim": embedding_dim(),
            "available": is_available(),
        },
        "search_mode": "text_fallback",
        "document_counts": counts,
        "sample_documents": sample_documents,
        "scenarios": scenarios,
    }


def _render_text(report: dict[str, Any]) -> str:
    rebuild = report.get("rebuild") or {}
    counts = report.get("document_counts") or {}
    lines = [
        "RouteBrain Semantic Memory Report",
        f"generated_at: {report.get('generated_at')}",
        f"search_mode: {report.get('search_mode')}",
        f"embedding_provider: {json.dumps(report.get('embedding_provider'), ensure_ascii=False)}",
        f"pgvector: {json.dumps(report.get('pgvector'), ensure_ascii=False)}",
        "",
        "Rebuild summary:",
        f"  scope: {rebuild.get('scope')}",
        f"  dry_run: {rebuild.get('dry_run')}",
        f"  force: {rebuild.get('force')}",
        f"  total_documents: {rebuild.get('total_documents')}",
        f"  created: {rebuild.get('created')}",
        f"  updated: {rebuild.get('updated')}",
        f"  unchanged: {rebuild.get('unchanged')}",
        f"  status: {rebuild.get('status')}",
        "",
        "Document counts:",
        f"  total_documents: {counts.get('total_documents')}",
        f"  by_object_type: {json.dumps(counts.get('by_object_type'), ensure_ascii=False)}",
        f"  embedding_status_counts: {json.dumps(counts.get('embedding_status_counts'), ensure_ascii=False)}",
        "",
        "Scenarios:",
    ]
    for scenario in report.get("scenarios") or []:
        lines.append(f"  - {scenario.get('label')}: {scenario.get('query')} -> {scenario.get('results_count')} results")
        for result in scenario.get("results") or []:
            lines.append(
                "    * "
                f"{result.get('object_type')} {result.get('object_ref')} | "
                f"{result.get('title')} | confidence={result.get('confidence')} | score={result.get('score')}"
            )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reconstrói a Semantic Memory do RouteBrain.")
    parser.add_argument("--scope", default="all")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-existing", action="store_true", default=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--report",
        action="store_true",
        help="Mantido por compatibilidade; o relatório é gerado sempre.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rebuild_result = rebuild_semantic_documents(
        args.scope,
        limit=args.limit,
        dry_run=args.dry_run,
        skip_existing=args.skip_existing,
        force=args.force,
    )
    report = _build_report(rebuild_result)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = _timestamp()
    json_path = REPORT_DIR / f"routebrain_semantic_memory_{timestamp}.json"
    txt_path = REPORT_DIR / f"routebrain_semantic_memory_{timestamp}.txt"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    txt_path.write_text(_render_text(report) + "\n", encoding="utf-8")
    print(json.dumps({"json": str(json_path), "txt": str(txt_path), "scope": args.scope, "status": rebuild_result.get("status")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
