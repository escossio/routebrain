#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

os.environ.setdefault("PSYCOPG_IMPL", "python")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import get_connection
from app.services.embedding_provider import embedding_dim, embedding_model, is_available, provider_name
from app.services.semantic_memory import upsert_semantic_embedding
from psycopg.rows import dict_row

REPORT_DIR = PROJECT_ROOT / "data" / "processed" / "reports"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp() -> str:
    return _now().strftime("%Y%m%dT%H%M%SZ")


def _normalize_text(value: str | None) -> str:
    return " ".join(str(value or "").split()).strip()


def _build_document_text(title: str | None, content: str | None) -> str:
    normalized_title = _normalize_text(title)
    normalized_content = _normalize_text(content)
    if normalized_title and normalized_content:
        return f"{normalized_title}\n\n{normalized_content}"
    return normalized_title or normalized_content


def _load_model(model_name: str, device: str) -> Any:
    try:
        from FlagEmbedding import BGEM3FlagModel
    except Exception as exc:  # pragma: no cover - runtime dependency check
        raise RuntimeError(f"FlagEmbedding indisponível: {exc}") from exc
    try:
        return BGEM3FlagModel(model_name, device=device, use_fp16=(device != "cpu"))
    except Exception as exc:  # pragma: no cover - runtime dependency check
        raise RuntimeError(f"Falha ao carregar o modelo {model_name}: {exc}") from exc


def _encode_batch(model: Any, texts: list[str], batch_size: int, max_length: int) -> list[list[float]]:
    try:
        output = model.encode(
            texts,
            batch_size=batch_size,
            max_length=max_length,
            return_dense=True,
            normalize_embeddings=True,
        )
    except TypeError:
        output = model.encode(texts, batch_size=batch_size, max_length=max_length, return_dense=True)
    dense_vecs = output.get("dense_vecs") if isinstance(output, dict) else None
    if dense_vecs is None:
        raise RuntimeError("Modelo não retornou dense_vecs.")
    vectors: list[list[float]] = []
    for vector in dense_vecs:
        if hasattr(vector, "tolist"):
            vector = vector.tolist()
        vectors.append([float(value) for value in vector])
    return vectors


def _fetch_documents(
    *,
    model_name: str,
    provider_name_value: str,
    limit: int | None,
    skip_existing: bool,
    force: bool,
) -> list[dict[str, Any]]:
    params: list[Any] = [model_name, provider_name_value, force]
    where_bits = [
        "(%s::bool or coalesce(d.embedding_status, 'text_only') in ('text_only', 'pending'))",
    ]
    if skip_existing and not force:
        where_bits.append("coalesce(e.status, '') <> 'ok'")
    if limit is not None:
        limit_clause = "limit %s"
        params.append(limit)
    else:
        limit_clause = ""
    sql = f"""
        select
          d.id,
          d.document_uid,
          d.object_type,
          d.object_ref,
          d.title,
          d.content,
          d.embedding_status,
          d.embedding_model,
          d.embedding_error,
          e.status as existing_status,
          e.error as existing_error
        from semantic_documents d
        left join semantic_embeddings e
          on e.document_id = d.id
         and e.embedding_model = %s::text
         and e.provider = %s::text
        where {' and '.join(where_bits)}
        order by d.updated_at asc, d.id asc
        {limit_clause};
    """
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
    return [dict(row) for row in rows]


def _vector_summary(vectors: list[list[float]]) -> dict[str, Any]:
    if not vectors:
        return {}
    dims = [len(vector) for vector in vectors]
    return {
        "count": len(vectors),
        "dim_min": min(dims),
        "dim_max": max(dims),
    }


def _write_reports(report: dict[str, Any], timestamp: str) -> dict[str, str]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORT_DIR / f"routebrain_semantic_embeddings_{timestamp}.json"
    txt_path = REPORT_DIR / f"routebrain_semantic_embeddings_{timestamp}.txt"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "RouteBrain Semantic Embeddings Report",
        f"generated_at: {report.get('generated_at')}",
        f"status: {report.get('status')}",
        f"provider: {json.dumps(report.get('provider'), ensure_ascii=False)}",
        f"runtime: {json.dumps(report.get('runtime'), ensure_ascii=False)}",
        f"documents: {json.dumps(report.get('documents'), ensure_ascii=False)}",
        f"results: {json.dumps(report.get('results'), ensure_ascii=False)}",
        f"failures: {json.dumps(report.get('failures'), ensure_ascii=False)}",
    ]
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"json": str(json_path), "txt": str(txt_path)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gera embeddings semânticos no RouteBrain.")
    parser.add_argument("--model", default="BAAI/bge-m3")
    parser.add_argument("--provider", default="bge_m3_flagembedding")
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--device", default=os.getenv("ROUTEBRAIN_EMBEDDING_DEVICE", "cpu"))
    parser.add_argument("--max-length", type=int, default=512)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started_at = _now()
    runtime_started = monotonic()
    if args.provider != "bge_m3_flagembedding":
        raise SystemExit("provider precisa ser bge_m3_flagembedding.")
    if args.model != "BAAI/bge-m3":
        raise SystemExit("model precisa ser BAAI/bge-m3.")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  exists(select 1 from pg_extension where extname = 'vector') as extension_installed,
                  exists(
                      select 1
                      from information_schema.columns
                      where table_schema = 'public'
                        and table_name = 'semantic_embeddings'
                        and column_name = 'embedding'
                  ) as embedding_column_present;
                """
            )
            vector_ready = cur.fetchone() or (False, False)
    if not bool(vector_ready[0]) or not bool(vector_ready[1]):
        raise SystemExit("pgvector não está disponível no banco RouteBrain; mantendo text_fallback.")

    model = _load_model(args.model, args.device)
    documents = _fetch_documents(
        model_name=args.model,
        provider_name_value=args.provider,
        limit=args.limit,
        skip_existing=bool(args.skip_existing),
        force=bool(args.force),
    )

    processed = 0
    embedded = 0
    skipped = 0
    failed = 0
    batches = 0
    failures: list[dict[str, Any]] = []
    results_counter: Counter[str] = Counter()
    observed_vector_dim: int | None = None

    if args.dry_run:
        skipped = len(documents)
    else:
        with get_connection() as conn:
            batch: list[dict[str, Any]] = []
            for document in documents:
                batch.append(document)
                if len(batch) < max(1, args.batch_size):
                    continue
                batches += 1
                texts = [_build_document_text(item.get("title"), item.get("content")) for item in batch]
                vectors = _encode_batch(model, texts, max(1, args.batch_size), max(1, args.max_length))
                for item, vector in zip(batch, vectors, strict=False):
                    if observed_vector_dim is None:
                        observed_vector_dim = len(vector)
                    processed += 1
                    try:
                        with conn.transaction():
                            upsert_semantic_embedding(
                                item["document_uid"],
                                vector,
                                embedding_model_name=args.model,
                                embedding_provider_name=args.provider,
                                embedding_dim_value=len(vector),
                                status="ok",
                                error=None,
                                conn=conn,
                            )
                        embedded += 1
                        results_counter["embedded"] += 1
                    except Exception as exc:
                        failed += 1
                        results_counter["failed"] += 1
                        failures.append(
                            {
                                "document_uid": item.get("document_uid"),
                                "object_type": item.get("object_type"),
                                "object_ref": item.get("object_ref"),
                                "title": item.get("title"),
                                "error": str(exc),
                            }
                        )
                        with conn.transaction():
                            try:
                                upsert_semantic_embedding(
                                    item["document_uid"],
                                    vector,
                                    embedding_model_name=args.model,
                                    embedding_provider_name=args.provider,
                                    embedding_dim_value=len(vector),
                                    status="failed",
                                    error=str(exc),
                                    conn=conn,
                                )
                            except Exception:
                                pass
                batch = []

            if batch:
                batches += 1
                texts = [_build_document_text(item.get("title"), item.get("content")) for item in batch]
                vectors = _encode_batch(model, texts, max(1, args.batch_size), max(1, args.max_length))
                for item, vector in zip(batch, vectors, strict=False):
                    if observed_vector_dim is None:
                        observed_vector_dim = len(vector)
                    processed += 1
                    try:
                        with conn.transaction():
                            upsert_semantic_embedding(
                                item["document_uid"],
                                vector,
                                embedding_model_name=args.model,
                                embedding_provider_name=args.provider,
                                embedding_dim_value=len(vector),
                                status="ok",
                                error=None,
                                conn=conn,
                            )
                        embedded += 1
                        results_counter["embedded"] += 1
                    except Exception as exc:
                        failed += 1
                        results_counter["failed"] += 1
                        failures.append(
                            {
                                "document_uid": item.get("document_uid"),
                                "object_type": item.get("object_type"),
                                "object_ref": item.get("object_ref"),
                                "title": item.get("title"),
                                "error": str(exc),
                            }
                        )
                        with conn.transaction():
                            try:
                                upsert_semantic_embedding(
                                    item["document_uid"],
                                    vector,
                                    embedding_model_name=args.model,
                                    embedding_provider_name=args.provider,
                                    embedding_dim_value=len(vector),
                                    status="failed",
                                    error=str(exc),
                                    conn=conn,
                                )
                            except Exception:
                                pass

    runtime_seconds = monotonic() - runtime_started
    report = {
        "generated_at": started_at.isoformat(),
        "status": "ok" if failed == 0 else "partial",
        "provider": {
            "provider": args.provider,
            "model": args.model,
            "dim": embedding_dim(),
            "available": is_available(),
        },
        "runtime": {
            "python": sys.version.split()[0],
            "executable": sys.executable,
            "device": args.device,
            "batch_size": args.batch_size,
            "max_length": args.max_length,
            "seconds": round(runtime_seconds, 3),
        },
        "documents": {
            "selected": len(documents),
            "processed": processed,
            "embedded": embedded,
            "skipped": skipped,
            "failed": failed,
        },
        "results": dict(results_counter),
        "failures": failures[:50],
        "sample_documents": [
            {
                "document_uid": item.get("document_uid"),
                "object_type": item.get("object_type"),
                "object_ref": item.get("object_ref"),
                "title": item.get("title"),
            }
            for item in documents[:10]
        ],
        "model_vector_summary": {
            "observed_dim": observed_vector_dim,
            "expected_dim": embedding_dim(),
        },
    }
    timestamp = _timestamp()
    paths = _write_reports(report, timestamp)
    freeze_path = REPORT_DIR / f"routebrain_embedding_runtime_freeze_{timestamp}.txt"
    if args.dry_run:
        freeze_path.write_text("", encoding="utf-8")
    else:
        from subprocess import run

        freeze_result = run(
            [sys.executable, "-m", "pip", "freeze"],
            check=False,
            capture_output=True,
            text=True,
        )
        freeze_path.write_text(freeze_result.stdout, encoding="utf-8")

    print(
        json.dumps(
            {
                "status": report["status"],
                "documents": report["documents"],
                "reports": paths,
                "freeze": str(freeze_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
