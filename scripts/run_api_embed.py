#!/usr/bin/env python3

from __future__ import annotations

import os
import sys
from pathlib import Path

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            os.environ.setdefault(key, value)


def _configure_embedding_runtime() -> None:
    os.environ.setdefault("ROUTEBRAIN_EMBEDDING_PROVIDER", "bge_m3_flagembedding")
    os.environ.setdefault("ROUTEBRAIN_EMBEDDING_MODEL", "BAAI/bge-m3")
    os.environ.setdefault("ROUTEBRAIN_EMBEDDING_DIM", "1024")
    os.environ.setdefault("ROUTEBRAIN_EMBEDDING_DEVICE", "cpu")


def _api_host() -> str:
    return os.getenv("ROUTEBRAIN_API_HOST", "127.0.0.1").strip() or "127.0.0.1"


def _api_port() -> int:
    raw_port = os.getenv("ROUTEBRAIN_API_PORT", "8000").strip()
    try:
        port = int(raw_port)
    except ValueError:
        raise SystemExit(f"Invalid ROUTEBRAIN_API_PORT={raw_port!r}") from None
    if not 1 <= port <= 65535:
        raise SystemExit(f"Invalid ROUTEBRAIN_API_PORT={raw_port!r}")
    return port


def _warmup_embedding_runtime() -> None:
    provider = os.getenv("ROUTEBRAIN_EMBEDDING_PROVIDER", "none").strip().lower()
    if provider in {"", "none", "text_fallback"}:
        print("RouteBrain embedding warmup skipped: provider=none", flush=True)
        return
    try:
        from app.services.embedding_provider import warmup_embedding_provider
    except Exception as exc:
        print(f"RouteBrain embedding warmup unavailable: {exc}", flush=True)
        return
    result = warmup_embedding_provider()
    print(
        "RouteBrain embedding warmup "
        f"status={result.get('status')} "
        f"provider={result.get('provider')} "
        f"model={result.get('model')} "
        f"dim={result.get('dim')} "
        f"total={float(result.get('total_warmup_seconds') or 0.0):.3f}s "
        f"first_embedding={float(result.get('first_embedding_seconds') or 0.0):.3f}s",
        flush=True,
    )
    if result.get("status") not in {"ok", "unavailable"}:
        print(f"RouteBrain embedding warmup error: {result.get('error')}", flush=True)


def main() -> None:
    _load_dotenv(PROJECT_ROOT / ".env")
    _configure_embedding_runtime()
    _warmup_embedding_runtime()
    print(
        "RouteBrain API starting with semantic vector provider "
        f"{os.getenv('ROUTEBRAIN_EMBEDDING_PROVIDER')} workers=1 reload=false",
        flush=True,
    )
    uvicorn.run(
        "app.api.main:app",
        host=_api_host(),
        port=_api_port(),
        reload=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
