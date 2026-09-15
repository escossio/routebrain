from __future__ import annotations

import os
import threading
import time
import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _normalize_text(value: str | None) -> str:
    return " ".join(str(value or "").split()).strip()


def _normalize_provider_name(value: str | None) -> str:
    provider = _normalize_text(value).lower()
    return provider or "text_fallback"


def _parse_int(value: str | None, default: int) -> int:
    try:
        parsed = int(str(value or "").strip())
    except ValueError:
        return default
    return parsed if parsed > 0 else default


_MODEL_LOCK = threading.Lock()
_MODEL: Any | None = None
_MODEL_CONFIG: tuple[str, str] | None = None
_MODEL_ERROR: str | None = None
_MODEL_LOADED_AT: str | None = None
_MODEL_LOAD_SECONDS: float | None = None
_METRICS_LOCK = threading.Lock()
_METRICS: dict[str, Any] = {
    "total_embed_calls": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "total_embed_seconds": 0.0,
    "last_embed_seconds": 0.0,
    "last_text_hash": None,
    "last_text_preview": None,
    "last_query_cache_hit": None,
}
_QUERY_CACHE_LOCK = threading.Lock()
_QUERY_EMBEDDING_CACHE: OrderedDict[tuple[str, str, str], tuple[float, list[float]]] = OrderedDict()
_QUERY_CACHE_MAX_SIZE = 256
_QUERY_CACHE_TTL_SECONDS = 3600.0


def _load_flag_embedding_model(model_name: str, device: str) -> Any:
    global _MODEL, _MODEL_CONFIG, _MODEL_ERROR, _MODEL_LOADED_AT, _MODEL_LOAD_SECONDS
    config = (model_name, device)
    if _MODEL is not None and _MODEL_CONFIG == config:
        return _MODEL
    if _MODEL_ERROR is not None and _MODEL_CONFIG == config:
        return None
    with _MODEL_LOCK:
        if _MODEL is not None and _MODEL_CONFIG == config:
            return _MODEL
        if _MODEL_ERROR is not None and _MODEL_CONFIG == config:
            return None
        _MODEL = None
        _MODEL_CONFIG = config
        _MODEL_ERROR = None
        _MODEL_LOADED_AT = None
        _MODEL_LOAD_SECONDS = None
        started = time.perf_counter()
        try:
            from FlagEmbedding import BGEM3FlagModel
        except Exception as exc:  # pragma: no cover - optional runtime dependency
            _MODEL_ERROR = f"FlagEmbedding indisponível: {exc}"
            return None
        try:
            _MODEL = BGEM3FlagModel(model_name, device=device, use_fp16=(device != "cpu"))
            _MODEL_LOADED_AT = datetime.now(timezone.utc).isoformat()
            _MODEL_LOAD_SECONDS = time.perf_counter() - started
        except Exception as exc:  # pragma: no cover - runtime model load failure
            _MODEL_ERROR = f"Falha ao carregar {model_name}: {exc}"
            _MODEL = None
            _MODEL_LOAD_SECONDS = time.perf_counter() - started
        return _MODEL


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _preview_text(value: str, limit: int = 80) -> str:
    preview = value[:limit]
    return preview + "..." if len(value) > limit else preview


def _normalize_query_cache_text(value: str | None) -> str:
    return _normalize_text(value).lower()


def _record_embed_call(text: str, seconds: float) -> None:
    with _METRICS_LOCK:
        _METRICS["total_embed_calls"] += 1
        _METRICS["total_embed_seconds"] = float(_METRICS["total_embed_seconds"]) + seconds
        _METRICS["last_embed_seconds"] = seconds
        _METRICS["last_text_hash"] = _hash_text(text)
        _METRICS["last_text_preview"] = _preview_text(text)


def _record_query_cache_hit(hit: bool) -> None:
    with _METRICS_LOCK:
        if hit:
            _METRICS["cache_hits"] += 1
        else:
            _METRICS["cache_misses"] += 1
        _METRICS["last_query_cache_hit"] = hit


@dataclass(frozen=True)
class EmbeddingProvider:
    name: str = "text_fallback"
    model: str = "BAAI/bge-m3"
    dim: int = 1024
    available: bool = False
    device: str = "cpu"
    batch_size: int = 8
    error: str | None = None

    def is_available(self) -> bool:
        return self.available

    def provider_name(self) -> str:
        return self.name

    def embedding_model(self) -> str:
        return self.model

    def embedding_dim(self) -> int:
        return self.dim

    def embed_text(self, text: str) -> list[float] | None:
        normalized = _normalize_text(text)
        if not normalized or self.name != "bge_m3_flagembedding" or not self.available:
            return None
        started = time.perf_counter()
        model = _load_flag_embedding_model(self.model, self.device)
        if model is None:
            _record_embed_call(normalized, time.perf_counter() - started)
            return None
        try:
            output = model.encode([normalized], batch_size=1, max_length=8192, return_dense=True)
        except TypeError:
            output = model.encode([normalized])
        except Exception:  # pragma: no cover - runtime model failure
            _record_embed_call(normalized, time.perf_counter() - started)
            return None
        dense_vecs = output.get("dense_vecs") if isinstance(output, dict) else None
        if dense_vecs is None:
            _record_embed_call(normalized, time.perf_counter() - started)
            return None
        vector = dense_vecs[0]
        if hasattr(vector, "tolist"):
            vector = vector.tolist()
        result = [float(value) for value in vector]
        _record_embed_call(normalized, time.perf_counter() - started)
        return result

    def describe(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "provider_name": self.name,
            "model": self.model,
            "dim": self.dim,
            "available": self.available,
            "is_available": self.available,
            "device": self.device,
            "batch_size": self.batch_size,
            "error": self.error or _MODEL_ERROR,
            "loaded_at": _MODEL_LOADED_AT,
            "load_seconds": _MODEL_LOAD_SECONDS,
            "model_loaded": _MODEL is not None,
        }


_PROVIDER_SINGLETON: EmbeddingProvider | None = None
_PROVIDER_CONFIG: tuple[str, str, int, str, int] | None = None


def _current_provider_config() -> tuple[str, str, int, str, int]:
    provider_name = _normalize_provider_name(os.getenv("ROUTEBRAIN_EMBEDDING_PROVIDER"))
    model = _normalize_text(os.getenv("ROUTEBRAIN_EMBEDDING_MODEL", "BAAI/bge-m3")) or "BAAI/bge-m3"
    dim = _parse_int(os.getenv("ROUTEBRAIN_EMBEDDING_DIM", "1024"), 1024)
    device = _normalize_text(os.getenv("ROUTEBRAIN_EMBEDDING_DEVICE", "cpu")) or "cpu"
    batch_size = _parse_int(os.getenv("ROUTEBRAIN_EMBEDDING_BATCH_SIZE", "8"), 8)
    return (provider_name, model, dim, device, batch_size)


def _build_provider(config: tuple[str, str, int, str, int]) -> EmbeddingProvider:
    provider_name, model, dim, device, batch_size = config

    available = False
    error: str | None = None
    if provider_name == "bge_m3_flagembedding":
        try:
            from FlagEmbedding import BGEM3FlagModel  # noqa: F401
        except Exception as exc:  # pragma: no cover - optional runtime dependency
            error = f"FlagEmbedding indisponível: {exc}"
        else:
            available = True
    elif provider_name not in {"none", "text_fallback"}:
        error = f"Provider desconhecido: {provider_name}"
        provider_name = "none"

    return EmbeddingProvider(
        name=provider_name,
        model=model,
        dim=dim,
        available=available,
        device=device,
        batch_size=batch_size,
        error=error,
    )


def get_embedding_provider() -> EmbeddingProvider:
    global _PROVIDER_SINGLETON, _PROVIDER_CONFIG
    config = _current_provider_config()
    if _PROVIDER_SINGLETON is not None and _PROVIDER_CONFIG == config:
        return _PROVIDER_SINGLETON
    _PROVIDER_SINGLETON = _build_provider(config)
    _PROVIDER_CONFIG = config
    return _PROVIDER_SINGLETON


def warmup_embedding_provider(sample_text: str = "routebrain semantic warmup") -> dict[str, Any]:
    started_total = time.perf_counter()
    provider_load_seconds = 0.0
    first_embedding_seconds = 0.0
    try:
        started_provider = time.perf_counter()
        provider = get_embedding_provider()
        provider_load_seconds = time.perf_counter() - started_provider
        if not provider.is_available():
            return {
                "status": "unavailable",
                "provider": provider.provider_name(),
                "model": provider.embedding_model(),
                "dim": provider.embedding_dim(),
                "provider_load_seconds": provider_load_seconds,
                "first_embedding_seconds": first_embedding_seconds,
                "total_warmup_seconds": time.perf_counter() - started_total,
                "error": provider.describe().get("error"),
            }
        started_embedding = time.perf_counter()
        vector = provider.embed_text(sample_text)
        first_embedding_seconds = time.perf_counter() - started_embedding
        return {
            "status": "ok" if vector else "unavailable",
            "provider": provider.provider_name(),
            "model": provider.embedding_model(),
            "dim": provider.embedding_dim(),
            "provider_load_seconds": provider_load_seconds,
            "first_embedding_seconds": first_embedding_seconds,
            "total_warmup_seconds": time.perf_counter() - started_total,
            "loaded_at": provider.describe().get("loaded_at"),
            "load_seconds": provider.describe().get("load_seconds"),
            "vector_dim": len(vector) if vector else 0,
            "error": None if vector else provider.describe().get("error"),
        }
    except Exception as exc:  # pragma: no cover - startup defensive path
        return {
            "status": "error",
            "provider_load_seconds": provider_load_seconds,
            "first_embedding_seconds": first_embedding_seconds,
            "total_warmup_seconds": time.perf_counter() - started_total,
            "error": str(exc),
        }


def is_available() -> bool:
    return get_embedding_provider().is_available()


def provider_name() -> str:
    return get_embedding_provider().provider_name()


def embedding_model() -> str:
    return get_embedding_provider().embedding_model()


def embedding_dim() -> int:
    return get_embedding_provider().embedding_dim()


def embed_text(text: str) -> list[float] | None:
    return get_embedding_provider().embed_text(text)


def embed_query_cached(text: str) -> list[float] | None:
    normalized = _normalize_query_cache_text(text)
    if not normalized:
        return None
    provider = get_embedding_provider()
    if not provider.is_available():
        return None
    cache_key = (provider.provider_name(), provider.embedding_model(), normalized)
    now = time.monotonic()
    with _QUERY_CACHE_LOCK:
        cached = _QUERY_EMBEDDING_CACHE.get(cache_key)
        if cached is not None:
            created_at, vector = cached
            if now - created_at <= _QUERY_CACHE_TTL_SECONDS:
                _QUERY_EMBEDDING_CACHE.move_to_end(cache_key)
                _record_query_cache_hit(True)
                return list(vector)
            _QUERY_EMBEDDING_CACHE.pop(cache_key, None)
    _record_query_cache_hit(False)
    vector = provider.embed_text(normalized)
    if vector is None:
        return None
    with _QUERY_CACHE_LOCK:
        _QUERY_EMBEDDING_CACHE[cache_key] = (now, list(vector))
        _QUERY_EMBEDDING_CACHE.move_to_end(cache_key)
        while len(_QUERY_EMBEDDING_CACHE) > _QUERY_CACHE_MAX_SIZE:
            _QUERY_EMBEDDING_CACHE.popitem(last=False)
    return vector


def get_embedding_provider_metrics() -> dict[str, Any]:
    provider = get_embedding_provider()
    provider_state = provider.describe()
    with _METRICS_LOCK:
        metrics = dict(_METRICS)
    with _QUERY_CACHE_LOCK:
        cache_size = len(_QUERY_EMBEDDING_CACHE)
    metrics.update(
        {
            "provider": provider_state,
            "provider_cached": bool(provider_state.get("model_loaded")),
            "provider_load_seconds": provider_state.get("load_seconds"),
            "query_cache_size": cache_size,
            "query_cache_max_size": _QUERY_CACHE_MAX_SIZE,
            "query_cache_ttl_seconds": _QUERY_CACHE_TTL_SECONDS,
        }
    )
    return metrics
