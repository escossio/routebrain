from __future__ import annotations

import hashlib
import json
import re
import os
import logging
import unicodedata
from decimal import Decimal
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

os.environ.setdefault("PSYCOPG_IMPL", "python")

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db.connection import get_connection
from app.services.embedding_provider import (
    embed_query_cached,
    embedding_dim,
    embedding_model,
    get_embedding_provider,
    get_embedding_provider_metrics,
    is_available,
    provider_name,
)
from app.services.external_enrichment import get_external_asn_enrichment, get_external_ip_enrichment
from app.services.inventory_queries import (
    get_host,
    get_site,
    list_hosts,
    list_hosts_by_site,
    list_peer_links,
    list_sites,
)
from app.services.ixbr_discovery_queries import (
    get_ixbr_participant,
    get_inventory_public_context,
    list_ixbr_locations,
    list_ixbr_participants,
)
from app.services.learning_classifier import get_classifications_for_entity, get_request_classifications
from app.services.learning_memory import get_learning_memory_for_domain, get_recent_evidence
from app.services.learning_orchestrator import get_learning_request, list_learning_requests

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 500
VECTOR_CANDIDATE_LIMIT = 80
TEXT_MATCH_CONTENT_LIMIT = 2000
SNIPPET_SOURCE_LIMIT = 3000
TEXT_SEARCH_MODE = "text_fallback"
VECTOR_SEARCH_MODE = "vector_bge_m3_hybrid"
VECTOR_SEARCH_MODE_LEGACY = "vector_bge_m3"
EMBEDDING_FUTURE_MODEL = "BAAI/bge-m3"
EMBEDDING_FUTURE_DIM = 1024
SEARCH_STOPWORDS = {
    "a",
    "ao",
    "aos",
    "as",
    "com",
    "da",
    "das",
    "de",
    "del",
    "do",
    "dos",
    "e",
    "em",
    "for",
    "from",
    "na",
    "nas",
    "no",
    "nos",
    "o",
    "os",
    "para",
    "por",
    "que",
    "sobre",
    "the",
    "to",
    "un",
    "uma",
    "um",
}
SEARCH_OBJECT_TYPE_BOOSTS = {
    "domain_memory": 12,
    "inventory_site": 11,
    "inventory_host": 10,
    "inventory_interface": 7,
    "inventory_peer_link": 6,
    "ixbr_participant": 5,
    "external_asn_enrichment": 4,
    "external_ip_enrichment": 4,
    "operational_answer": 5,
    "learning_request": 4,
    "routebrain_question": 4,
    "learning_evidence_summary": 3,
    "learning_classification_summary": 3,
}

OBJECT_TYPE_WEIGHTS = {
    "domain_memory": 0.20,
    "inventory_site": 0.20,
    "inventory_host": 0.20,
    "external_asn_enrichment": 0.12,
    "external_ip_enrichment": 0.12,
    "ixbr_participant": 0.08,
    "operational_answer": 0.04,
    "routebrain_question": 0.02,
    "learning_request": 0.00,
    "learning_classification_summary": -0.08,
    "learning_evidence_summary": -0.10,
}

QUERY_TYPE_BOOSTS = {
    "domain": {
        "domain_memory": 0.18,
        "external_asn_enrichment": 0.05,
        "external_ip_enrichment": 0.05,
        "learning_request": -0.08,
        "learning_classification_summary": -0.10,
        "learning_evidence_summary": -0.10,
    },
    "site": {
        "inventory_site": 0.18,
        "inventory_host": 0.05,
        "learning_request": -0.06,
        "learning_classification_summary": -0.08,
        "learning_evidence_summary": -0.08,
    },
    "host": {
        "inventory_host": 0.18,
        "inventory_site": 0.05,
        "learning_request": -0.06,
        "learning_classification_summary": -0.08,
        "learning_evidence_summary": -0.08,
    },
    "asn": {
        "external_asn_enrichment": 0.16,
        "ixbr_participant": 0.08,
        "learning_request": -0.05,
        "learning_classification_summary": -0.06,
        "learning_evidence_summary": -0.06,
    },
}


def _now() -> datetime:
    return datetime.now().astimezone()


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    return value


def _json_value(value: Any) -> Json:
    return Json(_safe_json(value))


def _vector_literal(values: Iterable[float]) -> str:
    return "[" + ",".join(f"{float(value):.10f}" for value in values) + "]"


def _normalize_text(value: str | None) -> str:
    return " ".join(str(value or "").split()).strip()


def _strip_accents(value: str | None) -> str:
    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKD", str(value))
    return "".join(char for char in normalized if not unicodedata.combining(char))


def _normalize_search_text(value: str | None) -> str:
    return _strip_accents(_normalize_text(value)).lower()


def _search_tokens(value: str | None) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", _normalize_search_text(value))
    filtered = [token for token in tokens if token not in SEARCH_STOPWORDS and len(token) > 1]
    return filtered or tokens


def _metadata_search_text(metadata: dict[str, Any] | None) -> str:
    if not metadata:
        return ""
    return _normalize_search_text(json.dumps(_safe_json(metadata), ensure_ascii=False, sort_keys=True))


def _metadata_compact_search_text(metadata: dict[str, Any] | None) -> str:
    if not isinstance(metadata, dict):
        return ""
    parts: list[str] = []
    parts.extend(_metadata_aliases(metadata))
    for key in ("family_key", "summary_text", "summary", "note", "reason"):
        value = metadata.get(key)
        if isinstance(value, str):
            text = _normalize_text(value)
            if text:
                parts.append(text[:500])
    return _normalize_search_text(" ".join(parts))


def _dedupe_text_items(items: Iterable[str | None]) -> list[str]:
    normalized: list[str] = []
    for item in items:
        text = _normalize_text(item)
        if text and text not in normalized:
            normalized.append(text)
    return normalized


def _search_hint_block(lines: Iterable[str | None]) -> str:
    hints = _dedupe_text_items(lines)
    if not hints:
        return ""
    return "\n".join(["Search hints:", _join_bullets(hints)])


def _metadata_aliases(metadata: dict[str, Any] | None) -> list[str]:
    if not isinstance(metadata, dict):
        return []
    aliases = metadata.get("aliases") or []
    if isinstance(aliases, (str, bytes)):
        aliases = [aliases]
    return _dedupe_text_items(str(item) for item in aliases if _normalize_text(item))


def _infer_query_profile(query: str, query_tokens: list[str]) -> dict[str, Any]:
    normalized_query = _normalize_search_text(query)
    token_set = {token for token in query_tokens if token}
    profile = "generic"
    preferred = ""
    if any(
        marker in normalized_query
        for marker in (
            "cloudflare",
            "baidu",
            "domain",
            "dominio",
            ".com",
            "latencia",
            "latency",
            "internacional",
            "international",
            "cdn",
            "edge",
            "anycast",
        )
    ):
        profile = "domain"
        preferred = "domain_memory"
    elif any(
        marker in normalized_query
        for marker in (
            "ptt",
            "ix",
            "site",
            "hosts pertencem",
            "pertencem",
            "pertence",
            "inventario",
            "inventory",
        )
    ):
        profile = "site"
        preferred = "inventory_site"
    elif token_set.intersection({"maquina", "máquina", "host", "hosts", "notebook", "worker", "servidor"}):
        profile = "host"
        preferred = "inventory_host"
    elif token_set.intersection({"asn", "autnum", "participant", "participants", "peering", "peer"}) or re.search(r"\bas\d+\b", normalized_query):
        profile = "asn"
        preferred = "external_asn_enrichment"

    boosts = dict(QUERY_TYPE_BOOSTS.get(profile, {}))
    return {
        "profile": profile,
        "preferred": preferred,
        "boosts": boosts,
        "reason": f"object_type {preferred} preferred for {profile}-like query" if preferred else "generic query",
    }


def _intent_boost(object_type: str | None, query_profile: dict[str, Any]) -> float:
    query_boosts = query_profile.get("boosts") or {}
    return float(query_boosts.get(str(object_type or ""), 0.0))


def _text_match_score(
    *,
    row: dict[str, Any],
    normalized_query: str,
    query_tokens: list[str],
) -> dict[str, Any]:
    tags = [str(tag) for tag in (row.get("tags") or []) if _normalize_text(tag)]
    title = _normalize_text(row.get("title"))
    content = _normalize_text(row.get("content"))
    metadata = _safe_json(row.get("metadata") or {})
    metadata_aliases = _metadata_aliases(metadata if isinstance(metadata, dict) else {})
    metadata_text = _metadata_compact_search_text(metadata if isinstance(metadata, dict) else {})
    object_ref = _normalize_search_text(row.get("object_ref"))
    title_text = _normalize_search_text(title)
    content_for_match = (content or "")[:TEXT_MATCH_CONTENT_LIMIT]
    content_text = _normalize_search_text(content_for_match)
    tags_text = _normalize_search_text(" ".join(tags))
    aliases_text = _normalize_search_text(" ".join(metadata_aliases))
    normalized_query_text = _normalize_search_text(normalized_query)
    exact_phrase = any(
        normalized_query_text and normalized_query_text in candidate
        for candidate in (title_text, content_text, tags_text, aliases_text, metadata_text, object_ref)
    )

    matched_title = False
    matched_content = False
    matched_tags = False
    matched_metadata = False
    matched_object_ref = False
    matched_aliases = False
    matched_tokens: list[str] = []
    score = 0.0

    if object_ref and normalized_query_text == object_ref:
        matched_object_ref = True
        score += 0.30

    if exact_phrase:
        score += 0.18

    for token in query_tokens:
        token_hit = False
        if token in title_text:
            matched_title = True
            token_hit = True
            score += 0.10
        if token in tags_text:
            matched_tags = True
            token_hit = True
            score += 0.07
        if token in aliases_text:
            matched_aliases = True
            token_hit = True
            score += 0.08
        if token in content_text:
            matched_content = True
            token_hit = True
            score += 0.04
        if token in metadata_text:
            matched_metadata = True
            token_hit = True
            score += 0.03
        if token in object_ref:
            matched_object_ref = True
            token_hit = True
            score += 0.08
        if token_hit and token not in matched_tokens:
            matched_tokens.append(token)

    score = min(score, 0.65)
    snippet_source = ((content or "")[:SNIPPET_SOURCE_LIMIT]) or title or normalized_query
    snippet = snippet_source[:240]
    if matched_tokens:
        normalized_snippet_source = _normalize_search_text(snippet_source)
        for token in matched_tokens:
            idx = normalized_snippet_source.find(token)
            if idx >= 0:
                start = max(0, idx - 80)
                end = min(len(snippet_source), idx + 160)
                snippet = snippet_source[start:end]
                break

    return {
        "text_score": score,
        "snippet": snippet,
        "confidence_bonus": 1.0 if row.get("confidence") == "confirmed" else 0.0,
        "matched_title": matched_title,
        "matched_content": matched_content,
        "matched_tags": matched_tags,
        "matched_metadata": matched_metadata,
        "matched_object_ref": matched_object_ref,
        "matched_aliases": matched_aliases,
        "matched_tokens": matched_tokens,
        "exact_phrase": exact_phrase,
        "tags": tags,
        "metadata": metadata,
    }


def _object_type_weight(object_type: str | None, query_profile: dict[str, Any]) -> float:
    del query_profile
    return float(OBJECT_TYPE_WEIGHTS.get(str(object_type or ""), 0.0))


def _hybrid_score(
    *,
    vector_score: float | None,
    text_score: float,
    object_type_weight: float,
    intent_boost: float = 0.0,
    confidence_bonus: float = 0.0,
) -> float:
    score = float(vector_score or 0.0) + float(text_score or 0.0) + float(object_type_weight or 0.0) + float(intent_boost or 0.0)
    score += float(confidence_bonus or 0.0) * 0.01
    return score


def _canonical_result_reason(row: dict[str, Any]) -> str:
    bits = []
    raw_vector_score = row.get("raw_vector_score")
    if raw_vector_score is not None:
        bits.append(f"vector={float(raw_vector_score):.4f}")
    text_score = row.get("text_score")
    if text_score:
        bits.append(f"text={float(text_score):.4f}")
    object_type_weight = row.get("object_type_weight")
    if object_type_weight:
        bits.append(f"type={float(object_type_weight):+.2f}")
    intent_boost = row.get("intent_boost")
    if intent_boost:
        bits.append(f"intent_boost={float(intent_boost):+.2f}")
    query_intent = row.get("query_intent")
    if query_intent and query_intent != "generic":
        bits.append(f"intent={query_intent}")
    if row.get("matched_object_ref"):
        bits.append("object_ref")
    if row.get("matched_title"):
        bits.append("title")
    if row.get("matched_tags"):
        bits.append("tags")
    if row.get("matched_aliases"):
        bits.append("aliases")
    if row.get("matched_content"):
        bits.append("content")
    if row.get("matched_metadata"):
        bits.append("metadata")
    if row.get("exact_phrase"):
        bits.append("phrase")
    if row.get("matched_tokens"):
        bits.append("tokens=" + ",".join(list(row.get("matched_tokens") or [])[:6]))
    if row.get("family_key"):
        bits.append(f"family_key={row.get('family_key')}")
    if int(row.get("related_count") or 1) > 1:
        bits.append(f"related_count={int(row.get('related_count') or 1)}")
    if not bits:
        return "Hybrid semantic match"
    return "Hybrid semantic match: " + ", ".join(bits)


def _ranking_debug(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "vector_score": row.get("vector_score"),
        "text_score": row.get("text_score"),
        "object_type_weight": row.get("object_type_weight"),
        "intent_boost": row.get("intent_boost"),
        "hybrid_score": row.get("score"),
        "family_key": row.get("family_key"),
        "related_count": row.get("related_count"),
    }


def _result_metadata(metadata: dict[str, Any] | None, family_key: str) -> dict[str, Any]:
    metadata_dict = metadata if isinstance(metadata, dict) else {}
    result: dict[str, Any] = {"family_key": family_key}
    aliases = _metadata_aliases(metadata_dict)
    if aliases:
        result["aliases"] = aliases[:8]
    for key in ("summary_text", "summary", "note"):
        value = metadata_dict.get(key)
        if isinstance(value, str):
            text = _normalize_text(value)
            if text:
                result[key] = text[:240]
                break
    return result


def _attach_family_metadata(
    metadata: dict[str, Any] | None,
    *,
    family_key: str,
    aliases: Iterable[str] | None = None,
) -> dict[str, Any]:
    enriched = dict(metadata or {})
    if family_key:
        enriched["family_key"] = family_key
    if aliases:
        enriched["aliases"] = _dedupe_text_items(aliases)
    return enriched


def _family_key_for_row(row: dict[str, Any]) -> str:
    metadata = row.get("metadata") or {}
    if isinstance(metadata, dict):
        family_key = str(metadata.get("family_key") or "").strip()
        if family_key:
            return family_key
    object_type = str(row.get("object_type") or "").strip().lower()
    object_ref = str(row.get("object_ref") or "").strip().lower()
    if object_type == "domain_memory":
        return f"domain:{object_ref}"
    if object_type == "inventory_site":
        return f"site:{object_ref}"
    if object_type == "inventory_host":
        return f"host:{object_ref}"
    if object_type in {
        "learning_request",
        "routebrain_question",
        "operational_answer",
        "learning_evidence_summary",
        "learning_classification_summary",
    }:
        return f"request:{object_ref}"
    if object_ref:
        return f"{object_type}:{object_ref}"
    return object_type or "document"


def _build_search_result_reason(row: dict[str, Any]) -> str:
    return _canonical_result_reason(row)


def _normalize_scope(scope: str | None) -> str:
    normalized = _normalize_text(scope).lower()
    if not normalized:
        return "all"
    if normalized not in {"inventory", "learning", "domains", "ixbr", "enrichment", "all"}:
        raise ValueError("Escopo inválido.")
    return normalized


def _clamp_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    if limit < 1:
        raise ValueError("Limite inválido.")
    return min(int(limit), DEFAULT_LIMIT)


def _fetch_all(
    sql: str,
    params: tuple[Any, ...] = (),
    *,
    conn: psycopg.Connection | None = None,
) -> list[dict[str, Any]]:
    if conn is not None:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
    with get_connection() as fresh_conn:
        with fresh_conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


def _fetch_one(
    sql: str,
    params: tuple[Any, ...] = (),
    *,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any] | None:
    rows = _fetch_all(sql, params, conn=conn)
    return rows[0] if rows else None


def _fetch_scalar(
    sql: str,
    params: tuple[Any, ...] = (),
    *,
    conn: psycopg.Connection | None = None,
) -> Any:
    row = _fetch_one(sql, params, conn=conn)
    if not row:
        return None
    return next(iter(row.values()))


def _execute(
    sql: str,
    params: tuple[Any, ...] = (),
    *,
    conn: psycopg.Connection | None = None,
) -> None:
    if conn is not None:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        return
    with get_connection() as fresh_conn:
        with fresh_conn.cursor() as cur:
            cur.execute(sql, params)


def _stable_uid(object_type: str, object_ref: str) -> str:
    source = f"{_normalize_text(object_type).lower()}|{_normalize_text(object_ref).lower()}"
    digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:24]
    return f"sd_{digest}"


def make_document_uid(object_type: str, object_ref: str) -> str:
    return _stable_uid(object_type, object_ref)


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _normalize_tags(tags: Iterable[str] | None) -> list[str]:
    normalized: list[str] = []
    for tag in tags or []:
        text = _normalize_text(tag).lower()
        if text and text not in normalized:
            normalized.append(text)
    return normalized


def _split_lines(*parts: str | None) -> str:
    cleaned = [_normalize_text(part) for part in parts if _normalize_text(part)]
    return "\n".join(cleaned)


def _join_bullets(items: Iterable[str | None]) -> str:
    cleaned = [_normalize_text(item) for item in items if _normalize_text(item)]
    return "\n".join(f"- {item}" for item in cleaned)


def _format_key_values(rows: Iterable[tuple[str, str | None]]) -> str:
    lines = []
    for key, value in rows:
        value_text = _normalize_text(value) or "n/a"
        lines.append(f"{key}: {value_text}")
    return "\n".join(lines)


def _document_row(document_uid: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
    row = _fetch_one(
        """
        select
          id,
          document_uid,
          object_type,
          object_ref,
          title,
          content,
          content_hash,
          source,
          confidence,
          tags,
          metadata,
          created_at,
          updated_at,
          embedded_at,
          embedding_status,
          embedding_model,
          embedding_error
        from semantic_documents
        where document_uid = %s
        limit 1;
        """,
        (document_uid,),
        conn=conn,
    )
    if row is None:
        return None
    row["tags"] = list(row.get("tags") or [])
    if isinstance(row.get("metadata"), (dict, list)):
        row["metadata"] = _safe_json(row["metadata"])
    return row


def _preview_document_status(
    *,
    document_uid: str,
    title: str | None,
    content: str,
    tags: list[str],
    metadata: dict[str, Any],
    confidence: str,
    source: str | None,
    conn: psycopg.Connection | None = None,
) -> str:
    existing = _document_row(document_uid, conn=conn)
    new_hash = _content_hash(content)
    if existing is None:
        return "created"
    if str(existing.get("content_hash") or "") == new_hash:
        return "unchanged"
    return "updated"


def upsert_semantic_document(
    object_type: str,
    object_ref: str,
    title: str | None,
    content: str,
    metadata: dict[str, Any] | None = None,
    tags: Iterable[str] | None = None,
    confidence: str = "suggested",
    source: str | None = None,
    *,
    conn: psycopg.Connection | None = None,
    force: bool = False,
) -> dict[str, Any]:
    normalized_object_type = _normalize_text(object_type)
    normalized_object_ref = _normalize_text(object_ref)
    if not normalized_object_type or not normalized_object_ref:
        raise ValueError("Objeto semântico inválido.")

    normalized_title = _normalize_text(title)
    normalized_content = _normalize_text(content)
    if not normalized_content:
        raise ValueError("Conteúdo semântico vazio.")

    normalized_tags = _normalize_tags(tags)
    normalized_metadata = _safe_json(metadata or {})
    document_uid = make_document_uid(normalized_object_type, normalized_object_ref)
    content_hash = _content_hash(normalized_content)
    existing = _document_row(document_uid, conn=conn)

    if existing is not None and not force and str(existing.get("content_hash") or "") == content_hash:
        return {
            "status": "unchanged",
            "document_uid": document_uid,
            "id": existing.get("id"),
            "object_type": normalized_object_type,
            "object_ref": normalized_object_ref,
            "title": existing.get("title"),
            "content_hash": existing.get("content_hash"),
            "embedding_status": existing.get("embedding_status"),
        }

    if existing is None:
        _execute(
            """
            insert into semantic_documents (
              document_uid,
              object_type,
              object_ref,
              title,
              content,
              content_hash,
              source,
              confidence,
              tags,
              metadata,
              created_at,
              updated_at,
              embedded_at,
              embedding_status,
              embedding_model,
              embedding_error
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now(), null, 'text_only', null, null)
            on conflict (document_uid)
            do update set
              object_type = excluded.object_type,
              object_ref = excluded.object_ref,
              title = excluded.title,
              content = excluded.content,
              content_hash = excluded.content_hash,
              source = excluded.source,
              confidence = excluded.confidence,
              tags = excluded.tags,
              metadata = excluded.metadata,
              updated_at = now(),
              embedded_at = null,
              embedding_status = 'text_only',
              embedding_model = null,
              embedding_error = null;
            """,
            (
                document_uid,
                normalized_object_type,
                normalized_object_ref,
                normalized_title,
                normalized_content,
                content_hash,
                source,
                confidence,
                normalized_tags,
                _json_value(normalized_metadata),
            ),
            conn=conn,
        )
        status = "created"
    else:
        _execute(
            """
            update semantic_documents
            set
              object_type = %s,
              object_ref = %s,
              title = %s,
              content = %s,
              content_hash = %s,
              source = %s,
              confidence = %s,
              tags = %s,
              metadata = %s,
              updated_at = now(),
              embedded_at = null,
              embedding_status = 'text_only',
              embedding_model = null,
              embedding_error = null
            where document_uid = %s;
            """,
            (
                normalized_object_type,
                normalized_object_ref,
                normalized_title,
                normalized_content,
                content_hash,
                source,
                confidence,
                normalized_tags,
                _json_value(normalized_metadata),
                document_uid,
            ),
            conn=conn,
        )
        status = "updated"

    row = _document_row(document_uid, conn=conn)
    return {
        "status": status,
        "document_uid": document_uid,
        "id": row.get("id") if row else None,
        "object_type": normalized_object_type,
        "object_ref": normalized_object_ref,
        "title": normalized_title,
        "content_hash": content_hash,
        "embedding_status": "text_only",
    }


def _doc_result(
    *,
    object_type: str,
    object_ref: str,
    title: str | None,
    content: str,
    metadata: dict[str, Any] | None = None,
    tags: Iterable[str] | None = None,
    confidence: str = "suggested",
    source: str | None = None,
) -> dict[str, Any]:
    return {
        "object_type": _normalize_text(object_type),
        "object_ref": _normalize_text(object_ref),
        "title": _normalize_text(title),
        "content": _normalize_text(content),
        "metadata": _safe_json(metadata or {}),
        "tags": _normalize_tags(tags),
        "confidence": confidence,
        "source": source,
    }


def build_inventory_host_document(hostname: str) -> dict[str, Any] | None:
    host = get_host(hostname)
    if host is None:
        return None
    interfaces = host.get("interfaces") or []
    peer_links = host.get("peer_links") or []
    observations = host.get("observations") or []
    tags = [tag.get("tag") for tag in host.get("tags") or [] if isinstance(tag, dict)]
    interface_lines = []
    for item in interfaces:
        if not isinstance(item, dict):
            continue
        interface_lines.append(
            f"{item.get('interface_name') or 'interface'} {item.get('interface_ip') or ''} "
            f"{item.get('description') or ''} {item.get('peer_ip') or ''} ASN {item.get('peer_asn') or ''}"
        )
    peer_lines = []
    for item in peer_links:
        if not isinstance(item, dict):
            continue
        peer_lines.append(
            f"{item.get('peer_ip') or 'peer'} ASN {item.get('peer_asn') or 'n/a'} "
            f"{item.get('relation_type') or ''} {item.get('confidence') or ''} {item.get('source') or ''}"
        )
    observation_lines = []
    for item in observations:
        if not isinstance(item, dict):
            continue
        observation_lines.append(
            f"{item.get('observation_type') or 'observation'}: {item.get('observation') or ''} ({item.get('source') or 'n/a'})"
        )

    hostname_value = str(host.get("hostname") or "").strip()
    title = f"Inventory host {hostname_value}"
    search_hints = [hostname_value, host.get("role"), host.get("site_code"), host.get("site_name")]
    if hostname_value == "example-server":
        search_hints.extend(
            [
                "example-server",
                "servidor principal",
                "banco RouteBrain",
                "PostgreSQL",
                "API",
                "CLI",
                "Grafana Docker",
                "routebrain-grafana",
                "processamento do banco",
            ]
        )
    if hostname_value == "example-worker":
        search_hints.extend(
            [
                "example-worker",
                "notebook",
                "notebook worker",
                "worker BGP",
                "máquina que processou BGP pesado",
                "processamento BGP pesado",
                "bootstrap BGP",
                "parse de RIB",
                "geração de CSV",
                "CSVs do RouteViews",
                "worker offline",
                "./worker",
                "worker CPU capacity",
                "worker memory capacity",
            ]
        )
    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Hostname", host.get("hostname")),
                    ("Management IP", host.get("mgmt_ip")),
                    ("Site code", host.get("site_code")),
                    ("Site name", host.get("site_name")),
                    ("Role", host.get("role")),
                    ("Vendor", host.get("vendor")),
                    ("Model", host.get("model")),
                    ("OS", host.get("os_name")),
                    ("Status", host.get("status")),
                    ("Interfaces", str(host.get("interface_count"))),
                    ("Peer links", str(host.get("peer_link_count"))),
                    ("Tags", ", ".join(tags) if tags else None),
                    ("Notes", host.get("notes")),
                ]
            ),
            "Interfaces:",
            _join_bullets(interface_lines) or "- none",
            "Peer links:",
            _join_bullets(peer_lines) or "- none",
            "Observations:",
            _join_bullets(observation_lines) or "- none",
            _search_hint_block(search_hints),
        ]
    )
    metadata = {
        "host": _safe_json(host),
        "interfaces": _safe_json(interfaces),
        "peer_links": _safe_json(peer_links),
        "observations": _safe_json(observations),
    }
    doc_tags = [host.get("hostname"), host.get("site_code"), host.get("site_name"), host.get("role")] + tags + search_hints
    return _doc_result(
        object_type="inventory_host",
        object_ref=hostname_value,
        title=title,
        content=content,
        metadata=_attach_family_metadata(metadata, family_key=f"host:{hostname_value.lower()}", aliases=search_hints),
        tags=doc_tags,
        confidence="confirmed",
        source="inventory",
    )


def build_inventory_interface_document(hostname: str, interface_name: str) -> dict[str, Any] | None:
    host = get_host(hostname)
    if host is None:
        return None
    interface = next(
        (item for item in (host.get("interfaces") or []) if isinstance(item, dict) and str(item.get("interface_name") or "").strip() == interface_name),
        None,
    )
    if interface is None:
        return None
    title = f"Interface {hostname}:{interface_name}"
    content = _format_key_values(
        [
            ("Host", host.get("hostname")),
            ("Interface", interface.get("interface_name")),
            ("Interface IP", interface.get("interface_ip")),
            ("Description", interface.get("description")),
            ("Speed Mbps", str(interface.get("speed_mbps"))),
            ("VLAN", str(interface.get("vlan"))),
            ("Circuit ref", interface.get("circuit_ref")),
            ("Peer IP", interface.get("peer_ip")),
            ("Peer ASN", str(interface.get("peer_asn"))),
            ("Status", interface.get("status")),
            ("Notes", interface.get("notes")),
        ]
    )
    metadata = {"host": _safe_json(host), "interface": _safe_json(interface)}
    return _doc_result(
        object_type="inventory_interface",
        object_ref=f"{hostname}:{interface_name}",
        title=title,
        content=content,
        metadata=metadata,
        tags=[hostname, interface_name, host.get("site_code"), host.get("role")],
        confidence="confirmed",
        source="inventory",
    )


def build_inventory_peer_link_document(hostname: str, peer_ip: str, peer_asn: int | None = None) -> dict[str, Any] | None:
    host = get_host(hostname)
    if host is None:
        return None
    peer_links = [item for item in (host.get("peer_links") or []) if isinstance(item, dict)]
    peer_link = None
    for item in peer_links:
        if str(item.get("peer_ip") or "") == str(peer_ip):
            if peer_asn is None or int(item.get("peer_asn") or 0) == int(peer_asn):
                peer_link = item
                break
    if peer_link is None:
        return None
    title = f"Peer link {peer_ip} on {hostname}"
    content = _format_key_values(
        [
            ("Host", host.get("hostname")),
            ("Peer IP", peer_link.get("peer_ip")),
            ("Peer ASN", str(peer_link.get("peer_asn"))),
            ("Relation", peer_link.get("relation_type")),
            ("Confidence", peer_link.get("confidence")),
            ("Source", peer_link.get("source")),
            ("Interface", peer_link.get("interface_name")),
            ("Interface IP", peer_link.get("interface_ip")),
            ("Site code", peer_link.get("site_code")),
            ("Site name", peer_link.get("site_name")),
            ("Notes", peer_link.get("notes")),
        ]
    )
    metadata = {"host": _safe_json(host), "peer_link": _safe_json(peer_link)}
    return _doc_result(
        object_type="inventory_peer_link",
        object_ref=f"{hostname}:{peer_ip}:{peer_link.get('peer_asn') or ''}",
        title=title,
        content=content,
        metadata=metadata,
        tags=[hostname, peer_ip, str(peer_link.get("peer_asn") or ""), host.get("site_code")],
        confidence=str(peer_link.get("confidence") or "suggested"),
        source=str(peer_link.get("source") or "inventory"),
    )


def build_inventory_site_document(site_code: str) -> dict[str, Any] | None:
    site = get_site(site_code)
    if site is None:
        return None
    site_code_norm = str(site.get("site_code") or site_code).strip().upper()
    site_hosts = list_hosts_by_site(site_code_norm, include_interfaces=True, include_peers=True) or {}
    public_context = None
    if site_code_norm == "PTT-CE":
        try:
            public_context = get_inventory_public_context(
                site_code=site_code_norm,
                locality_code="CE",
                limit=20,
                include_unmatched_bgp_peers=False,
            )
        except RuntimeError:
            public_context = None
    confirmed_hosts = site_hosts.get("confirmed_hosts") or []
    peer_links = site_hosts.get("peer_links") or []
    title = f"Inventory site {site_code_norm}"
    host_names = [str(host.get("hostname") or "") for host in confirmed_hosts if isinstance(host, dict) and host.get("hostname")]
    public_summary_lines = []
    search_hints = [
        site_code_norm,
        site.get("name"),
        "IX.br CE",
        "IX Fortaleza",
        "participantes públicos",
        "916 participantes",
        "877 vistos como origin",
        "nenhum host confirmado",
        "inventário interno",
        "public_ix_context",
    ]
    if public_context is not None:
        public_summary_lines.append(
            f"IX.br público: {int(public_context.get('public_participants_count') or 0)} participantes, "
            f"{int(public_context.get('public_participants_seen_as_origin_count') or 0)} vistos como origin."
        )
        public_summary_lines.append(str(public_context.get("note") or ""))
        if site_code_norm == "PTT-CE" and not confirmed_hosts:
            public_summary_lines.append("PTT-CE ainda não tem hosts internos confirmados no inventário.")

    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Site code", site.get("site_code")),
                    ("Name", site.get("name")),
                    ("Site type", site.get("site_type")),
                    ("City", site.get("city")),
                    ("State", site.get("state")),
                    ("Country", site.get("country")),
                    ("Facility", site.get("facility")),
                    ("Hosts confirmed", str(site.get("host_count"))),
                    ("Interfaces", str(site.get("interface_count"))),
                    ("Peer links", str(site.get("peer_link_count"))),
                    ("Notes", site.get("notes")),
                ]
            ),
            "Hosts confirmados:",
            _join_bullets(host_names) or "- none",
            "Peer links:",
            _join_bullets(
                f"{item.get('peer_ip') or ''} ASN {item.get('peer_asn') or ''} {item.get('relation_type') or ''}"
                for item in peer_links
                if isinstance(item, dict)
            )
            or "- none",
            "IX.br público:",
            _join_bullets(public_summary_lines) or "- none",
            _search_hint_block(search_hints),
        ]
    )
    metadata = {
        "site": _safe_json(site),
        "site_hosts": _safe_json(site_hosts),
        "public_context": _safe_json(public_context),
    }
    tags = [site_code_norm, site.get("site_type"), site.get("city"), site.get("state"), site.get("country"), "ixbr"] + search_hints
    if site_code_norm == "PTT-CE":
        tags.append("ptt-ce")
    return _doc_result(
        object_type="inventory_site",
        object_ref=site_code_norm,
        title=title,
        content=content,
        metadata=_attach_family_metadata(metadata, family_key=f"site:{site_code_norm}", aliases=search_hints),
        tags=tags,
        confidence="confirmed",
        source="inventory",
    )


def _build_ixbr_participant_document_from_row(
    participant: dict[str, Any],
    *,
    external_asn: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not participant:
        return None
    locality_code = str(participant.get("locality_code") or "").strip().upper()
    asn = participant.get("asn")
    if asn is None:
        return None
    title = f"IX.br participant {participant.get('participant_name') or asn}"
    content = _format_key_values(
        [
            ("Locality", participant.get("locality_code")),
            ("ASN", str(participant.get("asn"))),
            ("Participant", participant.get("participant_name")),
            ("Participation type", participant.get("participation_type")),
            ("ATM v4", str(participant.get("atm_v4"))),
            ("ATM v6", str(participant.get("atm_v6"))),
            ("Transport L2", str(participant.get("transport_l2"))),
            ("CIX", str(participant.get("cix"))),
            ("Seen as origin", str(bool(participant.get("seen_as_origin")))),
            ("Route count", str(participant.get("route_count"))),
            ("Prefix count", str(participant.get("prefix_count"))),
            ("Peer count", str(participant.get("peer_count"))),
            ("Collector count", str(participant.get("collector_count"))),
            ("BGP updated at", participant.get("bgp_updated_at")),
            ("Source URL", participant.get("source_url")),
            ("External organization", (external_asn or {}).get("organization_name")),
            ("External country", (external_asn or {}).get("country")),
            ("External network type", (external_asn or {}).get("network_type")),
        ]
    )
    metadata = {"participant": _safe_json(participant), "external_asn": _safe_json(external_asn)}
    tags = [
        locality_code,
        str(asn),
        participant.get("participant_name"),
        participant.get("participation_type"),
        "ixbr",
        "public",
    ]
    if participant.get("seen_as_origin"):
        tags.append("seen-as-origin")
    return _doc_result(
        object_type="ixbr_participant",
        object_ref=f"{locality_code}:{asn}",
        title=title,
        content=content,
        metadata=metadata,
        tags=tags,
        confidence="confirmed" if participant.get("seen_as_origin") else "suggested",
        source="ixbr_discovery_queries",
    )


def build_ixbr_participant_document(locality_code: str, asn: int) -> dict[str, Any] | None:
    participant = get_ixbr_participant(locality_code, asn)
    if participant is None:
        return None
    external_asn = None
    try:
        external_asn = get_external_asn_enrichment(asn)
    except RuntimeError:
        external_asn = None
    return _build_ixbr_participant_document_from_row(participant, external_asn=external_asn)


def build_external_asn_document(asn: int) -> dict[str, Any] | None:
    asn_row = get_external_asn_enrichment(asn)
    if asn_row is None:
        return None
    classifications = get_classifications_for_entity("asn", str(asn))
    title = f"External ASN enrichment {asn}"
    content = "\n".join(
        [
            _format_key_values(
                [
                    ("ASN", str(asn_row.get("asn"))),
                    ("Organization", asn_row.get("organization_name")),
                    ("Country", asn_row.get("country")),
                    ("Network name", asn_row.get("network_name")),
                    ("Website", asn_row.get("website")),
                    ("Looking glass", asn_row.get("looking_glass")),
                    ("Route server", asn_row.get("route_server")),
                    ("Network type", asn_row.get("network_type")),
                    ("Info type", asn_row.get("info_type")),
                    ("Prefixes v4", str(asn_row.get("info_prefixes4"))),
                    ("Prefixes v6", str(asn_row.get("info_prefixes6"))),
                    ("Peering policy", asn_row.get("peering_policy")),
                    ("Source", asn_row.get("source")),
                    ("Confidence", asn_row.get("confidence")),
                ]
            ),
            "Classificações relacionadas:",
            _join_bullets(
                f"{item.get('classification_type')}={item.get('classification_value')} ({item.get('confidence')})"
                for item in classifications.get("classifications", [])
            )
            or "- none",
            _search_hint_block([asn_row.get("organization_name"), asn_row.get("country"), asn_row.get("network_name"), asn]),
        ]
    )
    metadata = {"external_asn_enrichment": _safe_json(asn_row), "classifications": _safe_json(classifications)}
    tags = [str(asn), asn_row.get("organization_name"), asn_row.get("network_name"), asn_row.get("country"), "asn"]
    return _doc_result(
        object_type="external_asn_enrichment",
        object_ref=str(asn),
        title=title,
        content=content,
        metadata=_attach_family_metadata(metadata, family_key=f"asn:{asn}", aliases=[asn_row.get("organization_name"), asn_row.get("country"), asn_row.get("network_name")]),
        tags=tags,
        confidence=str(asn_row.get("confidence") or "suggested"),
        source=str(asn_row.get("source") or "external_enrichment"),
    )


def build_external_ip_document(ip: str) -> dict[str, Any] | None:
    ip_row = get_external_ip_enrichment(ip)
    if ip_row is None:
        return None
    asn_row = None
    if ip_row.get("asn") is not None:
        try:
            asn_row = get_external_asn_enrichment(int(ip_row.get("asn")))
        except (RuntimeError, ValueError):
            asn_row = None
    title = f"External IP enrichment {ip}"
    content = _format_key_values(
        [
            ("IP", str(ip_row.get("ip"))),
            ("ASN", str(ip_row.get("asn"))),
            ("Organization", ip_row.get("organization_name")),
            ("Country", ip_row.get("country")),
            ("Network name", ip_row.get("network_name")),
            ("Source", ip_row.get("source")),
            ("Confidence", ip_row.get("confidence")),
            ("ASN organization", (asn_row or {}).get("organization_name")),
            ("ASN country", (asn_row or {}).get("country")),
        ]
    )
    search_hints = [ip, ip_row.get("organization_name"), ip_row.get("country"), ip_row.get("network_name")]
    metadata = {"external_ip_enrichment": _safe_json(ip_row), "external_asn_enrichment": _safe_json(asn_row)}
    tags = [str(ip_row.get("ip")), ip_row.get("organization_name"), ip_row.get("country"), "ip"] + search_hints
    return _doc_result(
        object_type="external_ip_enrichment",
        object_ref=str(ip_row.get("ip")),
        title=title,
        content=content,
        metadata=_attach_family_metadata(metadata, family_key=f"ip:{ip_row.get('ip')}", aliases=search_hints),
        tags=tags,
        confidence=str(ip_row.get("confidence") or "suggested"),
        source=str(ip_row.get("source") or "external_enrichment"),
    )


def _learning_bundle(request_uid: str) -> dict[str, Any] | None:
    try:
        return get_learning_request(request_uid)
    except ValueError:
        return None


def build_learning_request_document(request_uid: str) -> dict[str, Any] | None:
    bundle = _learning_bundle(request_uid)
    if bundle is None:
        return None
    request = bundle.get("request") or {}
    entities = bundle.get("entities") or []
    gaps = bundle.get("gaps") or []
    tasks = bundle.get("tasks") or []
    evidence = bundle.get("evidence") or []
    classifications = bundle.get("classifications") or []
    answer = bundle.get("answer") or {}
    title = f"Learning request {request_uid}"
    family_key = f"request:{request_uid}"
    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Request UID", request.get("request_uid")),
                    ("Question", request.get("question")),
                    ("Normalized question", request.get("normalized_question")),
                    ("Intent", request.get("intent")),
                    ("Scope", request.get("scope")),
                    ("Status", request.get("status")),
                    ("Operator", request.get("operator")),
                    ("Requires consent", str(request.get("requires_consent"))),
                    ("Consent status", request.get("consent_status")),
                    ("Confidence before", str(request.get("confidence_before"))),
                    ("Confidence after", str(request.get("confidence_after"))),
                    ("Answer summary", request.get("answer_summary")),
                ]
            ),
            "Entities:",
            _join_bullets(
                f"{item.get('entity_type')}={item.get('entity_value')} ({item.get('confidence')})"
                for item in entities
                if isinstance(item, dict)
            )
            or "- none",
            "Gaps:",
            _join_bullets(
                f"{item.get('gap_type')} {item.get('description')} [{item.get('severity')}]"
                for item in gaps
                if isinstance(item, dict)
            )
            or "- none",
            "Tasks:",
            _join_bullets(
                f"{item.get('task_type')} {item.get('status')} {item.get('command_preview')}"
                for item in tasks
                if isinstance(item, dict)
            )
            or "- none",
            "Evidence:",
            _join_bullets(
                f"{item.get('evidence_type')} {item.get('entity_type')}={item.get('entity_value')} {item.get('summary')}"
                for item in evidence
                if isinstance(item, dict)
            )
            or "- none",
            "Classifications:",
            _join_bullets(
                f"{item.get('classification_type')}={item.get('classification_value')} ({item.get('confidence')})"
                for item in classifications
                if isinstance(item, dict)
            )
            or "- none",
            "Answer:",
            _normalize_text(answer.get("answer_summary") or request.get("answer_summary") or "") or "- none",
            _search_hint_block([request.get("question"), request.get("intent"), request.get("scope"), request.get("status"), request_uid]),
        ]
    )
    metadata = {"request": _safe_json(request), "entities": _safe_json(entities), "gaps": _safe_json(gaps), "tasks": _safe_json(tasks)}
    tags = [request.get("intent"), request.get("scope"), request.get("status"), request_uid] + [item.get("entity_value") for item in entities if isinstance(item, dict)]
    return _doc_result(
        object_type="learning_request",
        object_ref=request_uid,
        title=title,
        content=content,
        metadata=_attach_family_metadata(metadata, family_key=family_key, aliases=[request.get("question"), request.get("intent"), request.get("scope"), request_uid]),
        tags=tags,
        confidence="confirmed" if request.get("status") == "completed" else "suggested",
        source="learning_orchestrator",
    )


def build_routebrain_question_document(request_uid: str) -> dict[str, Any] | None:
    bundle = _learning_bundle(request_uid)
    if bundle is None:
        return None
    request = bundle.get("request") or {}
    entities = bundle.get("entities") or []
    title = f"Question {request_uid}"
    family_key = f"request:{request_uid}"
    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Question", request.get("question")),
                    ("Intent", request.get("intent")),
                    ("Scope", request.get("scope")),
                    ("Status", request.get("status")),
                ]
            ),
            "Entities:",
            _join_bullets(
                f"{item.get('entity_type')}={item.get('entity_value')}"
                for item in entities
                if isinstance(item, dict)
            )
            or "- none",
            "Gaps:",
            _join_bullets(
                f"{item.get('gap_type')} {item.get('description')}"
                for item in (bundle.get("gaps") or [])
                if isinstance(item, dict)
            )
            or "- none",
            _search_hint_block([request.get("question"), request.get("intent"), request.get("scope"), request_uid]),
        ]
    )
    return _doc_result(
        object_type="routebrain_question",
        object_ref=request_uid,
        title=title,
        content=content,
        metadata=_attach_family_metadata({"request": _safe_json(request), "entities": _safe_json(entities)}, family_key=family_key, aliases=[request.get("question"), request.get("intent"), request.get("scope"), request_uid]),
        tags=[request.get("intent"), request.get("scope"), request_uid] + [item.get("entity_value") for item in entities if isinstance(item, dict)],
        confidence="suggested",
        source="learning_orchestrator",
    )


def build_operational_answer_document(request_uid: str) -> dict[str, Any] | None:
    bundle = _learning_bundle(request_uid)
    if bundle is None:
        return None
    request = bundle.get("request") or {}
    answer = bundle.get("answer") or {}
    title = f"Operational answer {request_uid}"
    family_key = f"request:{request_uid}"
    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Question", request.get("question")),
                    ("Intent", request.get("intent")),
                    ("Status", request.get("status")),
                    ("Answer summary", answer.get("answer_summary") or request.get("answer_summary")),
                ]
            ),
            "Next actions:",
            _join_bullets(answer.get("next_actions") or []) or "- none",
            "Classifications:",
            _join_bullets(
                f"{item.get('classification_type')}={item.get('classification_value')} ({item.get('confidence')})"
                for item in (answer.get("classifications") or [])
                if isinstance(item, dict)
            )
            or "- none",
            _search_hint_block([request.get("question"), request.get("intent"), request_uid]),
        ]
    )
    return _doc_result(
        object_type="operational_answer",
        object_ref=request_uid,
        title=title,
        content=content,
        metadata=_attach_family_metadata({"request": _safe_json(request), "answer": _safe_json(answer)}, family_key=family_key, aliases=[request.get("question"), request.get("intent"), request_uid]),
        tags=[request.get("intent"), request.get("scope"), request.get("status"), request_uid],
        confidence="confirmed" if request.get("status") == "completed" else "suggested",
        source="learning_orchestrator",
    )


def build_learning_evidence_summary_document(request_uid: str) -> dict[str, Any] | None:
    bundle = _learning_bundle(request_uid)
    if bundle is None:
        return None
    request = bundle.get("request") or {}
    evidence = bundle.get("evidence") or []
    counts = Counter(str(item.get("evidence_type") or "unknown") for item in evidence if isinstance(item, dict))
    title = f"Evidence summary {request_uid}"
    family_key = f"request:{request_uid}"
    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Question", request.get("question")),
                    ("Intent", request.get("intent")),
                    ("Status", request.get("status")),
                    ("Evidence count", str(len(evidence))),
                ]
            ),
            "Evidence types:",
            _join_bullets(f"{etype}: {count}" for etype, count in counts.items()) or "- none",
            "Evidence samples:",
            _join_bullets(
                f"{item.get('evidence_type')} {item.get('entity_type')}={item.get('entity_value')} {item.get('summary')}"
                for item in evidence[:10]
                if isinstance(item, dict)
            )
            or "- none",
            _search_hint_block([request.get("question"), request.get("intent"), request_uid]),
        ]
    )
    return _doc_result(
        object_type="learning_evidence_summary",
        object_ref=request_uid,
        title=title,
        content=content,
        metadata=_attach_family_metadata({"request": _safe_json(request), "evidence": _safe_json(evidence), "counts": dict(counts)}, family_key=family_key, aliases=[request.get("question"), request.get("intent"), request_uid]),
        tags=[request.get("intent"), request.get("scope"), request_uid] + list(counts.keys()),
        confidence="suggested",
        source="learning_orchestrator",
    )


def build_learning_classification_summary_document(request_uid: str) -> dict[str, Any] | None:
    bundle = _learning_bundle(request_uid)
    if bundle is None:
        return None
    request = bundle.get("request") or {}
    classifications = bundle.get("classifications") or []
    title = f"Classification summary {request_uid}"
    family_key = f"request:{request_uid}"
    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Question", request.get("question")),
                    ("Intent", request.get("intent")),
                    ("Status", request.get("status")),
                    ("Classification count", str(len(classifications))),
                ]
            ),
            "Classifications:",
            _join_bullets(
                f"{item.get('entity_type')}={item.get('entity_value')} {item.get('classification_type')}={item.get('classification_value')} ({item.get('confidence')})"
                for item in classifications[:20]
                if isinstance(item, dict)
            )
            or "- none",
            _search_hint_block([request.get("question"), request.get("intent"), request_uid]),
        ]
    )
    tags = [request.get("intent"), request.get("scope"), request_uid] + [item.get("classification_type") for item in classifications if isinstance(item, dict)]
    return _doc_result(
        object_type="learning_classification_summary",
        object_ref=request_uid,
        title=title,
        content=content,
        metadata=_attach_family_metadata({"request": _safe_json(request), "classifications": _safe_json(classifications)}, family_key=family_key, aliases=[request.get("question"), request.get("intent"), request_uid]),
        tags=tags,
        confidence="suggested",
        source="learning_classifier",
    )


def build_domain_memory_document(domain: str) -> dict[str, Any] | None:
    normalized_domain = _normalize_text(domain).lower()
    if not normalized_domain:
        return None
    memory = get_learning_memory_for_domain(normalized_domain)
    if not memory:
        return None
    classifications = get_classifications_for_entity("domain", normalized_domain)
    title = f"Domain memory {normalized_domain}"
    dns = memory.get("dns") or {}
    ips = memory.get("ips") or []
    evidence_lines = []
    for ip_state in ips:
        if not isinstance(ip_state, dict):
            continue
        ip_value = str(ip_state.get("ip") or "").strip()
        if not ip_value:
            continue
        bgp_state = ip_state.get("bgp") or {}
        ping_state = ip_state.get("ping") or {}
        traceroute_state = ip_state.get("traceroute") or {}
        bgp_latest = bgp_state.get("latest") or {}
        ping_latest = ping_state.get("latest") or {}
        traceroute_latest = traceroute_state.get("latest") or {}
        ping_metrics = (ping_latest.get("data") or {}).get("metrics") or {}
        evidence_lines.append(
            f"{ip_value} | bgp={bgp_state.get('status')} {bgp_latest.get('evidence_type')} | "
            f"ping={ping_state.get('status')} {ping_metrics.get('packet_loss_percent')}%/{ping_metrics.get('rtt_avg_ms')}ms | "
            f"traceroute={traceroute_state.get('status')} {((traceroute_latest.get('data') or {}).get('total_hops'))} hops"
        )
    classification_lines = []
    for item in classifications.get("classifications", [])[:20]:
        if not isinstance(item, dict):
            continue
        classification_lines.append(
            f"{item.get('classification_type')}={item.get('classification_value')} ({item.get('confidence')})"
        )

    external_bits = []
    for ip_state in ips:
        if not isinstance(ip_state, dict):
            continue
        ip_value = str(ip_state.get("ip") or "").strip()
        if not ip_value:
            continue
        external_ip = get_external_ip_enrichment(ip_value)
        if external_ip is None:
            continue
        external_bits.append(
            f"{ip_value}: {external_ip.get('organization_name') or 'n/a'} / {external_ip.get('country') or 'n/a'} / {external_ip.get('network_name') or 'n/a'}"
        )

    content = "\n".join(
        [
            _format_key_values(
                [
                    ("Domain", normalized_domain),
                    ("DNS status", (dns.get("freshness") or {}).get("status")),
                    ("DNS age", (dns.get("freshness") or {}).get("age_human")),
                    ("Resolved IPs", ", ".join(dns.get("resolved_ips") or [])),
                    ("Memory freshness", str(memory.get("freshness"))),
                    ("Memory summary", memory.get("summary_text")),
                    ("Related requests", str(len(memory.get("related_requests") or []))),
                ]
            ),
            "BGP / Ping / Traceroute by IP:",
            _join_bullets(evidence_lines) or "- none",
            "Classifications:",
            _join_bullets(classification_lines) or "- none",
            "External enrichment:",
            _join_bullets(external_bits) or "- none",
            "Gaps:",
            _join_bullets(
                f"{item.get('gap_type')} {item.get('description')}"
                for item in (memory.get("related_requests") or [])
                if isinstance(item, dict)
            )
            or "- none",
            _search_hint_block(
                [
                    normalized_domain,
                    "cloudflare.com" if "cloudflare" in normalized_domain else None,
                    "Cloudflare Inc" if "cloudflare" in normalized_domain else None,
                    "Cloudflare, Inc." if "cloudflare" in normalized_domain else None,
                    "CDN" if "cloudflare" in normalized_domain else None,
                    "edge" if "cloudflare" in normalized_domain else None,
                    "anycast" if "cloudflare" in normalized_domain else None,
                    "low latency" if "cloudflare" in normalized_domain else None,
                    "baixa latência" if "cloudflare" in normalized_domain else None,
                    "IPv4 respondeu" if "cloudflare" in normalized_domain else None,
                    "IPv6 100% loss" if "cloudflare" in normalized_domain else None,
                    "bgp_coverage no_local_match" if "cloudflare" in normalized_domain else None,
                    "ping 10 ms" if "cloudflare" in normalized_domain else None,
                    "traceroute" if "cloudflare" in normalized_domain else None,
                    "baidu.com" if "baidu" in normalized_domain else None,
                    "China" if "baidu" in normalized_domain else None,
                    "CN" if "baidu" in normalized_domain else None,
                    "alta latência internacional" if "baidu" in normalized_domain else None,
                    "very_high_latency" if "baidu" in normalized_domain else None,
                    "international_high_latency" if "baidu" in normalized_domain else None,
                    "route_category international_high_latency" if "baidu" in normalized_domain else None,
                    "latency_category very_high_latency" if "baidu" in normalized_domain else None,
                    "BGP no-match" if "baidu" in normalized_domain else None,
                    "ping 311 ms" if "baidu" in normalized_domain else None,
                    "ping 373 ms" if "baidu" in normalized_domain else None,
                    "traceroute longo" if "baidu" in normalized_domain else None,
                    "PTT-CE" if normalized_domain == "ptt-ce" else None,
                    "IX.br CE" if normalized_domain == "ptt-ce" else None,
                    "IX.br/CE" if normalized_domain == "ptt-ce" else None,
                ]
            ),
        ]
    )
    metadata = {"memory": _safe_json(memory), "classifications": _safe_json(classifications)}
    aliases = [normalized_domain]
    if "cloudflare" in normalized_domain:
        aliases.extend(
            [
                "cloudflare",
                "cloudflare.com",
                "Cloudflare Inc",
                "Cloudflare, Inc.",
                "CDN",
                "edge",
                "anycast",
                "low latency",
                "baixa latência",
                "IPv4 respondeu",
                "IPv6 100% loss",
                "bgp_coverage no_local_match",
                "ping 10 ms",
                "traceroute",
            ]
        )
    if "baidu" in normalized_domain:
        aliases.extend(
            [
                "baidu",
                "baidu.com",
                "China",
                "CN",
                "alta latência internacional",
                "very_high_latency",
                "international_high_latency",
                "route_category international_high_latency",
                "latency_category very_high_latency",
                "destino chinês",
                "rota internacional",
                "ping 311 ms",
                "ping 373 ms",
                "traceroute longo",
                "BGP no-match",
            ]
        )
    if normalized_domain == "ptt-ce":
        aliases.extend(
            [
                "PTT-CE",
                "IX.br CE",
                "IX.br/CE",
                "IX Fortaleza",
                "participantes públicos",
                "916 participantes",
                "877 vistos como origin",
                "nenhum host confirmado",
                "inventário interno",
                "public_ix_context",
            ]
        )
    tags = [normalized_domain, "domain", "learning_memory"] + aliases
    if "cloudflare" in normalized_domain:
        tags.extend(["cloudflare", "cdn"])
    if "baidu" in normalized_domain:
        tags.extend(["baidu", "china", "high-latency"])
    return _doc_result(
        object_type="domain_memory",
        object_ref=normalized_domain,
        title=title,
        content=content,
        metadata=_attach_family_metadata(metadata, family_key=f"domain:{normalized_domain}", aliases=aliases),
        tags=tags,
        confidence="confirmed" if dns.get("freshness", {}).get("status") == "fresh" else "suggested",
        source="learning_memory",
    )


def _inventory_documents(limit: int | None = None) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    seen_hostnames: set[str] = set()
    site_rows = list_sites()
    if limit is not None:
        site_rows = site_rows[:limit]
    for site in site_rows:
        site_code = str(site.get("site_code") or "").strip()
        if not site_code:
            continue
        spec = build_inventory_site_document(site_code)
        if spec is not None:
            docs.append(spec)
        host_rows = list_hosts(site_code=site_code, limit=DEFAULT_LIMIT)
        for host in host_rows:
            hostname = str(host.get("hostname") or "").strip()
            if not hostname:
                continue
            seen_hostnames.add(hostname.lower())
            spec = build_inventory_host_document(hostname)
            if spec is not None:
                docs.append(spec)
            host_full = get_host(hostname)
            if host_full is None:
                continue
            for interface in host_full.get("interfaces") or []:
                if not isinstance(interface, dict):
                    continue
                interface_name = str(interface.get("interface_name") or "").strip()
                if not interface_name:
                    continue
                spec = build_inventory_interface_document(hostname, interface_name)
                if spec is not None:
                    docs.append(spec)
            for peer_link in host_full.get("peer_links") or []:
                if not isinstance(peer_link, dict):
                    continue
                peer_ip = str(peer_link.get("peer_ip") or "").strip()
                if not peer_ip:
                    continue
                spec = build_inventory_peer_link_document(hostname, peer_ip, peer_link.get("peer_asn"))
                if spec is not None:
                    docs.append(spec)
    for host in list_hosts(limit=DEFAULT_LIMIT):
        hostname = str(host.get("hostname") or "").strip()
        if not hostname or hostname.lower() in seen_hostnames:
            continue
        spec = build_inventory_host_document(hostname)
        if spec is not None:
            docs.append(spec)
        host_full = get_host(hostname)
        if host_full is None:
            continue
        for interface in host_full.get("interfaces") or []:
            if not isinstance(interface, dict):
                continue
            interface_name = str(interface.get("interface_name") or "").strip()
            if not interface_name:
                continue
            spec = build_inventory_interface_document(hostname, interface_name)
            if spec is not None:
                docs.append(spec)
        for peer_link in host_full.get("peer_links") or []:
            if not isinstance(peer_link, dict):
                continue
            peer_ip = str(peer_link.get("peer_ip") or "").strip()
            if not peer_ip:
                continue
            spec = build_inventory_peer_link_document(hostname, peer_ip, peer_link.get("peer_asn"))
            if spec is not None:
                docs.append(spec)
    return docs


def _domain_objects(limit: int | None = None) -> list[str]:
    rows = _fetch_all(
        """
        select distinct lower(entity_value) as domain
        from learning_entities
        where entity_type = 'domain'
        order by domain asc;
        """
    )
    domains = [str(row.get("domain") or "").strip() for row in rows if str(row.get("domain") or "").strip()]
    if limit is not None:
        return domains[:limit]
    return domains


def _learning_documents(limit: int | None = None) -> list[dict[str, Any]]:
    rows = list_learning_requests(limit=limit or DEFAULT_LIMIT)
    docs: list[dict[str, Any]] = []
    for request in rows:
        request_uid = str(request.get("request_uid") or "").strip()
        if not request_uid:
            continue
        for builder in (
            build_learning_request_document,
            build_routebrain_question_document,
            build_operational_answer_document,
            build_learning_evidence_summary_document,
            build_learning_classification_summary_document,
        ):
            spec = builder(request_uid)
            if spec is not None:
                docs.append(spec)
    return docs


def _ixbr_documents(limit: int | None = None) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    external_asn_map = {
        int(row.get("asn")): row
        for row in _fetch_all(
            """
            select
              asn,
              source_priority,
              organization_name,
              country,
              network_name,
              website,
              looking_glass,
              route_server,
              network_type,
              info_type,
              info_prefixes4,
              info_prefixes6,
              peering_policy,
              source,
              confidence,
              raw_data,
              fetched_at
            from external_asn_enrichment;
            """
        )
        if row.get("asn") is not None
    }
    location_rows = list_ixbr_locations()
    if limit is not None:
        location_rows = location_rows[:limit]
    for location in location_rows:
        locality_code = str(location.get("locality_code") or "").strip().upper()
        if not locality_code:
            continue
        participants = list_ixbr_participants(locality_code=locality_code, limit=DEFAULT_LIMIT)
        for participant in participants:
            asn = participant.get("asn")
            if asn is None:
                continue
            spec = _build_ixbr_participant_document_from_row(
                participant,
                external_asn=external_asn_map.get(int(asn)),
            )
            if spec is not None:
                docs.append(spec)
    return docs


def _enrichment_documents(limit: int | None = None) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    asn_rows = _fetch_all(
        """
        select asn
        from external_asn_enrichment
        order by asn asc;
        """
    )
    if limit is not None:
        asn_rows = asn_rows[:limit]
    for row in asn_rows:
        asn = row.get("asn")
        if asn is None:
            continue
        spec = build_external_asn_document(int(asn))
        if spec is not None:
            docs.append(spec)
    ip_rows = _fetch_all(
        """
        select host(ip) as ip
        from external_ip_enrichment
        order by ip asc;
        """
    )
    for row in ip_rows:
        ip_value = str(row.get("ip") or "").strip()
        if not ip_value:
            continue
        spec = build_external_ip_document(ip_value)
        if spec is not None:
            docs.append(spec)
    return docs


def _domain_documents(limit: int | None = None) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    domains = _domain_objects(limit=limit)
    for domain in domains:
        spec = build_domain_memory_document(domain)
        if spec is not None:
            docs.append(spec)
    return docs


def _apply_document_specs(
    specs: list[dict[str, Any]],
    *,
    conn: psycopg.Connection | None = None,
    dry_run: bool = False,
    skip_existing: bool = True,
    force: bool = False,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for spec in specs:
        object_type = str(spec.get("object_type") or "")
        object_ref = str(spec.get("object_ref") or "")
        title = spec.get("title")
        content = str(spec.get("content") or "")
        metadata = spec.get("metadata") or {}
        tags = spec.get("tags") or []
        confidence = str(spec.get("confidence") or "suggested")
        source = spec.get("source")
        document_uid = make_document_uid(object_type, object_ref)
        existing = _document_row(document_uid, conn=conn)
        new_hash = _content_hash(content)
        if existing is None:
            status = "created"
        elif str(existing.get("content_hash") or "") == new_hash:
            status = "unchanged"
        else:
            status = "updated"
        if dry_run:
            results.append(
                {
                    "status": status,
                    "document_uid": document_uid,
                    "object_type": object_type,
                    "object_ref": object_ref,
                    "title": title,
                    "embedding_status": "text_only",
                }
            )
            continue
        if existing is not None and skip_existing and status == "unchanged" and not force:
            results.append(
                {
                    "status": "unchanged",
                    "document_uid": document_uid,
                    "object_type": object_type,
                    "object_ref": object_ref,
                    "title": title,
                    "embedding_status": existing.get("embedding_status") or "text_only",
                }
            )
            continue
        result = upsert_semantic_document(
            object_type,
            object_ref,
            title,
            content,
            metadata=metadata,
            tags=tags,
            confidence=confidence,
            source=source,
            conn=conn,
            force=force or not skip_existing,
        )
        results.append(result)
    return results


def rebuild_semantic_documents(
    scope: str = "all",
    *,
    limit: int | None = None,
    dry_run: bool = False,
    skip_existing: bool = True,
    force: bool = False,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    normalized_scope = _normalize_scope(scope)
    normalized_limit = _clamp_limit(limit)
    providers = {
        "inventory": _inventory_documents,
        "learning": _learning_documents,
        "domains": _domain_documents,
        "ixbr": _ixbr_documents,
        "enrichment": _enrichment_documents,
    }
    selected_scopes = list(providers.keys()) if normalized_scope == "all" else [normalized_scope]
    specs: list[dict[str, Any]] = []
    for selected_scope in selected_scopes:
        specs.extend(providers[selected_scope](limit=normalized_limit))

    results = _apply_document_specs(
        specs,
        conn=conn,
        dry_run=dry_run,
        skip_existing=skip_existing,
        force=force,
    )

    counts = Counter(str(item.get("status") or "unknown") for item in results)
    by_object_type = Counter(str(item.get("object_type") or "unknown") for item in results)
    embedding_status_counts = Counter(
        str(row.get("embedding_status") or "text_only")
        for row in list_semantic_documents(limit=DEFAULT_LIMIT * 20, conn=conn)
    )
    errors = [item for item in results if item.get("status") == "error"]
    return {
        "scope": normalized_scope,
        "limit": normalized_limit,
        "dry_run": dry_run,
        "skip_existing": skip_existing,
        "force": force,
        "status": "ok" if not errors else "partial",
        "total_documents": len(results),
        "created": counts.get("created", 0),
        "updated": counts.get("updated", 0),
        "unchanged": counts.get("unchanged", 0),
        "by_object_type": dict(by_object_type),
        "embedding_status_counts": dict(embedding_status_counts),
        "documents": results,
        "errors": errors,
        "provider": {
            "provider": provider_name(),
            "model": embedding_model(),
            "dim": embedding_dim(),
            "available": is_available(),
        },
        "search_mode": TEXT_SEARCH_MODE,
    }


def _record_search_run(
    query: str,
    search_mode: str,
    status: str,
    results_count: int = 0,
    metadata: dict[str, Any] | None = None,
    error: str | None = None,
    *,
    conn: psycopg.Connection | None = None,
) -> None:
    payload = _json_value(metadata or {})
    _execute(
        """
        insert into semantic_search_runs (
          query,
          search_mode,
          status,
          results_count,
          started_at,
          finished_at,
          error,
          metadata
        )
        values (%s, %s, %s, %s, now(), now(), %s, %s);
        """,
        (query, search_mode, status, results_count, error, payload),
        conn=conn,
    )


def _finalize_semantic_search_rows(
    *,
    normalized_query: str,
    query_tokens: list[str],
    scored_rows: list[dict[str, Any]],
    search_mode: str,
    object_type: str | None,
    limit: int,
    conn: psycopg.Connection | None = None,
    metadata: dict[str, Any] | None = None,
    debug_timing: dict[str, float] | None = None,
    record_search: bool = True,
) -> dict[str, Any]:
    started_finalize = datetime.now().timestamp()
    started_grouping = datetime.now().timestamp()
    started_sorting = datetime.now().timestamp()
    grouped: dict[str, dict[str, Any]] = {}
    ordered_rows = sorted(
        scored_rows,
        key=lambda row: (
            float(row.get("score") or 0.0),
            float(row.get("vector_score") or row.get("raw_vector_score") or 0.0),
            float(row.get("text_score") or 0.0),
            float(row.get("object_type_weight") or 0.0),
            float(row.get("intent_boost") or 0.0),
            row.get("updated_at") or datetime.min.replace(tzinfo=timezone.utc),
            row.get("document_uid") or "",
        ),
        reverse=True,
    )
    if debug_timing is not None:
        debug_timing["sorting_seconds"] = max(0.0, datetime.now().timestamp() - started_sorting)
    for row in ordered_rows:
        started_family_key = datetime.now().timestamp()
        family_key = str(row.get("family_key") or "")
        if debug_timing is not None:
            debug_timing["family_key_total_seconds"] = float(debug_timing.get("family_key_total_seconds") or 0.0) + max(
                0.0, datetime.now().timestamp() - started_family_key
            )
        entry = grouped.get(family_key)
        if entry is None:
            row["related_count"] = 1
            row["related_object_types"] = [row.get("object_type")]
            grouped[family_key] = row
            continue
        entry["related_count"] = int(entry.get("related_count") or 1) + 1
        related_types = list(entry.get("related_object_types") or [])
        row_type = row.get("object_type")
        if row_type and row_type not in related_types:
            related_types.append(row_type)
            entry["related_object_types"] = related_types
    if debug_timing is not None:
        debug_timing["grouping_seconds"] = max(0.0, datetime.now().timestamp() - started_grouping)

    started_ranking = datetime.now().timestamp()
    results = sorted(
        grouped.values(),
        key=lambda row: (
            float(row.get("score") or 0.0),
            float(row.get("vector_score") or row.get("raw_vector_score") or 0.0),
            float(row.get("text_score") or 0.0),
            float(row.get("object_type_weight") or 0.0),
            float(row.get("intent_boost") or 0.0),
            int(row.get("related_count") or 1),
            row.get("updated_at") or datetime.min.replace(tzinfo=timezone.utc),
            row.get("document_uid") or "",
        ),
        reverse=True,
    )
    if debug_timing is not None:
        debug_timing["ranking_seconds"] = max(0.0, datetime.now().timestamp() - started_ranking)

    normalized_limit = _clamp_limit(limit) or len(results)
    started_limit_slice = datetime.now().timestamp()
    results = results[:normalized_limit]
    if debug_timing is not None:
        debug_timing["limit_slice_seconds"] = max(0.0, datetime.now().timestamp() - started_limit_slice)

    started_debug_reason = datetime.now().timestamp()
    for row in results:
        row["reason"] = _build_search_result_reason(row)
        row["debug"] = _ranking_debug(row)
        row.pop("matched_title", None)
        row.pop("matched_content", None)
        row.pop("matched_tags", None)
        row.pop("matched_metadata", None)
        row.pop("matched_object_ref", None)
        row.pop("matched_tokens", None)
        row.pop("matched_aliases", None)
        row.pop("exact_phrase", None)
        row.pop("query_intent_boost", None)
    if debug_timing is not None:
        debug_timing["debug_reason_seconds"] = max(0.0, datetime.now().timestamp() - started_debug_reason)

    started_record = datetime.now().timestamp()
    if record_search:
        _record_search_run(
            normalized_query,
            search_mode,
            "ok" if results else "empty",
            results_count=len(results),
            metadata={
                "object_type": object_type,
                "grouping": "family_key",
                "query_tokens": query_tokens,
                "query_profile": (metadata or {}).get("query_profile"),
                "query_profile_reason": (metadata or {}).get("query_profile_reason"),
                **(metadata or {}),
            },
            conn=conn,
        )
    if debug_timing is not None:
        debug_timing["record_search_run_seconds"] = max(0.0, datetime.now().timestamp() - started_record)

    started_response = datetime.now().timestamp()
    response = {
        "query": normalized_query,
        "search_mode": search_mode,
        "object_type": object_type,
        "grouping": "family_key",
        "query_tokens": query_tokens,
        "results_count": len(results),
        "results": results,
        "embedding_provider": {
            "provider": provider_name(),
            "model": embedding_model(),
            "dim": embedding_dim(),
            "available": is_available(),
        },
    }
    if debug_timing is not None:
        debug_timing["response_build_seconds"] = max(0.0, datetime.now().timestamp() - started_response)
        debug_timing["finalize_total_seconds"] = max(0.0, datetime.now().timestamp() - started_finalize)
        debug_timing["returned_results_count"] = len(results)
    return response


def _semantic_vector_search(
    query: str,
    *,
    limit: int,
    object_type: str | None,
    query_tokens: list[str],
    conn: psycopg.Connection | None = None,
    debug_timing: dict[str, float] | None = None,
    record_search: bool = True,
) -> dict[str, Any] | None:
    if not is_available():
        return None
    if provider_name() != "bge_m3_flagembedding" or embedding_model() != EMBEDDING_FUTURE_MODEL or embedding_dim() != EMBEDDING_FUTURE_DIM:
        return None
    try:
        started_sql = datetime.now().timestamp()
        vector_ready = _fetch_one(
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
            """,
            conn=conn,
        )
        if debug_timing is not None:
            debug_timing["vector_capability_check_seconds"] = max(0.0, datetime.now().timestamp() - started_sql)
        if not vector_ready or not vector_ready.get("extension_installed") or not vector_ready.get("embedding_column_present"):
            return None
        started_embedding = datetime.now().timestamp()
        metrics_before = get_embedding_provider_metrics() if debug_timing is not None else {}
        if debug_timing is not None:
            provider_state = metrics_before.get("provider") or get_embedding_provider().describe()
            debug_timing["provider_cached"] = bool(provider_state.get("model_loaded"))
            debug_timing["provider_load_seconds"] = float(provider_state.get("load_seconds") or 0.0)
        query_embedding = embed_query_cached(query)
        if debug_timing is not None:
            metrics_after = get_embedding_provider_metrics()
            debug_timing["query_embedding_seconds"] = max(0.0, datetime.now().timestamp() - started_embedding)
            debug_timing["query_embedding_cache_hit"] = bool(metrics_after.get("last_query_cache_hit"))
            debug_timing["embed_call_count_delta"] = int(metrics_after.get("total_embed_calls") or 0) - int(
                metrics_before.get("total_embed_calls") or 0
            )
            debug_timing["query_cache_hits_delta"] = int(metrics_after.get("cache_hits") or 0) - int(
                metrics_before.get("cache_hits") or 0
            )
            debug_timing["query_cache_misses_delta"] = int(metrics_after.get("cache_misses") or 0) - int(
                metrics_before.get("cache_misses") or 0
            )
        if not query_embedding:
            return None
        if len(query_embedding) != embedding_dim():
            return None
        normalized_object_type = _normalize_text(object_type)
        vector_text = _vector_literal(query_embedding)
        query_profile = _infer_query_profile(query, query_tokens)
        candidate_limit = max(int(limit or 10) * 8, VECTOR_CANDIDATE_LIMIT)
        started_sql = datetime.now().timestamp()
        with (conn or get_connection()) as fresh_conn:
            rows = _fetch_all(
                """
                select
                  d.id,
                  d.document_uid,
                  d.object_type,
                  d.object_ref,
                  d.title,
                  d.content,
                  d.content_hash,
                  d.source,
                  d.confidence,
                  d.tags,
                  d.metadata,
                  d.created_at,
                  d.updated_at,
                  d.embedded_at,
                  d.embedding_status as document_embedding_status,
                  d.embedding_model as document_embedding_model,
                  d.embedding_error as document_embedding_error,
                  e.embedding_model,
                  e.provider as embedding_provider,
                  e.embedding_dim,
                  e.status as embedding_status,
                  e.error as embedding_error,
                  e.embedding <=> %s::vector as vector_distance
                from semantic_documents d
                join semantic_embeddings e
                  on e.document_id = d.id
                where (%s::text is null or d.object_type = %s::text)
                  and e.embedding_model = %s::text
                  and e.provider = %s::text
                  and coalesce(e.status, 'ok') = 'ok'
                order by e.embedding <=> %s::vector asc, d.updated_at desc, d.id desc
                limit %s;
                """,
                (
                    vector_text,
                    normalized_object_type or None,
                    normalized_object_type or None,
                    embedding_model(),
                    provider_name(),
                    vector_text,
                    candidate_limit,
                ),
                conn=fresh_conn,
            )
            preferred_object_type = _normalize_text(query_profile.get("preferred"))
            if preferred_object_type and not normalized_object_type:
                preferred_rows = _fetch_all(
                    """
                    select
                      d.id,
                      d.document_uid,
                      d.object_type,
                      d.object_ref,
                      d.title,
                      d.content,
                      d.content_hash,
                      d.source,
                      d.confidence,
                      d.tags,
                      d.metadata,
                      d.created_at,
                      d.updated_at,
                      d.embedded_at,
                      d.embedding_status as document_embedding_status,
                      d.embedding_model as document_embedding_model,
                      d.embedding_error as document_embedding_error,
                      e.embedding_model,
                      e.provider as embedding_provider,
                      e.embedding_dim,
                      e.status as embedding_status,
                      e.error as embedding_error,
                      e.embedding <=> %s::vector as vector_distance
                    from semantic_documents d
                    join semantic_embeddings e
                      on e.document_id = d.id
                    where d.object_type = %s::text
                      and e.embedding_model = %s::text
                      and e.provider = %s::text
                      and coalesce(e.status, 'ok') = 'ok'
                    order by e.embedding <=> %s::vector asc, d.updated_at desc, d.id desc
                    limit %s;
                    """,
                    (
                        vector_text,
                        preferred_object_type,
                        embedding_model(),
                        provider_name(),
                        vector_text,
                        candidate_limit,
                    ),
                    conn=fresh_conn,
                )
                seen_ids = {row.get("id") for row in rows}
                for preferred_row in preferred_rows:
                    if preferred_row.get("id") not in seen_ids:
                        rows.append(preferred_row)
                        seen_ids.add(preferred_row.get("id"))
        if debug_timing is not None:
            debug_timing["pgvector_sql_seconds"] = max(0.0, datetime.now().timestamp() - started_sql)
            debug_timing["rows_fetched_count"] = len(rows)
            debug_timing["candidate_limit"] = candidate_limit
            debug_timing["preferred_object_type"] = preferred_object_type or ""

        started_ranking = datetime.now().timestamp()
        scored_rows: list[dict[str, Any]] = []
        for row in rows:
            vector_distance = float(row.get("vector_distance") or 0.0)
            vector_score = 1.0 - vector_distance
            started_text_score = datetime.now().timestamp()
            text_info = _text_match_score(row=row, normalized_query=query, query_tokens=query_tokens)
            if debug_timing is not None:
                debug_timing["text_score_total_seconds"] = float(debug_timing.get("text_score_total_seconds") or 0.0) + max(
                    0.0, datetime.now().timestamp() - started_text_score
                )
            object_type_weight = _object_type_weight(row.get("object_type"), query_profile)
            intent_boost = _intent_boost(row.get("object_type"), query_profile)
            hybrid_score = _hybrid_score(
                vector_score=vector_score,
                text_score=float(text_info["text_score"] or 0.0),
                object_type_weight=object_type_weight,
                intent_boost=intent_boost,
                confidence_bonus=float(text_info["confidence_bonus"] or 0.0),
            )
            scored_rows.append(
                {
                    "document_uid": row.get("document_uid"),
                    "object_type": row.get("object_type"),
                    "object_ref": row.get("object_ref"),
                    "title": row.get("title"),
                    "snippet": text_info["snippet"],
                    "score": hybrid_score,
                    "hybrid_score": hybrid_score,
                    "raw_vector_score": vector_score,
                    "vector_score": vector_score,
                    "vector_distance": vector_distance,
                    "text_score": float(text_info["text_score"] or 0.0),
                    "object_type_weight": object_type_weight,
                    "intent_boost": intent_boost,
                    "confidence": row.get("confidence"),
                    "tags": list(text_info["tags"] or []),
                    "metadata": _result_metadata(text_info["metadata"] or {}, _family_key_for_row(row)),
                    "search_mode": VECTOR_SEARCH_MODE,
                    "query_intent": query_profile.get("profile"),
                    "query_intent_reason": query_profile.get("reason"),
                    "matched_title": bool(text_info["matched_title"]),
                    "matched_content": bool(text_info["matched_content"]),
                    "matched_tags": bool(text_info["matched_tags"]),
                    "matched_metadata": bool(text_info["matched_metadata"]),
                    "matched_aliases": bool(text_info["matched_aliases"]),
                    "matched_object_ref": bool(text_info["matched_object_ref"]),
                    "matched_tokens": list(text_info["matched_tokens"] or []),
                    "exact_phrase": bool(text_info["exact_phrase"]),
                    "created_at": row.get("created_at"),
                    "updated_at": row.get("updated_at"),
                    "embedded_at": row.get("embedded_at"),
                    "embedding_status": row.get("embedding_status") or row.get("document_embedding_status"),
                    "embedding_model": row.get("embedding_model") or row.get("document_embedding_model"),
                    "embedding_error": row.get("embedding_error") or row.get("document_embedding_error"),
                    "embedding_provider": row.get("embedding_provider"),
                    "embedding_dim": row.get("embedding_dim"),
                    "family_key": _family_key_for_row(row),
                }
            )

        if not scored_rows:
            return None
        if debug_timing is not None:
            debug_timing["vector_ranking_seconds"] = max(0.0, datetime.now().timestamp() - started_ranking)
            debug_timing["candidate_results_count"] = len(scored_rows)

        return _finalize_semantic_search_rows(
            normalized_query=_normalize_text(query),
            query_tokens=query_tokens,
            scored_rows=scored_rows,
            search_mode=VECTOR_SEARCH_MODE,
            object_type=normalized_object_type or None,
            limit=limit,
            conn=conn,
            metadata={
                "vector": True,
                "provider": provider_name(),
                "model": embedding_model(),
                "dim": embedding_dim(),
                "query_profile": query_profile.get("profile"),
                "query_profile_reason": query_profile.get("reason"),
            },
            debug_timing=debug_timing,
            record_search=record_search,
        )
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.warning("semantic hybrid vector search failed; falling back to text search: %s", exc)
        return None


def semantic_search(
    query: str,
    limit: int = 10,
    object_type: str | None = None,
    *,
    conn: psycopg.Connection | None = None,
    debug_timing: dict[str, float] | None = None,
    record_search: bool = True,
) -> dict[str, Any]:
    normalized_query = _normalize_text(query)
    if not normalized_query:
        raise ValueError("Busca vazia.")
    normalized_limit = _clamp_limit(limit) or 10
    normalized_object_type = _normalize_text(object_type)
    query_tokens = _search_tokens(normalized_query)
    query_profile = _infer_query_profile(normalized_query, query_tokens)

    started_total = datetime.now().timestamp()
    vector_result = _semantic_vector_search(
        normalized_query,
        limit=normalized_limit,
        object_type=normalized_object_type or None,
        query_tokens=query_tokens,
        conn=conn,
        debug_timing=debug_timing,
        record_search=record_search,
    )
    if vector_result is not None:
        if debug_timing is not None:
            debug_timing["total_seconds"] = max(0.0, datetime.now().timestamp() - started_total)
        return vector_result

    started_sql = datetime.now().timestamp()
    with (conn or get_connection()) as fresh_conn:
        rows = _fetch_all(
            """
            select
              id,
              document_uid,
              object_type,
              object_ref,
              title,
              content,
              content_hash,
              source,
              confidence,
              tags,
              metadata,
              created_at,
              updated_at,
              embedded_at,
              embedding_status,
              embedding_model,
              embedding_error
            from semantic_documents
            where (%s::text is null or object_type = %s::text)
            order by updated_at desc, id desc;
            """,
            (normalized_object_type or None, normalized_object_type or None),
            conn=fresh_conn,
        )
    if debug_timing is not None:
        debug_timing["text_sql_seconds"] = max(0.0, datetime.now().timestamp() - started_sql)

    started_ranking = datetime.now().timestamp()
    scored_rows: list[dict[str, Any]] = []
    for row in rows:
        text_info = _text_match_score(row=row, normalized_query=normalized_query, query_tokens=query_tokens)
        if float(text_info["text_score"] or 0.0) <= 0:
            continue
        object_type_weight = _object_type_weight(row.get("object_type"), query_profile)
        intent_boost = _intent_boost(row.get("object_type"), query_profile)
        hybrid_score = _hybrid_score(
            vector_score=None,
            text_score=float(text_info["text_score"] or 0.0),
            object_type_weight=object_type_weight,
            intent_boost=intent_boost,
            confidence_bonus=float(text_info["confidence_bonus"] or 0.0),
        )

        scored_rows.append(
            {
                "document_uid": row.get("document_uid"),
                "object_type": row.get("object_type"),
                "object_ref": row.get("object_ref"),
                "title": row.get("title"),
                "snippet": text_info["snippet"],
                "score": hybrid_score,
                "hybrid_score": hybrid_score,
                "raw_vector_score": None,
                "vector_score": None,
                "text_score": float(text_info["text_score"] or 0.0),
                "object_type_weight": object_type_weight,
                "intent_boost": intent_boost,
                "confidence": row.get("confidence"),
                "tags": list(text_info["tags"] or []),
                "metadata": _result_metadata(text_info["metadata"] or {}, _family_key_for_row(row)),
                "search_mode": TEXT_SEARCH_MODE,
                "query_intent": query_profile.get("profile"),
                "query_intent_reason": query_profile.get("reason"),
                "matched_title": bool(text_info["matched_title"]),
                "matched_content": bool(text_info["matched_content"]),
                "matched_tags": bool(text_info["matched_tags"]),
                "matched_metadata": bool(text_info["matched_metadata"]),
                "matched_aliases": bool(text_info["matched_aliases"]),
                "matched_object_ref": bool(text_info["matched_object_ref"]),
                "matched_tokens": list(text_info["matched_tokens"] or []),
                "exact_phrase": bool(text_info["exact_phrase"]),
                "created_at": row.get("created_at"),
                "updated_at": row.get("updated_at"),
                "embedded_at": row.get("embedded_at"),
                "embedding_status": row.get("embedding_status"),
                "embedding_model": row.get("embedding_model"),
                "embedding_error": row.get("embedding_error"),
                "family_key": _family_key_for_row(row),
            }
        )
    return _finalize_semantic_search_rows(
        normalized_query=normalized_query,
        query_tokens=query_tokens,
        scored_rows=scored_rows,
        search_mode=TEXT_SEARCH_MODE,
        object_type=normalized_object_type or None,
        limit=normalized_limit,
        conn=conn,
        metadata={
            "query_profile": query_profile.get("profile"),
            "query_profile_reason": query_profile.get("reason"),
        },
        debug_timing=debug_timing,
        record_search=record_search,
    )


def _parse_vector_dim(type_name: str | None) -> int | None:
    match = re.search(r"vector\((\d+)\)", str(type_name or ""))
    return int(match.group(1)) if match else None


def semantic_healthcheck() -> dict[str, Any]:
    started = datetime.now().timestamp()
    warnings: list[str] = []
    errors: list[str] = []
    expected_dim = EMBEDDING_FUTURE_DIM
    expected_search_mode = VECTOR_SEARCH_MODE
    expected_top = {"object_type": "domain_memory", "object_ref": "cloudflare.com"}

    try:
        provider_metrics = get_embedding_provider_metrics()
    except Exception as exc:  # pragma: no cover - defensive provider diagnostics
        provider_metrics = {}
        warnings.append(f"provider_metrics_unavailable: {exc}")
    provider_info = dict(provider_metrics.get("provider") or get_embedding_provider().describe())
    provider_available = bool(provider_info.get("is_available") or provider_info.get("available"))
    configured_provider = str(provider_info.get("provider_name") or provider_info.get("provider") or provider_name())
    if configured_provider in {"none", "text_fallback"} or not provider_available:
        warnings.append("vector_provider_unavailable_text_fallback_possible")

    schema = {
        "semantic_documents_exists": False,
        "semantic_embeddings_exists": False,
        "embedding_column_exists": False,
        "embedding_dim_column_exists": False,
    }
    pgvector = {
        "installed": False,
        "version": None,
        "embedding_column_exists": False,
        "embedding_column_type": None,
        "embedding_column_dim": None,
        "expected_dim": expected_dim,
        "embedding_dim_column_exists": False,
        "embedding_dim_distribution": [],
    }
    documents = {
        "semantic_documents": 0,
        "semantic_embeddings": 0,
        "embedded": 0,
        "ok_embeddings": 0,
    }

    try:
        schema_row = _fetch_one(
            """
            select
              to_regclass('public.semantic_documents') is not null as semantic_documents_exists,
              to_regclass('public.semantic_embeddings') is not null as semantic_embeddings_exists,
              exists(select 1 from pg_extension where extname = 'vector') as vector_installed,
              (select extversion from pg_extension where extname = 'vector') as vector_version,
              exists(
                select 1
                from information_schema.columns
                where table_schema = 'public'
                  and table_name = 'semantic_embeddings'
                  and column_name = 'embedding'
              ) as embedding_column_exists,
              exists(
                select 1
                from information_schema.columns
                where table_schema = 'public'
                  and table_name = 'semantic_embeddings'
                  and column_name = 'embedding_dim'
              ) as embedding_dim_column_exists,
              (
                select format_type(a.atttypid, a.atttypmod)
                from pg_attribute a
                join pg_class c on c.oid = a.attrelid
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = 'public'
                  and c.relname = 'semantic_embeddings'
                  and a.attname = 'embedding'
                  and not a.attisdropped
                limit 1
              ) as embedding_column_type;
            """
        ) or {}
        schema.update(
            {
                "semantic_documents_exists": bool(schema_row.get("semantic_documents_exists")),
                "semantic_embeddings_exists": bool(schema_row.get("semantic_embeddings_exists")),
                "embedding_column_exists": bool(schema_row.get("embedding_column_exists")),
                "embedding_dim_column_exists": bool(schema_row.get("embedding_dim_column_exists")),
            }
        )
        pgvector.update(
            {
                "installed": bool(schema_row.get("vector_installed")),
                "version": schema_row.get("vector_version"),
                "embedding_column_exists": bool(schema_row.get("embedding_column_exists")),
                "embedding_column_type": schema_row.get("embedding_column_type"),
                "embedding_column_dim": _parse_vector_dim(schema_row.get("embedding_column_type")),
                "embedding_dim_column_exists": bool(schema_row.get("embedding_dim_column_exists")),
            }
        )
    except Exception as exc:
        errors.append(f"semantic_schema_check_failed: {exc}")

    if not schema["semantic_documents_exists"]:
        errors.append("semantic_documents_missing")
    if not schema["semantic_embeddings_exists"]:
        errors.append("semantic_embeddings_missing")
    if not pgvector["installed"]:
        errors.append("pgvector_extension_missing")
    if schema["semantic_embeddings_exists"] and not pgvector["embedding_column_exists"]:
        errors.append("semantic_embeddings_embedding_column_missing")
    if pgvector["embedding_column_dim"] is not None and pgvector["embedding_column_dim"] != expected_dim:
        errors.append(f"semantic_embeddings_embedding_dim_mismatch:{pgvector['embedding_column_dim']}")

    try:
        if schema["semantic_documents_exists"]:
            documents["semantic_documents"] = int(_fetch_scalar("select count(*) from semantic_documents;") or 0)
        if schema["semantic_embeddings_exists"]:
            emb_row = _fetch_one(
                """
                select
                  count(*) as semantic_embeddings,
                  count(*) filter (where coalesce(status, 'ok') = 'ok') as ok_embeddings,
                  count(distinct document_id) filter (where coalesce(status, 'ok') = 'ok') as embedded
                from semantic_embeddings;
                """
            ) or {}
            documents.update(
                {
                    "semantic_embeddings": int(emb_row.get("semantic_embeddings") or 0),
                    "ok_embeddings": int(emb_row.get("ok_embeddings") or 0),
                    "embedded": int(emb_row.get("embedded") or 0),
                }
            )
            if schema["embedding_dim_column_exists"]:
                dim_rows = _fetch_all(
                    """
                    select embedding_dim, count(*) as count
                    from semantic_embeddings
                    group by embedding_dim
                    order by count(*) desc, embedding_dim;
                    """
                )
                pgvector["embedding_dim_distribution"] = [
                    {"embedding_dim": row.get("embedding_dim"), "count": int(row.get("count") or 0)}
                    for row in dim_rows
                ]
    except Exception as exc:
        errors.append(f"semantic_counts_check_failed: {exc}")

    if documents["semantic_documents"] <= 0:
        errors.append("semantic_documents_empty")
    if documents["semantic_embeddings"] <= 0:
        errors.append("semantic_embeddings_empty")
    if documents["semantic_documents"] and documents["semantic_embeddings"]:
        if documents["semantic_documents"] != documents["semantic_embeddings"]:
            warnings.append("semantic_documents_embeddings_count_mismatch")
        if documents["embedded"] != documents["semantic_documents"]:
            warnings.append("semantic_documents_not_fully_embedded")
    if pgvector["embedding_dim_distribution"]:
        observed_dims = {row.get("embedding_dim") for row in pgvector["embedding_dim_distribution"]}
        if expected_dim not in observed_dims:
            errors.append("semantic_embeddings_expected_dim_not_found")

    search: dict[str, Any] = {
        "query": "cloudflare",
        "expected_search_mode": expected_search_mode,
        "expected_top_object_type": expected_top["object_type"],
        "expected_top_object_ref": expected_top["object_ref"],
        "status": "skipped",
        "elapsed_seconds": None,
        "search_mode": None,
        "top_object_type": None,
        "top_object_ref": None,
        "score": None,
        "hybrid_score": None,
        "debug_timing": {},
    }
    if not errors:
        debug_timing: dict[str, float] = {}
        search_started = datetime.now().timestamp()
        try:
            payload = semantic_search("cloudflare", limit=1, debug_timing=debug_timing, record_search=False)
            elapsed = max(0.0, datetime.now().timestamp() - search_started)
            results = payload.get("results") or []
            top = results[0] if results else {}
            search.update(
                {
                    "status": "ok" if results else "empty",
                    "elapsed_seconds": elapsed,
                    "search_mode": payload.get("search_mode"),
                    "top_object_type": top.get("object_type"),
                    "top_object_ref": top.get("object_ref"),
                    "score": top.get("score"),
                    "hybrid_score": top.get("hybrid_score"),
                    "debug_timing": debug_timing,
                }
            )
            if not results:
                errors.append("semantic_health_search_empty")
            if payload.get("search_mode") != expected_search_mode:
                warnings.append(f"semantic_health_search_mode={payload.get('search_mode')}")
            if top.get("object_type") != expected_top["object_type"] or top.get("object_ref") != expected_top["object_ref"]:
                warnings.append(
                    "semantic_health_top_unexpected:"
                    f"{top.get('object_type')}:{top.get('object_ref')}"
                )
            if elapsed > 10:
                warnings.append(f"semantic_health_search_slow:{elapsed:.3f}s")
        except Exception as exc:
            search["status"] = "error"
            search["elapsed_seconds"] = max(0.0, datetime.now().timestamp() - search_started)
            search["error"] = str(exc)
            errors.append(f"semantic_health_search_failed: {exc}")

    if errors:
        status = "failed"
    elif warnings:
        status = "degraded"
    else:
        status = "ok"

    return {
        "status": status,
        "provider": configured_provider,
        "model": provider_info.get("model"),
        "expected_dim": expected_dim,
        "provider_info": {
            "provider": configured_provider,
            "model": provider_info.get("model"),
            "dim": provider_info.get("dim"),
            "available": provider_available,
            "is_available": provider_available,
            "loaded_at": provider_info.get("loaded_at"),
            "load_seconds": provider_info.get("load_seconds"),
            "provider_cached": bool(provider_metrics.get("provider_cached")),
            "query_cache_size": provider_metrics.get("query_cache_size"),
            "total_embed_calls": provider_metrics.get("total_embed_calls"),
            "cache_hits": provider_metrics.get("cache_hits"),
            "cache_misses": provider_metrics.get("cache_misses"),
            "error": provider_info.get("error"),
        },
        "pgvector": pgvector,
        "documents": documents,
        "search": search,
        "fallback": {
            "text_fallback_available": True,
            "fallback_possible": True,
        },
        "warnings": warnings,
        "errors": errors,
        "elapsed_seconds": max(0.0, datetime.now().timestamp() - started),
    }


def learning_search(query: str, limit: int = 10) -> dict[str, Any]:
    base = semantic_search(query, limit=limit)
    allowed_prefixes = {
        "learning_request",
        "routebrain_question",
        "operational_answer",
        "learning_evidence_summary",
        "learning_classification_summary",
        "domain_memory",
        "inventory_host",
        "inventory_site",
        "inventory_interface",
        "inventory_peer_link",
        "ixbr_participant",
        "external_asn_enrichment",
        "external_ip_enrichment",
    }
    filtered = [row for row in base.get("results", []) if str(row.get("object_type") or "") in allowed_prefixes]
    base["results"] = filtered[:limit]
    base["results_count"] = len(base["results"])
    return base


def list_semantic_documents(
    limit: int = 50,
    object_type: str | None = None,
    *,
    conn: psycopg.Connection | None = None,
) -> list[dict[str, Any]]:
    normalized_limit = _clamp_limit(limit) or 50
    normalized_object_type = _normalize_text(object_type)
    params: list[Any] = []
    where = ""
    if normalized_object_type:
        where = "where object_type = %s"
        params.append(normalized_object_type)
    params.append(normalized_limit)
    return _fetch_all(
        f"""
        select
          id,
          document_uid,
          object_type,
          object_ref,
          title,
          content,
          content_hash,
          source,
          confidence,
          tags,
          metadata,
          created_at,
          updated_at,
          embedded_at,
          embedding_status,
          embedding_model,
          embedding_error
        from semantic_documents
        {where}
        order by updated_at desc, id desc
        limit %s;
        """,
        tuple(params),
        conn=conn,
    )


def get_semantic_document(document_uid: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
    return _document_row(document_uid, conn=conn)


def upsert_semantic_embedding(
    document_uid: str,
    embedding: Iterable[float],
    *,
    embedding_model_name: str | None = None,
    embedding_provider_name: str | None = None,
    embedding_dim_value: int | None = None,
    status: str = "ok",
    error: str | None = None,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    normalized_document_uid = _normalize_text(document_uid)
    if not normalized_document_uid:
        raise ValueError("Documento semântico inválido.")
    vector_ready = _fetch_one(
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
        """,
        conn=conn,
    )
    if not vector_ready or not vector_ready.get("extension_installed") or not vector_ready.get("embedding_column_present"):
        raise RuntimeError("pgvector não está disponível no banco RouteBrain.")
    document = _document_row(normalized_document_uid, conn=conn)
    if document is None:
        raise ValueError("Documento semântico não encontrado.")

    vector = [float(value) for value in embedding]
    if not vector:
        raise ValueError("Embedding vazio.")
    if embedding_dim_value is not None and int(embedding_dim_value) != len(vector):
        raise ValueError("Dimensão do embedding incompatível.")

    model_name = _normalize_text(embedding_model_name) or embedding_model()
    provider_value = _normalize_text(embedding_provider_name) or provider_name()
    dim_value = int(embedding_dim_value or len(vector))
    normalized_status = _normalize_text(status).lower() or "ok"
    normalized_error = _normalize_text(error)
    document_status = "embedded" if normalized_status == "ok" else "failed"
    document_error = None if normalized_status == "ok" else normalized_error

    _execute(
        """
        insert into semantic_embeddings (
          document_id,
          embedding_model,
          embedding_dim,
          embedding_json,
          embedding,
          provider,
          status,
          error,
          created_at
        )
        values (%s, %s, %s, %s, %s::vector, %s, %s, %s, now())
        on conflict (document_id, embedding_model)
        do update set
          embedding_dim = excluded.embedding_dim,
          embedding_json = excluded.embedding_json,
          embedding = excluded.embedding,
          provider = excluded.provider,
          status = excluded.status,
          error = excluded.error;
        """,
        (
            document["id"],
            model_name,
            dim_value,
            _json_value(vector),
            _vector_literal(vector),
            provider_value,
            normalized_status,
            document_error,
        ),
        conn=conn,
    )
    _execute(
        """
        update semantic_documents
        set
          embedding_status = %s,
          embedding_model = %s,
          embedding_error = %s,
          embedded_at = case when %s = 'ok' then now() else embedded_at end
        where document_uid = %s;
        """,
        (
            document_status,
            model_name,
            document_error,
            normalized_status,
            normalized_document_uid,
        ),
        conn=conn,
    )
    return {
        "document_uid": normalized_document_uid,
        "document_id": document["id"],
        "embedding_model": model_name,
        "embedding_dim": dim_value,
        "provider": provider_value,
        "status": normalized_status,
        "error": document_error,
    }
