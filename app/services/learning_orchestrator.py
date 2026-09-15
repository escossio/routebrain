from __future__ import annotations

import ipaddress
import shutil
import re
import shlex
import socket
import subprocess
import uuid
from datetime import date, datetime, time, timedelta
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db.connection import get_connection
from app.services.bgp_operational_queries import get_asn_lookup, get_peer_lookup, get_prefix_lookup, lookup_bgp_by_ip
from app.services.external_enrichment import enrich_asn, enrich_ip, get_external_asn_enrichment, get_external_ip_enrichment
from app.services.inventory_queries import get_host, get_site, list_hosts, search_hosts
from app.services.ixbr_discovery_queries import get_inventory_public_context, summarize_ixbr_vs_bgp
from app.services.learning_classifier import classify_learning_request, get_classifications_for_entity, get_request_classifications, list_known_networks
from app.services.learning_memory import (
    classify_evidence_freshness,
    get_learning_memory_for_domain,
    get_recent_evidence,
    summarize_learning_memory,
)

MAX_LIMIT = 500
MAX_DNS_RESULTS = 20
DNS_CACHE_TTL = timedelta(hours=6)
BGP_CACHE_TTL = timedelta(hours=12)
SAFE_TASK_TYPES = {"dns_resolve", "bgp_prefix_lookup", "bgp_asn_lookup", "inventory_lookup", "ixbr_lookup"}
INVASIVE_TASK_TYPES = {"ping_measurement", "traceroute_measurement", "synthetic_browser_run"}
ACTIVE_MEASUREMENT_POLICY = {
    "max_targets_per_request": 5,
    "ping_count": 3,
    "ping_timeout_seconds": 3,
    "traceroute_max_hops": 20,
    "traceroute_timeout_seconds": 3,
    "max_total_runtime_seconds": 120,
    "deny_private_ips": True,
    "deny_loopback": True,
    "deny_link_local": True,
    "deny_multicast": True,
    "deny_reserved": True,
    "allow_ipv6": True,
}
DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."

DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b",
    re.IGNORECASE,
)
ASN_RE = re.compile(r"\b(?:AS\s*)?([1-9]\d{0,9})\b", re.IGNORECASE)
EXPLICIT_ASN_RE = re.compile(r"\b(?:ASN|AS)\s*([1-9]\d{0,9})\b", re.IGNORECASE)
PTT_SITE_RE = re.compile(r"\b(?:PTT[-\s]?CE|IX\.?BR|IX\.?BR/CE|FORTALEZA)\b", re.IGNORECASE)


def _fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
                return dict(row) if row is not None else None
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split()).strip()
    return text or None


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(value)
    return value


def _json_value(value: Any) -> Json:
    return Json(_safe_json(value))


def _clamp_limit(limit: int) -> int:
    if limit < 1:
        raise ValueError("Limite inválido.")
    return min(limit, MAX_LIMIT)


def _request_bundle_from_uid(request_uid: str) -> dict[str, Any] | None:
    request_row = _fetch_one(
        """
        select
          id,
          request_uid,
          question,
          normalized_question,
          intent,
          scope,
          status,
          operator,
          requires_consent,
          consent_status,
          confidence_before,
          confidence_after,
          answer_summary,
          created_at,
          updated_at,
          started_at,
          finished_at,
          raw_context,
          result,
          error
        from learning_requests
        where request_uid = %s
        limit 1;
        """,
        (request_uid,),
    )
    if request_row is None:
        return None

    request_id = int(request_row["id"])
    entities = _fetch_all(
        """
        select
          id,
          request_id,
          entity_type,
          entity_value,
          normalized_value,
          confidence,
          source,
          metadata,
          created_at
        from learning_entities
        where request_id = %s
        order by id asc;
        """,
        (request_id,),
    )
    gaps = _fetch_all(
        """
        select
          id,
          request_id,
          gap_type,
          description,
          severity,
          blocks_answer,
          recommended_task_type,
          status,
          created_at,
          resolved_at,
          metadata
        from learning_gaps
        where request_id = %s
        order by id asc;
        """,
        (request_id,),
    )
    tasks = _fetch_all(
        """
        select
          id,
          request_id,
          task_uid,
          task_type,
          status,
          priority,
          requires_consent,
          command_preview,
          input,
          output,
          error,
          created_at,
          started_at,
          finished_at
        from learning_tasks
        where request_id = %s
        order by priority asc, id asc;
        """,
        (request_id,),
    )
    evidence = _fetch_all(
        """
        select
          id,
          request_id,
          task_id,
          evidence_type,
          entity_type,
          entity_value,
          confidence,
          source,
          source_ref,
          summary,
          data,
          created_at
        from learning_evidence
        where request_id = %s
        order by id asc;
        """,
        (request_id,),
    )
    classifications = _fetch_all(
        """
        select
          c.id,
          c.request_id,
          r.request_uid,
          c.entity_type,
          c.entity_value,
          c.classification_type,
          c.classification_value,
          c.confidence,
          c.source,
          c.source_ref,
          c.reason,
          c.data,
          c.created_at,
          c.updated_at
        from learning_classifications c
        join learning_requests r on r.id = c.request_id
        where c.request_id = %s
        order by c.created_at desc, c.id desc;
        """,
        (request_id,),
    )
    return {
        "request": request_row,
        "entities": entities,
        "gaps": gaps,
        "tasks": tasks,
        "evidence": evidence,
        "classifications": classifications,
        "analysis": (request_row.get("result") or {}).get("analysis", {}),
        "execution": (request_row.get("result") or {}).get("execution", {}),
        "answer": (request_row.get("result") or {}).get("answer", {}),
        "semantic_context": _semantic_context_from_request(request_row),
    }


def _request_summary_row(request_uid: str) -> dict[str, Any] | None:
    return _fetch_one(
        """
        select
          r.id,
          r.request_uid,
          r.question,
          r.normalized_question,
          r.intent,
          r.scope,
          r.status,
          r.operator,
          r.requires_consent,
          r.consent_status,
          r.confidence_before,
          r.confidence_after,
          r.answer_summary,
          r.created_at,
          r.updated_at,
          r.started_at,
          r.finished_at,
          r.raw_context,
          r.result,
          r.error,
          coalesce(e.entity_count, 0)::bigint as entity_count,
          coalesce(g.gap_count, 0)::bigint as gap_count,
          coalesce(t.task_count, 0)::bigint as task_count,
          coalesce(v.evidence_count, 0)::bigint as evidence_count
        from learning_requests r
        left join lateral (
            select count(*)::bigint as entity_count
            from learning_entities e
            where e.request_id = r.id
        ) e on true
        left join lateral (
            select count(*)::bigint as gap_count
            from learning_gaps g
            where g.request_id = r.id
        ) g on true
        left join lateral (
            select count(*)::bigint as task_count
            from learning_tasks t
            where t.request_id = r.id
        ) t on true
        left join lateral (
            select count(*)::bigint as evidence_count
            from learning_evidence v
            where v.request_id = r.id
        ) v on true
        where r.request_uid = %s
        limit 1;
        """,
        (request_uid,),
    )


def _cache_upsert(
    conn: psycopg.Connection,
    *,
    cache_key: str,
    cache_type: str,
    entity_type: str | None,
    entity_value: str | None,
    data: Any,
    confidence: str = "suggested",
    source: str | None = None,
    expires_at=None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into learning_cache (
              cache_key,
              cache_type,
              entity_type,
              entity_value,
              data,
              confidence,
              source,
              expires_at
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (cache_key)
            do update set
              cache_type = excluded.cache_type,
              entity_type = excluded.entity_type,
              entity_value = excluded.entity_value,
              data = excluded.data,
              confidence = excluded.confidence,
              source = excluded.source,
              expires_at = excluded.expires_at,
              updated_at = now();
            """,
            (
                cache_key,
                cache_type,
                entity_type,
                entity_value,
                _json_value(data),
                confidence,
                source,
                expires_at,
            ),
        )


def _add_evidence(
    conn: psycopg.Connection,
    *,
    request_id: int,
    task_id: int | None = None,
    evidence_type: str,
    entity_type: str | None = None,
    entity_value: str | None = None,
    confidence: str = "suggested",
    source: str | None = None,
    source_ref: str | None = None,
    summary: str | None = None,
    data: Any = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into learning_evidence (
              request_id,
              task_id,
              evidence_type,
              entity_type,
              entity_value,
              confidence,
              source,
              source_ref,
              summary,
              data
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (
                request_id,
                task_id,
                evidence_type,
                entity_type,
                entity_value,
                confidence,
                source,
                source_ref,
                summary,
            _json_value(data or {}),
        ),
        )


def _fetch_learning_cache_row(conn: psycopg.Connection, cache_key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            select
              id,
              cache_key,
              cache_type,
              entity_type,
              entity_value,
              data,
              confidence,
              source,
              expires_at,
              created_at,
              updated_at
            from learning_cache
            where cache_key = %s
              and (expires_at is null or expires_at > now())
            limit 1;
            """,
            (cache_key,),
        )
        row = cur.fetchone()
        return dict(row) if row is not None else None


def _resolve_learning_gaps(conn: psycopg.Connection, request_id: int, gap_types: list[str]) -> None:
    if not gap_types:
        return
    with conn.cursor() as cur:
        cur.execute(
            """
            update learning_gaps
            set status = 'resolved',
                resolved_at = coalesce(resolved_at, now())
            where request_id = %s
              and gap_type = any(%s)
              and status = 'open';
            """,
            (request_id, gap_types),
        )


def _resolve_domain_ips(domain: str) -> list[dict[str, Any]]:
    resolved: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    try:
        addrinfos = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise RuntimeError(str(exc)) from exc

    for family, _socktype, _proto, _canonname, sockaddr in addrinfos:
        if not sockaddr:
            continue
        ip_text = str(sockaddr[0]).strip()
        if not ip_text:
            continue
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        record_type = "AAAA" if address.version == 6 else "A"
        key = (record_type, str(address))
        if key in seen:
            continue
        seen.add(key)
        resolved.append(
            {
                "domain": domain,
                "record_type": record_type,
                "ip": str(address),
                "family": "ipv6" if address.version == 6 else "ipv4",
                "resolved_at": datetime.now().astimezone(),
                "ttl_seconds": int(DNS_CACHE_TTL.total_seconds()),
                "ttl_source": "default",
            }
        )
        if len(resolved) >= MAX_DNS_RESULTS:
            break

    return resolved


def execute_bgp_lookup_for_ip(
    conn: psycopg.Connection,
    *,
    request_id: int,
    task_id: int | None,
    ip: str,
    force_refresh: bool = False,
) -> dict[str, Any]:
    normalized_ip = str(ipaddress.ip_address(ip))
    cache_key = f"ip:{normalized_ip}:bgp"
    cached = None if force_refresh else _fetch_learning_cache_row(conn, cache_key)
    if cached is None and not force_refresh:
        recent_bgp = get_recent_evidence("ip", normalized_ip, limit=5, conn=conn)
        latest_bgp = next(
            (
                row
                for row in recent_bgp
                if row.get("evidence_type") in {"bgp_prefix_match", "bgp_prefix_not_found", "bgp_prefix_lookup"}
            ),
            None,
        )
        if latest_bgp is not None:
            cached = {
                "source": "learning_evidence",
                "confidence": latest_bgp.get("confidence") or "suggested",
                "expires_at": latest_bgp.get("freshness", {}).get("expires_at"),
                "data": latest_bgp.get("data") or {},
                "freshness": latest_bgp.get("freshness") or {},
                "request_uid": latest_bgp.get("request_uid"),
            }
    if cached is not None:
        payload = cached.get("data") or {}
        cached_match_type = "bgp_prefix_match" if payload.get("matched_prefix") else "bgp_prefix_not_found"
        cached_summary = (
            f"Cache reutilizado para BGP lookup de {normalized_ip}."
            if payload.get("matched_prefix")
            else f"Cache reutilizado para BGP lookup sem match para {normalized_ip}."
        )
        output = {
            "status": payload.get("status") or "completed",
            "cache_hit": True,
            "source": "learning_cache",
            "cache_key": cache_key,
            "ip": normalized_ip,
            "matched_prefix": payload.get("matched_prefix"),
            "origin_asn": payload.get("origin_asn"),
            "origin_type": payload.get("origin_type"),
            "peer_count": payload.get("peer_count"),
            "sample_peers": payload.get("sample_peers") or [],
            "sample_as_paths": payload.get("sample_as_paths") or [],
            "summary": payload.get("summary"),
            "result": payload,
            "reuse_freshness": cached.get("freshness"),
            "reused_from_request_uid": cached.get("request_uid"),
        }
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=task_id,
            evidence_type="linked_prior_evidence",
            entity_type="ip",
            entity_value=normalized_ip,
            confidence=cached.get("confidence") or "suggested",
            source=cached.get("source") or "learning_cache",
            source_ref=cache_key,
            summary=cached_summary,
            data=payload,
        )
        return output

    payload = lookup_bgp_by_ip(normalized_ip, limit_peers=MAX_DNS_RESULTS)
    if payload is None:
        output = {
            "status": "failed",
            "cache_hit": False,
            "source": "bgp_current_routes",
            "ip": normalized_ip,
            "matched_prefix": None,
            "origin_asn": None,
            "origin_type": None,
            "peer_count": 0,
            "sample_peers": [],
            "sample_as_paths": [],
            "summary": None,
            "error": "No BGP match found",
        }
        expires_at = datetime.now().astimezone() + BGP_CACHE_TTL
        _cache_upsert(
            conn,
            cache_key=cache_key,
            cache_type="bgp_prefix_lookup",
            entity_type="ip",
            entity_value=normalized_ip,
            data=output,
            confidence="unknown",
            source="bgp_current_routes",
            expires_at=expires_at,
        )
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=task_id,
            evidence_type="bgp_prefix_not_found",
            entity_type="ip",
            entity_value=normalized_ip,
            confidence="unknown",
            source="bgp_current_routes",
            source_ref=normalized_ip,
            summary=f"Nenhum match BGP encontrado para {normalized_ip}.",
            data=output,
        )
        return output

    output_payload = {
        "matched_prefix": payload.get("matched_prefix"),
        "origin_asn": payload.get("origin_asn"),
        "origin_type": payload.get("origin_type"),
        "peer_count": int(payload.get("peer_count") or 0),
        "collector_count": int(payload.get("collector_count") or 0),
        "sample_peers": payload.get("sample_peers") or [],
        "sample_as_paths": payload.get("sample_as_paths") or [],
        "summary": payload.get("summary"),
        "current_routes": payload.get("current_routes") or [],
        "peer_counts": payload.get("peer_counts") or [],
        "match_route_count": int(payload.get("match_route_count") or 0),
    }
    expires_at = datetime.now().astimezone() + BGP_CACHE_TTL
    _cache_upsert(
        conn,
        cache_key=cache_key,
        cache_type="bgp_prefix_lookup",
        entity_type="ip",
        entity_value=normalized_ip,
        data=output_payload,
        confidence="confirmed",
        source="bgp_current_routes",
        expires_at=expires_at,
    )
    _add_evidence(
        conn,
        request_id=request_id,
        task_id=task_id,
        evidence_type="bgp_prefix_match",
        entity_type="ip",
        entity_value=normalized_ip,
        confidence="confirmed",
        source="bgp_current_routes",
        source_ref=payload.get("matched_prefix"),
        summary=f"IP {normalized_ip} mapeado para {payload.get('matched_prefix')}.",
        data=output_payload,
    )
    return {
        "status": "completed",
        "cache_hit": False,
        "source": "bgp_current_routes",
        "ip": normalized_ip,
        **output_payload,
    }


def classify_question(question: str) -> dict[str, str]:
    text = _normalize_text(question) or ""
    lower = text.lower()

    if PTT_SITE_RE.search(text) or "ptt-ce" in lower or "ix.br" in lower:
        return {"intent": "ix_inventory_context", "scope": "inventory"}

    visibility_terms = (
        "enxerga",
        "enxergo",
        "vê",
        "ve",
        "visão",
        "visao",
        "como o asn",
        "como o as",
        "como chega",
        "como alcança",
        "como alcanca",
        "caminho",
        "rota para o ip",
        "aparece no caminho",
        "aparece no as path",
        "aparece no caminho para",
    )
    if re.search(r"\b(?:asn|as)\b", lower) and (re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text) or re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", text)) and any(term in lower for term in visibility_terms):
        return {"intent": "bgp_asn_ip_visibility", "scope": "bgp"}

    if DOMAIN_RE.search(text) and any(token in lower for token in ("roteamento", "route", "rota", "path", "caminho")):
        return {"intent": "route_to_domain", "scope": "routing"}

    if re.search(r"\b(?:asn|as)\b", lower) and EXPLICIT_ASN_RE.search(text):
        if any(term in lower for term in ("mudança de rota", "mudanca de rota", "mudança de roteamento", "mudanca de roteamento", "route change", "routing change", "alteração de rota", "alteracao de rota", "mudou o roteamento", "teve mudança de rota", "teve mudanca de rota")):
            return {"intent": "asn_route_change_check", "scope": "asn"}
        if any(term in lower for term in ("monitor", "monitoramento", "acompan", "coloca", "adiciona")):
            return {"intent": "asn_route_monitoring_request", "scope": "asn"}
        return {"intent": "asn_analysis", "scope": "asn"}

    if "/" in text and any(token in lower for token in ("prefix", "prefixo", "route", "rota")):
        try:
            ipaddress.ip_network(text.split()[-1], strict=False)
            return {"intent": "prefix_analysis", "scope": "prefix"}
        except ValueError:
            pass

    has_ip = bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", text))
    has_explicit_asn = bool(EXPLICIT_ASN_RE.search(text))
    if has_ip and not has_explicit_asn:
        return {"intent": "ip_operational_check", "scope": "ip"}

    if "peer" in lower:
        return {"intent": "peer_analysis", "scope": "peer"}

    if DOMAIN_RE.search(text):
        return {"intent": "domain_analysis", "scope": "routing"}

    return {"intent": "general_network_question", "scope": "general"}


def extract_entities(question: str) -> list[dict[str, Any]]:
    text = _normalize_text(question) or ""
    entities: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(entity_type: str, entity_value: str, *, confidence: float = 0.9, metadata: dict[str, Any] | None = None) -> None:
        normalized_value = entity_value.strip()
        key = (entity_type, normalized_value.lower())
        if key in seen:
            return
        seen.add(key)
        entities.append(
            {
                "entity_type": entity_type,
                "entity_value": entity_value,
                "normalized_value": normalized_value,
                "confidence": confidence,
                "source": "rule",
                "metadata": metadata or {},
            }
        )

    for match in DOMAIN_RE.finditer(text):
        add("domain", match.group(0).lower(), confidence=0.95)

    service_domain_aliases = {
        "google": "google.com",
        "facebook": "facebook.com",
        "cloudflare": "cloudflare.com",
        "baidu": "baidu.com",
    }
    lowered_text = text.lower()
    for alias, domain in service_domain_aliases.items():
        if re.search(rf"\b{re.escape(alias)}\b", lowered_text):
            add("domain", domain, confidence=0.9, metadata={"source": "service_alias"})

    for match in EXPLICIT_ASN_RE.finditer(text):
        clean = match.group(1).strip()
        if not clean:
            continue
        try:
            asn = int(clean)
        except ValueError:
            continue
        if 0 < asn < 4294967296:
            add("asn", str(asn), confidence=0.95)

    cidr_candidates = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", text)
    for candidate in cidr_candidates:
        try:
            add("prefix", str(ipaddress.ip_network(candidate, strict=False)), confidence=0.95)
        except ValueError:
            continue

    for ip_candidate in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        try:
            address = ipaddress.ip_address(ip_candidate)
        except ValueError:
            continue
        if any(entity["entity_value"] == ip_candidate for entity in entities if entity["entity_type"] == "prefix"):
            continue
        add("ip", str(address), confidence=0.85)

    if PTT_SITE_RE.search(text) or "ptt-ce" in text.lower():
        add("site", "PTT-CE", confidence=0.95, metadata={"locality_code": "CE"})

    if "ix.br" in text.lower() or "ixbr" in text.lower():
        add("ix", "IX.br", confidence=0.8, metadata={"locality_code": "CE"})

    if "peer" in text.lower():
        add("peer", "peer", confidence=0.5)

    if not entities:
        add("unknown", text or question, confidence=0.1)

    return entities


def _safe_prefix_from_entity(entity: dict[str, Any]) -> str | None:
    entity_type = entity.get("entity_type")
    value = str(entity.get("normalized_value") or entity.get("entity_value") or "").strip()
    if not value:
        return None
    if entity_type == "prefix":
        return value
    if entity_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        suffix = "/32" if address.version == 4 else "/128"
        return f"{address}{suffix}"
    return None


def _safe_domain_from_entities(entities: list[dict[str, Any]]) -> str | None:
    for entity in entities:
        if entity.get("entity_type") == "domain":
            return str(entity.get("normalized_value") or entity.get("entity_value") or "").strip().lower() or None
    return None


def _safe_asn_from_entities(entities: list[dict[str, Any]]) -> int | None:
    for entity in entities:
        if entity.get("entity_type") == "asn":
            try:
                return int(entity.get("normalized_value") or entity.get("entity_value"))
            except (TypeError, ValueError):
                continue
    return None


def _safe_site_from_entities(entities: list[dict[str, Any]]) -> str | None:
    for entity in entities:
        if entity.get("entity_type") == "site":
            return str(entity.get("normalized_value") or entity.get("entity_value") or "").strip() or None
    return None


def _request_learning_memory(request: dict[str, Any]) -> dict[str, Any] | None:
    raw_context = request.get("raw_context") or {}
    result = request.get("result") or {}
    for source in (result, raw_context):
        memory = source.get("learning_memory")
        if isinstance(memory, dict):
            return memory
    return None


def _domain_memory_from_request(request: dict[str, Any], entities: list[dict[str, Any]]) -> dict[str, Any] | None:
    memory = _request_learning_memory(request)
    if memory is not None and str(memory.get("entity_type") or "").lower() == "domain":
        return memory
    domain = _safe_domain_from_entities(entities)
    if not domain:
        return None
    summary = summarize_learning_memory({"entity_type": "domain", "entity_value": domain})
    memory = summary.get("memory")
    return memory if isinstance(memory, dict) else None


def get_semantic_context_for_question(
    question: str,
    limit: int = 5,
    debug_timing: dict[str, float] | None = None,
) -> dict[str, Any]:
    normalized_question = _normalize_text(question) or ""
    context: dict[str, Any] = {
        "query": normalized_question,
        "search_mode": None,
        "results": [],
        "error": None,
        "note": "Contexto semântico é sugestivo e não confirma fatos sem evidência estruturada.",
    }
    if not normalized_question:
        context["error"] = "empty_query"
        return context
    semantic_debug: dict[str, float] = {}
    try:
        from app.services.semantic_memory import semantic_search

        payload = semantic_search(normalized_question, limit=limit, debug_timing=semantic_debug)
    except Exception as exc:
        context["search_mode"] = "unavailable"
        context["error"] = str(exc)
        return context

    context["search_mode"] = payload.get("search_mode")
    if debug_timing is not None:
        context["debug_timing"] = semantic_debug
    if debug_timing is not None:
        debug_timing["semantic_search_total_seconds"] = float(semantic_debug.get("total_seconds") or 0.0)
        debug_timing["semantic_search_embed_call_count_delta"] = float(semantic_debug.get("embed_call_count_delta") or 0.0)
        debug_timing["semantic_search_query_embedding_cache_hit"] = 1.0 if semantic_debug.get("query_embedding_cache_hit") else 0.0
    compact_results: list[dict[str, Any]] = []
    for row in payload.get("results") or []:
        if not isinstance(row, dict):
            continue
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        compact_results.append(
            {
                "object_type": row.get("object_type"),
                "object_ref": row.get("object_ref"),
                "title": row.get("title"),
                "snippet": row.get("snippet"),
                "confidence": row.get("confidence"),
                "family_key": row.get("family_key") or metadata.get("family_key"),
                "related_count": row.get("related_count") or metadata.get("related_count"),
                "search_mode": row.get("search_mode") or payload.get("search_mode"),
                "reason": row.get("reason") or row.get("query_intent_reason"),
                "metadata": {
                    key: value
                    for key, value in metadata.items()
                    if key in {"entity_type", "entity_value", "aliases", "freshness", "status", "site_code", "domain"}
                },
            }
        )
    context["results"] = compact_results
    return context


def _semantic_context_from_request(request: dict[str, Any]) -> dict[str, Any] | None:
    raw_context = request.get("raw_context") or {}
    result = request.get("result") or {}
    for source in (result, raw_context):
        context = source.get("semantic_context")
        if isinstance(context, dict):
            return context
    return None


def _top_semantic_context_result(semantic_context: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(semantic_context, dict):
        return None
    for row in semantic_context.get("results") or []:
        if isinstance(row, dict) and row.get("object_type") and row.get("object_ref"):
            return row
    return None


def _semantic_domain_ref(semantic_context: dict[str, Any] | None) -> str | None:
    top = _top_semantic_context_result(semantic_context)
    if not top or top.get("object_type") != "domain_memory":
        return None
    value = str(top.get("object_ref") or "").strip().lower()
    return value or None


def _semantic_context_summary(semantic_context: dict[str, Any] | None) -> str | None:
    top = _top_semantic_context_result(semantic_context)
    if not top:
        return None
    object_type = top.get("object_type")
    object_ref = top.get("object_ref")
    return f"A memória semântica encontrou contexto relacionado: {object_type} {object_ref}."


def _semantic_context_short_label(semantic_context: dict[str, Any] | None) -> str | None:
    top = _top_semantic_context_result(semantic_context)
    if not top:
        return None
    object_type = str(top.get("object_type") or "").strip()
    object_ref = str(top.get("object_ref") or "").strip()
    if not object_type or not object_ref:
        return None
    return f"{object_type} {object_ref}"


def _semantic_context_marker(top: dict[str, Any] | None) -> dict[str, Any]:
    if not top:
        return {}
    return {
        "semantic_context_suggested": True,
        "semantic_context_object_type": top.get("object_type"),
        "semantic_context_object_ref": top.get("object_ref"),
        "semantic_context_family_key": top.get("family_key"),
        "semantic_context_search_mode": top.get("search_mode"),
    }


def _memory_statuses(memory: dict[str, Any] | None, evidence_kind: str) -> list[str]:
    if not isinstance(memory, dict):
        return []
    if evidence_kind == "dns":
        status = str(((memory.get("dns") or {}).get("freshness") or {}).get("status") or "").strip()
        return [status] if status else []
    statuses: list[str] = []
    for item in memory.get("ips") or []:
        if not isinstance(item, dict):
            continue
        status = str(((item.get(evidence_kind) or {}).get("status")) or "").strip()
        latest = (item.get(evidence_kind) or {}).get("latest")
        if status and latest is not None:
            statuses.append(status)
    return statuses


def _has_fresh_structured_domain_evidence(memory: dict[str, Any] | None, evidence_kind: str) -> bool:
    return any(status == "fresh" for status in _memory_statuses(memory, evidence_kind))


def _has_any_structured_domain_evidence(memory: dict[str, Any] | None, evidence_kind: str) -> bool:
    return bool(_memory_statuses(memory, evidence_kind))


def _gap_evidence_kind(gap_type: str | None) -> str | None:
    text = str(gap_type or "")
    if "dns" in text:
        return "dns"
    if "bgp" in text:
        return "bgp"
    if "ping" in text:
        return "ping"
    if "traceroute" in text:
        return "traceroute"
    return None


def _evidence_freshness_status(value: dict[str, Any] | None) -> str:
    if not isinstance(value, dict):
        return "missing"
    return str(value.get("status") or "missing").strip().lower() or "missing"


def apply_semantic_context_gap_policy(
    request_uid: str,
    semantic_context: dict[str, Any] | None,
    known_context: dict[str, Any],
    gaps: list[dict[str, Any]],
    *,
    memory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Annotate gaps with semantic-context policy decisions.

    Semantic context is only a pointer. Gaps are reduced only when the pointer
    leads to structured inventory or learning-memory evidence.
    """
    top = _top_semantic_context_result(semantic_context)
    policy: dict[str, Any] = {
        "request_uid": request_uid,
        "applied": bool(top),
        "top_result": top,
        "reduced_gap_types": [],
        "preserved_gap_types": [],
        "structured_evidence": [],
        "suggested_only": [],
    }
    if not top:
        return policy

    marker = _semantic_context_marker(top)
    object_type = str(top.get("object_type") or "")
    object_ref = str(top.get("object_ref") or "").strip()
    known = known_context.get("known") or []

    def annotate_gap(
        gap: dict[str, Any],
        *,
        can_reduce: bool,
        reason: str,
        structured: str | None = None,
        status: str | None = None,
    ) -> None:
        metadata = dict(gap.get("metadata") or {})
        metadata.update(marker)
        metadata["semantic_context_can_reduce"] = can_reduce
        metadata["semantic_context_reason"] = reason
        if structured:
            metadata["structured_evidence_reused"] = structured
        if status:
            metadata["semantic_context_gap_status"] = status
        gap["metadata"] = metadata
        if can_reduce:
            if gap.get("gap_type") not in policy["reduced_gap_types"]:
                policy["reduced_gap_types"].append(gap.get("gap_type"))
        else:
            if gap.get("gap_type") not in policy["preserved_gap_types"]:
                policy["preserved_gap_types"].append(gap.get("gap_type"))

    if object_type == "domain_memory":
        domain_memory_matches = (
            isinstance(memory, dict)
            and str(memory.get("entity_type") or "").lower() == "domain"
            and str(memory.get("entity_value") or "").lower() == object_ref.lower()
        )
        domain_dns = memory.get("dns") if domain_memory_matches and isinstance(memory, dict) else None
        domain_dns_status = _evidence_freshness_status((domain_dns or {}).get("freshness") if isinstance(domain_dns, dict) else None)
        if not domain_memory_matches:
            policy["suggested_only"].append("domain_memory_without_learning_memory")
        for gap in gaps:
            kind = _gap_evidence_kind(gap.get("gap_type"))
            if kind is None:
                continue
            if not domain_memory_matches:
                annotate_gap(
                    gap,
                    can_reduce=False,
                    reason="semantic_context apontou domain_memory, mas não há learning_memory estruturada correspondente.",
                    status="suggested_by_semantic_context",
                )
                continue
            if kind == "dns":
                if domain_dns_status == "fresh":
                    annotate_gap(
                        gap,
                        can_reduce=True,
                        reason="learning_memory estruturada fresh encontrada para dns.",
                        structured="learning_memory.dns",
                        status="resolved",
                    )
                    policy["structured_evidence"].append({"kind": kind, "statuses": [domain_dns_status]})
                elif domain_dns_status in {"stale", "expired"}:
                    annotate_gap(
                        gap,
                        can_reduce=False,
                        reason="learning_memory estruturada para dns está stale/expired e precisa de refresh.",
                        structured="learning_memory.dns",
                        status="stale",
                    )
                    policy["suggested_only"].append("dns_stale_or_expired")
                else:
                    annotate_gap(
                        gap,
                        can_reduce=False,
                        reason="semantic_context sugeriu domínio, mas não há evidência estruturada para dns.",
                        status="suggested_by_semantic_context",
                    )
                    policy["suggested_only"].append("dns_missing_structured_evidence")
                continue
            statuses = _memory_statuses(memory, kind)
            if _has_fresh_structured_domain_evidence(memory, kind):
                annotate_gap(
                    gap,
                    can_reduce=True,
                    reason=f"learning_memory estruturada fresh encontrada para {kind}.",
                    structured=f"learning_memory.{kind}",
                    status="resolved",
                )
                policy["structured_evidence"].append({"kind": kind, "statuses": statuses})
            elif _has_any_structured_domain_evidence(memory, kind):
                annotate_gap(
                    gap,
                    can_reduce=False,
                    reason=f"learning_memory estruturada existe para {kind}, mas está stale/expired e precisa de refresh.",
                    structured=f"learning_memory.{kind}",
                    status="stale",
                )
                policy["suggested_only"].append(f"{kind}_stale_or_expired")
            else:
                annotate_gap(
                    gap,
                    can_reduce=False,
                    reason=f"semantic_context sugeriu domínio, mas não há evidência estruturada para {kind}.",
                    status="suggested_by_semantic_context",
                )
                policy["suggested_only"].append(f"{kind}_missing_structured_evidence")

    elif object_type == "inventory_host":
        host_known = next(
            (
                item
                for item in known
                if item.get("kind") == "inventory_host"
                and str(item.get("entity_value") or "").lower() == object_ref.lower()
                and item.get("confidence") == "confirmed"
            ),
            None,
        )
        if host_known is not None:
            policy["structured_evidence"].append({"kind": "inventory_host", "object_ref": object_ref})
        for gap in gaps:
            if gap.get("gap_type") in {"unknown_entity", "host_identification", "missing_inventory_link"}:
                annotate_gap(
                    gap,
                    can_reduce=host_known is not None,
                    reason=(
                        f"inventário estruturado confirmou o host {object_ref}."
                        if host_known is not None
                        else f"semantic_context apontou {object_ref}, mas o host não foi confirmado no inventário."
                    ),
                    structured="inventory_hosts" if host_known is not None else None,
                    status="resolved" if host_known is not None else "suggested_by_semantic_context",
                )

    elif object_type == "inventory_site":
        site_known = next(
            (
                item
                for item in known
                if item.get("kind") == "site"
                and str(item.get("entity_value") or "").lower() == object_ref.lower()
                and item.get("confidence") == "confirmed"
            ),
            None,
        )
        public_context_known = next((item for item in known if item.get("kind") == "ixbr_public_context"), None)
        if site_known is not None:
            policy["structured_evidence"].append({"kind": "inventory_site", "object_ref": object_ref})
        if public_context_known is not None:
            policy["structured_evidence"].append({"kind": "ixbr_public_context", "object_ref": object_ref})
        for gap in gaps:
            gap_type = gap.get("gap_type")
            if gap_type == "missing_ix_context":
                annotate_gap(
                    gap,
                    can_reduce=public_context_known is not None,
                    reason=(
                        "contexto público IX.br estruturado está disponível."
                        if public_context_known is not None
                        else "semantic_context apontou site, mas contexto IX.br estruturado não está disponível."
                    ),
                    structured="ixbr_public_context" if public_context_known is not None else None,
                    status="resolved" if public_context_known is not None else "suggested_by_semantic_context",
                )
            elif gap_type in {"missing_inventory_link", "missing_confirmed_hosts"}:
                annotate_gap(
                    gap,
                    can_reduce=False,
                    reason="inventory_site confirma o site, mas não confirma hosts internos sem vínculos em inventory_hosts.",
                    structured="inventory_sites" if site_known is not None else None,
                    status="suggested_by_semantic_context" if site_known is not None else None,
                )

    elif object_type in {"ixbr_participant", "ixbr_public_context"}:
        for gap in gaps:
            if gap.get("gap_type") == "missing_ix_context":
                annotate_gap(
                    gap,
                    can_reduce=True,
                    reason="contexto público IX.br pode reduzir lacuna de contexto IX.br.",
                    structured="ixbr_public_context",
                    status="resolved",
                )
            elif gap.get("gap_type") in {"missing_inventory_link", "missing_confirmed_hosts"}:
                annotate_gap(
                    gap,
                    can_reduce=False,
                    reason="contexto público IX.br não confirma hosts internos.",
                    status="suggested_by_semantic_context",
                )
            elif gap.get("gap_type") == "unknown_entity":
                annotate_gap(
                    gap,
                    can_reduce=False,
                    reason="contexto público IX.br sugere caminho de investigação, mas não identifica equipamento interno.",
                    status="suggested_by_semantic_context",
                )

    elif object_type in {"learning_classification_summary", "learning_evidence_summary"}:
        for gap in gaps:
            annotate_gap(
                gap,
                can_reduce=False,
                reason=f"{object_type} ajuda no contexto da resposta, mas não resolve gap factual sem evidência estruturada correspondente.",
                status="suggested_by_semantic_context",
            )
        policy["suggested_only"].append(object_type)

    else:
        for gap in gaps:
            annotate_gap(
                gap,
                can_reduce=False,
                reason=f"semantic_context do tipo {object_type} é apenas sugestivo para este gap.",
                status="suggested_by_semantic_context",
            )
        policy["suggested_only"].append(object_type)

    return policy


def _add_semantic_context_known_items(
    request: dict[str, Any],
    known: list[dict[str, Any]],
    semantic_context: dict[str, Any] | None,
) -> None:
    top = _top_semantic_context_result(semantic_context)
    if not top:
        return
    object_type = str(top.get("object_type") or "")
    object_ref = str(top.get("object_ref") or "").strip()
    if not object_ref:
        return
    known.append(
        {
            "kind": "semantic_context",
            "entity_type": object_type,
            "entity_value": object_ref,
            "confidence": "suggested",
            "source": "semantic_memory",
            "summary": _semantic_context_summary(semantic_context),
            "data": top,
        }
    )
    if object_type == "inventory_host":
        host = get_host(object_ref)
        if host is not None:
            known.append(
                {
                    "kind": "inventory_host",
                    "entity_type": "host",
                    "entity_value": object_ref,
                    "confidence": "confirmed",
                    "source": "inventory",
                    "summary": f"Host {object_ref} encontrado no inventário estruturado.",
                    "data": host,
                }
            )
    elif object_type == "inventory_site":
        site = get_site(object_ref)
        if site is not None:
            known.append(
                {
                    "kind": "site",
                    "entity_type": "site",
                    "entity_value": object_ref,
                    "confidence": "confirmed",
                    "source": "inventory",
                    "summary": f"Site {object_ref} encontrado no inventário estruturado.",
                    "data": {"site": site},
                }
            )


def knowledge_check(
    request: dict[str, Any],
    entities: list[dict[str, Any]],
    memory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    known: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []

    site_code = _safe_site_from_entities(entities)
    domain = _safe_domain_from_entities(entities)
    domain_memory = memory if isinstance(memory, dict) and str(memory.get("entity_type") or "").lower() == "domain" else None
    semantic_context = request.get("semantic_context") if isinstance(request.get("semantic_context"), dict) else None
    _add_semantic_context_known_items(request, known, semantic_context)
    if site_code:
        site = get_site(site_code)
        public_context = get_inventory_public_context(site_code=site_code, locality_code="CE", limit=20)
        known.append(
            {
                "kind": "site",
                "entity_type": "site",
                "entity_value": site_code,
                "confidence": "confirmed" if site is not None else "unknown",
                "source": "inventory",
                "summary": (
                    f"Site {site_code} existe no inventário interno."
                    if site is not None
                    else f"Site {site_code} não encontrado no inventário interno."
                ),
                "data": {"site": site, "public_context": public_context},
            }
        )
        if public_context is not None:
            known.append(
                {
                    "kind": "ixbr_public_context",
                    "entity_type": "site",
                    "entity_value": site_code,
                    "confidence": "probable",
                    "source": "ixbr_public_discovery",
                    "summary": (
                        "IX.br/CE fornece contexto público para o PTT-CE com "
                        f"{public_context.get('public_participants_count', 0)} participantes e "
                        f"{public_context.get('public_participants_seen_as_origin_count', 0)} vistos como origin."
                    ),
                    "data": public_context,
                }
            )
            _store_public_context_artifacts(
                conn=request["conn"],
                request_id=request["id"],
                site_code=site_code,
                public_context=public_context,
            )
        else:
            unknown.append(
                {
                    "kind": "ixbr_public_context",
                    "entity_type": "site",
                    "entity_value": site_code,
                    "summary": "Contexto público IX.br indisponível nesta consulta.",
                }
            )

    if domain and domain_memory is not None and request.get("intent") in {"route_to_domain", "domain_analysis"}:
        dns_context = domain_memory.get("dns") or {}
        dns_freshness = dns_context.get("freshness") or {}
        known.append(
            {
                "kind": "reused_learning_context",
                "entity_type": "domain",
                "entity_value": domain,
                "confidence": "confirmed" if dns_freshness.get("status") == "fresh" else "probable",
                "source": "learning_memory",
                "summary": domain_memory.get("summary_text") or f"Aprendizado reutilizado para {domain}.",
                "data": domain_memory,
            }
        )
        if dns_context.get("resolved_ips"):
            known.append(
                {
                    "kind": "dns_resolution",
                    "entity_type": "domain",
                    "entity_value": domain,
                    "confidence": "confirmed" if dns_freshness.get("status") == "fresh" else "probable",
                    "source": "learning_memory",
                    "summary": (
                        f"DNS de {domain} já foi aprendido e retornou {len(dns_context.get('resolved_ips') or [])} IP(s)."
                    ),
                    "data": dns_context,
                }
            )
        for item in domain_memory.get("ips") or []:
            ip_value = str(item.get("ip") or "").strip()
            if not ip_value:
                continue
            bgp_context = item.get("bgp") or {}
            if bgp_context.get("latest") is not None:
                known.append(
                    {
                        "kind": "bgp_prefix_lookup",
                        "entity_type": "ip",
                        "entity_value": ip_value,
                        "confidence": "confirmed" if bgp_context.get("status") == "fresh" else "probable",
                        "source": "learning_memory",
                        "summary": f"BGP para {ip_value} já foi aprendido com status {bgp_context.get('status')}.",
                        "data": bgp_context,
                    }
                )
            ping_context = item.get("ping") or {}
            if ping_context.get("latest") is not None:
                known.append(
                    {
                        "kind": "ping_measurement",
                        "entity_type": "ip",
                        "entity_value": ip_value,
                        "confidence": "confirmed" if ping_context.get("status") == "fresh" else "probable",
                        "source": "learning_memory",
                        "summary": f"Ping para {ip_value} já existe com status {ping_context.get('status')}.",
                        "data": ping_context,
                    }
                )
            traceroute_context = item.get("traceroute") or {}
            if traceroute_context.get("latest") is not None:
                known.append(
                    {
                        "kind": "traceroute_measurement",
                        "entity_type": "ip",
                        "entity_value": ip_value,
                        "confidence": "confirmed" if traceroute_context.get("status") == "fresh" else "probable",
                        "source": "learning_memory",
                        "summary": f"Traceroute para {ip_value} já existe com status {traceroute_context.get('status')}.",
                        "data": traceroute_context,
                    }
                )

    for entity in entities:
        entity_type = entity.get("entity_type")
        normalized_value = str(entity.get("normalized_value") or entity.get("entity_value") or "").strip()
        if entity_type == "prefix":
            prefix = _safe_prefix_from_entity(entity)
            if not prefix:
                unknown.append({"kind": "bgp_prefix_lookup", "entity_type": entity_type, "entity_value": normalized_value})
                continue
            data = get_prefix_lookup(prefix, limit=20)
            if data:
                known.append(
                    {
                        "kind": "bgp_prefix_lookup",
                        "entity_type": entity_type,
                        "entity_value": normalized_value,
                        "confidence": "confirmed",
                        "source": "bgp_current_routes",
                        "summary": f"Prefixo {prefix} encontrado na base BGP.",
                        "data": data,
                    }
                )
                _cache_upsert(
                    request["conn"],
                    cache_key=f"prefix:{prefix}:bgp",
                    cache_type="bgp",
                    entity_type="prefix",
                    entity_value=prefix,
                    data=data,
                    confidence="confirmed",
                    source="bgp_current_routes",
                    expires_at=None,
                )
                _add_evidence(
                    request["conn"],
                    request_id=request["id"],
                    evidence_type="bgp_prefix_lookup",
                    entity_type="prefix",
                    entity_value=prefix,
                    confidence="confirmed",
                    source="bgp_current_routes",
                    source_ref=prefix,
                    summary=f"Prefixo {prefix} encontrado na base BGP.",
                    data=data,
                )
            else:
                unknown.append({"kind": "bgp_prefix_lookup", "entity_type": entity_type, "entity_value": normalized_value})
        elif entity_type == "ip":
            data = lookup_bgp_by_ip(normalized_value, limit_peers=20)
            if data:
                known.append(
                    {
                        "kind": "bgp_prefix_lookup",
                        "entity_type": entity_type,
                        "entity_value": normalized_value,
                        "confidence": "confirmed",
                        "source": "bgp_current_routes",
                        "summary": f"IP {normalized_value} mapeado para prefixo {data.get('matched_prefix')}.",
                        "data": data,
                    }
                )
                _cache_upsert(
                    request["conn"],
                    cache_key=f"ip:{normalized_value}:bgp",
                    cache_type="bgp",
                    entity_type="ip",
                    entity_value=normalized_value,
                    data=data,
                    confidence="confirmed",
                    source="bgp_current_routes",
                    expires_at=None,
                )
                _add_evidence(
                    request["conn"],
                    request_id=request["id"],
                    evidence_type="bgp_prefix_match",
                    entity_type="ip",
                    entity_value=normalized_value,
                    confidence="confirmed",
                    source="bgp_current_routes",
                    source_ref=str(data.get("matched_prefix") or normalized_value),
                    summary=f"IP {normalized_value} mapeado para prefixo {data.get('matched_prefix')}.",
                    data=data,
                )
            else:
                unknown.append({"kind": "bgp_prefix_lookup", "entity_type": entity_type, "entity_value": normalized_value})
        elif entity_type == "asn":
            asn = _safe_asn_from_entities([entity])
            if asn is None:
                unknown.append({"kind": "bgp_asn_lookup", "entity_type": entity_type, "entity_value": normalized_value})
                continue
            data = get_asn_lookup(asn, limit=20)
            if data:
                known.append(
                    {
                        "kind": "bgp_asn_lookup",
                        "entity_type": entity_type,
                        "entity_value": normalized_value,
                        "confidence": "confirmed",
                        "source": "bgp_current_routes",
                        "summary": f"ASN {asn} encontrado na base BGP.",
                        "data": data,
                    }
                )
                _cache_upsert(
                    request["conn"],
                    cache_key=f"asn:{asn}:summary",
                    cache_type="bgp",
                    entity_type="asn",
                    entity_value=str(asn),
                    data=data,
                    confidence="confirmed",
                    source="bgp_current_routes",
                    expires_at=None,
                )
                _add_evidence(
                    request["conn"],
                    request_id=request["id"],
                    evidence_type="bgp_asn_lookup",
                    entity_type="asn",
                    entity_value=str(asn),
                    confidence="confirmed",
                    source="bgp_current_routes",
                    source_ref=str(asn),
                    summary=f"ASN {asn} encontrado na base BGP.",
                    data=data,
                )
            else:
                unknown.append({"kind": "bgp_asn_lookup", "entity_type": entity_type, "entity_value": normalized_value})
        elif entity_type == "peer":
            peer_data = get_peer_lookup(normalized_value, limit=20)
            if peer_data:
                known.append(
                    {
                        "kind": "peer_lookup",
                        "entity_type": entity_type,
                        "entity_value": normalized_value,
                        "confidence": "confirmed",
                        "source": "bgp_current_routes",
                        "summary": "Peer observado na base BGP.",
                        "data": peer_data,
                    }
                )
                _add_evidence(
                    request["conn"],
                    request_id=request["id"],
                    evidence_type="peer_lookup",
                    entity_type="peer",
                    entity_value=normalized_value,
                    confidence="confirmed",
                    source="bgp_current_routes",
                    source_ref=normalized_value,
                    summary="Peer observado na base BGP.",
                    data=peer_data,
                )
            else:
                unknown.append({"kind": "peer_lookup", "entity_type": entity_type, "entity_value": normalized_value})
        elif entity_type == "domain":
            unknown.append({"kind": "dns_resolution", "entity_type": entity_type, "entity_value": normalized_value})
        elif entity_type in {"site", "ix"}:
            continue
        else:
            unknown.append({"kind": "unknown_entity", "entity_type": entity_type, "entity_value": normalized_value})

    confidence_before = 0.0
    if known:
        confidence_before = min(0.95, round(0.25 + 0.15 * len(known), 2))

    return {
        "known": known,
        "unknown": unknown,
        "confidence_before": confidence_before,
    }


def _store_public_context_artifacts(
    *,
    conn: psycopg.Connection,
    request_id: int,
    site_code: str,
    public_context: dict[str, Any] | None,
) -> None:
    if public_context is None:
        return
    expires_at = None
    try:
        expires_at = (public_context.get("bgp_summary", {}) or {}).get("participants_fetched_at")
        if expires_at is not None:
            expires_at = expires_at + timedelta(days=7)
    except Exception:
        expires_at = None

    _cache_upsert(
        conn,
        cache_key=f"site:{site_code}:public-context",
        cache_type="inventory",
        entity_type="site",
        entity_value=site_code,
        data=public_context,
        confidence="probable",
        source="inventory_queries.get_inventory_public_context",
        expires_at=expires_at,
    )
    _cache_upsert(
        conn,
        cache_key=f"site:{site_code}:ixbr-summary",
        cache_type="ixbr",
        entity_type="site",
        entity_value=site_code,
        data=public_context.get("bgp_summary") or {},
        confidence="probable",
        source="ixbr_discovery_queries.summarize_ixbr_vs_bgp",
        expires_at=expires_at,
    )
    _add_evidence(
        conn,
        request_id=request_id,
        evidence_type="inventory_lookup",
        entity_type="site",
        entity_value=site_code,
        confidence="probable",
        source="inventory_queries.get_inventory_public_context",
        source_ref=site_code,
        summary=(
            f"Site {site_code} consultado com contexto público IX.br e inventário interno."
            f" Hosts confirmados={int(public_context.get('confirmed_hosts_count') or 0)}."
        ),
        data=public_context,
    )
    _add_evidence(
        conn,
        request_id=request_id,
        evidence_type="ixbr_lookup",
        entity_type="site",
        entity_value=site_code,
        confidence="probable",
        source="ixbr_discovery_queries.summarize_ixbr_vs_bgp",
        source_ref=site_code,
        summary=(
            f"IX.br/CE correlacionado ao site {site_code} com "
            f"{int(public_context.get('public_participants_count') or 0)} participantes públicos."
        ),
        data=public_context.get("bgp_summary") or {},
    )


def detect_gaps(
    request: dict[str, Any],
    known_context: dict[str, Any],
    memory: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    entities = request.get("entities", [])
    intent = request.get("intent") or "general_network_question"
    gaps: list[dict[str, Any]] = []
    domain_memory = memory if isinstance(memory, dict) and str(memory.get("entity_type") or "").lower() == "domain" else None

    def add_gap(
        gap_type: str,
        description: str,
        *,
        severity: str = "medium",
        blocks_answer: bool = False,
        recommended_task_type: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        gaps.append(
            {
                "gap_type": gap_type,
                "description": description,
                "severity": severity,
                "blocks_answer": blocks_answer,
                "recommended_task_type": recommended_task_type,
                "status": "open",
                "metadata": metadata or {},
            }
        )

    has_domain = any(entity.get("entity_type") == "domain" for entity in entities)
    domain_label = _safe_domain_from_entities(entities) or "domínio"
    has_site_ptt_ce = any(
        entity.get("entity_type") == "site" and str(entity.get("normalized_value") or entity.get("entity_value")) == "PTT-CE"
        for entity in entities
    )
    has_asn = any(entity.get("entity_type") == "asn" for entity in entities)
    has_prefix = any(entity.get("entity_type") in {"prefix", "ip"} for entity in entities)
    has_peer = any(entity.get("entity_type") == "peer" for entity in entities)
    has_unknown = any(entity.get("entity_type") == "unknown" for entity in entities)

    known = known_context.get("known", [])
    site_known = next((item for item in known if item.get("kind") == "site"), None)
    public_context_known = next((item for item in known if item.get("kind") == "ixbr_public_context"), None)
    inventory_host_known = next((item for item in known if item.get("kind") == "inventory_host" and item.get("confidence") == "confirmed"), None)

    if has_domain:
        dns_context = (domain_memory or {}).get("dns") or {}
        dns_freshness = dns_context.get("freshness") or {}
        dns_status = str(dns_freshness.get("status") or "missing")
        if dns_status == "fresh":
            pass
        elif dns_status == "stale":
            add_gap(
                "stale_dns_resolution",
                f"DNS de {domain_label} está stale e deve ser reavaliado.",
                severity="medium",
                blocks_answer=False,
                recommended_task_type="dns_resolve",
                metadata={"age_human": dns_freshness.get("age_human"), "resolved_ips": dns_context.get("resolved_ips") or []},
            )
        elif dns_status == "expired":
            add_gap(
                "expired_dns_resolution",
                f"DNS de {domain_label} expirou e deve ser atualizado.",
                severity="high",
                blocks_answer=False,
                recommended_task_type="dns_resolve",
                metadata={"age_human": dns_freshness.get("age_human"), "resolved_ips": dns_context.get("resolved_ips") or []},
            )
        else:
            add_gap(
                "missing_dns_resolution",
                "Domínio citado na pergunta ainda não foi resolvido nesta rodada.",
                severity="high",
                blocks_answer=True,
                recommended_task_type="dns_resolve",
            )

        ip_states = [item for item in (domain_memory or {}).get("ips") or [] if isinstance(item, dict)]

        def _worst_status(statuses: list[str]) -> str:
            if "expired" in statuses:
                return "expired"
            if "stale" in statuses:
                return "stale"
            if "fresh" in statuses:
                return "fresh"
            return "missing"

        bgp_statuses = [str((item.get("bgp") or {}).get("status") or "missing") for item in ip_states if (item.get("bgp") or {}).get("latest") is not None]
        ping_statuses = [str((item.get("ping") or {}).get("status") or "missing") for item in ip_states if (item.get("ping") or {}).get("latest") is not None]
        traceroute_statuses = [
            str((item.get("traceroute") or {}).get("status") or "missing")
            for item in ip_states
            if (item.get("traceroute") or {}).get("latest") is not None
        ]

        if bgp_statuses:
            bgp_status = _worst_status(bgp_statuses)
            if bgp_status == "stale":
                add_gap(
                    "stale_bgp_match",
                    "Há evidência BGP reutilizável, mas ela já está stale.",
                    severity="medium",
                    blocks_answer=False,
                    recommended_task_type="bgp_prefix_lookup",
                    metadata={"statuses": bgp_statuses},
                )
            elif bgp_status == "expired":
                add_gap(
                    "expired_bgp_match",
                    "Há evidência BGP antiga e ela deve ser atualizada.",
                    severity="high",
                    blocks_answer=False,
                    recommended_task_type="bgp_prefix_lookup",
                    metadata={"statuses": bgp_statuses},
                )
        else:
            add_gap(
                "missing_bgp_match",
                "Ainda não há mapeamento BGP suficiente para fechar a rota do domínio.",
                severity="high",
                blocks_answer=True,
                recommended_task_type="bgp_prefix_lookup",
            )

        if ping_statuses:
            ping_status = _worst_status(ping_statuses)
            if ping_status == "stale":
                add_gap(
                    "stale_ping_measurement",
                    "Ping reutilizável existe, mas já está stale.",
                    severity="medium",
                    blocks_answer=False,
                    recommended_task_type="ping_measurement",
                    metadata={"statuses": ping_statuses},
                )
            elif ping_status == "expired":
                add_gap(
                    "expired_ping_measurement",
                    "Ping reutilizável existe, mas já expirou.",
                    severity="high",
                    blocks_answer=False,
                    recommended_task_type="ping_measurement",
                    metadata={"statuses": ping_statuses},
                )
        else:
            add_gap(
                "missing_ping_measurement",
                "Pergunta de roteamento por domínio ainda não tem ping recente associado.",
                severity="medium",
                blocks_answer=False,
                recommended_task_type="ping_measurement",
            )

        if traceroute_statuses:
            traceroute_status = _worst_status(traceroute_statuses)
            if traceroute_status == "stale":
                add_gap(
                    "stale_traceroute_measurement",
                    "Traceroute reutilizável existe, mas já está stale.",
                    severity="medium",
                    blocks_answer=False,
                    recommended_task_type="traceroute_measurement",
                    metadata={"statuses": traceroute_statuses},
                )
            elif traceroute_status == "expired":
                add_gap(
                    "expired_traceroute_measurement",
                    "Traceroute reutilizável existe, mas já expirou.",
                    severity="high",
                    blocks_answer=False,
                    recommended_task_type="traceroute_measurement",
                    metadata={"statuses": traceroute_statuses},
                )
        else:
            add_gap(
                "missing_traceroute_measurement",
                "Pergunta de roteamento por domínio ainda não tem traceroute recente associado.",
                severity="medium",
                blocks_answer=True,
                recommended_task_type="traceroute_measurement",
            )

    if has_site_ptt_ce:
        confirmed_hosts_count = 0
        if site_known and isinstance(site_known.get("data"), dict):
            confirmed_hosts_count = int(((site_known["data"].get("site") or {}).get("host_count")) or 0)
        if confirmed_hosts_count == 0:
            add_gap(
                "missing_inventory_link",
                "PTT-CE ainda não tem hosts internos confirmados no inventário.",
                severity="medium",
                blocks_answer=False,
                recommended_task_type="inventory_lookup",
                metadata={"confirmed_hosts_count": 0},
            )
        if public_context_known is None:
            add_gap(
                "missing_ix_context",
                "Contexto público IX.br para PTT-CE ainda não foi coletado nesta request.",
                severity="low",
                blocks_answer=False,
                recommended_task_type="ixbr_lookup",
            )

    if has_asn and not any(item.get("kind") == "bgp_asn_lookup" for item in known):
        add_gap(
            "missing_bgp_match",
            "ASN citado ainda não foi confirmado na base BGP nesta request.",
            severity="high",
            blocks_answer=True,
            recommended_task_type="bgp_asn_lookup",
        )

    if has_prefix and not any(item.get("kind") == "bgp_prefix_lookup" for item in known):
        add_gap(
            "missing_bgp_match",
            "Prefixo/IP citado ainda não foi confirmado na base BGP nesta request.",
            severity="high",
            blocks_answer=True,
            recommended_task_type="bgp_prefix_lookup",
        )

    if has_peer and not any(item.get("kind") == "peer_lookup" for item in known):
        add_gap(
            "missing_inventory_link",
            "Peer citado ainda não tem vínculo confirmado com o inventário.",
            severity="medium",
            blocks_answer=False,
            recommended_task_type="inventory_lookup",
        )

    if has_unknown and inventory_host_known is None:
        unknown_value = next((str(entity.get("normalized_value") or entity.get("entity_value") or "") for entity in entities if entity.get("entity_type") == "unknown"), "")
        add_gap(
            "unknown_entity",
            "A pergunta menciona entidade operacional genérica que ainda não foi confirmada por inventário ou evidência estruturada.",
            severity="low",
            blocks_answer=False,
            recommended_task_type="answer_build",
            metadata={"entity_value": unknown_value},
        )

    if not entities:
        add_gap(
            "unknown_entity",
            "Nenhuma entidade operacional relevante foi extraída da pergunta.",
            severity="low",
            blocks_answer=False,
            recommended_task_type="answer_build",
        )

    if intent == "ix_inventory_context" and has_site_ptt_ce and not any(gap["gap_type"] == "missing_inventory_link" for gap in gaps):
        add_gap(
            "missing_inventory_link",
            "A pergunta depende de hosts confirmados, mas ainda não há vínculo explícito para o site.",
            severity="medium",
            blocks_answer=False,
            recommended_task_type="inventory_lookup",
        )

    return gaps


def build_learning_plan(
    request: dict[str, Any],
    gaps: list[dict[str, Any]],
    memory: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    entities = request.get("entities", [])
    intent = request.get("intent") or "general_network_question"
    task_specs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    domain_memory = memory if isinstance(memory, dict) and str(memory.get("entity_type") or "").lower() == "domain" else None

    def add_task(
        task_type: str,
        *,
        priority: int = 100,
        requires_consent: bool = False,
        command_preview: str | None = None,
        input_data: dict[str, Any] | None = None,
        status: str | None = None,
    ) -> None:
        key = (task_type, _safe_json(input_data or {}).__repr__())
        if key in seen:
            return
        seen.add(key)
        task_specs.append(
            {
                "task_uid": f"lt_{uuid.uuid4().hex}",
                "task_type": task_type,
                "status": status or ("waiting_consent" if requires_consent else "planned"),
                "priority": priority,
                "requires_consent": requires_consent,
                "command_preview": command_preview,
                "input": input_data or {},
                "output": {},
                "error": None,
            }
        )

    domain = _safe_domain_from_entities(entities)
    site_code = _safe_site_from_entities(entities)
    asn = _safe_asn_from_entities(entities)

    for gap in gaps:
        gap_type = gap.get("gap_type")
        recommended = gap.get("recommended_task_type")
        if gap_type in {"missing_dns_resolution", "stale_dns_resolution", "expired_dns_resolution"} and domain:
            add_task(
                "dns_resolve",
                priority=10,
                input_data={"domain": domain},
                command_preview=f"Resolver DNS de {domain}",
            )
        elif gap_type in {"missing_bgp_match", "stale_bgp_match", "expired_bgp_match"} and (
            domain or asn or any(e.get("entity_type") in {"prefix", "ip"} for e in entities)
        ):
            if any(e.get("entity_type") in {"prefix", "ip"} for e in entities):
                target = next((e for e in entities if e.get("entity_type") in {"prefix", "ip"}), None)
                if target is not None:
                    add_task(
                        "bgp_prefix_lookup",
                        priority=20,
                        input_data={"entity": target},
                        command_preview=f"Consultar BGP para {target.get('normalized_value') or target.get('entity_value')}",
                    )
            elif asn is not None:
                add_task(
                    "bgp_asn_lookup",
                    priority=20,
                    input_data={"asn": asn},
                    command_preview=f"Consultar BGP para ASN {asn}",
                )
            elif domain:
                add_task(
                        "bgp_prefix_lookup",
                        priority=20,
                        input_data={"domain": domain, "dependency": "dns_resolve"},
                        command_preview=f"Consultar BGP para o domínio {domain} após resolver DNS",
                    )
        elif gap_type == "missing_inventory_link" and site_code:
            add_task(
                "inventory_lookup",
                priority=30,
                input_data={"site_code": site_code},
                command_preview=f"Consultar inventário para {site_code}",
            )
        elif gap_type == "missing_ix_context" and site_code:
            add_task(
                "ixbr_lookup",
                priority=40,
                input_data={"site_code": site_code, "locality_code": "CE"},
                command_preview=f"Consultar contexto IX.br para {site_code}",
            )
        elif gap_type in {"missing_ping_measurement", "stale_ping_measurement", "expired_ping_measurement"}:
            add_task(
                "ping_measurement",
                priority=80,
                requires_consent=True,
                input_data={"target": domain or site_code or asn},
                command_preview="Executar ping controlado sob consentimento",
            )
        elif gap_type in {"missing_traceroute_measurement", "stale_traceroute_measurement", "expired_traceroute_measurement"}:
            add_task(
                "traceroute_measurement",
                priority=90,
                requires_consent=True,
                input_data={"target": domain or site_code or asn},
                command_preview="Executar traceroute controlado sob consentimento",
            )

    if site_code == "PTT-CE":
        add_task(
            "inventory_lookup",
            priority=30,
            input_data={"site_code": site_code},
            command_preview=f"Consultar inventário para {site_code}",
        )
        add_task(
            "ixbr_lookup",
            priority=40,
            input_data={"site_code": site_code, "locality_code": "CE"},
            command_preview=f"Consultar contexto IX.br para {site_code}",
        )

    if asn is not None and not any(task["task_type"] == "bgp_asn_lookup" for task in task_specs):
        add_task(
            "bgp_asn_lookup",
            priority=20,
            input_data={"asn": asn},
            command_preview=f"Consultar BGP para ASN {asn}",
        )

    if any(entity.get("entity_type") in {"prefix", "ip"} for entity in entities):
        target = next((e for e in entities if e.get("entity_type") in {"prefix", "ip"}), None)
        if target is not None and not any(task["task_type"] == "bgp_prefix_lookup" for task in task_specs):
            add_task(
                "bgp_prefix_lookup",
                priority=20,
                input_data={"entity": target},
                command_preview=f"Consultar BGP para {target.get('normalized_value') or target.get('entity_value')}",
            )

    add_task(
        "answer_build",
        priority=100,
        input_data={"intent": intent},
        command_preview="Construir resposta final a partir do conhecimento, lacunas e evidências",
    )

    task_specs.sort(key=lambda item: (int(item.get("priority", 100)), item.get("task_type", ""), item.get("task_uid", "")))
    return task_specs


def _insert_request(
    conn: psycopg.Connection,
    *,
    request_uid: str,
    question: str,
    normalized_question: str,
    intent: str,
    scope: str,
    operator: str | None,
    raw_context: dict[str, Any] | None,
) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            insert into learning_requests (
              request_uid,
              question,
              normalized_question,
              intent,
              scope,
              status,
              operator,
              requires_consent,
              consent_status,
              raw_context
            )
            values (%s, %s, %s, %s, %s, 'created', %s, false, 'not_required', %s)
            returning id, request_uid, question, normalized_question, intent, scope, status, operator,
                      requires_consent, consent_status, confidence_before, confidence_after, answer_summary,
                      created_at, updated_at, started_at, finished_at, raw_context, result, error;
            """,
            (
                request_uid,
                question,
                normalized_question,
                intent,
                scope,
                operator,
                _json_value(raw_context or {}),
            ),
        )
        return dict(cur.fetchone())


def _insert_entities(conn: psycopg.Connection, request_id: int, entities: list[dict[str, Any]]) -> None:
    if not entities:
        return
    with conn.cursor() as cur:
        for entity in entities:
            cur.execute(
                """
                insert into learning_entities (
                  request_id,
                  entity_type,
                  entity_value,
                  normalized_value,
                  confidence,
                  source,
                  metadata
                )
                values (%s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    request_id,
                    entity.get("entity_type"),
                    entity.get("entity_value"),
                    entity.get("normalized_value"),
                    entity.get("confidence"),
                    entity.get("source", "rule"),
                    _json_value(entity.get("metadata") or {}),
                ),
            )


def _insert_gaps(conn: psycopg.Connection, request_id: int, gaps: list[dict[str, Any]]) -> None:
    if not gaps:
        return
    with conn.cursor() as cur:
        for gap in gaps:
            cur.execute(
                """
                insert into learning_gaps (
                  request_id,
                  gap_type,
                  description,
                  severity,
                  blocks_answer,
                  recommended_task_type,
                  status,
                  metadata
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    request_id,
                    gap.get("gap_type"),
                    gap.get("description"),
                    gap.get("severity", "medium"),
                    bool(gap.get("blocks_answer", False)),
                    gap.get("recommended_task_type"),
                    gap.get("status", "open"),
                    _json_value(gap.get("metadata") or {}),
                ),
            )


def _insert_tasks(conn: psycopg.Connection, request_id: int, tasks: list[dict[str, Any]]) -> None:
    if not tasks:
        return
    with conn.cursor() as cur:
        for task in tasks:
            cur.execute(
                """
                insert into learning_tasks (
                  request_id,
                  task_uid,
                  task_type,
                  status,
                  priority,
                  requires_consent,
                  command_preview,
                  input,
                  output,
                  error
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    request_id,
                    task["task_uid"],
                    task["task_type"],
                    task["status"],
                    int(task.get("priority", 100)),
                    bool(task.get("requires_consent", False)),
                    task.get("command_preview"),
                    _json_value(task.get("input") or {}),
                    _json_value(task.get("output") or {}),
                    task.get("error"),
                ),
            )


def _task_input_entities(task: dict[str, Any]) -> list[dict[str, Any]]:
    input_data = task.get("input") or {}
    if not isinstance(input_data, dict):
        return []
    entity = input_data.get("entity")
    if isinstance(entity, dict):
        return [entity]
    if "domain" in input_data:
        return [{"entity_type": "domain", "entity_value": input_data["domain"], "normalized_value": str(input_data["domain"]).lower()}]
    if "asn" in input_data:
        return [{"entity_type": "asn", "entity_value": str(input_data["asn"]), "normalized_value": str(input_data["asn"])}]
    if "site_code" in input_data:
        return [{"entity_type": "site", "entity_value": input_data["site_code"], "normalized_value": input_data["site_code"]}]
    return []


def classify_target_ip(ip: str) -> dict[str, Any]:
    ip_obj = ipaddress.ip_address(str(ip).strip())
    blocked_reasons: list[str] = []
    if ACTIVE_MEASUREMENT_POLICY["deny_private_ips"] and ip_obj.is_private:
        blocked_reasons.append("private_ip")
    if ACTIVE_MEASUREMENT_POLICY["deny_loopback"] and ip_obj.is_loopback:
        blocked_reasons.append("loopback_ip")
    if ACTIVE_MEASUREMENT_POLICY["deny_link_local"] and ip_obj.is_link_local:
        blocked_reasons.append("link_local_ip")
    if ACTIVE_MEASUREMENT_POLICY["deny_multicast"] and ip_obj.is_multicast:
        blocked_reasons.append("multicast_ip")
    if ACTIVE_MEASUREMENT_POLICY["deny_reserved"] and ip_obj.is_reserved:
        blocked_reasons.append("reserved_ip")
    if not ip_obj.is_global:
        blocked_reasons.append("non_global_ip")

    allowed = not blocked_reasons
    return {
        "ip": str(ip_obj),
        "version": ip_obj.version,
        "is_global": ip_obj.is_global,
        "is_private": ip_obj.is_private,
        "is_loopback": ip_obj.is_loopback,
        "is_link_local": ip_obj.is_link_local,
        "is_multicast": ip_obj.is_multicast,
        "is_reserved": ip_obj.is_reserved,
        "allowed": allowed,
        "reason_if_blocked": blocked_reasons[0] if blocked_reasons else None,
        "blocked_reasons": blocked_reasons,
    }


def _request_dns_resolution_ips(bundle: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    resolved_ips: list[str] = []
    for evidence in bundle.get("evidence", []):
        if not isinstance(evidence, dict) or evidence.get("evidence_type") != "dns_resolution":
            continue
        data = evidence.get("data") or {}
        if not isinstance(data, dict):
            continue
        for record in data.get("resolved_records") or []:
            if not isinstance(record, dict):
                continue
            ip_value = record.get("ip")
            if not ip_value:
                continue
            ip_text = str(ip_value).strip()
            if not ip_text or ip_text in seen:
                continue
            seen.add(ip_text)
            resolved_ips.append(ip_text)
        for ip_value in data.get("resolved_ips") or []:
            ip_text = str(ip_value).strip()
            if not ip_text or ip_text in seen:
                continue
            seen.add(ip_text)
            resolved_ips.append(ip_text)
    return resolved_ips


def select_measurement_targets(request_uid: str) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    resolved_ips = _request_dns_resolution_ips(bundle)
    return _select_measurement_targets_from_ips(request_uid=request_uid, resolved_ips=resolved_ips)


def _select_measurement_targets_from_ips(request_uid: str, resolved_ips: list[str]) -> dict[str, Any]:
    selected_targets: list[dict[str, Any]] = []
    blocked_targets: list[dict[str, Any]] = []
    skipped_targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    max_targets = int(ACTIVE_MEASUREMENT_POLICY["max_targets_per_request"])

    for ip_text in resolved_ips:
        if ip_text in seen:
            skipped_targets.append({"ip": ip_text, "reason": "duplicate"})
            continue
        seen.add(ip_text)
        try:
            classification = classify_target_ip(ip_text)
        except ValueError:
            blocked_targets.append({"ip": ip_text, "reason": "invalid_ip"})
            continue
        if not classification["allowed"]:
            blocked_targets.append(
                {
                    "ip": classification["ip"],
                    "reason": classification["reason_if_blocked"],
                    "blocked_reasons": classification["blocked_reasons"],
                }
            )
            continue
        if len(selected_targets) >= max_targets:
            skipped_targets.append({"ip": classification["ip"], "reason": "target_limit_reached"})
            continue
        selected_targets.append(classification)

    return {
        "request_uid": request_uid,
        "resolved_ips": resolved_ips,
        "selected_targets": selected_targets,
        "blocked_targets": blocked_targets,
        "skipped_targets": skipped_targets,
        "limits": {
            "max_targets_per_request": max_targets,
            "ping_count": ACTIVE_MEASUREMENT_POLICY["ping_count"],
            "ping_timeout_seconds": ACTIVE_MEASUREMENT_POLICY["ping_timeout_seconds"],
            "traceroute_max_hops": ACTIVE_MEASUREMENT_POLICY["traceroute_max_hops"],
            "traceroute_timeout_seconds": ACTIVE_MEASUREMENT_POLICY["traceroute_timeout_seconds"],
            "max_total_runtime_seconds": ACTIVE_MEASUREMENT_POLICY["max_total_runtime_seconds"],
        },
    }


def preview_active_measurement_targets(request_uid: str) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    request_row = bundle["request"]
    entities = bundle["entities"]
    domain = _safe_domain_from_entities(entities)
    if not domain:
        return {
            "request_uid": request_uid,
            "requires_dns_resolution": False,
            "target_domain": None,
            "resolved_ips": [],
            "selected_targets": [],
            "blocked_targets": [],
            "skipped_targets": [],
            "active_targets_ready": False,
            "reason_if_blocked": "missing_target_domain",
            "next_safe_step": None,
        }
    dns_evidence = [
        evidence
        for evidence in bundle.get("evidence") or []
        if isinstance(evidence, dict)
        and evidence.get("evidence_type") == "dns_resolution"
        and str(evidence.get("entity_value") or "").strip().lower() == domain
    ]
    resolved_ips = _request_dns_resolution_ips(bundle)
    selection = _select_measurement_targets_from_ips(request_uid=request_uid, resolved_ips=resolved_ips)
    selected_targets = selection["selected_targets"]
    blocked_targets = selection["blocked_targets"]
    skipped_targets = selection["skipped_targets"]
    requires_dns_resolution = not bool(resolved_ips)
    reason_if_blocked = None
    next_safe_step = None
    if requires_dns_resolution:
        reason_if_blocked = "missing_dns_resolution_for_active_targets"
        next_safe_step = "dns_resolution"
    elif not selected_targets:
        reason_if_blocked = "no_allowed_targets"
        next_safe_step = "dns_resolution"
    return {
        "request_uid": request_uid,
        "target_domain": domain,
        "requires_dns_resolution": requires_dns_resolution,
        "resolved_ips": resolved_ips,
        "selected_targets": selected_targets,
        "blocked_targets": blocked_targets,
        "skipped_targets": skipped_targets,
        "active_targets_ready": bool(selected_targets),
        "reason_if_blocked": reason_if_blocked,
        "next_safe_step": next_safe_step,
        "dns_evidence_count": len(dns_evidence),
        "request_status": request_row.get("status"),
    }


def resolve_active_targets_for_request(
    request_uid: str,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    request_row = bundle["request"]
    request_id = int(request_row["id"])
    entities = bundle["entities"]
    domain = _safe_domain_from_entities(entities)
    if not domain:
        return {
            "request_uid": request_uid,
            "status": "skipped",
            "reason": "missing_target_domain",
            "resolved_ips": [],
            "selected_targets": [],
            "blocked_targets": [],
            "skipped_targets": [],
        }
    learning_memory_summary = summarize_learning_memory({"entity_type": "domain", "entity_value": domain})
    learning_memory = learning_memory_summary.get("memory") if isinstance(learning_memory_summary, dict) else None
    dns_output: dict[str, Any]
    with get_connection() as conn:
        cache_key = f"domain:{domain}:dns"
        cached = None if force_refresh else _fetch_learning_cache_row(conn, cache_key)
        if cached is None and isinstance(learning_memory, dict):
            memory_dns = learning_memory.get("dns") or {}
            if memory_dns.get("resolved_ips"):
                cached = {
                    "source": "learning_memory",
                    "confidence": "probable",
                    "expires_at": memory_dns.get("freshness", {}).get("expires_at"),
                    "data": (memory_dns.get("cache") or {}).get("data") or ((memory_dns.get("evidence") or [{}])[0].get("data") if memory_dns.get("evidence") else {}),
                    "freshness": memory_dns.get("freshness") or {},
                    "request_uid": memory_dns.get("request_uid"),
                }
        if cached is not None:
            cached_data = cached.get("data") or {}
            resolved_records = cached_data.get("resolved_records") or []
            resolved_ips = [str(record.get("ip")) for record in resolved_records if record.get("ip")]
            if not resolved_ips:
                resolved_ips = [str(ip) for ip in (cached_data.get("resolved_ips") or []) if ip]
            dns_output = {
                "status": "completed",
                "cache_hit": True,
                "source": cached.get("source") or "learning_cache",
                "cache_key": cache_key,
                "domain": domain,
                "resolved_ips": resolved_ips,
                "resolved_records": resolved_records,
                "resolved_at": cached_data.get("resolved_at"),
                "ttl_seconds": cached_data.get("ttl_seconds"),
                "cache_expires_at": cached.get("expires_at"),
                "reuse_freshness": cached.get("freshness"),
                "reused_from_request_uid": cached.get("request_uid"),
            }
        else:
            try:
                resolved_records = _resolve_domain_ips(domain)
                resolved_ips = [str(record.get("ip")) for record in resolved_records if record.get("ip")]
                dns_output = {
                    "status": "completed",
                    "cache_hit": False,
                    "source": "socket.getaddrinfo",
                    "cache_key": cache_key,
                    "domain": domain,
                    "resolved_ips": resolved_ips,
                    "resolved_records": resolved_records,
                    "resolved_at": resolved_records[0]["resolved_at"] if resolved_records else datetime.now().astimezone(),
                    "ttl_seconds": int(DNS_CACHE_TTL.total_seconds()),
                }
                _cache_upsert(
                    conn,
                    cache_key=cache_key,
                    cache_type="dns_resolution",
                    entity_type="domain",
                    entity_value=domain,
                    data=dns_output,
                    confidence="probable",
                    source="socket.getaddrinfo",
                    expires_at=datetime.now().astimezone() + DNS_CACHE_TTL,
                )
                _add_evidence(
                    conn,
                    request_id=request_id,
                    evidence_type="dns_resolution",
                    entity_type="domain",
                    entity_value=domain,
                    confidence="probable",
                    source="socket.getaddrinfo",
                    source_ref=domain,
                    summary=f"DNS resolvido para {domain}: {', '.join(resolved_ips) if resolved_ips else 'nenhum IP'}.",
                    data=dns_output,
                )
            except RuntimeError as exc:
                dns_output = {
                    "status": "failed",
                    "cache_hit": False,
                    "source": "socket.getaddrinfo",
                    "domain": domain,
                    "resolved_ips": [],
                    "resolved_records": [],
                    "error": str(exc),
                }
    resolved_ips = [str(ip) for ip in dns_output.get("resolved_ips") or [] if ip]
    selection = _select_measurement_targets_from_ips(request_uid=request_uid, resolved_ips=resolved_ips)
    return {
        "request_uid": request_uid,
        "status": dns_output.get("status") or "completed",
        "domain": domain,
        "dns": dns_output,
        "resolved_ips": resolved_ips,
        "selected_targets": selection["selected_targets"],
        "blocked_targets": selection["blocked_targets"],
        "skipped_targets": selection["skipped_targets"],
        "next_safe_step": "active_measurements" if selection["selected_targets"] else "dns_resolution",
    }


def resolve_dns_for_domain(
    request_uid: str,
    domain: str,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    request_id = int(bundle["request"]["id"])
    normalized_domain = str(domain or "").strip().lower()
    if not normalized_domain:
        return {
            "request_uid": request_uid,
            "status": "skipped",
            "reason": "missing_domain",
            "resolved_ips": [],
            "resolved_records": [],
        }
    with get_connection() as conn:
        cache_key = f"domain:{normalized_domain}:dns"
        cached = None if force_refresh else _fetch_learning_cache_row(conn, cache_key)
        if cached is not None:
            cached_data = cached.get("data") or {}
            resolved_records = cached_data.get("resolved_records") or []
            resolved_ips = [str(record.get("ip")) for record in resolved_records if record.get("ip")]
            if not resolved_ips:
                resolved_ips = [str(ip) for ip in (cached_data.get("resolved_ips") or []) if ip]
            output = {
                "status": "completed",
                "cache_hit": True,
                "source": cached.get("source") or "learning_cache",
                "cache_key": cache_key,
                "domain": normalized_domain,
                "resolved_ips": resolved_ips,
                "resolved_records": resolved_records,
                "resolved_at": cached_data.get("resolved_at"),
                "ttl_seconds": cached_data.get("ttl_seconds"),
                "cache_expires_at": cached.get("expires_at"),
                "reuse_freshness": cached.get("freshness"),
                "reused_from_request_uid": cached.get("request_uid"),
            }
            _add_evidence(
                conn,
                request_id=request_id,
                evidence_type="linked_prior_evidence",
                entity_type="domain",
                entity_value=normalized_domain,
                confidence=cached.get("confidence") or "probable",
                source=cached.get("source") or "learning_cache",
                source_ref=cache_key,
                summary=f"DNS de {normalized_domain} reutilizado com {len(resolved_ips)} IP(s).",
                data=output,
            )
            return output
        try:
            resolved_records = _resolve_domain_ips(normalized_domain)
        except RuntimeError as exc:
            output = {
                "status": "failed",
                "cache_hit": False,
                "source": "socket.getaddrinfo",
                "domain": normalized_domain,
                "resolved_ips": [],
                "resolved_records": [],
                "error": str(exc),
            }
            _add_evidence(
                conn,
                request_id=request_id,
                evidence_type="dns_resolution",
                entity_type="domain",
                entity_value=normalized_domain,
                confidence="unknown",
                source="socket.getaddrinfo",
                source_ref=normalized_domain,
                summary=f"Falha ao resolver DNS de {normalized_domain}: {str(exc)}",
                data=output,
            )
            return output
        resolved_ips = [str(record.get("ip")) for record in resolved_records if record.get("ip")]
        output = {
            "status": "completed",
            "cache_hit": False,
            "source": "socket.getaddrinfo",
            "cache_key": cache_key,
            "domain": normalized_domain,
            "resolved_ips": resolved_ips,
            "resolved_records": resolved_records,
            "resolved_at": resolved_records[0]["resolved_at"] if resolved_records else datetime.now().astimezone(),
            "ttl_seconds": int(DNS_CACHE_TTL.total_seconds()),
        }
        _cache_upsert(
            conn,
            cache_key=cache_key,
            cache_type="dns_resolution",
            entity_type="domain",
            entity_value=normalized_domain,
            data=output,
            confidence="probable",
            source="socket.getaddrinfo",
            expires_at=datetime.now().astimezone() + DNS_CACHE_TTL,
        )
        _add_evidence(
            conn,
            request_id=request_id,
            evidence_type="dns_resolution",
            entity_type="domain",
            entity_value=normalized_domain,
            confidence="probable",
            source="socket.getaddrinfo",
            source_ref=normalized_domain,
            summary=f"DNS resolvido para {normalized_domain}: {', '.join(resolved_ips) if resolved_ips else 'nenhum IP'}.",
            data=output,
        )
        return output


def build_active_measurement_plan(request_uid: str) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    selection = _select_measurement_targets_from_ips(request_uid=request_uid, resolved_ips=_request_dns_resolution_ips(bundle))
    selected_targets = selection["selected_targets"]
    blocked_targets = selection["blocked_targets"]
    ping_commands: list[dict[str, Any]] = []
    traceroute_commands: list[dict[str, Any]] = []
    for target in selected_targets:
        ip_text = target["ip"]
        if target["version"] == 6 and not ACTIVE_MEASUREMENT_POLICY["allow_ipv6"]:
            blocked_targets.append({"ip": ip_text, "reason": "ipv6_disabled"})
            continue
        if target["version"] == 4:
            ping_cmd = ["ping", "-c", str(ACTIVE_MEASUREMENT_POLICY["ping_count"]), "-W", str(ACTIVE_MEASUREMENT_POLICY["ping_timeout_seconds"]), ip_text]
        else:
            ping_cmd = ["ping", "-6", "-c", str(ACTIVE_MEASUREMENT_POLICY["ping_count"]), "-W", str(ACTIVE_MEASUREMENT_POLICY["ping_timeout_seconds"]), ip_text]
        traceroute_cmd = ["traceroute", "-m", str(ACTIVE_MEASUREMENT_POLICY["traceroute_max_hops"]), "-w", str(ACTIVE_MEASUREMENT_POLICY["traceroute_timeout_seconds"]), ip_text]
        if target["version"] == 6:
            traceroute_cmd = [
                "traceroute",
                "-6",
                "-m",
                str(ACTIVE_MEASUREMENT_POLICY["traceroute_max_hops"]),
                "-w",
                str(ACTIVE_MEASUREMENT_POLICY["traceroute_timeout_seconds"]),
                ip_text,
            ]
        ping_commands.append({"ip": ip_text, "command": shlex.join(ping_cmd)})
        traceroute_commands.append({"ip": ip_text, "command": shlex.join(traceroute_cmd)})

    estimated_runtime_seconds = min(
        ACTIVE_MEASUREMENT_POLICY["max_total_runtime_seconds"],
        max(10, len(selected_targets) * 18),
    )
    return {
        "request_uid": request_uid,
        "selected_targets": selected_targets,
        "blocked_targets": blocked_targets,
        "skipped_targets": selection["skipped_targets"],
        "ping_commands": ping_commands,
        "traceroute_commands": traceroute_commands,
        "estimated_runtime_seconds": estimated_runtime_seconds,
        "consent_required": bool(selected_targets),
        "policy": ACTIVE_MEASUREMENT_POLICY,
    }


PING_PACKET_RE = re.compile(
    r"(?P<tx>\d+)\s+packets transmitted,\s+(?P<rx>\d+)\s+(?:packets\s+)?received,.*?(?P<loss>\d+(?:\.\d+)?)% packet loss",
    re.IGNORECASE | re.DOTALL,
)
PING_RTT_RE = re.compile(
    r"(?:rtt|round-trip) min/avg/max(?:/(?:mdev|stddev))? = (?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)(?:/(?P<mdev>[\d.]+))? ms",
    re.IGNORECASE,
)


def _measurement_deadline_started_at(started_at: datetime | None) -> datetime:
    return started_at or datetime.now().astimezone()


def _measurement_remaining_seconds(started_at: datetime, limit_seconds: int) -> float:
    elapsed = (datetime.now().astimezone() - started_at).total_seconds()
    return max(0.0, float(limit_seconds) - elapsed)


def _select_traceroute_command(ip_text: str, version: int) -> tuple[list[str] | None, str | None]:
    traceroute_cmd = shutil.which("traceroute")
    if traceroute_cmd:
        base = [traceroute_cmd]
        if version == 6:
            base.append("-6")
        base.extend(["-m", str(ACTIVE_MEASUREMENT_POLICY["traceroute_max_hops"]), "-w", str(ACTIVE_MEASUREMENT_POLICY["traceroute_timeout_seconds"]), ip_text])
        return base, "traceroute"
    tracepath_cmd = shutil.which("tracepath")
    if tracepath_cmd:
        base = [tracepath_cmd]
        if version == 6:
            base.append("-6")
        base.extend(["-n", "-m", str(ACTIVE_MEASUREMENT_POLICY["traceroute_max_hops"]), ip_text])
        return base, "tracepath"
    return None, None


def _parse_ping_output(stdout: str) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    packet_match = PING_PACKET_RE.search(stdout or "")
    if packet_match:
        metrics["packets_transmitted"] = int(packet_match.group("tx"))
        metrics["packets_received"] = int(packet_match.group("rx"))
        metrics["packet_loss_percent"] = float(packet_match.group("loss"))
    rtt_match = PING_RTT_RE.search(stdout or "")
    if rtt_match:
        metrics["rtt_min_ms"] = float(rtt_match.group("min"))
        metrics["rtt_avg_ms"] = float(rtt_match.group("avg"))
        metrics["rtt_max_ms"] = float(rtt_match.group("max"))
        if rtt_match.group("mdev") is not None:
            metrics["rtt_mdev_ms"] = float(rtt_match.group("mdev"))
    return metrics


def _parse_traceroute_output(stdout: str) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("traceroute to") or line.lower().startswith("tracepath to"):
            continue
        hop_match = re.match(r"^(?P<hop>\d+)\s+(?P<rest>.*)$", line)
        if not hop_match:
            continue
        rest = hop_match.group("rest")
        hop_ip_match = re.search(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})", rest)
        hops.append(
            {
                "hop_number": int(hop_match.group("hop")),
                "hop_ip": hop_ip_match.group("ip") if hop_ip_match else None,
                "raw_line": raw_line,
            }
        )
    return hops


def execute_ping_measurement_task(
    conn: psycopg.Connection,
    *,
    request_id: int,
    task_row: dict[str, Any],
    request_row: dict[str, Any],
    execution_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    input_data = task_row.get("input") or {}
    if str(request_row.get("consent_status") or "").lower() != "approved":
        return {"status": "skipped", "reason": "consent_required"}
    force_refresh = bool((execution_context or {}).get("force_refresh"))
    learning_memory = (execution_context or {}).get("learning_memory")
    if not force_refresh and isinstance(learning_memory, dict) and str(learning_memory.get("entity_type") or "").lower() == "domain":
        reused_results: list[dict[str, Any]] = []
        for item in learning_memory.get("ips") or []:
            if not isinstance(item, dict):
                continue
            ping_context = item.get("ping") or {}
            latest = ping_context.get("latest")
            if not latest:
                continue
            data = latest.get("data") or {}
            metrics = data.get("metrics") or {}
            reused_results.append(
                {
                    "ip": item.get("ip"),
                    "status": "completed",
                    "reused": True,
                    "metrics": metrics,
                    "freshness": latest.get("freshness") or ping_context.get("freshness"),
                    "evidence_request_uid": latest.get("request_uid"),
                }
            )
        if reused_results:
            plan = _select_measurement_targets_from_ips(
                str(request_row.get("request_uid")),
                [str(item.get("ip")) for item in learning_memory.get("ips") or [] if item.get("ip")],
            )
            output = {
                "status": "completed",
                "reused": True,
                "source": "learning_evidence",
                "targets": plan.get("selected_targets") or [],
                "blocked_targets": plan.get("blocked_targets") or [],
                "results": reused_results,
                "plan": plan,
            }
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="linked_prior_evidence",
                entity_type="domain",
                entity_value=str(input_data.get("target") or "").strip().lower(),
                confidence="probable",
                source="learning_evidence",
                source_ref=str(learning_memory.get("dns", {}).get("request_uid") or ""),
                summary=f"Ping reutilizado para {len(reused_results)} destino(s) a partir de evidência anterior.",
                data=output,
            )
            return output
    plan = (execution_context or {}).get("active_measurement_plan")
    if not plan:
        dns_resolutions = (execution_context or {}).get("dns_resolutions") or {}
        resolved_ips: list[str] = []
        for dns_result in dns_resolutions.values():
            if not isinstance(dns_result, dict):
                continue
            resolved_ips.extend([str(ip) for ip in dns_result.get("resolved_ips") or [] if ip])
        plan = _select_measurement_targets_from_ips(str(request_row.get("request_uid")), resolved_ips)
    targets = plan.get("selected_targets") or []
    started_at = _measurement_deadline_started_at(datetime.now().astimezone())
    results: list[dict[str, Any]] = []
    blocked_targets = plan.get("blocked_targets") or []
    if execution_context is not None:
        execution_context.setdefault("active_measurement_plan", plan)
        execution_context.setdefault("active_measurements", {}).setdefault("blocked", [])
        execution_context["active_measurements"]["blocked"] = blocked_targets

    if not targets:
        for blocked in blocked_targets:
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="active_measurement_blocked",
                entity_type="ip",
                entity_value=str(blocked.get("ip")),
                confidence="unknown",
                source="active_measurement_policy",
                source_ref=str(blocked.get("ip")),
                summary=f"Destino bloqueado pela política: {blocked.get('reason')}",
                data=blocked,
            )
        return {"status": "skipped", "reason": "no_allowed_targets", "plan": plan}

    for target in targets:
        remaining = _measurement_remaining_seconds(started_at, int(ACTIVE_MEASUREMENT_POLICY["max_total_runtime_seconds"]))
        if remaining <= 0:
            results.append({"ip": target["ip"], "status": "skipped", "reason": "runtime_budget_exhausted"})
            continue
        ping_cmd = ["ping", "-c", str(ACTIVE_MEASUREMENT_POLICY["ping_count"]), "-W", str(ACTIVE_MEASUREMENT_POLICY["ping_timeout_seconds"])]
        if target["version"] == 6:
            ping_cmd.insert(1, "-6")
        ping_cmd.append(target["ip"])
        try:
            completed = subprocess.run(
                ping_cmd,
                capture_output=True,
                text=True,
                timeout=min(max(1, int(remaining)), int(ACTIVE_MEASUREMENT_POLICY["max_total_runtime_seconds"])),
                check=False,
            )
        except FileNotFoundError as exc:
            error = "ping command not available"
            result = {"ip": target["ip"], "status": "failed", "error": error}
            results.append(result)
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="ping_measurement",
                entity_type="ip",
                entity_value=target["ip"],
                confidence="unknown",
                source="ping",
                source_ref=target["ip"],
                summary=error,
                data=result,
            )
            continue
        except subprocess.TimeoutExpired:
            result = {"ip": target["ip"], "status": "failed", "error": "ping timeout"}
            results.append(result)
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="ping_measurement",
                entity_type="ip",
                entity_value=target["ip"],
                confidence="unknown",
                source="ping",
                source_ref=target["ip"],
                summary="Ping excedeu o timeout permitido.",
                data=result,
            )
            continue

        metrics = _parse_ping_output(completed.stdout)
        status = "completed" if metrics else "failed"
        result = {
            "ip": target["ip"],
            "version": target["version"],
            "command": shlex.join(ping_cmd),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "metrics": metrics,
            "status": status,
        }
        results.append(result)
        confidence = "confirmed" if metrics else "unknown"
        summary = (
            f"Ping executado para {target['ip']} com perda {metrics.get('packet_loss_percent')}%."
            if metrics
            else f"Ping executado para {target['ip']} sem métricas completas."
        )
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="ping_measurement",
            entity_type="ip",
            entity_value=target["ip"],
            confidence=confidence,
            source="ping",
            source_ref=target["ip"],
            summary=summary,
            data=result,
        )

    for blocked in blocked_targets:
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="active_measurement_blocked",
            entity_type="ip",
            entity_value=str(blocked.get("ip")),
            confidence="unknown",
            source="active_measurement_policy",
            source_ref=str(blocked.get("ip")),
            summary=f"Destino bloqueado pela política: {blocked.get('reason')}",
            data=blocked,
        )

    output_status = "completed" if any(item.get("status") == "completed" for item in results) else "failed"
    return {
        "status": output_status,
        "targets": targets,
        "blocked_targets": blocked_targets,
        "results": results,
        "plan": plan,
    }


def execute_traceroute_measurement_task(
    conn: psycopg.Connection,
    *,
    request_id: int,
    task_row: dict[str, Any],
    request_row: dict[str, Any],
    execution_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    input_data = task_row.get("input") or {}
    if str(request_row.get("consent_status") or "").lower() != "approved":
        return {"status": "skipped", "reason": "consent_required"}
    force_refresh = bool((execution_context or {}).get("force_refresh"))
    learning_memory = (execution_context or {}).get("learning_memory")
    if not force_refresh and isinstance(learning_memory, dict) and str(learning_memory.get("entity_type") or "").lower() == "domain":
        reused_results: list[dict[str, Any]] = []
        for item in learning_memory.get("ips") or []:
            if not isinstance(item, dict):
                continue
            traceroute_context = item.get("traceroute") or {}
            latest = traceroute_context.get("latest")
            if not latest:
                continue
            data = latest.get("data") or {}
            reused_results.append(
                {
                    "ip": item.get("ip"),
                    "status": "completed",
                    "reused": True,
                    "hops": data.get("hops") or [],
                    "total_hops": data.get("total_hops") or len(data.get("hops") or []),
                    "freshness": latest.get("freshness") or traceroute_context.get("freshness"),
                    "evidence_request_uid": latest.get("request_uid"),
                }
            )
        if reused_results:
            plan = _select_measurement_targets_from_ips(
                str(request_row.get("request_uid")),
                [str(item.get("ip")) for item in learning_memory.get("ips") or [] if item.get("ip")],
            )
            output = {
                "status": "completed",
                "reused": True,
                "source": "learning_evidence",
                "targets": plan.get("selected_targets") or [],
                "blocked_targets": plan.get("blocked_targets") or [],
                "results": reused_results,
                "plan": plan,
            }
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="linked_prior_evidence",
                entity_type="domain",
                entity_value=str(input_data.get("target") or "").strip().lower(),
                confidence="probable",
                source="learning_evidence",
                source_ref=str(learning_memory.get("dns", {}).get("request_uid") or ""),
                summary=f"Traceroute reutilizado para {len(reused_results)} destino(s) a partir de evidência anterior.",
                data=output,
            )
            return output
    plan = (execution_context or {}).get("active_measurement_plan")
    if not plan:
        dns_resolutions = (execution_context or {}).get("dns_resolutions") or {}
        resolved_ips: list[str] = []
        for dns_result in dns_resolutions.values():
            if not isinstance(dns_result, dict):
                continue
            resolved_ips.extend([str(ip) for ip in dns_result.get("resolved_ips") or [] if ip])
        plan = _select_measurement_targets_from_ips(str(request_row.get("request_uid")), resolved_ips)
    targets = plan.get("selected_targets") or []
    blocked_targets = plan.get("blocked_targets") or []
    results: list[dict[str, Any]] = []
    if execution_context is not None:
        execution_context.setdefault("active_measurement_plan", plan)
        execution_context.setdefault("active_measurements", {}).setdefault("blocked", [])
        execution_context["active_measurements"]["blocked"] = blocked_targets

    if not targets:
        for blocked in blocked_targets:
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="active_measurement_blocked",
                entity_type="ip",
                entity_value=str(blocked.get("ip")),
                confidence="unknown",
                source="active_measurement_policy",
                source_ref=str(blocked.get("ip")),
                summary=f"Destino bloqueado pela política: {blocked.get('reason')}",
                data=blocked,
            )
        return {"status": "skipped", "reason": "no_allowed_targets", "plan": plan}

    started_at = _measurement_deadline_started_at(datetime.now().astimezone())
    for target in targets:
        remaining = _measurement_remaining_seconds(started_at, int(ACTIVE_MEASUREMENT_POLICY["max_total_runtime_seconds"]))
        cmd, source = _select_traceroute_command(target["ip"], int(target["version"]))
        if cmd is None or source is None:
            result = {"ip": target["ip"], "status": "failed", "error": "traceroute command not available"}
            results.append(result)
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="traceroute_measurement",
                entity_type="ip",
                entity_value=target["ip"],
                confidence="unknown",
                source="traceroute",
                source_ref=target["ip"],
                summary="traceroute command not available",
                data=result,
            )
            continue
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=min(max(1, int(remaining)), int(ACTIVE_MEASUREMENT_POLICY["max_total_runtime_seconds"])),
                check=False,
            )
        except subprocess.TimeoutExpired:
            result = {"ip": target["ip"], "status": "failed", "error": "traceroute timeout"}
            results.append(result)
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="traceroute_measurement",
                entity_type="ip",
                entity_value=target["ip"],
                confidence="unknown",
                source=source,
                source_ref=target["ip"],
                summary="Traceroute excedeu o timeout permitido.",
                data=result,
            )
            continue
        except FileNotFoundError:
            result = {"ip": target["ip"], "status": "failed", "error": "traceroute command not available"}
            results.append(result)
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="traceroute_measurement",
                entity_type="ip",
                entity_value=target["ip"],
                confidence="unknown",
                source=source,
                source_ref=target["ip"],
                summary="traceroute command not available",
                data=result,
            )
            continue

        hops = _parse_traceroute_output(completed.stdout)
        result = {
            "ip": target["ip"],
            "version": target["version"],
            "command": shlex.join(cmd),
            "source": source,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "hops": hops,
            "total_hops": len(hops),
            "status": "completed" if hops or completed.returncode == 0 else "failed",
        }
        results.append(result)
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="traceroute_measurement",
            entity_type="ip",
            entity_value=target["ip"],
            confidence="confirmed" if result["status"] == "completed" else "unknown",
            source=source,
            source_ref=target["ip"],
            summary=f"Traceroute executado para {target['ip']} com {len(hops)} hop(s).",
            data=result,
        )

    for blocked in blocked_targets:
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="active_measurement_blocked",
            entity_type="ip",
            entity_value=str(blocked.get("ip")),
            confidence="unknown",
            source="active_measurement_policy",
            source_ref=str(blocked.get("ip")),
            summary=f"Destino bloqueado pela política: {blocked.get('reason')}",
            data=blocked,
        )

    output_status = "completed" if any(item.get("status") == "completed" for item in results) else "failed"
    return {
        "status": output_status,
        "targets": targets,
        "blocked_targets": blocked_targets,
        "results": results,
        "plan": plan,
    }


def _execute_safe_task(
    conn: psycopg.Connection,
    *,
    request_id: int,
    task_row: dict[str, Any],
    request_row: dict[str, Any],
    entities: list[dict[str, Any]],
    execution_context: dict[str, Any] | None = None,
    force_refresh: bool = False,
    learning_memory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    task_uid = task_row["task_uid"]
    task_type = task_row["task_type"]
    input_data = task_row.get("input") or {}
    if task_type == "dns_resolve":
        domain = str(input_data.get("domain") or _safe_domain_from_entities(entities) or "").strip().lower()
        if not domain:
            return {"status": "skipped", "reason": "missing_domain"}
        cache_key = f"domain:{domain}:dns"
        cached = None if force_refresh else _fetch_learning_cache_row(conn, cache_key)
        if cached is None and not force_refresh and isinstance(learning_memory, dict):
            memory_dns = learning_memory.get("dns") or {}
            if memory_dns.get("resolved_ips"):
                cached = {
                    "source": "learning_memory",
                    "confidence": "probable",
                    "expires_at": memory_dns.get("freshness", {}).get("expires_at"),
                    "data": (memory_dns.get("cache") or {}).get("data") or ((memory_dns.get("evidence") or [{}])[0].get("data") if memory_dns.get("evidence") else {}),
                    "freshness": memory_dns.get("freshness") or {},
                    "request_uid": memory_dns.get("request_uid"),
                }
        if cached is not None:
            cached_data = cached.get("data") or {}
            resolved_records = cached_data.get("resolved_records") or []
            resolved_ips = [str(record.get("ip")) for record in resolved_records if record.get("ip")]
            if not resolved_ips:
                resolved_ips = [str(ip) for ip in (cached_data.get("resolved_ips") or []) if ip]
            output = {
                "status": "completed",
                "cache_hit": True,
                "source": cached.get("source") or "learning_cache",
                "cache_key": cache_key,
                "domain": domain,
                "resolved_ips": resolved_ips,
                "resolved_records": resolved_records,
                "resolved_at": cached_data.get("resolved_at"),
                "ttl_seconds": cached_data.get("ttl_seconds"),
                "cache_expires_at": cached.get("expires_at"),
                "reuse_freshness": cached.get("freshness"),
                "reused_from_request_uid": cached.get("request_uid"),
            }
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="linked_prior_evidence",
                entity_type="domain",
                entity_value=domain,
                confidence=cached.get("confidence") or "probable",
                source=cached.get("source") or "learning_cache",
                source_ref=cache_key,
                summary=f"DNS de {domain} reutilizado com {len(resolved_ips)} IP(s).",
                data=output,
            )
            if execution_context is not None:
                execution_context.setdefault("dns_resolutions", {})[domain] = output
            return output

        try:
            resolved_records = _resolve_domain_ips(domain)
        except RuntimeError as exc:
            output = {
                "status": "failed",
                "cache_hit": False,
                "source": "socket.getaddrinfo",
                "domain": domain,
                "resolved_ips": [],
                "resolved_records": [],
                "error": str(exc),
            }
            _add_evidence(
                conn,
                request_id=request_id,
                task_id=int(task_row["id"]),
                evidence_type="dns_resolution",
                entity_type="domain",
                entity_value=domain,
                confidence="unknown",
                source="socket.getaddrinfo",
                source_ref=domain,
                summary=f"Falha ao resolver DNS de {domain}: {str(exc)}",
                data=output,
            )
            if execution_context is not None:
                execution_context.setdefault("dns_failures", {})[domain] = output
            return output

        resolved_ips = [str(record.get("ip")) for record in resolved_records if record.get("ip")]
        output = {
            "status": "completed",
            "cache_hit": False,
            "source": "socket.getaddrinfo",
            "cache_key": cache_key,
            "domain": domain,
            "resolved_ips": resolved_ips,
            "resolved_records": resolved_records,
            "resolved_at": resolved_records[0]["resolved_at"] if resolved_records else datetime.now().astimezone(),
            "ttl_seconds": int(DNS_CACHE_TTL.total_seconds()),
        }
        _cache_upsert(
            conn,
            cache_key=cache_key,
            cache_type="dns_resolution",
            entity_type="domain",
            entity_value=domain,
            data=output,
            confidence="probable",
            source="socket.getaddrinfo",
            expires_at=datetime.now().astimezone() + DNS_CACHE_TTL,
        )
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="dns_resolution",
            entity_type="domain",
            entity_value=domain,
            confidence="probable",
            source="socket.getaddrinfo",
            source_ref=domain,
            summary=f"DNS resolvido para {domain}: {', '.join(resolved_ips) if resolved_ips else 'nenhum IP'}.",
            data=output,
        )
        if execution_context is not None:
            execution_context.setdefault("dns_resolutions", {})[domain] = output

        bgp_results: list[dict[str, Any]] = []
        if resolved_ips:
            for resolved_ip in resolved_ips[:MAX_DNS_RESULTS]:
                bgp_results.append(
                    execute_bgp_lookup_for_ip(
                        conn,
                        request_id=request_id,
                        task_id=int(task_row["id"]),
                        ip=resolved_ip,
                        force_refresh=force_refresh,
                    )
                )
            output["bgp_lookups"] = bgp_results
            if execution_context is not None:
                execution_context.setdefault("bgp_lookups", {})[domain] = bgp_results
        return output

    if task_type == "bgp_prefix_lookup":
        target_entity = input_data.get("entity")
        if "domain" in input_data:
            domain = str(input_data.get("domain") or "").strip().lower()
            if execution_context is not None:
                cached_followup = (execution_context.get("bgp_lookups") or {}).get(domain)
                if cached_followup is not None:
                    return {
                        "status": "completed",
                        "domain": domain,
                        "source": "dns_followup",
                        "bgp_lookups": cached_followup,
                        "cache_hit": True,
                    }
                dns_result = (execution_context.get("dns_resolutions") or {}).get(domain)
                if dns_result and dns_result.get("resolved_ips"):
                    bgp_results = []
                    for resolved_ip in dns_result.get("resolved_ips", [])[:MAX_DNS_RESULTS]:
                        bgp_results.append(
                            execute_bgp_lookup_for_ip(
                                conn,
                                request_id=request_id,
                                task_id=int(task_row["id"]),
                                ip=resolved_ip,
                                force_refresh=force_refresh,
                            )
                        )
                    execution_context.setdefault("bgp_lookups", {})[domain] = bgp_results
                    return {
                        "status": "completed",
                        "domain": domain,
                        "source": "dns_followup",
                        "bgp_lookups": bgp_results,
                        "cache_hit": False,
                    }
            return {"status": "skipped", "reason": "missing_dns_dependency", "dependency": "dns_resolve"}

        prefix = None
        if isinstance(target_entity, dict):
            prefix = _safe_prefix_from_entity(target_entity)
        if not prefix:
            return {"status": "skipped", "reason": "missing_prefix"}
        data = get_prefix_lookup(prefix, limit=20)
        output = {"status": "completed", "prefix": prefix, "result": data}
        _cache_upsert(
            conn,
            cache_key=f"prefix:{prefix}:bgp",
            cache_type="bgp_prefix_lookup",
            entity_type="prefix",
            entity_value=prefix,
            data=data or {},
            confidence="confirmed",
            source="bgp_current_routes",
            expires_at=datetime.now().astimezone() + BGP_CACHE_TTL,
        )
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="bgp_prefix_lookup",
            entity_type="prefix",
            entity_value=prefix,
            confidence="confirmed",
            source="bgp_current_routes",
            source_ref=prefix,
            summary=f"Prefixo {prefix} consultado na base BGP.",
            data=data or {},
        )
        return output

    if task_type == "bgp_asn_lookup":
        asn = input_data.get("asn")
        try:
            asn_int = int(asn)
        except (TypeError, ValueError):
            return {"status": "skipped", "reason": "missing_asn"}
        data = get_asn_lookup(asn_int, limit=20)
        output = {"status": "completed", "asn": asn_int, "result": data}
        _cache_upsert(
            conn,
            cache_key=f"asn:{asn_int}:summary",
            cache_type="bgp_asn_lookup",
            entity_type="asn",
            entity_value=str(asn_int),
            data=data or {},
            confidence="confirmed",
            source="bgp_current_routes",
            expires_at=datetime.now().astimezone() + BGP_CACHE_TTL,
        )
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="bgp_asn_lookup",
            entity_type="asn",
            entity_value=str(asn_int),
            confidence="confirmed",
            source="bgp_current_routes",
            source_ref=str(asn_int),
            summary=f"ASN {asn_int} consultado na base BGP.",
            data=data or {},
        )
        return output

    if task_type == "inventory_lookup":
        site_code = str(input_data.get("site_code") or "").strip()
        if not site_code:
            return {"status": "skipped", "reason": "missing_site_code"}
        data = get_inventory_public_context(site_code=site_code, locality_code="CE", limit=20)
        output = {"status": "completed", "site_code": site_code, "result": data}
        _cache_upsert(
            conn,
            cache_key=f"site:{site_code}:public-context",
            cache_type="inventory",
            entity_type="site",
            entity_value=site_code,
            data=data or {},
            confidence="probable",
            source="inventory_queries.get_inventory_public_context",
            expires_at=datetime.now().astimezone() + BGP_CACHE_TTL,
        )
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="inventory_lookup",
            entity_type="site",
            entity_value=site_code,
            confidence="probable",
            source="inventory_queries.get_inventory_public_context",
            source_ref=site_code,
            summary=f"Inventário consultado para {site_code}.",
            data=data or {},
        )
        return output

    if task_type == "ixbr_lookup":
        site_code = str(input_data.get("site_code") or "").strip()
        locality_code = str(input_data.get("locality_code") or "CE").strip().upper()
        if not site_code:
            return {"status": "skipped", "reason": "missing_site_code"}
        data = summarize_ixbr_vs_bgp(locality_code=locality_code)
        output = {"status": "completed", "site_code": site_code, "locality_code": locality_code, "result": data}
        _cache_upsert(
            conn,
            cache_key=f"site:{site_code}:ixbr:{locality_code}",
            cache_type="ixbr",
            entity_type="site",
            entity_value=site_code,
            data=data,
            confidence="probable",
            source="ixbr_discovery_queries.summarize_ixbr_vs_bgp",
            expires_at=datetime.now().astimezone() + BGP_CACHE_TTL,
        )
        _add_evidence(
            conn,
            request_id=request_id,
            task_id=int(task_row["id"]),
            evidence_type="ixbr_lookup",
            entity_type="site",
            entity_value=site_code,
            confidence="probable",
            source="ixbr_discovery_queries.summarize_ixbr_vs_bgp",
            source_ref=locality_code,
            summary=f"Contexto IX.br consultado para {site_code}.",
            data=data,
        )
        return output

    return {"status": "skipped", "reason": "unsupported_task_type", "task_type": task_type}


def _execute_request_internal(
    request_uid: str,
    *,
    dry_run: bool,
    allow_safe_tasks: bool = True,
    allow_active_measurements: bool = False,
    force_refresh: bool = False,
) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    request_row = bundle["request"]
    tasks = bundle["tasks"]
    entities = bundle["entities"]
    gaps = [dict(gap) for gap in bundle["gaps"]]
    request_id = int(request_row["id"])
    domain_memory = _domain_memory_from_request(request_row, entities)

    planned_safe_tasks = [task for task in tasks if task["task_type"] in SAFE_TASK_TYPES or task["task_type"] == "answer_build"]
    planned_invasive_tasks = [task for task in tasks if task["task_type"] in INVASIVE_TASK_TYPES]

    if dry_run:
        active_plan = build_active_measurement_plan(request_uid) if planned_invasive_tasks else {
            "request_uid": request_uid,
            "selected_targets": [],
            "blocked_targets": [],
            "skipped_targets": [],
            "ping_commands": [],
            "traceroute_commands": [],
            "estimated_runtime_seconds": 0,
            "consent_required": False,
            "policy": ACTIVE_MEASUREMENT_POLICY,
        }
        return {
            "dry_run": True,
            "request_uid": request_uid,
            "would_execute": [task for task in planned_safe_tasks if task["task_type"] in SAFE_TASK_TYPES],
            "would_wait_for_consent": planned_invasive_tasks,
            "active_measurement_plan": active_plan,
            "note": "Modo dry-run: nenhuma tarefa foi executada.",
        }

    if not allow_safe_tasks:
        raise ValueError("Execução segura desabilitada para esta request.")

    with get_connection() as conn:
        consent_approved = str(request_row.get("consent_status") or "").lower() == "approved"
        with conn.cursor() as cur:
            cur.execute(
                """
                update learning_requests
                set status = 'running',
                    started_at = coalesce(started_at, now()),
                    updated_at = now()
                where id = %s;
                """,
                (request_id,),
            )

        execution_results: list[dict[str, Any]] = []
        execution_context: dict[str, Any] = {
            "dns_resolutions": {},
            "dns_failures": {},
            "bgp_lookups": {},
            "task_results": [],
            "force_refresh": force_refresh,
            "learning_memory": domain_memory,
            "active_measurements": {
                "ping": [],
                "traceroute": [],
                "blocked": [],
                "deferred": [],
            },
        }
        completed_safe_tasks = 0
        bgp_match_found = False
        active_measurements_performed = False

        def _mark_local_gaps_resolved(gap_types: list[str]) -> None:
            if not gap_types:
                return
            for gap in gaps:
                if gap.get("gap_type") in gap_types and str(gap.get("status") or "open").lower() == "open":
                    gap["status"] = "resolved"
                    gap["resolved_at"] = datetime.now().astimezone()

        for task in tasks:
            if task["task_type"] in SAFE_TASK_TYPES:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update learning_tasks
                        set status = 'running',
                            started_at = coalesce(started_at, now())
                        where id = %s;
                        """,
                        (task["id"],),
                    )
                task_output = _execute_safe_task(
                    conn,
                    request_id=request_id,
                    task_row=task,
                    request_row=request_row,
                    entities=entities,
                    execution_context=execution_context,
                    force_refresh=force_refresh,
                    learning_memory=domain_memory,
                )
                execution_results.append({"task_uid": task["task_uid"], "task_type": task["task_type"], "output": task_output})
                task_status = task_output.get("status", "completed")
                final_status = "completed" if task_status == "completed" else "failed" if task_status == "failed" else "skipped"
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update learning_tasks
                        set status = %s,
                            output = %s,
                            error = %s,
                            finished_at = now()
                        where id = %s;
                        """,
                        (
                            final_status,
                            _json_value(task_output),
                            task_output.get("error") if isinstance(task_output, dict) else None,
                            task["id"],
                        ),
                    )
                execution_context["task_results"].append(
                    {
                        "task_uid": task["task_uid"],
                        "task_type": task["task_type"],
                        "status": final_status,
                        "output": task_output,
                    }
                )
                if final_status == "completed":
                    completed_safe_tasks += 1

                if task["task_type"] == "dns_resolve":
                    domain = str(task_output.get("domain") or "").strip().lower()
                    if task_output.get("status") == "completed" and task_output.get("resolved_ips"):
                        dns_gap_types = ["missing_dns_resolution", "stale_dns_resolution", "expired_dns_resolution"]
                        _resolve_learning_gaps(conn, request_id, dns_gap_types)
                        _mark_local_gaps_resolved(dns_gap_types)
                        bgp_lookups = task_output.get("bgp_lookups") or []
                        if any(result.get("status") == "completed" and result.get("matched_prefix") for result in bgp_lookups):
                            bgp_gap_types = ["missing_bgp_match", "stale_bgp_match", "expired_bgp_match"]
                            _resolve_learning_gaps(conn, request_id, bgp_gap_types)
                            _mark_local_gaps_resolved(bgp_gap_types)
                            bgp_match_found = True
                        if domain and bgp_lookups:
                            execution_context.setdefault("bgp_lookups", {})[domain] = bgp_lookups
                    elif task_output.get("status") == "failed":
                        execution_context.setdefault("dns_failures", {})[domain or task["task_uid"]] = task_output
                elif task["task_type"] == "bgp_prefix_lookup":
                    task_bgp_results = task_output.get("bgp_lookups") if isinstance(task_output, dict) else None
                    if task_output.get("status") == "completed" and (
                        task_output.get("matched_prefix")
                        or (task_bgp_results and any(result.get("matched_prefix") for result in task_bgp_results))
                    ):
                        bgp_gap_types = ["missing_bgp_match", "stale_bgp_match", "expired_bgp_match"]
                        _resolve_learning_gaps(conn, request_id, bgp_gap_types)
                        _mark_local_gaps_resolved(bgp_gap_types)
                        bgp_match_found = True
                elif task["task_type"] == "bgp_asn_lookup" and task_output.get("status") == "completed":
                    bgp_gap_types = ["missing_bgp_match", "stale_bgp_match", "expired_bgp_match"]
                    _resolve_learning_gaps(conn, request_id, bgp_gap_types)
                    _mark_local_gaps_resolved(bgp_gap_types)
                    bgp_match_found = True
                continue

            if task["task_type"] == "ping_measurement":
                if not consent_approved:
                    execution_context["active_measurements"]["deferred"].append(
                        {"task_uid": task["task_uid"], "task_type": task["task_type"], "reason": "consent_required"}
                    )
                    continue
                if not allow_active_measurements:
                    execution_context["active_measurements"]["deferred"].append(
                        {"task_uid": task["task_uid"], "task_type": task["task_type"], "reason": "active_flag_disabled"}
                    )
                    continue
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update learning_tasks
                        set status = 'running',
                            started_at = coalesce(started_at, now())
                        where id = %s;
                        """,
                        (task["id"],),
                    )
                task_output = execute_ping_measurement_task(
                    conn,
                    request_id=request_id,
                    task_row=task,
                    request_row=request_row,
                    execution_context=execution_context,
                )
                execution_results.append({"task_uid": task["task_uid"], "task_type": task["task_type"], "output": task_output})
                task_status = task_output.get("status", "failed")
                final_task_status = "completed" if task_status == "completed" else "skipped" if task_status == "skipped" else "failed"
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update learning_tasks
                        set status = %s,
                            output = %s,
                            error = %s,
                            finished_at = now()
                        where id = %s;
                        """,
                        (
                            final_task_status,
                            _json_value(task_output),
                            task_output.get("error") if isinstance(task_output, dict) else None,
                            task["id"],
                        ),
                    )
                execution_context["task_results"].append(
                    {
                        "task_uid": task["task_uid"],
                        "task_type": task["task_type"],
                        "status": final_task_status,
                        "output": task_output,
                    }
                )
                execution_context["active_measurements"]["ping"].append(task_output)
                if final_task_status != "skipped":
                    active_measurements_performed = True
                if any(result.get("status") == "completed" for result in task_output.get("results", [])):
                    ping_gap_types = ["missing_ping_measurement", "stale_ping_measurement", "expired_ping_measurement"]
                    _resolve_learning_gaps(conn, request_id, ping_gap_types)
                    _mark_local_gaps_resolved(ping_gap_types)
                continue

            if task["task_type"] == "traceroute_measurement":
                if not consent_approved:
                    execution_context["active_measurements"]["deferred"].append(
                        {"task_uid": task["task_uid"], "task_type": task["task_type"], "reason": "consent_required"}
                    )
                    continue
                if not allow_active_measurements:
                    execution_context["active_measurements"]["deferred"].append(
                        {"task_uid": task["task_uid"], "task_type": task["task_type"], "reason": "active_flag_disabled"}
                    )
                    continue
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update learning_tasks
                        set status = 'running',
                            started_at = coalesce(started_at, now())
                        where id = %s;
                        """,
                        (task["id"],),
                    )
                task_output = execute_traceroute_measurement_task(
                    conn,
                    request_id=request_id,
                    task_row=task,
                    request_row=request_row,
                    execution_context=execution_context,
                )
                execution_results.append({"task_uid": task["task_uid"], "task_type": task["task_type"], "output": task_output})
                task_status = task_output.get("status", "failed")
                final_task_status = "completed" if task_status == "completed" else "skipped" if task_status == "skipped" else "failed"
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update learning_tasks
                        set status = %s,
                            output = %s,
                            error = %s,
                            finished_at = now()
                        where id = %s;
                        """,
                        (
                            final_task_status,
                            _json_value(task_output),
                            task_output.get("error") if isinstance(task_output, dict) else None,
                            task["id"],
                        ),
                    )
                execution_context["task_results"].append(
                    {
                        "task_uid": task["task_uid"],
                        "task_type": task["task_type"],
                        "status": final_task_status,
                        "output": task_output,
                    }
                )
                execution_context["active_measurements"]["traceroute"].append(task_output)
                if final_task_status != "skipped":
                    active_measurements_performed = True
                if any(result.get("status") == "completed" for result in task_output.get("results", [])):
                    traceroute_gap_types = [
                        "missing_traceroute_measurement",
                        "stale_traceroute_measurement",
                        "expired_traceroute_measurement",
                    ]
                    _resolve_learning_gaps(conn, request_id, traceroute_gap_types)
                    _mark_local_gaps_resolved(traceroute_gap_types)
                continue

            if task["task_type"] == "synthetic_browser_run":
                execution_context["active_measurements"]["deferred"].append(
                    {"task_uid": task["task_uid"], "task_type": task["task_type"], "reason": "not_enabled"}
                )

        remaining_waiting_consent = any(task["task_type"] in INVASIVE_TASK_TYPES for task in tasks) and not consent_approved
        final_status = "waiting_consent" if remaining_waiting_consent else "completed"
        confidence_before = float(request_row.get("confidence_before") or 0.0)
        confidence_after = confidence_before
        if execution_context["dns_resolutions"]:
            confidence_after += 0.2
        if bgp_match_found:
            confidence_after += 0.2
        if active_measurements_performed:
            confidence_after += 0.15
        if execution_context["dns_failures"]:
            confidence_after -= 0.05
        if completed_safe_tasks:
            confidence_after += min(0.1, 0.02 * completed_safe_tasks)
        confidence_after = max(confidence_before, min(0.99, confidence_after))
        active_plan = _select_measurement_targets_from_ips(
            request_uid,
            [
                str(ip)
                for dns_result in execution_context["dns_resolutions"].values()
                if isinstance(dns_result, dict)
                for ip in (dns_result.get("resolved_ips") or [])
                if ip
            ],
        ) if planned_invasive_tasks else {
            "request_uid": request_uid,
            "selected_targets": [],
            "blocked_targets": [],
            "skipped_targets": [],
            "ping_commands": [],
            "traceroute_commands": [],
            "estimated_runtime_seconds": 0,
            "consent_required": False,
            "policy": ACTIVE_MEASUREMENT_POLICY,
        }
        execution_context["active_measurements"]["blocked"] = active_plan.get("blocked_targets") or []
        execution_summary = {
            "task_results": execution_results,
            "completed_safe_tasks": completed_safe_tasks,
            "dns_resolutions": execution_context["dns_resolutions"],
            "dns_failures": execution_context["dns_failures"],
            "bgp_lookups": execution_context["bgp_lookups"],
            "bgp_match_found": bgp_match_found,
            "waiting_consent_tasks": [task for task in planned_invasive_tasks] if not consent_approved else [],
            "deferred_active_tasks": execution_context["active_measurements"]["deferred"],
            "active_measurement_plan": active_plan,
            "active_measurements": execution_context["active_measurements"],
            "consent_approved": consent_approved,
            "allow_active_measurements": allow_active_measurements,
            "force_refresh": force_refresh,
            "active_measurements_performed": active_measurements_performed,
            "learning_memory": domain_memory,
        }
        classification_result: dict[str, Any] = {"classifications": [], "summary_text": "Nenhuma classificação operacional calculada."}
        try:
            classification_result = classify_learning_request(request_uid, persist=True, conn=conn)
        except RuntimeError:
            classification_result = {"classifications": [], "summary_text": "Classificação operacional indisponível nesta execução."}
        execution_summary["classifications"] = classification_result.get("classifications") or []
        execution_summary["classification_summary"] = classification_result.get("summary_text")
        answer = _build_answer_payload(
            request_uid=request_uid,
            request_row={**request_row, "status": final_status},
            entities=entities,
            known=bundle["analysis"].get("known") or [],
            unknown=bundle["analysis"].get("unknown") or [],
            gaps=gaps,
            tasks=tasks,
            evidence=bundle["evidence"],
            execution=execution_summary,
            memory=domain_memory,
            classifications=classification_result.get("classifications") or [],
        )
        with conn.cursor() as cur:
            cur.execute(
                """
                update learning_requests
                set status = %s,
                    confidence_after = %s,
                    answer_summary = %s,
                    result = coalesce(result, '{}'::jsonb) || %s::jsonb,
                    finished_at = case when %s = 'completed' then now() else finished_at end,
                    error = null,
                    updated_at = now()
                where id = %s;
                """,
                (
                    final_status,
                    confidence_after,
                    answer.get("answer_summary"),
                    _json_value({"execution": execution_summary, "answer": answer}),
                    final_status,
                    request_id,
                ),
            )

    return {
        "dry_run": False,
        "request_uid": request_uid,
        "execution": execution_summary,
        "status": final_status,
        "answer": answer,
    }


def create_learning_request(
    question: str,
    operator: str | None = None,
    raw_context: dict[str, Any] | None = None,
    *,
    debug_timing: dict[str, float] | None = None,
) -> dict[str, Any]:
    normalized_question = _normalize_text(question)
    if not normalized_question:
        raise ValueError("Pergunta vazia.")

    total_started = datetime.now().timestamp()
    step_started = datetime.now().timestamp()
    classification = classify_question(normalized_question)
    if debug_timing is not None:
        debug_timing["classify_question_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
    step_started = datetime.now().timestamp()
    entities = extract_entities(normalized_question)
    if debug_timing is not None:
        debug_timing["extract_entities_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
    step_started = datetime.now().timestamp()
    semantic_context = get_semantic_context_for_question(normalized_question, limit=5, debug_timing=debug_timing)
    if debug_timing is not None:
        debug_timing["semantic_context_lookup_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
    step_started = datetime.now().timestamp()
    semantic_domain = _semantic_domain_ref(semantic_context)
    lowered_question = normalized_question.lower()
    route_inventory_terms = ("hop", "hops", "router", "routers", "roteador", "roteadores", "rota", "roteamento", "inventari")
    if semantic_domain and not _safe_domain_from_entities(entities) and not any(term in lowered_question for term in route_inventory_terms):
        semantic_domain_label = semantic_domain.split(".", 1)[0].lower()
        if semantic_domain_label and semantic_domain_label in normalized_question.lower():
            entities = [entity for entity in entities if entity.get("entity_type") != "unknown"]
        entities.append(
            {
                "entity_type": "domain",
                "entity_value": semantic_domain,
                "normalized_value": semantic_domain,
                "confidence": 0.65,
                "source": "semantic_memory",
                "metadata": {
                    "suggested": True,
                    "reason": "Domínio sugerido por semantic_context; exige evidência estruturada para confirmação factual.",
                },
            }
        )
        classification = {"intent": "domain_analysis", "scope": "routing"}
    domain = _safe_domain_from_entities(entities)
    memory_summary = summarize_learning_memory({"entity_type": "domain", "entity_value": domain}) if domain else None
    if debug_timing is not None:
        debug_timing["learning_memory_lookup_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
    request_uid = f"lr_{uuid.uuid4().hex}"
    request_raw_context = raw_context or {}
    request_raw_context = {
        **request_raw_context,
        "question": normalized_question,
        "operator": operator,
        "semantic_context": semantic_context,
        "learning_memory": memory_summary.get("memory") if isinstance(memory_summary, dict) else None,
        "learning_memory_summary": memory_summary.get("summary_text") if isinstance(memory_summary, dict) else None,
    }

    with get_connection() as conn:
        request_row = _insert_request(
            conn,
            request_uid=request_uid,
            question=question,
            normalized_question=normalized_question,
            intent=classification["intent"],
            scope=classification["scope"],
            operator=operator,
            raw_context=request_raw_context,
        )
        request_id = int(request_row["id"])
        _insert_entities(conn, request_id, entities)
        request_for_analysis = {
            "id": request_id,
            "request_uid": request_uid,
            "question": question,
            "normalized_question": normalized_question,
            "intent": classification["intent"],
            "scope": classification["scope"],
            "entities": entities,
            "conn": conn,
            "learning_memory": memory_summary.get("memory") if isinstance(memory_summary, dict) else None,
            "semantic_context": semantic_context,
        }
        step_started = datetime.now().timestamp()
        knowledge = knowledge_check(request_for_analysis, entities, memory=request_for_analysis.get("learning_memory"))
        if debug_timing is not None:
            debug_timing["knowledge_check_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
        step_started = datetime.now().timestamp()
        gaps = detect_gaps(request_for_analysis, knowledge, memory=request_for_analysis.get("learning_memory"))
        if debug_timing is not None:
            debug_timing["detect_gaps_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
        step_started = datetime.now().timestamp()
        semantic_gap_policy = apply_semantic_context_gap_policy(
            request_uid,
            semantic_context,
            knowledge,
            gaps,
            memory=request_for_analysis.get("learning_memory"),
        )
        if debug_timing is not None:
            debug_timing["semantic_gap_policy_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
        step_started = datetime.now().timestamp()
        tasks = build_learning_plan(request_for_analysis, gaps, memory=request_for_analysis.get("learning_memory"))
        if debug_timing is not None:
            debug_timing["build_learning_plan_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
        _insert_gaps(conn, request_id, gaps)
        _insert_tasks(conn, request_id, tasks)
        requires_consent = any(task["requires_consent"] for task in tasks)
        status = "completed" if len(tasks) == 1 and tasks[0]["task_type"] == "answer_build" else "waiting_consent" if requires_consent else "planned"
        consent_status = "required" if requires_consent else "not_required"
        if memory_summary and isinstance(memory_summary, dict) and memory_summary.get("memory") is not None:
            _add_evidence(
                conn,
                request_id=request_id,
                evidence_type="reused_learning_context",
                entity_type="domain",
                entity_value=domain,
                confidence="probable",
                source="learning_memory",
                source_ref=(memory_summary.get("memory") or {}).get("dns", {}).get("request_uid"),
                summary=memory_summary.get("summary_text"),
                data=memory_summary.get("memory"),
            )
        if semantic_context.get("results"):
            top_families = []
            for item in semantic_context.get("results") or []:
                family = item.get("family_key") or f"{item.get('object_type')}:{item.get('object_ref')}"
                if family and family not in top_families:
                    top_families.append(str(family))
            _add_evidence(
                conn,
                request_id=request_id,
                evidence_type="semantic_context_lookup",
                entity_type="semantic_context",
                entity_value=normalized_question,
                confidence="suggested",
                source="semantic_memory",
                source_ref=semantic_context.get("search_mode"),
                summary=(
                    "Contexto semântico sugestivo encontrado: "
                    + ", ".join(top_families[:3])
                    + ". Não é confirmação factual isolada."
                ),
                data=semantic_context,
            )
        classification_result: dict[str, Any] = {"classifications": [], "summary_text": "Classificação operacional indisponível."}
        step_started = datetime.now().timestamp()
        try:
            classification_result = classify_learning_request(request_uid, persist=False, conn=conn)
        except RuntimeError:
            classification_result = {"classifications": [], "summary_text": "Classificação operacional indisponível."}
        if debug_timing is not None:
            debug_timing["classify_learning_request_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
        step_started = datetime.now().timestamp()
        answer = _build_answer_payload(
            request_uid=request_uid,
            request_row={**request_row, "status": status, "requires_consent": requires_consent, "consent_status": consent_status},
            entities=entities,
            known=knowledge["known"],
            unknown=knowledge["unknown"],
            gaps=gaps,
            tasks=tasks,
            evidence=[],
            execution={},
            memory=memory_summary.get("memory") if isinstance(memory_summary, dict) else None,
            classifications=classification_result.get("classifications") or [],
            semantic_context=semantic_context,
        )
        if debug_timing is not None:
            debug_timing["build_answer_seconds"] = max(0.0, datetime.now().timestamp() - step_started)
        with conn.cursor() as cur:
            cur.execute(
                """
                update learning_requests
                set status = %s,
                    requires_consent = %s,
                    consent_status = %s,
                    confidence_before = %s,
                    answer_summary = %s,
                    result = %s,
                    updated_at = now()
                where id = %s;
                """,
                (
                    status,
                    requires_consent,
                    consent_status,
                    knowledge["confidence_before"],
                    answer["answer_summary"],
                    _json_value(
                        {
                            "analysis": answer["analysis"],
                            "answer": answer,
                            "semantic_context": semantic_context,
                            "semantic_gap_policy": semantic_gap_policy,
                            "learning_memory": memory_summary.get("memory") if isinstance(memory_summary, dict) else None,
                            "classifications": classification_result.get("classifications") or [],
                        }
                    ),
                    request_id,
                ),
            )
    if debug_timing is not None:
        debug_timing["total_seconds"] = max(0.0, datetime.now().timestamp() - total_started)

    return get_learning_request(request_uid) or {}


def list_learning_requests(status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit)
    params: list[Any] = []
    where = ""
    if status:
        where = "where r.status = %s"
        params.append(status)
    params.append(limit)
    return _fetch_all(
        f"""
        select
          r.request_uid,
          r.question,
          r.normalized_question,
          r.intent,
          r.scope,
          r.status,
          r.operator,
          r.requires_consent,
          r.consent_status,
          r.confidence_before,
          r.confidence_after,
          r.answer_summary,
          r.created_at,
          r.updated_at,
          r.started_at,
          r.finished_at,
          coalesce(e.entity_count, 0)::bigint as entity_count,
          coalesce(g.gap_count, 0)::bigint as gap_count,
          coalesce(t.task_count, 0)::bigint as task_count,
          coalesce(v.evidence_count, 0)::bigint as evidence_count
        from learning_requests r
        left join lateral (
            select count(*)::bigint as entity_count
            from learning_entities e
            where e.request_id = r.id
        ) e on true
        left join lateral (
            select count(*)::bigint as gap_count
            from learning_gaps g
            where g.request_id = r.id
        ) g on true
        left join lateral (
            select count(*)::bigint as task_count
            from learning_tasks t
            where t.request_id = r.id
        ) t on true
        left join lateral (
            select count(*)::bigint as evidence_count
            from learning_evidence v
            where v.request_id = r.id
        ) v on true
        {where}
        order by r.created_at desc, r.id desc
        limit %s;
        """,
        tuple(params),
    )


def get_learning_request(request_uid: str) -> dict[str, Any] | None:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        return None
    request = bundle["request"]
    analysis = bundle["analysis"] or request.get("result", {}).get("analysis", {})
    execution = bundle["execution"] or request.get("result", {}).get("execution", {})
    try:
        answer = build_answer(request_uid)
    except ValueError:
        answer = bundle["answer"] or request.get("result", {}).get("answer", {})
    return {
        "request": request,
        "entities": bundle["entities"],
        "gaps": bundle["gaps"],
        "tasks": bundle["tasks"],
        "evidence": bundle["evidence"],
        "classifications": bundle.get("classifications", []),
        "analysis": analysis,
        "execution": execution,
        "answer": answer,
        "semantic_context": bundle.get("semantic_context"),
    }


def approve_learning_request(request_uid: str) -> dict[str, Any] | None:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        return None
    request_id = int(bundle["request"]["id"])
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update learning_requests
                set consent_status = 'approved',
                    status = case when status = 'waiting_consent' then 'planned' else status end,
                    updated_at = now()
                where id = %s;
                """,
                (request_id,),
            )
            cur.execute(
                """
                update learning_tasks
                set status = 'planned'
                where request_id = %s
                  and task_type in ('ping_measurement', 'traceroute_measurement')
                  and status = 'waiting_consent';
                """,
                (request_id,),
            )
            cur.execute(
                """
                update learning_requests
                set result = coalesce(result, '{}'::jsonb) || %s::jsonb,
                    updated_at = now()
                where id = %s;
                """,
                (
                    _json_value(
                        {
                            "consent": {
                                "status": "approved",
                                "approved_at": datetime.now().astimezone(),
                                "active_measurements": [task["task_type"] for task in bundle["tasks"] if task["task_type"] in INVASIVE_TASK_TYPES],
                            }
                        }
                    ),
                    request_id,
                ),
            )
    return get_learning_request(request_uid)


def execute_learning_request(
    request_uid: str,
    dry_run: bool = True,
    allow_safe_tasks: bool = True,
    allow_active_measurements: bool = False,
    force_refresh: bool = False,
) -> dict[str, Any]:
    return _execute_request_internal(
        request_uid,
        dry_run=dry_run,
        allow_safe_tasks=allow_safe_tasks,
        allow_active_measurements=allow_active_measurements,
        force_refresh=force_refresh,
    )


def enrich_learning_request(
    request_uid: str,
    *,
    force_refresh: bool = False,
    allow_external: bool = True,
) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")

    request_row = bundle["request"]
    request_id = int(request_row["id"])
    entities = bundle["entities"]
    request_memory = _request_learning_memory(request_row)
    if request_memory is None:
        domain_value = _safe_domain_from_entities(entities)
        if domain_value:
            memory_summary = summarize_learning_memory({"entity_type": "domain", "entity_value": domain_value})
            request_memory = memory_summary.get("memory") if isinstance(memory_summary, dict) else None

    asn_values: set[int] = set()
    ip_values: set[str] = set()
    for entity in entities:
        entity_type = str(entity.get("entity_type") or "").lower()
        value = str(entity.get("normalized_value") or entity.get("entity_value") or "").strip()
        if entity_type == "asn":
            try:
                asn_values.add(int(value))
            except ValueError:
                continue
        elif entity_type == "ip":
            try:
                ip_values.add(str(ipaddress.ip_address(value)))
            except ValueError:
                continue

    if isinstance(request_memory, dict):
        for ip_state in request_memory.get("ips") or []:
            if not isinstance(ip_state, dict):
                continue
            ip_value = str(ip_state.get("ip") or "").strip()
            if ip_value:
                try:
                    ip_values.add(str(ipaddress.ip_address(ip_value)))
                except ValueError:
                    continue
    domain_value = _safe_domain_from_entities(entities)
    if domain_value:
        memory_summary = summarize_learning_memory({"entity_type": "domain", "entity_value": domain_value})
        if isinstance(memory_summary, dict) and isinstance(memory_summary.get("memory"), dict):
            for ip_state in memory_summary["memory"].get("ips") or []:
                if not isinstance(ip_state, dict):
                    continue
                ip_value = str(ip_state.get("ip") or "").strip()
                if ip_value:
                    try:
                        ip_values.add(str(ipaddress.ip_address(ip_value)))
                    except ValueError:
                        continue

    enrichment_results: list[dict[str, Any]] = []
    warnings: list[str] = []
    with get_connection() as conn:
        if allow_external:
            for asn in sorted(asn_values):
                try:
                    result = enrich_asn(asn, force_refresh=force_refresh, allow_external=True, conn=conn)
                    enrichment_results.append(result)
                    _add_evidence(
                        conn,
                        request_id=request_id,
                        evidence_type="external_enrichment",
                        entity_type="asn",
                        entity_value=str(asn),
                        confidence=str(result.get("confidence") or "suggested"),
                        source=str(result.get("source") or "external_enrichment"),
                        source_ref=f"asn:{asn}",
                        summary=(
                            f"ASN {asn} enriquecido externamente com organização {result.get('organization_name') or 'n/a'} "
                            f"e país {result.get('country') or 'n/a'}."
                        ),
                        data=result,
                    )
                except Exception as exc:
                    warnings.append(f"asn {asn}: {exc}")
            for ip_value in sorted(ip_values):
                try:
                    result = enrich_ip(ip_value, force_refresh=force_refresh, allow_external=True, conn=conn)
                    enrichment_results.append(result)
                    _add_evidence(
                        conn,
                        request_id=request_id,
                        evidence_type="external_enrichment",
                        entity_type="ip",
                        entity_value=ip_value,
                        confidence=str(result.get("confidence") or "suggested"),
                        source=str(result.get("source") or "external_enrichment"),
                        source_ref=f"ip:{ip_value}",
                        summary=(
                            f"IP {ip_value} enriquecido externamente com organização {result.get('organization_name') or 'n/a'} "
                            f"e ASN {result.get('asn') or 'n/a'}."
                        ),
                        data=result,
                    )
                except Exception as exc:
                    warnings.append(f"ip {ip_value}: {exc}")
        else:
            for asn in sorted(asn_values):
                cached = get_external_asn_enrichment(asn, conn=conn)
                if cached is not None:
                    enrichment_results.append(cached)
                    _add_evidence(
                        conn,
                        request_id=request_id,
                        evidence_type="external_enrichment",
                        entity_type="asn",
                        entity_value=str(asn),
                        confidence=str(cached.get("confidence") or "suggested"),
                        source=str(cached.get("source") or "external_enrichment_cache"),
                        source_ref=f"asn:{asn}",
                        summary=(
                            f"ASN {asn} enriquecido a partir do cache local com organização {cached.get('organization_name') or 'n/a'} "
                            f"e país {cached.get('country') or 'n/a'}."
                        ),
                        data=cached,
                    )
            for ip_value in sorted(ip_values):
                cached = get_external_ip_enrichment(ip_value, conn=conn)
                if cached is not None:
                    enrichment_results.append(cached)
                    _add_evidence(
                        conn,
                        request_id=request_id,
                        evidence_type="external_enrichment",
                        entity_type="ip",
                        entity_value=ip_value,
                        confidence=str(cached.get("confidence") or "suggested"),
                        source=str(cached.get("source") or "external_enrichment_cache"),
                        source_ref=f"ip:{ip_value}",
                        summary=(
                            f"IP {ip_value} enriquecido a partir do cache local com organização {cached.get('organization_name') or 'n/a'} "
                            f"e ASN {cached.get('asn') or 'n/a'}."
                        ),
                        data=cached,
                    )

        classification_result: dict[str, Any] = {"classifications": [], "summary_text": "Classificação operacional indisponível."}
        try:
            classification_result = classify_learning_request(request_uid, persist=True, conn=conn)
        except RuntimeError:
            classification_result = {"classifications": [], "summary_text": "Classificação operacional indisponível."}

        with conn.cursor() as cur:
            cur.execute(
                """
                update learning_requests
                set result = coalesce(result, '{}'::jsonb) || %s::jsonb,
                    updated_at = now()
                where id = %s;
                """,
                (
                    _json_value(
                        {
                            "external_enrichment": {
                                "force_refresh": force_refresh,
                                "allow_external": allow_external,
                                "results": enrichment_results,
                                "warnings": warnings,
                            },
                            "classifications": classification_result.get("classifications") or [],
                            "classification_summary": classification_result.get("summary_text"),
                        }
                    ),
                    request_id,
                ),
            )

    return {
        "request_uid": request_uid,
        "status": "completed" if not warnings else "partial",
        "force_refresh": force_refresh,
        "allow_external": allow_external,
        "warnings": warnings,
        "enrichment_results": enrichment_results,
        "classifications": classification_result.get("classifications") or [],
        "summary_text": classification_result.get("summary_text"),
    }


def _build_answer_payload(
    *,
    request_uid: str,
    request_row: dict[str, Any],
    entities: list[dict[str, Any]],
    known: list[dict[str, Any]],
    unknown: list[dict[str, Any]],
    gaps: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    execution: dict[str, Any],
    memory: dict[str, Any] | None = None,
    classifications: list[dict[str, Any]] | None = None,
    semantic_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    answer_summary_parts: list[str] = []
    open_gaps = [gap for gap in gaps if str(gap.get("status") or "open").lower() == "open"]
    dns_resolutions = execution.get("dns_resolutions") or {}
    bgp_lookups = execution.get("bgp_lookups") or {}
    memory_section = memory if isinstance(memory, dict) else None
    classification_section = classifications or execution.get("classifications") or []
    semantic_summary = _semantic_context_summary(semantic_context)
    if semantic_summary:
        answer_summary_parts.append("Contexto semântico encontrado:")
        answer_summary_parts.append(semantic_summary)
        answer_summary_parts.append(
            "Este contexto foi usado para localizar evidências e memória relacionada; ele não é confirmação isolada."
        )

    structured_sources: list[str] = []
    if memory_section is not None:
        memory_entity = str(memory_section.get("entity_value") or "").strip()
        structured_sources.append(f"learning_memory {memory_entity}".strip())
    inventory_host_known = next((item for item in known if item.get("kind") == "inventory_host"), None)
    if inventory_host_known:
        structured_sources.append(f"inventário host {inventory_host_known.get('entity_value')}")
    site_known_for_summary = next((item for item in known if item.get("kind") == "site"), None)
    if site_known_for_summary:
        structured_sources.append(f"inventário site {site_known_for_summary.get('entity_value')}")
    if any(item.get("kind") == "ixbr_public_context" for item in known):
        structured_sources.append("contexto público IX.br")
    if structured_sources:
        answer_summary_parts.append(
            "Evidência estruturada reutilizada: " + ", ".join(dict.fromkeys(structured_sources)) + "."
        )

    if request_row.get("intent") == "ix_inventory_context":
        site_code = _safe_site_from_entities(entities) or "PTT-CE"
        site_known = next((item for item in known if item.get("kind") == "site"), None)
        public_context_known = next((item for item in known if item.get("kind") == "ixbr_public_context"), None)
        if site_known and isinstance(site_known.get("data"), dict):
            site_data = site_known["data"].get("site") or {}
            host_count = int(site_data.get("host_count") or 0)
            if host_count == 0:
                answer_summary_parts.append(f"Nenhum host confirmado pertence ao {site_code} ainda.")
            else:
                answer_summary_parts.append(f"{host_count} host(s) já estão confirmados para o {site_code}.")
        if public_context_known is not None:
            public_context = public_context_known.get("data") or {}
            participants = public_context.get("public_participants_count", 0)
            seen = public_context.get("public_participants_seen_as_origin_count", 0)
            answer_summary_parts.append(
                f"O IX.br/CE traz {participants} participantes públicos e {seen} vistos como origin na base BGP."
            )
        answer_summary_parts.append(
            "Dados IX.br indicam participantes públicos do PTT-CE, mas isso não confirma hosts internos."
        )
    elif request_row.get("intent") in {"route_to_domain", "domain_analysis"}:
        domain = _safe_domain_from_entities(entities) or "domínio"
        domain_from_semantic = any(
            entity.get("entity_type") == "domain"
            and entity.get("source") == "semantic_memory"
            for entity in entities
        )
        question_text = str(request_row.get("normalized_question") or request_row.get("question") or "").lower()
        if domain_from_semantic and any(token in question_text for token in ("destinos", "alta lat", "internacional")):
            answer_summary_parts.append(
                f"{domain} é um caso conhecido relacionado pela memória semântica; isso não confirma todos os destinos internacionais."
            )
        if memory_section is not None:
            answer_summary_parts.append(memory_section.get("summary_text") or f"Aprendizado reutilizado para {domain}.")
        dns_result = dns_resolutions.get(domain) if isinstance(dns_resolutions, dict) else None
        bgp_result_list = bgp_lookups.get(domain) if isinstance(bgp_lookups, dict) else None
        active_measurements = execution.get("active_measurements") or {}
        consent_approved = bool(execution.get("consent_approved"))
        allow_active_measurements = bool(execution.get("allow_active_measurements"))
        active_performed = bool(execution.get("active_measurements_performed"))
        if dns_result and dns_result.get("resolved_ips"):
            resolved_ips = dns_result.get("resolved_ips") or []
            answer_summary_parts.append(
                f"DNS de {domain} resolveu {len(resolved_ips)} IP(s): {', '.join(resolved_ips)}."
            )
        elif any(gap.get("gap_type") == "missing_dns_resolution" for gap in open_gaps):
            answer_summary_parts.append(f"Ainda falta resolver DNS para {domain}.")
        matched_bgp_rows = []
        unmatched_bgp_rows = []
        if isinstance(bgp_result_list, list):
            for item in bgp_result_list:
                if not isinstance(item, dict):
                    continue
                if item.get("status") == "completed" and item.get("matched_prefix"):
                    matched_bgp_rows.append(item)
                elif item.get("status") in {"failed", "completed"}:
                    unmatched_bgp_rows.append(item)
        if matched_bgp_rows:
            prefixes = sorted({str(item.get("matched_prefix")) for item in matched_bgp_rows if item.get("matched_prefix")})
            origin_asns = sorted({str(item.get("origin_asn")) for item in matched_bgp_rows if item.get("origin_asn") is not None})
            matched_ips = sorted({str(item.get("ip")) for item in matched_bgp_rows if item.get("ip")})
            prefix_part = ", ".join(prefixes) if prefixes else "prefixo desconhecido"
            origin_part = ", ".join(origin_asns) if origin_asns else "ASN desconhecido"
            answer_summary_parts.append(
                f"BGP encontrou {len(matched_bgp_rows)} match(es) para {domain} nos IPs {', '.join(matched_ips) if matched_ips else 'observados'}: {prefix_part} (origin ASNs {origin_part})."
            )
            if unmatched_bgp_rows:
                unmatched_ips = sorted({str(item.get("ip")) for item in unmatched_bgp_rows if item.get("ip")})
                if unmatched_ips:
                    answer_summary_parts.append(
                        f"Sem match BGP para {len(unmatched_ips)} IP(s): {', '.join(unmatched_ips)}."
                    )
        elif dns_result and dns_result.get("resolved_ips"):
            answer_summary_parts.append(f"DNS foi resolvido para {domain}, mas ainda não houve match BGP para os IPs observados.")
        elif any(gap.get("gap_type") == "missing_bgp_match" for gap in open_gaps):
            answer_summary_parts.append(f"Ainda falta amarrar o caminho BGP para {domain}.")
        if any(gap.get("gap_type") == "missing_traceroute_measurement" for gap in open_gaps):
            answer_summary_parts.append("Traceroute recente ainda não existe para fechar a aprendizagem.")
        if any(gap.get("gap_type") == "missing_ping_measurement" for gap in open_gaps):
            answer_summary_parts.append("Ping recente ainda não existe para enriquecer a resposta.")
        if consent_approved and not allow_active_measurements and not active_performed:
            answer_summary_parts.append(
                "Medições ativas estão aprovadas, mas ainda não foram executadas porque a chamada de execução não usou --active."
            )
        if execution.get("waiting_consent_tasks"):
            answer_summary_parts.append(
                "Ainda não executei medições ativas. Para medir latência ou caminho real, aprove ping/traceroute."
            )
        if active_performed:
            ping_outputs = active_measurements.get("ping") or []
            traceroute_outputs = active_measurements.get("traceroute") or []
            ping_summaries: list[str] = []
            for task_output in ping_outputs:
                if not isinstance(task_output, dict):
                    continue
                for result in task_output.get("results") or []:
                    if not isinstance(result, dict):
                        continue
                    ip_value = result.get("ip")
                    if result.get("status") == "completed":
                        metrics = result.get("metrics") or {}
                        ping_summaries.append(
                            f"{ip_value} loss {metrics.get('packet_loss_percent')}% avg {metrics.get('rtt_avg_ms')} ms"
                        )
                    else:
                        ping_summaries.append(f"{ip_value} {result.get('status')}")
            if ping_summaries:
                answer_summary_parts.append(f"Ping ativo em {len(ping_summaries)} destino(s): {', '.join(ping_summaries[:5])}.")

            traceroute_summaries: list[str] = []
            for task_output in traceroute_outputs:
                if not isinstance(task_output, dict):
                    continue
                for result in task_output.get("results") or []:
                    if not isinstance(result, dict):
                        continue
                    ip_value = result.get("ip")
                    hops = result.get("hops") or []
                    hop_ips = [str(hop.get("hop_ip")) for hop in hops if isinstance(hop, dict) and hop.get("hop_ip")]
                    first_hops = ", ".join(hop_ips[:3]) if hop_ips else "sem hops resolvidos"
                    last_hop = hop_ips[-1] if hop_ips else None
                    if result.get("status") == "completed":
                        traceroute_summaries.append(
                            f"{ip_value} {len(hops)} hop(s), início {first_hops}{f', fim {last_hop}' if last_hop else ''}"
                        )
                    else:
                        traceroute_summaries.append(f"{ip_value} {result.get('status')}")
            if traceroute_summaries:
                answer_summary_parts.append(
                    f"Traceroute ativo em {len(traceroute_summaries)} destino(s): {', '.join(traceroute_summaries[:5])}."
                )

        blocked_active = active_measurements.get("blocked") or []
        if blocked_active:
            blocked_ips = ", ".join(str(item.get("ip")) for item in blocked_active[:5] if isinstance(item, dict))
            answer_summary_parts.append(f"A política bloqueou {len(blocked_active)} destino(s): {blocked_ips}.")
        if classification_section:
            classification_summaries: list[str] = []
            for item in classification_section[:8]:
                if not isinstance(item, dict):
                    continue
                classification_summaries.append(
                    f"{item.get('classification_type')}={item.get('classification_value')} ({item.get('confidence')})"
                )
            if classification_summaries:
                answer_summary_parts.append(
                    f"Classificação operacional: {'; '.join(classification_summaries)}."
                )
            else:
                answer_summary_parts.append("Classificação operacional calculada com base nas evidências existentes.")
        if not answer_summary_parts:
            answer_summary_parts.append(f"Pergunta de roteamento para {domain} ainda está em fase de aprendizagem.")
    else:
        inventory_host = next((item for item in known if item.get("kind") == "inventory_host"), None)
        if inventory_host:
            answer_summary_parts.append(
                f"Inventário estruturado confirma {inventory_host.get('entity_value')} como host relacionado à pergunta."
            )
        if known:
            answer_summary_parts.append("Há dados conhecidos suficientes para responder parcialmente.")
        if gaps:
            answer_summary_parts.append(f"{len(gaps)} lacuna(s) detectada(s) para continuar a aprendizagem.")
        if not answer_summary_parts:
            answer_summary_parts.append("Ainda não há base suficiente para uma resposta confiável.")

    if semantic_context:
        semantic_label = _semantic_context_short_label(semantic_context)
        if semantic_label:
            answer_summary_parts.append(f"Contexto semântico usado na busca: {semantic_label}.")

    if open_gaps:
        answer_summary_parts.append("Lacunas restantes:")
        gap_labels = []
        for gap in open_gaps[:5]:
            label = str(gap.get("gap_type") or "gap")
            metadata = gap.get("metadata") if isinstance(gap.get("metadata"), dict) else {}
            if metadata.get("semantic_context_suggested") and metadata.get("semantic_context_can_reduce") is False:
                label = f"{label} (contexto semântico apenas sugeriu caminho)"
            elif metadata.get("semantic_context_gap_status") == "stale":
                label = f"{label} (stale)"
            elif metadata.get("structured_evidence_reused"):
                label = f"{label} ({metadata.get('structured_evidence_reused')})"
            gap_labels.append(label)
        answer_summary_parts.append("Lacunas restantes: " + ", ".join(gap_labels) + ".")

    next_actions: list[str] = []
    for gap in open_gaps:
        if gap.get("recommended_task_type") == "dns_resolve":
            next_actions.append("Resolver DNS do domínio citado.")
        elif gap.get("recommended_task_type") == "bgp_prefix_lookup":
            next_actions.append("Consultar BGP para prefixo/IP/ASN citado.")
        elif gap.get("recommended_task_type") == "inventory_lookup":
            next_actions.append("Verificar inventário e vínculos confirmados.")
        elif gap.get("recommended_task_type") == "ixbr_lookup":
            next_actions.append("Cruzar contexto público IX.br com a base BGP.")
        elif gap.get("recommended_task_type") == "ping_measurement":
            next_actions.append("Aprovar ping controlado antes de executar.")
        elif gap.get("recommended_task_type") == "traceroute_measurement":
            next_actions.append("Aprovar traceroute controlado antes de executar.")

    if execution.get("consent_approved") and execution.get("deferred_active_tasks"):
        next_actions.append("Executar medições ativas aprovadas com --active.")

    if not next_actions:
        next_actions.append("Revisar lacunas e aprovar as tarefas pendentes, se houver.")

    planned_tasks = [
        {
            "task_uid": task["task_uid"],
            "task_type": task["task_type"],
            "status": task["status"],
            "priority": task["priority"],
            "requires_consent": task["requires_consent"],
            "command_preview": task.get("command_preview"),
            "input": task.get("input"),
            "output": task.get("output"),
            "error": task.get("error"),
        }
        for task in tasks
    ]
    return {
        "request_uid": request_uid,
        "intent": request_row.get("intent"),
        "scope": request_row.get("scope"),
        "status": request_row.get("status"),
        "analysis": {
            "known": known,
            "unknown": unknown,
            "gaps": gaps,
            "planned_tasks": planned_tasks,
        },
        "known": known,
        "unknown": unknown,
        "gaps": open_gaps,
        "planned_tasks": planned_tasks,
        "evidence": evidence,
        "execution": execution,
        "next_actions": next_actions,
        "answer_summary": " ".join(answer_summary_parts).strip(),
        "semantic_context": semantic_context,
        "learning_memory": memory_section,
        "classifications": classification_section,
    }


def build_answer(request_uid: str) -> dict[str, Any]:
    bundle = _request_bundle_from_uid(request_uid)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    request = bundle["request"]
    analysis = request.get("result", {}).get("analysis") or {}
    execution = request.get("result", {}).get("execution") or bundle["execution"] or {}
    known = bundle["analysis"].get("known") or analysis.get("known") or []
    unknown = bundle["analysis"].get("unknown") or analysis.get("unknown") or []
    gaps = bundle["gaps"] or analysis.get("gaps") or []
    tasks = bundle["tasks"] or analysis.get("planned_tasks") or []
    evidence = bundle["evidence"]
    memory = _request_learning_memory(request)
    if memory is None:
        memory = _domain_memory_from_request(request, bundle["entities"])
    semantic_context = _semantic_context_from_request(request)
    classifications = bundle.get("classifications") or []
    if not classifications:
        try:
            classifications = classify_learning_request(request_uid, persist=False)["classifications"]
        except RuntimeError:
            classifications = []
    answer = _build_answer_payload(
        request_uid=request_uid,
        request_row=request,
        entities=bundle["entities"],
        known=known,
        unknown=unknown,
        gaps=gaps,
        tasks=tasks,
        evidence=evidence,
        execution=execution,
        memory=memory,
        classifications=classifications,
        semantic_context=semantic_context,
    )
    return answer
