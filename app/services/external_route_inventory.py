from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import uuid
from decimal import Decimal
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.db.connection import get_connection
from app.services.active_ping import run_ping
from app.services.active_traceroute_lab import run_traceroute
from app.services.bgp_operational_queries import lookup_bgp_by_ip
from app.services.external_enrichment import (
    enrich_asn,
    enrich_ip,
    get_external_asn_enrichment,
    get_external_ip_enrichment,
)

DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."
MAX_LIMIT = 500

CONFIDENCE_ORDER = {"unknown": 0, "suggested": 1, "probable": 2, "confirmed": 3}

SERVICE_SEEDS: list[dict[str, Any]] = [
    {
        "service_slug": "google",
        "display_name": "Google",
        "category": "service",
        "description": "Rotas externas associadas a google.com, gstatic.com e googleapis.com.",
        "is_ptt": False,
    },
    {
        "service_slug": "youtube",
        "display_name": "YouTube",
        "category": "service",
        "description": "Rotas externas associadas a youtube.com, googlevideo.com e ytimg.com.",
        "is_ptt": False,
    },
    {
        "service_slug": "facebook",
        "display_name": "Facebook",
        "category": "service",
        "description": "Rotas externas associadas a facebook.com e fbcdn.net.",
        "is_ptt": False,
    },
    {
        "service_slug": "instagram",
        "display_name": "Instagram",
        "category": "service",
        "description": "Rotas externas associadas a instagram.com e cdninstagram.com.",
        "is_ptt": False,
    },
    {
        "service_slug": "whatsapp",
        "display_name": "WhatsApp",
        "category": "service",
        "description": "Rotas externas associadas a whatsapp.com, web.whatsapp.com e whatsapp.net.",
        "is_ptt": False,
    },
    {
        "service_slug": "netflix",
        "display_name": "Netflix",
        "category": "service",
        "description": "Rotas externas associadas a netflix.com, nflxvideo.net e nflximg.net.",
        "is_ptt": False,
    },
    {
        "service_slug": "ptt",
        "display_name": "PTT / IX",
        "category": "ix",
        "description": "Contexto de PTT/IX observável em hops externos, sem inventar IPs ou hops.",
        "is_ptt": True,
    },
    {
        "service_slug": "cloudflare",
        "display_name": "Cloudflare",
        "category": "service",
        "description": "Rotas e hops associados a cloudflare.com e 1.1.1.1.",
        "is_ptt": False,
    },
]

SERVICE_TARGET_SEEDS: list[dict[str, str]] = [
    {"service_slug": "google", "target_host": "google.com", "target_kind": "domain", "target_label": "google.com"},
    {"service_slug": "google", "target_host": "gstatic.com", "target_kind": "domain", "target_label": "gstatic.com"},
    {"service_slug": "google", "target_host": "googleapis.com", "target_kind": "domain", "target_label": "googleapis.com"},
    {"service_slug": "youtube", "target_host": "youtube.com", "target_kind": "domain", "target_label": "youtube.com"},
    {"service_slug": "youtube", "target_host": "googlevideo.com", "target_kind": "domain", "target_label": "googlevideo.com"},
    {"service_slug": "youtube", "target_host": "ytimg.com", "target_kind": "domain", "target_label": "ytimg.com"},
    {"service_slug": "facebook", "target_host": "facebook.com", "target_kind": "domain", "target_label": "facebook.com"},
    {"service_slug": "facebook", "target_host": "fbcdn.net", "target_kind": "domain", "target_label": "fbcdn.net"},
    {"service_slug": "instagram", "target_host": "instagram.com", "target_kind": "domain", "target_label": "instagram.com"},
    {"service_slug": "instagram", "target_host": "cdninstagram.com", "target_kind": "domain", "target_label": "cdninstagram.com"},
    {"service_slug": "whatsapp", "target_host": "whatsapp.com", "target_kind": "domain", "target_label": "whatsapp.com"},
    {"service_slug": "whatsapp", "target_host": "web.whatsapp.com", "target_kind": "hostname", "target_label": "web.whatsapp.com"},
    {"service_slug": "whatsapp", "target_host": "whatsapp.net", "target_kind": "domain", "target_label": "whatsapp.net"},
    {"service_slug": "netflix", "target_host": "netflix.com", "target_kind": "domain", "target_label": "netflix.com"},
    {"service_slug": "netflix", "target_host": "nflxvideo.net", "target_kind": "domain", "target_label": "nflxvideo.net"},
    {"service_slug": "netflix", "target_host": "nflximg.net", "target_kind": "domain", "target_label": "nflximg.net"},
    {"service_slug": "cloudflare", "target_host": "cloudflare.com", "target_kind": "domain", "target_label": "cloudflare.com"},
    {"service_slug": "cloudflare", "target_host": "1.1.1.1", "target_kind": "ip", "target_label": "1.1.1.1"},
]

SERVICE_HINTS: list[tuple[str, str]] = [
    ("googlevideo.com", "youtube"),
    ("youtube.com", "youtube"),
    ("ytimg.com", "youtube"),
    ("googleapis.com", "google"),
    ("gstatic.com", "google"),
    ("google.com", "google"),
    ("fbcdn.net", "facebook"),
    ("facebook.com", "facebook"),
    ("cdninstagram.com", "instagram"),
    ("instagram.com", "instagram"),
    ("whatsapp.net", "whatsapp"),
    ("web.whatsapp.com", "whatsapp"),
    ("whatsapp.com", "whatsapp"),
    ("nflxvideo.net", "netflix"),
    ("nflximg.net", "netflix"),
    ("netflix.com", "netflix"),
    ("cloudflare.com", "cloudflare"),
    ("1.1.1.1", "cloudflare"),
    ("ix.br", "ptt"),
    ("ptt", "ptt"),
    ("ixp", "ptt"),
]

PTT_HINTS = ("ixp", "ix.br", "ptt", "peering", "route server", "route-server")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_text(value: Any, *, max_chars: int = 240) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split()).strip()
    if not text:
        return None
    return text[:max_chars]


def _normalize_slug(value: Any) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return slug


def _normalize_host(value: Any) -> str | None:
    text = _normalize_text(value, max_chars=200)
    if text is None:
        return None
    return text.lower()


def _normalize_target_value(value: Any) -> str | None:
    text = _normalize_text(value, max_chars=240)
    if text is None:
        return None
    cleaned = text.strip().strip("[]()<>\"'")
    if "/" in cleaned:
        try:
            network = ipaddress.ip_network(cleaned, strict=False)
            return str(network.network_address)
        except ValueError:
            cleaned = cleaned.split("/", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned.lower()


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
        return float(value)
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    return value


def _json(value: Any) -> Jsonb:
    return Jsonb(_safe_json(value))


def _fetch_all(sql: str, params: tuple[Any, ...] = (), *, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    try:
        if conn is not None:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
        with get_connection() as fresh_conn:
            with fresh_conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _fetch_one(sql: str, params: tuple[Any, ...] = (), *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
    rows = _fetch_all(sql, params, conn=conn)
    return rows[0] if rows else None


def _execute(sql: str, params: tuple[Any, ...] = (), *, conn: psycopg.Connection | None = None) -> None:
    try:
        if conn is not None:
            with conn.cursor() as cur:
                cur.execute(sql, params)
            return
        with get_connection() as fresh_conn:
            with fresh_conn.cursor() as cur:
                cur.execute(sql, params)
            fresh_conn.commit()
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _confidence_rank(confidence: str | None) -> int:
    return CONFIDENCE_ORDER.get(str(confidence or "unknown").lower(), 0)


def _better_confidence(current: str | None, candidate: str | None) -> str:
    current_rank = _confidence_rank(current)
    candidate_rank = _confidence_rank(candidate)
    if candidate_rank >= current_rank:
        return str(candidate or current or "unknown").lower()
    return str(current or candidate or "unknown").lower()


def _ip_scope(value: str | None) -> str:
    if not value:
        return "unknown"
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "private"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved"
    return "public"


def _is_public(value: str | None) -> bool:
    return _ip_scope(value) == "public"


def _extract_ip(value: Any, raw_line: Any = None) -> str | None:
    candidates: list[str] = []
    text = _normalize_text(value, max_chars=128)
    if text:
        candidates.append(text)
    raw = _normalize_text(raw_line, max_chars=512)
    if raw:
        candidates.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw))
        candidates.extend(re.findall(r"\b[0-9a-fA-F:]{2,}\b", raw))
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate.split("%", 1)[0]))
        except ValueError:
            continue
    return None


def _extract_first_ip_from_line(raw_line: Any) -> str | None:
    return _extract_ip(None, raw_line)


def _contains_any(text: str | None, needles: Iterable[str]) -> bool:
    lowered = str(text or "").lower()
    return any(needle in lowered for needle in needles)


def _service_from_text(*values: Any) -> str | None:
    lowered = " ".join(_normalize_text(value, max_chars=200) or "" for value in values).lower()
    for needle, service_slug in SERVICE_HINTS:
        if needle in lowered:
            return service_slug
    return None


def _service_slug_for_target_host(target_host: str | None) -> str | None:
    if not target_host:
        return None
    return _service_from_text(target_host)


def _service_slug_for_target_value(target_value: str | None) -> str | None:
    if not target_value:
        return None
    return _service_from_text(_normalize_target_value(target_value))


def _is_ix_context(*values: Any) -> bool:
    return _contains_any(" ".join(_normalize_text(value, max_chars=200) or "" for value in values), PTT_HINTS)


def _service_row_map(conn: psycopg.Connection | None = None) -> dict[str, dict[str, Any]]:
    rows = _fetch_all(
        """
        select id, service_slug, display_name, category, description, is_ptt, enabled, created_at, updated_at
        from external_route_services
        order by display_name asc, service_slug asc;
        """,
        conn=conn,
    )
    return {str(row["service_slug"]): row for row in rows}


def _target_row_map(conn: psycopg.Connection | None = None) -> dict[str, dict[str, Any]]:
    rows = _fetch_all(
        """
        select t.id, t.service_id, s.service_slug, t.target_host, t.target_kind, t.target_label, t.notes
        from external_route_targets t
        join external_route_services s on s.id = t.service_id
        order by s.service_slug, t.target_host;
        """,
        conn=conn,
    )
    return {str(row["target_host"]).lower(): row for row in rows}


def _service_id(service_slug: str, *, conn: psycopg.Connection | None = None) -> int | None:
    row = _fetch_one(
        "select id from external_route_services where service_slug = %s limit 1;",
        (service_slug,),
        conn=conn,
    )
    return int(row["id"]) if row else None


def _target_id(service_id: int, target_host: str, *, conn: psycopg.Connection | None = None) -> int | None:
    row = _fetch_one(
        """
        select id
        from external_route_targets
        where service_id = %s and lower(target_host) = lower(%s)
        limit 1;
        """,
        (service_id, target_host),
        conn=conn,
    )
    return int(row["id"]) if row else None


def _hop_row_for_ip(hop_ip: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
    return _fetch_one(
        """
        select
          id,
          hop_ip::text as hop_ip,
          reverse_dns,
          asn,
          organization,
          country,
          category,
          role,
          confidence,
          confidence_rank,
          source_priority,
          evidence_sources,
          observation_count,
          first_seen_at,
          last_seen_at,
          metadata
        from external_route_hops
        where hop_ip = %s::inet
        limit 1;
        """,
        (hop_ip,),
        conn=conn,
    )


def _service_hop_summary_rows(service_slug: str, *, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          s.service_slug,
          s.display_name,
          s.category as service_category,
          h.hop_ip::text as hop_ip,
          h.reverse_dns,
          h.asn,
          h.organization,
          h.country,
          h.category,
          h.role,
          h.confidence,
          h.confidence_rank,
          h.source_priority,
          h.observation_count,
          h.first_seen_at,
          h.last_seen_at,
          hs.occurrence_count,
          hs.target_count,
          hs.min_hop_number,
          hs.max_hop_number,
          hs.target_hosts,
          hs.updated_at
        from external_route_service_hop_summary hs
        join external_route_services s on s.id = hs.service_id
        join external_route_hops h on h.id = hs.hop_id
        where s.service_slug = %s
        order by hs.occurrence_count desc, hs.last_seen_at desc, h.hop_ip asc;
        """,
        (service_slug,),
        conn=conn,
    )


def _service_target_hosts(service_slug: str, *, conn: psycopg.Connection | None = None) -> list[str]:
    rows = _fetch_all(
        """
        select lower(target_host) as target_host
        from external_route_targets t
        join external_route_services s on s.id = t.service_id
        where s.service_slug = %s
        order by target_host;
        """,
        (service_slug,),
        conn=conn,
    )
    return [str(row["target_host"]) for row in rows]


def _service_targets_count(service_slug: str, *, conn: psycopg.Connection | None = None) -> int:
    row = _fetch_one(
        """
        select count(*)::bigint as value
        from external_route_targets t
        join external_route_services s on s.id = t.service_id
        where s.service_slug = %s;
        """,
        (service_slug,),
        conn=conn,
    )
    return int(row["value"]) if row else 0


def _service_observation_count(service_slug: str, *, conn: psycopg.Connection | None = None) -> int:
    row = _fetch_one(
        """
        select count(*)::bigint as value
        from external_route_observations o
        join external_route_services s on s.id = o.service_id
        where s.service_slug = %s;
        """,
        (service_slug,),
        conn=conn,
    )
    return int(row["value"]) if row else 0


def _service_hop_count(service_slug: str, *, conn: psycopg.Connection | None = None) -> int:
    row = _fetch_one(
        """
        select count(distinct hs.hop_id)::bigint as value
        from external_route_service_hop_summary hs
        join external_route_services s on s.id = hs.service_id
        where s.service_slug = %s;
        """,
        (service_slug,),
        conn=conn,
    )
    return int(row["value"]) if row else 0


def _service_asn_count(service_slug: str, *, conn: psycopg.Connection | None = None) -> int:
    row = _fetch_one(
        """
        select count(distinct hs.asn)::bigint as value
        from external_route_service_hop_summary hs
        join external_route_services s on s.id = hs.service_id
        where s.service_slug = %s
          and hs.asn is not null;
        """,
        (service_slug,),
        conn=conn,
    )
    return int(row["value"]) if row else 0


def _public_trace_ip_candidates(value: str) -> list[str]:
    try:
        info = socket.getaddrinfo(value, None, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    candidates: list[str] = []
    for family, _, _, _, sockaddr in info:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        candidate = str(sockaddr[0]).split("%", 1)[0]
        if _is_public(candidate) and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _normalize_trace_target(value: Any) -> str | None:
    normalized = _normalize_target_value(value)
    if normalized is None:
        return None
    if _ip_scope(normalized) == "public":
        return normalized
    return normalized


def _sanitize_trace_hop(hop: dict[str, Any]) -> dict[str, Any]:
    return {
        "hop_number": hop.get("hop_number"),
        "hop_ip": hop.get("hop_ip"),
        "responded": hop.get("responded"),
        "rtt_avg_ms": hop.get("rtt_avg_ms"),
        "raw_line": hop.get("raw_line"),
        "ip_scope": hop.get("ip_scope") or _ip_scope(hop.get("hop_ip")),
    }


def _sanitize_trace_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": result.get("target"),
        "mode": result.get("mode"),
        "status": result.get("status"),
        "returncode": result.get("returncode"),
        "hop_count": len(result.get("hops") or []),
        "hops": [_sanitize_trace_hop(hop) for hop in result.get("hops") or []],
    }


def _select_external_route_trace_target(
    service_slug: str,
    *,
    target_override: str | None = None,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    service_row = _fetch_one(
        """
        select id, service_slug, display_name, category, description, is_ptt, enabled
        from external_route_services
        where service_slug = %s
        limit 1;
        """,
        (service_slug,),
        conn=conn,
    )
    if service_row is None:
        return {"status": "missing_service", "service": service_slug}

    def _build_target(target_value: str, *, source: str, reason: str, target_kind: str | None = None, target_row: dict[str, Any] | None = None) -> dict[str, Any]:
        normalized_value = _normalize_trace_target(target_value)
        if normalized_value is None:
            return {"status": "needs_target", "service": service_slug, "reason": "target_invalido"}
        if _ip_scope(normalized_value) == "public":
            return {
                "status": "ok",
                "service": service_slug,
                "service_row": service_row,
                "target_uid": target_row.get("target_host") if target_row else normalized_value,
                "target_host": target_row.get("target_host") if target_row else normalized_value,
                "target_resolved_ip": normalized_value,
                "target_source": source,
                "target_selection_reason": reason,
                "target_kind": target_kind or ("ip" if _ip_scope(normalized_value) == "public" else "domain"),
                "target_row": target_row,
            }
        resolved_candidates = _public_trace_ip_candidates(normalized_value)
        if not resolved_candidates:
            return {
                "status": "needs_target",
                "service": service_slug,
                "target_uid": target_row.get("target_host") if target_row else normalized_value,
                "target_host": target_row.get("target_host") if target_row else normalized_value,
                "target_source": source,
                "target_selection_reason": f"{reason}_sem_ip_public",
                "target_kind": target_kind or "domain",
                "target_row": target_row,
            }
        resolved_ip = resolved_candidates[0]
        return {
            "status": "ok",
            "service": service_slug,
            "service_row": service_row,
            "target_uid": target_row.get("target_host") if target_row else normalized_value,
            "target_host": target_row.get("target_host") if target_row else normalized_value,
            "target_resolved_ip": resolved_ip,
            "target_source": source,
            "target_selection_reason": reason,
            "target_kind": target_kind or "domain",
            "target_row": target_row,
        }

    if target_override:
        override = _normalize_trace_target(target_override)
        if override is None:
            return {"status": "needs_target", "service": service_slug, "reason": "target_override_invalido"}
        if _ip_scope(override) == "public":
            return _build_target(override, source="target_override", reason="override_public_ip", target_kind="ip")
        if _ip_scope(override) in {"private", "reserved"}:
            return {"status": "needs_target", "service": service_slug, "reason": "target_override_nao_publico"}
        return _build_target(override, source="target_override", reason="override_domain", target_kind="domain")

    target_row = _fetch_one(
        """
        select t.id, t.target_host, t.target_kind, t.target_label, t.notes
        from external_route_targets t
        join external_route_services s on s.id = t.service_id
        where s.service_slug = %s
        order by case when t.target_kind = 'ip' then 0 when t.target_kind in ('hostname', 'domain') then 1 else 2 end,
                 t.target_host asc
        limit 1;
        """,
        (service_slug,),
        conn=conn,
    )
    if target_row:
        target_host = str(target_row.get("target_host") or "").strip()
        if not target_host:
            return {"status": "needs_target", "service": service_slug, "reason": "target_vazio"}
        if target_row.get("target_kind") == "ip":
            return _build_target(target_host, source="service_target", reason="active_target_ip", target_kind="ip", target_row=target_row)
        return _build_target(target_host, source="service_target", reason="active_target_domain", target_kind=str(target_row.get("target_kind") or "domain"), target_row=target_row)

    observed_row = _fetch_one(
        """
        select o.target_host
        from external_route_observations o
        join external_route_services s on s.id = o.service_id
        where s.service_slug = %s
          and o.target_host is not null
        order by o.observed_at desc, o.id desc
        limit 1;
        """,
        (service_slug,),
        conn=conn,
    )
    if observed_row and observed_row.get("target_host"):
        return _build_target(str(observed_row["target_host"]), source="observed_destination", reason="observed_related_target", target_kind="observed")
    return {"status": "needs_target", "service": service_slug, "reason": "sem_target_valido"}


def _transition_type(
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
    *,
    is_last_edge: bool = False,
) -> str:
    previous_ip = str(previous.get("hop_ip") or "") if previous else ""
    current_ip = str(current.get("hop_ip") or "") if current else ""
    previous_scope = _ip_scope(previous_ip)
    current_scope = _ip_scope(current_ip)
    previous_role = str(previous.get("role") or previous.get("hop_role") or "unknown").lower() if previous else "unknown"
    current_role = str(current.get("role") or current.get("hop_role") or "unknown").lower() if current else "unknown"
    previous_category = str(previous.get("category") or "unknown").lower() if previous else "unknown"
    current_category = str(current.get("category") or "unknown").lower() if current else "unknown"

    if previous_ip and current_ip and previous_ip == current_ip:
        return "same_ip_repeated_next_hop"
    if not previous_ip or not current_ip:
        return "unknown_transition"
    if previous_scope == "private" and current_scope == "private":
        if previous_role in {"local_or_private", "unknown"} and current_role in {"local_or_private", "unknown"}:
            return "lan_to_cpe" if (previous.get("hop_number") or 0) <= 1 else "provider_private_to_provider_private"
        return "provider_private_to_provider_private"
    if previous_scope == "private" and current_scope == "public":
        return "cpe_to_provider_private" if (previous.get("hop_number") or 0) <= 1 else "provider_private_to_public_edge"
    if previous_scope == "public" and current_scope == "private":
        return "public_edge_to_transit"
    if current_category == "cdn" or current_role == "cdn_edge":
        return "transit_to_cdn"
    if is_last_edge and current_ip:
        if current_category == "cdn" or current_role == "cdn_edge":
            return "cdn_to_destination"
        return "transit_to_destination"
    if current_role == "destination":
        return "cdn_to_destination" if previous_category == "cdn" or previous_role == "cdn_edge" else "transit_to_destination"
    return "unknown_transition"


def _trace_edge_confidence(previous: dict[str, Any] | None, current: dict[str, Any] | None) -> str:
    if not previous or not current:
        return "unknown"
    if previous.get("confidence") == "confirmed" and current.get("confidence") == "confirmed":
        return "confirmed"
    if previous.get("confidence") in {"confirmed", "probable"} or current.get("confidence") in {"confirmed", "probable"}:
        return "probable"
    return "suggested"


def _trace_run_uid(service_slug: str) -> str:
    return f"etr-{service_slug}-{uuid.uuid4().hex[:16]}"


def _insert_trace_run(
    conn: psycopg.Connection,
    *,
    run_uid: str,
    service_uid: str,
    target_uid: str | None,
    target_host: str | None,
    target_resolved_ip: str | None,
    target_source: str,
    target_selection_reason: str | None,
    max_hops: int,
    requested_by_role: str | None,
    requested_by_username: str | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            insert into external_route_traceroute_runs (
              run_uid,
              service_uid,
              target_uid,
              target_host,
              target_resolved_ip,
              target_source,
              target_selection_reason,
              status,
              max_hops,
              requested_by_role,
              requested_by_username,
              observed_at,
              metadata
            )
            values (%s, %s, %s, %s, %s::inet, %s, %s, 'running', %s, %s, %s, now(), %s)
            on conflict (run_uid)
            do update set
              target_uid = excluded.target_uid,
              target_host = excluded.target_host,
              target_resolved_ip = excluded.target_resolved_ip,
              target_source = excluded.target_source,
              target_selection_reason = excluded.target_selection_reason,
              max_hops = excluded.max_hops,
              requested_by_role = excluded.requested_by_role,
              requested_by_username = excluded.requested_by_username,
              metadata = coalesce(external_route_traceroute_runs.metadata, '{}'::jsonb) || coalesce(excluded.metadata, '{}'::jsonb)
            returning run_uid, service_uid, target_uid, target_host, target_resolved_ip::text as target_resolved_ip, target_source, target_selection_reason, status, max_hops, metadata;
            """,
            (
                run_uid,
                service_uid,
                target_uid,
                target_host,
                target_resolved_ip,
                target_source,
                target_selection_reason,
                max_hops,
                requested_by_role,
                requested_by_username,
                _json(metadata),
            ),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("Falha ao iniciar run de traceroute externo.")
    return dict(row)


def _finalize_trace_run(
    conn: psycopg.Connection,
    *,
    run_uid: str,
    status: str,
    hop_count: int,
    unknown_count: int,
    edge_count: int,
    graph_available: bool,
    graph_url: str | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            update external_route_traceroute_runs
            set
              status = %s,
              hop_count = %s,
              unknown_count = %s,
              edge_count = %s,
              graph_available = %s,
              graph_url = %s,
              completed_at = now(),
              metadata = coalesce(metadata, '{}'::jsonb) || %s
            where run_uid = %s
            returning run_uid, service_uid, target_uid, target_host, target_resolved_ip::text as target_resolved_ip, target_source, target_selection_reason, status, hop_count, unknown_count, edge_count, graph_available, graph_url, observed_at, completed_at, metadata;
            """,
            (status, hop_count, unknown_count, edge_count, graph_available, graph_url, _json(metadata), run_uid),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("Falha ao finalizar run de traceroute externo.")
    return dict(row)


def _insert_trace_edges(
    conn: psycopg.Connection,
    *,
    run_uid: str,
    service_uid: str,
    target_uid: str | None,
    hops: list[dict[str, Any]],
    observed_at: datetime,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    ordered = sorted(hops, key=lambda item: int(item.get("hop_number") or 0))
    for index, current in enumerate(ordered):
        if index == 0:
            continue
        previous = ordered[index - 1]
        previous_ip = _normalize_target_value(previous.get("hop_ip"))
        current_ip = _normalize_target_value(current.get("hop_ip"))
        previous_scope = _ip_scope(previous_ip)
        current_scope = _ip_scope(current_ip)
        edge_uid = f"edge-{run_uid}-{index}"
        transition = _transition_type(previous, current, is_last_edge=index == len(ordered) - 1)
        confidence = _trace_edge_confidence(previous, current)
        metadata = {
            "service_uid": service_uid,
            "target_uid": target_uid,
            "run_uid": run_uid,
            "previous_hop": _sanitize_trace_hop(previous),
            "current_hop": _sanitize_trace_hop(current),
        }
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into external_route_hop_edges (
                  edge_uid,
                  service_uid,
                  target_uid,
                  traceroute_run_ref,
                  observed_at,
                  from_hop_ip,
                  from_hop_index,
                  to_hop_ip,
                  to_hop_index,
                  from_ip_type,
                  to_ip_type,
                  rtt_delta_ms,
                  transition_type,
                  confidence,
                  metadata
                )
                values (%s, %s, %s, %s, %s, %s::inet, %s, %s::inet, %s, %s, %s, %s, %s, %s, %s)
                on conflict (edge_uid)
                do update set
                  service_uid = excluded.service_uid,
                  target_uid = excluded.target_uid,
                  traceroute_run_ref = excluded.traceroute_run_ref,
                  observed_at = excluded.observed_at,
                  from_hop_ip = excluded.from_hop_ip,
                  from_hop_index = excluded.from_hop_index,
                  to_hop_ip = excluded.to_hop_ip,
                  to_hop_index = excluded.to_hop_index,
                  from_ip_type = excluded.from_ip_type,
                  to_ip_type = excluded.to_ip_type,
                  rtt_delta_ms = excluded.rtt_delta_ms,
                  transition_type = excluded.transition_type,
                  confidence = excluded.confidence,
                  metadata = coalesce(external_route_hop_edges.metadata, '{}'::jsonb) || coalesce(excluded.metadata, '{}'::jsonb)
                returning edge_uid, service_uid, target_uid, traceroute_run_ref, observed_at, from_hop_ip::text as from_hop_ip, from_hop_index, to_hop_ip::text as to_hop_ip, to_hop_index, from_ip_type, to_ip_type, rtt_delta_ms, transition_type, confidence, metadata;
                """,
                (
                    edge_uid,
                    service_uid,
                    target_uid,
                    run_uid,
                    observed_at,
                    previous_ip,
                    previous.get("hop_number"),
                    current_ip,
                    current.get("hop_number"),
                    previous_scope,
                    current_scope,
                    _rtt_delta(previous, current),
                    transition,
                    confidence,
                    _json(metadata),
                ),
            )
            row = cur.fetchone()
        if row is not None:
            edges.append(dict(row))
    return edges


def _rtt_delta(previous: dict[str, Any] | None, current: dict[str, Any] | None) -> float | None:
    previous_rtt = previous.get("rtt_avg_ms") if previous else None
    current_rtt = current.get("rtt_avg_ms") if current else None
    if previous_rtt is None or current_rtt is None:
        return None
    try:
        return round(float(current_rtt) - float(previous_rtt), 3)
    except (TypeError, ValueError):
        return None


def _service_trace_edges_rows(service_slug: str, *, limit: int = 100, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          edge_uid,
          service_uid,
          target_uid,
          traceroute_run_ref,
          observed_at,
          from_hop_ip::text as from_hop_ip,
          from_hop_index,
          to_hop_ip::text as to_hop_ip,
          to_hop_index,
          from_ip_type,
          to_ip_type,
          rtt_delta_ms,
          transition_type,
          confidence,
          metadata
        from external_route_hop_edges
        where service_uid = %s
        order by observed_at desc, edge_uid desc
        limit %s;
        """,
        (service_slug, limit),
        conn=conn,
    )


def _trace_run_graph(run_uid: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any]:
    run_row = _fetch_one(
        """
        select
          run_uid,
          service_uid,
          target_uid,
          target_host,
          target_resolved_ip::text as target_resolved_ip,
          target_source,
          target_selection_reason,
          status,
          max_hops,
          hop_count,
          unknown_count,
          edge_count,
          graph_available,
          graph_url,
          observed_at,
          completed_at,
          metadata
        from external_route_traceroute_runs
        where run_uid = %s
        limit 1;
        """,
        (run_uid,),
        conn=conn,
    )
    if run_row is None:
        return {"available": False, "reason": "no_trace_run"}
    metadata = run_row.get("metadata") if isinstance(run_row.get("metadata"), dict) else {}
    trace_result = metadata.get("trace_result") if isinstance(metadata, dict) else {}
    hops = trace_result.get("hops") if isinstance(trace_result, dict) else []
    nodes = []
    ordered_hops = sorted(hops or [], key=lambda item: int(item.get("hop_number") or 0))
    for hop in ordered_hops:
        hop_ip = _normalize_target_value(hop.get("hop_ip"))
        hop_row = _hop_row_for_ip(hop_ip, conn=conn) if hop_ip else None
        nodes.append(
            {
                "hop": hop.get("hop_number"),
                "ip": hop_ip,
                "rtt_ms": hop.get("rtt_avg_ms"),
                "role": hop_row.get("role") if hop_row else ("private" if _ip_scope(hop_ip) != "public" else "unknown"),
                "confidence": hop_row.get("confidence") if hop_row else ("confirmed" if _ip_scope(hop_ip) != "public" else "unknown"),
                "evidence_source": "external_route_trace",
                "raw_line": hop.get("raw_line"),
            }
        )
    edges = _fetch_all(
        """
        select
          edge_uid,
          from_hop_ip::text as from_hop_ip,
          from_hop_index,
          to_hop_ip::text as to_hop_ip,
          to_hop_index,
          from_ip_type,
          to_ip_type,
          rtt_delta_ms,
          transition_type,
          confidence
        from external_route_hop_edges
        where traceroute_run_ref = %s
        order by observed_at asc, edge_uid asc;
        """,
        (run_uid,),
        conn=conn,
    )
    return {
        "available": bool(nodes),
        "run_uid": run_uid,
        "service_uid": run_row.get("service_uid"),
        "target_uid": run_row.get("target_uid"),
        "target_host": run_row.get("target_host"),
        "target_resolved_ip": run_row.get("target_resolved_ip"),
        "status": run_row.get("status"),
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_hops": run_row.get("hop_count"),
            "unknown_count": run_row.get("unknown_count"),
            "edge_count": run_row.get("edge_count"),
            "graph_available": run_row.get("graph_available"),
        },
    }


def _hop_confidence_reason(hop_row: dict[str, Any] | None) -> str:
    if not hop_row:
        return "unknown"
    metadata = hop_row.get("metadata") if isinstance(hop_row.get("metadata"), dict) else {}
    sources = hop_row.get("evidence_sources") if isinstance(hop_row.get("evidence_sources"), dict) else {}
    reasons: list[str] = []
    if metadata.get("classification_source"):
        reasons.append(str(metadata.get("classification_source")))
    if "bgp" in sources:
        reasons.append("bgp_local")
    if "rdap" in sources:
        reasons.append("rdap")
    if "asn" in sources:
        reasons.append("asn_enrichment")
    if "rdns" in sources:
        reasons.append("reverse_dns")
    if not reasons and hop_row.get("category") == "private":
        reasons.append("private_path")
    if not reasons:
        reasons.append("path_only")
    return "+".join(dict.fromkeys(reasons))


def _sample_paths_for_hop(ip: str, *, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    observations = _fetch_all(
        """
        select
          o.source_ref,
          o.source_kind,
          o.hop_number,
          o.target_host,
          o.observed_at,
          r.service_uid,
          r.target_uid,
          r.target_host as run_target_host,
          r.target_resolved_ip::text as target_resolved_ip,
          r.metadata
        from external_route_observations o
        join external_route_hops h on h.id = o.hop_id
        left join external_route_traceroute_runs r on r.run_uid = o.source_ref
        where h.hop_ip = %s::inet
          and o.source_kind = 'external_route_trace'
        order by o.observed_at desc, o.id desc
        limit 10;
        """,
        (ip,),
        conn=conn,
    )
    samples: list[dict[str, Any]] = []
    for row in observations:
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        trace_result = metadata.get("trace_result") if isinstance(metadata, dict) else {}
        trace_hops = trace_result.get("hops") if isinstance(trace_result, dict) else []
        path = []
        hop_index = None
        for item in trace_hops or []:
            hop_ip = _normalize_target_value(item.get("hop_ip"))
            path.append(hop_ip)
            if hop_ip == ip:
                hop_index = int(item.get("hop_number") or 0)
        samples.append(
            {
                "run_uid": row.get("source_ref"),
                "service_uid": row.get("service_uid"),
                "target_uid": row.get("target_uid"),
                "target_host": row.get("run_target_host") or row.get("target_host"),
                "observed_at": row.get("observed_at"),
                "hop_number": row.get("hop_number"),
                "hop_index": hop_index,
                "path": [hop for hop in path if hop],
            }
        )
    return samples


def get_external_hop_context(ip: str) -> dict[str, Any]:
    normalized = _normalize_target_value(ip)
    if normalized is None:
        raise ValueError("IP inválido.")
    hop_row = _hop_row_for_ip(normalized)
    if hop_row is None:
        return {"status": "missing", "hop": None}
    observations = _fetch_all(
        """
        select
          o.observation_uid,
          o.service_id,
          s.service_slug,
          s.display_name,
          o.target_id,
          o.target_host,
          o.source_kind,
          o.source_ref,
          o.source_key,
          o.hop_number,
          o.hop_role,
          o.observed_at
        from external_route_observations o
        join external_route_hops h on h.id = o.hop_id
        join external_route_services s on s.id = o.service_id
        where h.hop_ip = %s::inet
        order by o.observed_at desc, o.id desc
        limit 50;
        """,
        (normalized,),
    )
    services = sorted({str(row.get("service_slug")) for row in observations if row.get("service_slug")})
    edges_in = _fetch_all(
        """
        select
          edge_uid,
          service_uid,
          target_uid,
          traceroute_run_ref,
          observed_at,
          from_hop_ip::text as from_hop_ip,
          from_hop_index,
          to_hop_ip::text as to_hop_ip,
          to_hop_index,
          from_ip_type,
          to_ip_type,
          rtt_delta_ms,
          transition_type,
          confidence,
          metadata
        from external_route_hop_edges
        where to_hop_ip = %s::inet
        order by observed_at desc, edge_uid desc
        limit 25;
        """,
        (normalized,),
    )
    edges_out = _fetch_all(
        """
        select
          edge_uid,
          service_uid,
          target_uid,
          traceroute_run_ref,
          observed_at,
          from_hop_ip::text as from_hop_ip,
          from_hop_index,
          to_hop_ip::text as to_hop_ip,
          to_hop_index,
          from_ip_type,
          to_ip_type,
          rtt_delta_ms,
          transition_type,
          confidence,
          metadata
        from external_route_hop_edges
        where from_hop_ip = %s::inet
        order by observed_at desc, edge_uid desc
        limit 25;
        """,
        (normalized,),
    )
    previous_hops = sorted({str(row.get("from_hop_ip")) for row in edges_in if row.get("from_hop_ip")})
    next_hops = sorted({str(row.get("to_hop_ip")) for row in edges_out if row.get("to_hop_ip")})
    confidence_reason = _hop_confidence_reason(hop_row)
    sample_paths = _sample_paths_for_hop(normalized)
    return {
        "status": "ok",
        "hop": {
            "hop_ip": hop_row.get("hop_ip"),
            "reverse_dns": hop_row.get("reverse_dns"),
            "asn": hop_row.get("asn"),
            "organization": hop_row.get("organization"),
            "country": hop_row.get("country"),
            "category": hop_row.get("category"),
            "role": hop_row.get("role"),
            "confidence": hop_row.get("confidence"),
            "confidence_rank": hop_row.get("confidence_rank"),
            "source_priority": hop_row.get("source_priority"),
            "observation_count": hop_row.get("observation_count"),
            "first_seen_at": hop_row.get("first_seen_at"),
            "last_seen_at": hop_row.get("last_seen_at"),
            "metadata": hop_row.get("metadata"),
        },
        "services": services,
        "observations": observations,
        "previous_hops": previous_hops,
        "next_hops": next_hops,
        "edges_in": edges_in,
        "edges_out": edges_out,
        "sample_paths": sample_paths,
        "classification": {
            "category": hop_row.get("category"),
            "role": hop_row.get("role"),
            "confidence": hop_row.get("confidence"),
            "confidence_rank": hop_row.get("confidence_rank"),
        },
        "confidence_reason": confidence_reason,
    }


def run_external_route_service_trace(
    service: str,
    *,
    confirm: bool = False,
    target_override: str | None = None,
    max_hops: int = 20,
    requested_by_role: str | None = None,
    requested_by_username: str | None = None,
    run_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not confirm:
        raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
    service_slug = _normalize_slug(service)
    max_hops = max(1, min(int(max_hops or 20), 20))
    with get_connection() as conn:
        selection = _select_external_route_trace_target(service_slug, target_override=target_override, conn=conn)
        if selection.get("status") != "ok":
            return {
                "status": "needs_target",
                "service": service_slug,
                "reason": selection.get("reason") or "sem_target",
                "target": None,
                "run_uid": None,
                "hops_count": 0,
                "edges_count": 0,
                "unknown_count": 0,
                "graph_url": None,
                "available_targets": _service_target_hosts(service_slug, conn=conn) if _service_id(service_slug, conn=conn) else [],
            }

        run_uid = _trace_run_uid(service_slug)
        target_resolved_ip = str(selection.get("target_resolved_ip") or "")
        target_host = str(selection.get("target_host") or "")
        observed_at = _now()
        trace_result = run_traceroute(target_resolved_ip, max_hops=max_hops)
        trace_result.setdefault("measured_at", observed_at)
        sanitized_trace_result = _sanitize_trace_result(trace_result)
        run_row = _insert_trace_run(
            conn,
            run_uid=run_uid,
            service_uid=service_slug,
            target_uid=str(selection.get("target_uid") or target_host or target_resolved_ip),
            target_host=target_host,
            target_resolved_ip=target_resolved_ip,
            target_source=str(selection.get("target_source") or "service_target"),
            target_selection_reason=str(selection.get("target_selection_reason") or "selected"),
            max_hops=max_hops,
            requested_by_role=requested_by_role,
            requested_by_username=requested_by_username,
            metadata={
                "selection": {
                    "status": selection.get("status"),
                    "target_kind": selection.get("target_kind"),
                    "target_source": selection.get("target_source"),
                    "target_selection_reason": selection.get("target_selection_reason"),
                    "target_uid": selection.get("target_uid"),
                    "target_host": target_host,
                    "target_resolved_ip": target_resolved_ip,
                },
                "trace_result": sanitized_trace_result,
                **({"route_learning": _safe_json(run_metadata)} if run_metadata else {}),
            },
        )
        service_count, hop_count, unknown_count = _emit_observations_for_measurement(
            conn,
            service_slug=service_slug,
            source_kind="external_route_trace",
            source_ref=run_uid,
            target_host=target_host,
            target_kind=str(selection.get("target_kind") or "domain"),
            hops=[{**hop, "traceroute_run_ref": run_uid} for hop in trace_result.get("hops") or []],
            measured_at=observed_at,
            target_hint=str(selection.get("target_selection_reason") or ""),
        )
        edges = _insert_trace_edges(
            conn,
            run_uid=run_uid,
            service_uid=service_slug,
            target_uid=str(selection.get("target_uid") or target_host or target_resolved_ip),
            hops=[{**hop, "traceroute_run_ref": run_uid} for hop in trace_result.get("hops") or []],
            observed_at=observed_at,
        )
        _build_summary_from_observations(conn, service_id=_service_id(service_slug, conn=conn))
        graph_url = f"/external-routes/services/{service_slug}/trace-runs/{run_uid}/graph" if hop_count > 0 else None
        final_status = "ok" if trace_result.get("status") == "SUCCESS" and hop_count > 0 else "partial" if hop_count > 0 else "failed"
        _finalize_trace_run(
            conn,
            run_uid=run_uid,
            status=final_status,
            hop_count=hop_count,
            unknown_count=unknown_count,
            edge_count=len(edges),
            graph_available=bool(graph_url),
            graph_url=graph_url,
            metadata={
                "final_status": final_status,
                "service_count": service_count,
                "hop_count": hop_count,
                "unknown_count": unknown_count,
                "edges_count": len(edges),
                **({"route_learning": _safe_json(run_metadata)} if run_metadata else {}),
            },
        )
        conn.commit()

    service_summary = get_service_route_summary(service_slug)
    return {
        "status": final_status,
        "service": service_slug,
        "run_uid": run_uid,
        "target": {
            "target_uid": str(selection.get("target_uid") or target_host or target_resolved_ip),
            "target_host": target_host,
            "target_resolved_ip": target_resolved_ip,
            "target_source": selection.get("target_source"),
            "target_selection_reason": selection.get("target_selection_reason"),
            "target_kind": selection.get("target_kind"),
        },
        "trace": sanitized_trace_result,
        "hops_count": hop_count,
        "edges_count": len(edges),
        "unknown_count": unknown_count,
        "graph_url": graph_url,
        "service_summary": service_summary.get("summary") if isinstance(service_summary, dict) else None,
        "service_hops": service_summary.get("hops") if isinstance(service_summary, dict) else [],
        "edges": edges,
    }


def run_cloudflare_dedicated_trace(
    *,
    confirm: bool,
    plan_uid: str,
    target: str,
    ip_family: str | None = None,
    requested_by_role: str | None = None,
    requested_by_username: str | None = None,
) -> dict[str, Any]:
    if not confirm:
        raise ValueError('Confirmação explícita obrigatória: envie {"confirm": true}.')
    normalized_plan_uid = str(plan_uid or "").strip()
    normalized_ip_family = str(ip_family or "").strip().lower() or None
    normalized_target = _normalize_trace_target(target)
    if normalized_target is None:
        raise ValueError("Target inválido.")
    plan_allowlist = {
        "plan-cloudflare-dedicated-trace-v1": {
            "targets": {"1.1.1.1", "cloudflare.com"},
            "ip_family": None,
        },
        "plan-cloudflare-ipv4-post-nat-ipv6-change-v1": {
            "targets": {"1.1.1.1"},
            "ip_family": "ipv4",
        },
        "plan-cloudflare-ipv6-post-nat-ipv6-change-v1": {
            "targets": {"2606:4700:4700::1111"},
            "ip_family": "ipv6",
        },
    }
    plan_policy = plan_allowlist.get(normalized_plan_uid)
    if plan_policy is None:
        raise ValueError("plan_uid inválido para a execução dedicada Cloudflare.")
    if normalized_target not in plan_policy["targets"]:
        raise ValueError("Target fora da allowlist desta rodada.")
    if plan_policy["ip_family"] and normalized_ip_family and normalized_ip_family != plan_policy["ip_family"]:
        raise ValueError("ip_family incompatível com o plano informado.")
    if plan_policy["ip_family"] and not normalized_ip_family:
        normalized_ip_family = plan_policy["ip_family"]
    if _ip_scope(normalized_target) in {"private", "reserved"}:
        raise ValueError("Target bloqueado pela política ativa: apenas IP público permitido.")
    resolved_candidates = _public_trace_ip_candidates(normalized_target)
    if not resolved_candidates:
        raise ValueError("Target não resolveu para IP público permitido.")
    resolved_target = resolved_candidates[0]

    ping_summary: dict[str, Any] = {}
    ping_error: str | None = None
    try:
        ping_row = run_ping(
            resolved_target,
            count=3,
            timeout=3,
            target_label=f"route-learning:{normalized_target}",
            source_label="route-learning-cloudflare",
        )
        ping_summary = {
            "target": str(ping_row.get("target")) if ping_row.get("target") is not None else resolved_target,
            "target_label": ping_row.get("target_label"),
            "source_label": ping_row.get("source_label"),
            "packets_sent": ping_row.get("packets_sent"),
            "packets_received": ping_row.get("packets_received"),
            "packet_loss_percent": ping_row.get("packet_loss_percent"),
            "rtt_avg_ms": ping_row.get("rtt_avg_ms"),
            "status": ping_row.get("status"),
            "measured_at": ping_row.get("measured_at"),
        }
    except Exception as exc:
        ping_error = str(exc)

    run_metadata = {
        "execution_type": "dedicated_trace_run",
        "plan_uid": normalized_plan_uid,
        "target": normalized_target,
        "ip_family": normalized_ip_family,
        "resolved_target": resolved_target,
        "active_action_confirmed": True,
        "confirmed_by_role": requested_by_role,
        "confirmed_by_username": requested_by_username,
        "ping_summary": _safe_json(ping_summary),
        "ping_error": ping_error,
    }

    trace_result = run_external_route_service_trace(
        "cloudflare",
        confirm=True,
        target_override=normalized_target,
        max_hops=20,
        requested_by_role=requested_by_role,
        requested_by_username=requested_by_username,
        run_metadata=run_metadata,
    )
    traceroute_summary = {
        "status": trace_result.get("status"),
        "run_uid": trace_result.get("run_uid"),
        "hops_count": trace_result.get("hops_count"),
        "edges_count": trace_result.get("edges_count"),
        "unknown_count": trace_result.get("unknown_count"),
        "graph_url": trace_result.get("graph_url"),
    }
    if ping_error:
        status = "partial" if trace_result.get("status") in {"ok", "partial"} else "failed"
    else:
        status = "executed" if trace_result.get("status") == "ok" else "partial" if trace_result.get("status") == "partial" else "failed"
    if ping_error and not ping_summary:
        status = "partial" if trace_result.get("status") in {"ok", "partial"} else "failed"
    return {
        "status": status,
        "service": "cloudflare",
        "plan_uid": normalized_plan_uid,
        "target": normalized_target,
        "ip_family": normalized_ip_family,
        "resolved_target": resolved_target,
        "active_action_executed": True,
        "dedicated_run_uid": trace_result.get("run_uid"),
        "ping_summary": ping_summary,
        "ping_error": ping_error,
        "traceroute_summary": traceroute_summary,
        "persisted": bool(trace_result.get("run_uid")),
        "route_learning_visual_endpoint": "/route-learning/sessions/demo/cloudflare/visual",
        "comparison_endpoint": "/route-learning/sessions/demo/cloudflare/learning-comparison-plan",
        "operator_message": "Run dedicada Cloudflare executada com confirmação explícita de admin." if trace_result.get("run_uid") else "A execução não persistiu evidência dedicada.",
        "limitations": [
            *(
                ["ping_failed"] if ping_error else []
            ),
            *(
                ["traceroute_partial"] if trace_result.get("status") == "partial" else []
            ),
        ],
        "trace_result": trace_result,
    }


def get_external_route_trace_graph(run_uid: str) -> dict[str, Any]:
    with get_connection() as conn:
        return _trace_run_graph(run_uid, conn=conn)


def list_external_route_edges(service: str, *, limit: int = 100) -> list[dict[str, Any]]:
    service_slug = _normalize_slug(service)
    with get_connection() as conn:
        return _service_trace_edges_rows(service_slug, limit=limit, conn=conn)
def _seed_hop_sources() -> tuple[list[dict[str, Any]], list[str]]:
    return [], []


def _base_observation_metadata(source_kind: str, source_ref: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    safe = {
        "source_kind": source_kind,
        "source_ref": source_ref,
    }
    if extra:
        safe.update({key: _safe_json(value) for key, value in extra.items() if value is not None})
    return safe


def _reverse_dns_safe(ip_value: str) -> str | None:
    if not _is_public(ip_value):
        return None
    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip_value)
        host = _normalize_text(host, max_chars=240)
        return host.lower() if host else None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)


def _public_hop_enrichment(ip_value: str, *, allow_external: bool = True, conn: psycopg.Connection | None = None) -> dict[str, Any]:
    ip_value = str(ipaddress.ip_address(ip_value))
    bgp_row: dict[str, Any] | None = None
    try:
        bgp_row = lookup_bgp_by_ip(ip_value)
    except Exception:
        bgp_row = None

    ip_cache = get_external_ip_enrichment(ip_value, conn=conn)
    if ip_cache is None and allow_external:
        try:
            ip_cache = enrich_ip(ip_value, force_refresh=False, allow_external=True, conn=conn)
        except Exception:
            ip_cache = None

    asn_value = None
    organization = None
    country = None
    source_priority = "unknown"
    evidence_sources: dict[str, Any] = {}
    confidence = "unknown"
    confidence_rank = 0

    if bgp_row:
        asn_value = bgp_row.get("origin_asn")
        source_priority = "bgp_local"
        confidence = "confirmed" if asn_value is not None else "probable"
        confidence_rank = _confidence_rank(confidence)
        evidence_sources["bgp"] = {
            "matched_prefix": bgp_row.get("matched_prefix"),
            "origin_asn": bgp_row.get("origin_asn"),
            "origin_type": bgp_row.get("origin_type"),
            "route_count": bgp_row.get("match_route_count"),
            "peer_count": bgp_row.get("peer_count"),
        }

    if ip_cache:
        if asn_value is None and ip_cache.get("asn") is not None:
            asn_value = ip_cache.get("asn")
        organization = ip_cache.get("organization_name") or ip_cache.get("organization")
        country = ip_cache.get("country")
        source_priority = "rdap" if source_priority == "unknown" else f"{source_priority}+rdap"
        evidence_sources["rdap"] = {
            "source": ip_cache.get("source"),
            "network_name": ip_cache.get("network_name"),
            "confidence": ip_cache.get("confidence"),
        }
        confidence = _better_confidence(confidence, str(ip_cache.get("confidence") or "suggested"))
        confidence_rank = max(confidence_rank, _confidence_rank(ip_cache.get("confidence")))

    if asn_value is not None:
        try:
            asn_enrichment = get_external_asn_enrichment(int(asn_value), conn=conn)
            if asn_enrichment is None and allow_external:
                asn_enrichment = enrich_asn(int(asn_value), force_refresh=False, allow_external=True, conn=conn)
        except Exception:
            asn_enrichment = None
        if asn_enrichment:
            organization = organization or asn_enrichment.get("organization_name")
            country = country or asn_enrichment.get("country")
            evidence_sources["asn"] = {
                "organization_name": asn_enrichment.get("organization_name"),
                "country": asn_enrichment.get("country"),
                "network_name": asn_enrichment.get("network_name"),
                "source": asn_enrichment.get("source"),
            }
            confidence = _better_confidence(confidence, str(asn_enrichment.get("confidence") or "suggested"))
            confidence_rank = max(confidence_rank, _confidence_rank(asn_enrichment.get("confidence")))
            source_priority = f"{source_priority}+asn" if source_priority != "unknown" else "asn"

    reverse_dns = _reverse_dns_safe(ip_value)
    if reverse_dns:
        evidence_sources["rdns"] = {"reverse_dns": reverse_dns}
        source_priority = f"{source_priority}+rdns" if source_priority != "unknown" else "rdns"
        confidence = _better_confidence(confidence, "probable")
        confidence_rank = max(confidence_rank, _confidence_rank("probable"))

    role = "unknown"
    category = "unknown"
    if _is_ix_context(reverse_dns, organization, ip_cache.get("network_name") if ip_cache else None):
        role = "ix"
        category = "ix"
        confidence = _better_confidence(confidence, "probable")
        confidence_rank = max(confidence_rank, _confidence_rank("probable"))
    elif organization:
        org_lower = organization.lower()
        if "cloudflare" in org_lower:
            category = "cdn"
            role = "cdn_edge"
        elif any(term in org_lower for term in ("google", "youtube", "gstatic")):
            category = "cloud"
            role = "provider_edge"
        elif any(term in org_lower for term in ("meta", "facebook", "instagram", "whatsapp")):
            category = "social"
            role = "provider_edge"
        elif any(term in org_lower for term in ("netflix", "nflx")):
            category = "video"
            role = "provider_edge"
        else:
            category = "transit"
            role = "transit"
    elif reverse_dns:
        role = "transit"
        category = "transit"

    return {
        "hop_ip": ip_value,
        "reverse_dns": reverse_dns,
        "asn": int(asn_value) if asn_value is not None else None,
        "organization": organization,
        "country": country,
        "category": category,
        "role": role,
        "confidence": confidence,
        "confidence_rank": confidence_rank,
        "source_priority": source_priority,
        "evidence_sources": evidence_sources,
        "metadata": {
            "ip_scope": _ip_scope(ip_value),
            "enriched": True,
        },
    }


def _private_hop_enrichment(ip_value: str) -> dict[str, Any]:
    return {
        "hop_ip": ip_value,
        "reverse_dns": None,
        "asn": None,
        "organization": None,
        "country": None,
        "category": "private",
        "role": "local_or_private",
        "confidence": "confirmed",
        "confidence_rank": _confidence_rank("confirmed"),
        "source_priority": "private",
        "evidence_sources": {"scope": _ip_scope(ip_value), "classification_source": "inferred_from_path"},
        "metadata": {
            "ip_scope": _ip_scope(ip_value),
            "enriched": False,
            "classification_source": "inferred_from_path",
        },
    }


def _hop_enrichment(ip_value: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any]:
    if not _is_public(ip_value):
        return _private_hop_enrichment(ip_value)
    return _public_hop_enrichment(ip_value, conn=conn)


def _upsert_hop_row(
    conn: psycopg.Connection,
    *,
    hop_data: dict[str, Any],
    seen_at: datetime | None = None,
    observation_count: int = 1,
) -> dict[str, Any]:
    ip_value = str(ipaddress.ip_address(str(hop_data["hop_ip"])))
    seen = seen_at or _now()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            insert into external_route_hops (
              hop_ip,
              reverse_dns,
              asn,
              organization,
              country,
              category,
              role,
              confidence,
              confidence_rank,
              source_priority,
              evidence_sources,
              observation_count,
              first_seen_at,
              last_seen_at,
              metadata
            )
            values (%s::inet, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (hop_ip)
            do update set
              reverse_dns = coalesce(excluded.reverse_dns, external_route_hops.reverse_dns),
              asn = coalesce(excluded.asn, external_route_hops.asn),
              organization = coalesce(excluded.organization, external_route_hops.organization),
              country = coalesce(excluded.country, external_route_hops.country),
              category = case
                when external_route_hops.category = 'unknown' then excluded.category
                when excluded.category = 'unknown' then external_route_hops.category
                else external_route_hops.category
              end,
              role = case
                when external_route_hops.role = 'unknown' then excluded.role
                when excluded.role = 'unknown' then external_route_hops.role
                else external_route_hops.role
              end,
              confidence = case
                when excluded.confidence_rank >= external_route_hops.confidence_rank then excluded.confidence
                else external_route_hops.confidence
              end,
              confidence_rank = greatest(external_route_hops.confidence_rank, excluded.confidence_rank),
              source_priority = case
                when external_route_hops.source_priority is null then excluded.source_priority
                when excluded.source_priority is null then external_route_hops.source_priority
                when external_route_hops.source_priority = excluded.source_priority then external_route_hops.source_priority
                else external_route_hops.source_priority || '+' || excluded.source_priority
              end,
              evidence_sources = coalesce(external_route_hops.evidence_sources, '{}'::jsonb) || coalesce(excluded.evidence_sources, '{}'::jsonb),
              observation_count = external_route_hops.observation_count + excluded.observation_count,
              first_seen_at = least(external_route_hops.first_seen_at, excluded.first_seen_at),
              last_seen_at = greatest(external_route_hops.last_seen_at, excluded.last_seen_at),
              metadata = coalesce(external_route_hops.metadata, '{}'::jsonb) || coalesce(excluded.metadata, '{}'::jsonb),
              updated_at = now()
            returning
              id,
              hop_ip::text as hop_ip,
              reverse_dns,
              asn,
              organization,
              country,
              category,
              role,
              confidence,
              confidence_rank,
              source_priority,
              evidence_sources,
              observation_count,
              first_seen_at,
              last_seen_at,
              metadata;
            """,
            (
                ip_value,
                hop_data.get("reverse_dns"),
                hop_data.get("asn"),
                hop_data.get("organization"),
                hop_data.get("country"),
                hop_data.get("category") or "unknown",
                hop_data.get("role") or "unknown",
                hop_data.get("confidence") or "unknown",
                int(hop_data.get("confidence_rank") or 0),
                hop_data.get("source_priority"),
                _json(hop_data.get("evidence_sources") or {}),
                observation_count,
                seen,
                seen,
                _json(hop_data.get("metadata") or {}),
            ),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("Falha ao persistir hop externo.")
    return dict(row)


def _upsert_observation_row(
    conn: psycopg.Connection,
    *,
    service_id: int,
    service_slug: str,
    target_id: int | None,
    target_host: str | None,
    hop_row: dict[str, Any],
    source_kind: str,
    source_ref: str,
    source_key: str,
    hop_number: int | None,
    hop_role: str | None,
    seen_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    seen = seen_at or _now()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            insert into external_route_observations (
              observation_uid,
              service_id,
              target_id,
              hop_id,
              target_host,
              source_kind,
              source_ref,
              source_key,
              hop_number,
              hop_role,
              observed_at,
              metadata
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (observation_uid)
            do update set
              target_id = coalesce(excluded.target_id, external_route_observations.target_id),
              hop_id = coalesce(excluded.hop_id, external_route_observations.hop_id),
              target_host = coalesce(excluded.target_host, external_route_observations.target_host),
              hop_number = coalesce(excluded.hop_number, external_route_observations.hop_number),
              hop_role = coalesce(excluded.hop_role, external_route_observations.hop_role),
              observed_at = greatest(external_route_observations.observed_at, excluded.observed_at),
              metadata = coalesce(external_route_observations.metadata, '{}'::jsonb) || coalesce(excluded.metadata, '{}'::jsonb)
            returning
              id,
              observation_uid,
              service_id,
              target_id,
              hop_id,
              target_host,
              source_kind,
              source_ref,
              source_key,
              hop_number,
              hop_role,
              observed_at,
              metadata;
            """,
            (
                source_key,
                service_id,
                target_id,
                hop_row.get("id"),
                target_host,
                source_kind,
                source_ref,
                source_key,
                hop_number,
                hop_role,
                seen,
                _json(metadata or {"service_slug": service_slug}),
            ),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("Falha ao persistir observação externa.")
    return dict(row)


def _upsert_service_hop_summary_row(
    conn: psycopg.Connection,
    *,
    service_id: int,
    hop_id: int,
    hop_ip: str,
    occurrence_count: int,
    target_count: int,
    first_seen_at: datetime,
    last_seen_at: datetime,
    min_hop_number: int | None,
    max_hop_number: int | None,
    asn: int | None,
    organization: str | None,
    country: str | None,
    category: str,
    role: str,
    confidence: str,
    confidence_rank: int,
    source_priority: str | None,
    target_hosts: list[str],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            insert into external_route_service_hop_summary (
              service_id,
              hop_id,
              hop_ip,
              occurrence_count,
              target_count,
              first_seen_at,
              last_seen_at,
              min_hop_number,
              max_hop_number,
              asn,
              organization,
              country,
              category,
              role,
              confidence,
              confidence_rank,
              source_priority,
              target_hosts,
              metadata
            )
            values (%s, %s, %s::inet, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (service_id, hop_id)
            do update set
              hop_ip = excluded.hop_ip,
              occurrence_count = excluded.occurrence_count,
              target_count = excluded.target_count,
              first_seen_at = least(external_route_service_hop_summary.first_seen_at, excluded.first_seen_at),
              last_seen_at = greatest(external_route_service_hop_summary.last_seen_at, excluded.last_seen_at),
              min_hop_number = case
                when external_route_service_hop_summary.min_hop_number is null then excluded.min_hop_number
                when excluded.min_hop_number is null then external_route_service_hop_summary.min_hop_number
                else least(external_route_service_hop_summary.min_hop_number, excluded.min_hop_number)
              end,
              max_hop_number = case
                when external_route_service_hop_summary.max_hop_number is null then excluded.max_hop_number
                when excluded.max_hop_number is null then external_route_service_hop_summary.max_hop_number
                else greatest(external_route_service_hop_summary.max_hop_number, excluded.max_hop_number)
              end,
              asn = coalesce(excluded.asn, external_route_service_hop_summary.asn),
              organization = coalesce(excluded.organization, external_route_service_hop_summary.organization),
              country = coalesce(excluded.country, external_route_service_hop_summary.country),
              category = case
                when external_route_service_hop_summary.category = 'unknown' then excluded.category
                when excluded.category = 'unknown' then external_route_service_hop_summary.category
                else external_route_service_hop_summary.category
              end,
              role = case
                when external_route_service_hop_summary.role = 'unknown' then excluded.role
                when excluded.role = 'unknown' then external_route_service_hop_summary.role
                else external_route_service_hop_summary.role
              end,
              confidence = case
                when excluded.confidence_rank >= external_route_service_hop_summary.confidence_rank then excluded.confidence
                else external_route_service_hop_summary.confidence
              end,
              confidence_rank = greatest(external_route_service_hop_summary.confidence_rank, excluded.confidence_rank),
              source_priority = case
                when external_route_service_hop_summary.source_priority is null then excluded.source_priority
                when excluded.source_priority is null then external_route_service_hop_summary.source_priority
                when external_route_service_hop_summary.source_priority = excluded.source_priority then external_route_service_hop_summary.source_priority
                else external_route_service_hop_summary.source_priority || '+' || excluded.source_priority
              end,
              target_hosts = (
                select coalesce(jsonb_agg(distinct value), '[]'::jsonb)
                from (
                    select jsonb_array_elements_text(coalesce(external_route_service_hop_summary.target_hosts, '[]'::jsonb)) as value
                    union
                    select jsonb_array_elements_text(coalesce(excluded.target_hosts, '[]'::jsonb)) as value
                ) items
              ),
              metadata = coalesce(external_route_service_hop_summary.metadata, '{}'::jsonb) || coalesce(excluded.metadata, '{}'::jsonb),
              updated_at = now()
            returning
              id,
              service_id,
              hop_id,
              hop_ip::text as hop_ip,
              occurrence_count,
              target_count,
              first_seen_at,
              last_seen_at,
              min_hop_number,
              max_hop_number,
              asn,
              organization,
              country,
              category,
              role,
              confidence,
              confidence_rank,
              source_priority,
              target_hosts,
              metadata;
            """,
            (
                service_id,
                hop_id,
                hop_ip,
                occurrence_count,
                target_count,
                first_seen_at,
                last_seen_at,
                min_hop_number,
                max_hop_number,
                asn,
                organization,
                country,
                category,
                role,
                confidence,
                confidence_rank,
                source_priority,
                _json(target_hosts),
                _json(metadata or {}),
            ),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("Falha ao persistir resumo externo.")
    return dict(row)


def seed_external_services() -> dict[str, Any]:
    inserted_services = 0
    inserted_targets = 0
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            for service in SERVICE_SEEDS:
                cur.execute(
                    """
                    insert into external_route_services (
                      service_slug,
                      display_name,
                      category,
                      description,
                      is_ptt,
                      enabled
                    )
                    values (%s, %s, %s, %s, %s, true)
                    on conflict (service_slug)
                    do update set
                      display_name = excluded.display_name,
                      category = excluded.category,
                      description = excluded.description,
                      is_ptt = excluded.is_ptt,
                      enabled = true,
                      updated_at = now()
                    returning (xmax = 0) as inserted, id;
                    """,
                    (
                        service["service_slug"],
                        service["display_name"],
                        service["category"],
                        service["description"],
                        bool(service["is_ptt"]),
                    ),
                )
                row = cur.fetchone()
                if row and row["inserted"]:
                    inserted_services += 1

            service_map = _service_row_map(conn)
            for target in SERVICE_TARGET_SEEDS:
                service_row = service_map.get(target["service_slug"])
                if service_row is None:
                    continue
                cur.execute(
                    """
                    insert into external_route_targets (
                      service_id,
                      target_host,
                      target_kind,
                      target_label,
                      notes
                    )
                    values (%s, %s, %s, %s, %s)
                    on conflict (service_id, target_host)
                    do update set
                      target_kind = excluded.target_kind,
                      target_label = excluded.target_label,
                      notes = excluded.notes,
                      updated_at = now()
                    returning (xmax = 0) as inserted;
                    """,
                    (
                        service_row["id"],
                        target["target_host"],
                        target["target_kind"],
                        target["target_label"],
                        "seed",
                    ),
                )
                row = cur.fetchone()
                if row and row["inserted"]:
                    inserted_targets += 1
        conn.commit()
    return {
        "status": "ok",
        "seeded_services": [service["service_slug"] for service in SERVICE_SEEDS],
        "inserted_services": inserted_services,
        "inserted_targets": inserted_targets,
    }


def list_external_services() -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          s.id,
          s.service_slug,
          s.display_name,
          s.category,
          s.description,
          s.is_ptt,
          s.enabled,
          count(distinct t.id)::bigint as target_count,
          count(distinct o.id)::bigint as observation_count,
          count(distinct hs.hop_id)::bigint as hop_count,
          count(distinct hs.asn)::bigint as distinct_asn_count,
          sum(case when hs.category = 'unknown' or hs.confidence = 'unknown' then 1 else 0 end)::bigint as unknown_hop_count,
          max(hs.last_seen_at) as last_seen_at,
          array_agg(distinct t.target_host order by t.target_host) filter (where t.target_host is not null) as targets
        from external_route_services s
        left join external_route_targets t on t.service_id = s.id
        left join external_route_observations o on o.service_id = s.id
        left join external_route_service_hop_summary hs on hs.service_id = s.id
        group by s.id
        order by s.display_name asc, s.service_slug asc;
        """
    )


def _list_hops_query(service_slug: str | None = None, unknown_only: bool = False) -> tuple[str, tuple[Any, ...]]:
    filters: list[str] = []
    params: list[Any] = []
    if service_slug:
        filters.append("exists (select 1 from external_route_service_hop_summary hs join external_route_services s on s.id = hs.service_id where hs.hop_id = h.id and s.service_slug = %s)")
        params.append(service_slug)
    if unknown_only:
        filters.append("(h.category = 'unknown' or h.confidence = 'unknown')")
    where_clause = f" where {' and '.join(filters)}" if filters else ""
    sql = f"""
        select
          h.id,
          h.hop_ip::text as hop_ip,
          h.reverse_dns,
          h.asn,
          h.organization,
          h.country,
          h.category,
          h.role,
          h.confidence,
          h.confidence_rank,
          h.source_priority,
          h.evidence_sources,
          h.observation_count,
          h.first_seen_at,
          h.last_seen_at,
          h.metadata,
          count(distinct hs.service_id)::bigint as service_count,
          array_agg(distinct s.service_slug order by s.service_slug) filter (where s.service_slug is not null) as services,
          count(distinct o.target_id)::bigint as target_count
        from external_route_hops h
        left join external_route_service_hop_summary hs on hs.hop_id = h.id
        left join external_route_services s on s.id = hs.service_id
        left join external_route_observations o on o.hop_id = h.id
        {where_clause}
        group by h.id
        order by h.last_seen_at desc, h.hop_ip asc
        limit %s;
    """
    return sql, tuple(params)


def list_external_hops(*, service: str | None = None, limit: int = 100, unknown_only: bool = False) -> list[dict[str, Any]]:
    value = max(1, min(int(limit), MAX_LIMIT))
    sql, params = _list_hops_query(service_slug=_normalize_slug(service) if service else None, unknown_only=unknown_only)
    return _fetch_all(sql, (*params, value))


def get_external_hop(ip: str) -> dict[str, Any] | None:
    normalized = _normalize_target_value(ip)
    if normalized is None:
        raise ValueError("IP inválido.")
    row = _fetch_one(
        """
        select
          h.id,
          h.hop_ip::text as hop_ip,
          h.reverse_dns,
          h.asn,
          h.organization,
          h.country,
          h.category,
          h.role,
          h.confidence,
          h.confidence_rank,
          h.source_priority,
          h.evidence_sources,
          h.observation_count,
          h.first_seen_at,
          h.last_seen_at,
          h.metadata,
          count(distinct hs.service_id)::bigint as service_count,
          array_agg(distinct s.service_slug order by s.service_slug) filter (where s.service_slug is not null) as services,
          count(distinct o.target_id)::bigint as target_count
        from external_route_hops h
        left join external_route_service_hop_summary hs on hs.hop_id = h.id
        left join external_route_services s on s.id = hs.service_id
        left join external_route_observations o on o.hop_id = h.id
        where h.hop_ip = %s::inet
        group by h.id
        limit 1;
        """,
        (normalized,),
    )
    if row is None:
        return None
    row["observations"] = _fetch_all(
        """
        select
          o.observation_uid,
          s.service_slug,
          s.display_name,
          o.target_host,
          o.source_kind,
          o.source_ref,
          o.source_key,
          o.hop_number,
          o.hop_role,
          o.observed_at
        from external_route_observations o
        join external_route_services s on s.id = o.service_id
        join external_route_hops h on h.id = o.hop_id
        where h.hop_ip = %s::inet
        order by o.observed_at desc, o.id desc
        limit 100;
        """,
        (normalized,),
    )
    row["service_summaries"] = _fetch_all(
        """
        select
          s.service_slug,
          s.display_name,
          hs.occurrence_count,
          hs.target_count,
          hs.first_seen_at,
          hs.last_seen_at,
          hs.min_hop_number,
          hs.max_hop_number,
          hs.category,
          hs.role,
          hs.confidence,
          hs.source_priority,
          hs.target_hosts
        from external_route_service_hop_summary hs
        join external_route_services s on s.id = hs.service_id
        join external_route_hops h on h.id = hs.hop_id
        where h.hop_ip = %s::inet
        order by hs.occurrence_count desc, s.service_slug asc;
        """,
        (normalized,),
    )
    return row


def enrich_external_hop(ip: str) -> dict[str, Any]:
    normalized = _normalize_target_value(ip)
    if normalized is None:
        raise ValueError("IP inválido.")
    hop_enrichment = _hop_enrichment(normalized)
    with get_connection() as conn:
        row = _upsert_hop_row(conn, hop_data=hop_enrichment, seen_at=_now())
        conn.commit()
    return {
        "status": "ok",
        "hop": row,
        "source": hop_enrichment.get("source_priority"),
    }


def upsert_external_hop(
    hop: dict[str, Any],
    *,
    seen_at: datetime | None = None,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    ip_value = _normalize_target_value(_extract_ip(hop.get("hop_ip"), hop.get("raw_line")))
    if ip_value is None:
        raise ValueError("Hop sem IP válido.")
    hop_enrichment = dict(_hop_enrichment(ip_value, conn=conn))
    for key in ("asn", "organization", "country", "category", "role", "confidence", "confidence_rank", "source_priority", "reverse_dns"):
        if hop.get(key) not in (None, ""):
            hop_enrichment[key] = hop.get(key)
    if hop.get("evidence_sources"):
        hop_enrichment["evidence_sources"] = {
            **(hop_enrichment.get("evidence_sources") or {}),
            **(hop.get("evidence_sources") or {}),
        }
    if hop.get("metadata"):
        hop_enrichment["metadata"] = {
            **(hop_enrichment.get("metadata") or {}),
            **(hop.get("metadata") or {}),
        }
    if hop.get("hop_role") and hop_enrichment.get("role", "unknown") == "unknown":
        hop_enrichment["role"] = hop.get("hop_role")
    if hop.get("category") and hop_enrichment.get("category", "unknown") == "unknown":
        hop_enrichment["category"] = hop.get("category")
    with (conn or get_connection()) as active_conn:
        row = _upsert_hop_row(active_conn, hop_data=hop_enrichment, seen_at=seen_at or _now())
        if conn is None:
            active_conn.commit()
    return row


def _observation_source_key(service_slug: str, target_host: str | None, source_kind: str, source_ref: str, hop_number: int | None, hop_ip: str) -> str:
    basis = "|".join(
        [
            service_slug,
            target_host or "",
            source_kind,
            source_ref,
            str(hop_number or ""),
            hop_ip,
        ]
    )
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()


def _target_service_slugs_for_route(service_slug: str, hop: dict[str, Any]) -> list[str]:
    slugs = [service_slug]
    if _is_ix_context(hop.get("hop_classification"), hop.get("hop_role"), hop.get("reverse_dns"), hop.get("organization")):
        if "ptt" not in slugs:
            slugs.append("ptt")
    return slugs


def _iter_active_measurement_sources(*, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    rows = _fetch_all(
        """
        select
          m.id as measurement_id,
          m.target::text as target,
          m.target_label,
          m.source_label,
          m.status,
          m.measured_at,
          h.hop_number,
          h.hop_ip::text as hop_ip,
          h.responded,
          h.rtt_avg_ms,
          h.raw_line,
          h.ip_scope,
          h.is_private,
          h.is_public,
          h.hop_classification,
          h.classification_confidence,
          h.classification_owner,
          h.classification_provider,
          h.classification_notes
        from active_traceroute_measurements m
        left join v_active_traceroute_hops_enriched_with_classification h on h.measurement_id = m.id
        order by m.measured_at desc, m.id desc, h.hop_number asc nulls last;
        """,
        conn=conn,
    )
    grouped: dict[int, dict[str, Any]] = {}
    for row in rows:
        measurement_id = int(row["measurement_id"])
        entry = grouped.setdefault(
            measurement_id,
            {
                "measurement_id": measurement_id,
                "target": row.get("target"),
                "target_label": row.get("target_label"),
                "source_label": row.get("source_label"),
                "status": row.get("status"),
                "measured_at": row.get("measured_at"),
                "hops": [],
            },
        )
        if row.get("hop_number") is None and row.get("hop_ip") is None and row.get("raw_line") is None:
            continue
        entry["hops"].append(
            {
                "measurement_id": measurement_id,
                "target": row.get("target"),
                "target_label": row.get("target_label"),
                "source_label": row.get("source_label"),
                "measured_at": row.get("measured_at"),
                "hop_number": row.get("hop_number"),
                "hop_ip": row.get("hop_ip"),
                "responded": row.get("responded"),
                "rtt_avg_ms": row.get("rtt_avg_ms"),
                "raw_line": row.get("raw_line"),
                "ip_scope": row.get("ip_scope"),
                "is_private": row.get("is_private"),
                "is_public": row.get("is_public"),
                "hop_classification": row.get("hop_classification"),
                "classification_confidence": row.get("classification_confidence"),
                "classification_owner": row.get("classification_owner"),
                "classification_provider": row.get("classification_provider"),
                "classification_notes": row.get("classification_notes"),
            }
        )
    return list(grouped.values())


def _iter_learning_evidence_sources(*, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          r.request_uid,
          r.question,
          r.intent,
          e.id as evidence_id,
          e.entity_value,
          e.source_ref,
          e.summary,
          e.data,
          e.created_at
        from learning_evidence e
        join learning_requests r on r.id = e.request_id
        where e.evidence_type = 'traceroute_measurement'
        order by e.created_at desc, e.id desc;
        """,
        conn=conn,
    )


def _iter_baseline_sources(*, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    rows = _fetch_all(
        """
        select
          b.baseline_uid,
          b.destination_ip::text as destination_ip,
          b.status,
          b.traceroute_run_id,
          m.id as measurement_id,
          m.target::text as target,
          m.target_label,
          m.source_label,
          m.measured_at,
          h.hop_number,
          h.hop_ip::text as hop_ip,
          h.responded,
          h.rtt_avg_ms,
          h.raw_line,
          h.ip_scope,
          h.is_private,
          h.is_public,
          h.hop_classification,
          h.classification_confidence,
          h.classification_owner,
          h.classification_provider,
          h.classification_notes
        from observed_destination_baseline_measurements b
        join active_traceroute_measurements m
          on b.traceroute_run_id ~ '^[0-9]+$'
         and m.id = b.traceroute_run_id::bigint
        left join v_active_traceroute_hops_enriched_with_classification h on h.measurement_id = m.id
        order by b.started_at desc, b.id desc, h.hop_number asc nulls last;
        """,
        conn=conn,
    )
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        baseline_uid = str(row.get("baseline_uid"))
        entry = grouped.setdefault(
            baseline_uid,
            {
                "baseline_uid": baseline_uid,
                "destination_ip": row.get("destination_ip"),
                "status": row.get("status"),
                "traceroute_run_id": row.get("traceroute_run_id"),
                "measurement_id": row.get("measurement_id"),
                "target": row.get("target"),
                "target_label": row.get("target_label"),
                "source_label": row.get("source_label"),
                "measured_at": row.get("measured_at"),
                "hops": [],
            },
        )
        if row.get("hop_number") is None and row.get("hop_ip") is None and row.get("raw_line") is None:
            continue
        entry["hops"].append(
            {
                "baseline_uid": baseline_uid,
                "destination_ip": row.get("destination_ip"),
                "measurement_id": row.get("measurement_id"),
                "target": row.get("target"),
                "target_label": row.get("target_label"),
                "source_label": row.get("source_label"),
                "measured_at": row.get("measured_at"),
                "hop_number": row.get("hop_number"),
                "hop_ip": row.get("hop_ip"),
                "responded": row.get("responded"),
                "rtt_avg_ms": row.get("rtt_avg_ms"),
                "raw_line": row.get("raw_line"),
                "ip_scope": row.get("ip_scope"),
                "is_private": row.get("is_private"),
                "is_public": row.get("is_public"),
                "hop_classification": row.get("hop_classification"),
                "classification_confidence": row.get("classification_confidence"),
                "classification_owner": row.get("classification_owner"),
                "classification_provider": row.get("classification_provider"),
                "classification_notes": row.get("classification_notes"),
            }
        )
    return list(grouped.values())


def _emit_observations_for_measurement(
    conn: psycopg.Connection,
    *,
    service_slug: str,
    source_kind: str,
    source_ref: str,
    target_host: str | None,
    target_kind: str | None,
    hops: list[dict[str, Any]],
    measured_at: datetime | None = None,
    target_hint: str | None = None,
) -> tuple[int, int, int]:
    service_map = _service_row_map(conn)
    service_row = service_map.get(service_slug)
    if service_row is None:
        return 0, 0, 0
    target_row = None
    if target_host:
        target_row = _fetch_one(
            """
            select id, service_id, target_host, target_kind
            from external_route_targets
            where service_id = %s and lower(target_host) = lower(%s)
            limit 1;
            """,
            (service_row["id"], target_host),
            conn=conn,
        )
    service_count = 0
    hop_count = 0
    unknown_count = 0
    for hop in hops:
        ip_value = _extract_ip(hop.get("hop_ip"), hop.get("raw_line"))
        if ip_value is None:
            continue
        hop_data = {
            "hop_ip": ip_value,
            "hop_classification": hop.get("hop_classification"),
            "hop_role": hop.get("hop_role"),
            "reverse_dns": hop.get("reverse_dns"),
            "organization": hop.get("organization"),
            "country": hop.get("country"),
            "category": hop.get("category"),
            "role": hop.get("role"),
            "confidence": hop.get("confidence") or hop.get("classification_confidence"),
            "confidence_rank": _confidence_rank(hop.get("confidence") or hop.get("classification_confidence")),
            "source_priority": hop.get("source_priority") or hop.get("classification_provider") or source_kind,
            "evidence_sources": {
                "source_kind": source_kind,
                "source_ref": source_ref,
                "target_hint": target_hint,
                "classification_owner": hop.get("classification_owner"),
                "classification_provider": hop.get("classification_provider"),
            },
            "metadata": {
                "target_host": target_host,
                "target_kind": target_kind,
                "source_kind": source_kind,
                "source_ref": source_ref,
                "hop_number": hop.get("hop_number"),
                "responded": hop.get("responded"),
                "rtt_avg_ms": hop.get("rtt_avg_ms"),
                "ip_scope": hop.get("ip_scope") or _ip_scope(ip_value),
            },
        }
        if hop.get("hop_classification") and hop_data.get("role", "unknown") == "unknown":
            hop_data["role"] = _normalize_slug(hop.get("hop_classification")).replace("-", "_") or "unknown"
        if _is_ix_context(
            hop.get("hop_classification"),
            hop.get("classification_owner"),
            hop.get("classification_provider"),
            hop.get("raw_line"),
            hop.get("organization"),
            hop.get("reverse_dns"),
        ):
            hop_data["category"] = "ix"
            hop_data["role"] = "ix"
            hop_data["confidence"] = _better_confidence(hop_data.get("confidence"), "probable")
            hop_data["confidence_rank"] = max(hop_data["confidence_rank"], _confidence_rank("probable"))
        if not _is_public(ip_value):
            hop_data = {**_private_hop_enrichment(ip_value), **hop_data}
        hop_row = _upsert_hop_row(conn, hop_data=hop_data, seen_at=measured_at or _now())
        service_slugs = _target_service_slugs_for_route(service_slug, hop_data)
        if "ptt" in service_slugs:
            service_count += 1
        hop_count += 1
        if hop_data.get("category") == "unknown" or hop_data.get("role") == "unknown":
            unknown_count += 1
        for slug in service_slugs:
            service_id = _service_id(slug, conn=conn)
            if service_id is None:
                continue
            target_id = int(target_row["id"]) if target_row else None
            observation_uid = _observation_source_key(
                slug,
                target_host,
                source_kind,
                source_ref,
                int(hop.get("hop_number") or 0) if hop.get("hop_number") is not None else None,
                ip_value,
            )
            _upsert_observation_row(
                conn,
                service_id=service_id,
                service_slug=slug,
                target_id=target_id,
                target_host=target_host,
                hop_row=hop_row,
                source_kind=source_kind,
                source_ref=source_ref,
                source_key=observation_uid,
                hop_number=int(hop.get("hop_number")) if hop.get("hop_number") is not None else None,
                hop_role=str(hop_data.get("role") or hop_data.get("hop_role") or "unknown"),
                seen_at=measured_at or _now(),
                metadata={
                    "target_hint": target_hint,
                    "target_kind": target_kind,
                    "source_kind": source_kind,
                    "source_ref": source_ref,
                    "measurement_id": hop.get("measurement_id"),
                    "request_uid": hop.get("request_uid"),
                    "baseline_uid": hop.get("baseline_uid"),
                    "ip_scope": hop_data.get("metadata", {}).get("ip_scope"),
                },
            )
    return service_count, hop_count, unknown_count


def _build_summary_from_observations(conn: psycopg.Connection, *, service_id: int | None = None) -> None:
    params: tuple[Any, ...] = ()
    where_clause = ""
    if service_id is not None:
        where_clause = "where o.service_id = %s"
        params = (service_id,)
    rows = _fetch_all(
        f"""
        select
          o.service_id,
          o.hop_id,
          h.hop_ip::text as hop_ip,
          count(*)::bigint as occurrence_count,
          count(distinct o.target_id)::bigint as target_count,
          min(o.observed_at) as first_seen_at,
          max(o.observed_at) as last_seen_at,
          min(o.hop_number) as min_hop_number,
          max(o.hop_number) as max_hop_number,
          h.asn,
          h.organization,
          h.country,
          h.category,
          h.role,
          h.confidence,
          h.confidence_rank,
          h.source_priority,
          array_agg(distinct o.target_host order by o.target_host) filter (where o.target_host is not null) as target_hosts
        from external_route_observations o
        join external_route_hops h on h.id = o.hop_id
        {where_clause}
        group by o.service_id, o.hop_id, h.hop_ip, h.asn, h.organization, h.country, h.category, h.role, h.confidence, h.confidence_rank, h.source_priority
        order by o.service_id, h.hop_ip;
        """,
        params,
        conn=conn,
    )
    if service_id is not None:
        _execute("delete from external_route_service_hop_summary where service_id = %s;", (service_id,), conn=conn)
    else:
        _execute("delete from external_route_service_hop_summary;", conn=conn)
    for row in rows:
        _upsert_service_hop_summary_row(
            conn,
            service_id=int(row["service_id"]),
            hop_id=int(row["hop_id"]),
            hop_ip=str(row["hop_ip"]),
            occurrence_count=int(row["occurrence_count"] or 0),
            target_count=int(row["target_count"] or 0),
            first_seen_at=row["first_seen_at"] or _now(),
            last_seen_at=row["last_seen_at"] or _now(),
            min_hop_number=row["min_hop_number"],
            max_hop_number=row["max_hop_number"],
            asn=row["asn"],
            organization=row["organization"],
            country=row["country"],
            category=str(row["category"] or "unknown"),
            role=str(row["role"] or "unknown"),
            confidence=str(row["confidence"] or "unknown"),
            confidence_rank=int(row["confidence_rank"] or 0),
            source_priority=row["source_priority"],
            target_hosts=[str(value) for value in (row.get("target_hosts") or []) if value],
            metadata={"rebuilt_at": _now()},
        )


def rebuild_service_hop_summary(*, service: str | None = None) -> dict[str, Any]:
    service_slug = _normalize_slug(service) if service else None
    with get_connection() as conn:
        service_id = _service_id(service_slug, conn=conn) if service_slug else None
        _build_summary_from_observations(conn, service_id=service_id)
        conn.commit()
    return {
        "status": "ok",
        "service": service_slug,
    }


def _service_ingest_candidates(*, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    for row in _iter_active_measurement_sources(conn=conn):
        target = _normalize_target_value(row.get("target"))
        service_slug = _service_slug_for_target_value(target) or _service_from_text(row.get("target_label"), row.get("source_label"))
        if service_slug is None:
            continue
        hops = []
        for hop in row.get("hops", []) if isinstance(row.get("hops"), list) else []:
            if not isinstance(hop, dict):
                continue
            hops.append(
                {
                    **hop,
                    "measurement_id": row.get("measurement_id"),
                    "target": target,
                    "target_label": row.get("target_label"),
                    "source_label": row.get("source_label"),
                    "measured_at": row.get("measured_at"),
                }
            )
        candidates.append(
            {
                "service_slug": service_slug,
                "source_kind": "active_traceroute_measurement",
                "source_ref": str(row.get("measurement_id")),
                "target_host": target,
                "target_kind": "ip" if target and _ip_scope(target) != "unknown" else "domain",
                "target_hint": row.get("target_label") or row.get("source_label"),
                "hops": hops,
                "measured_at": row.get("measured_at"),
            }
        )

    for row in _iter_learning_evidence_sources(conn=conn):
        service_slug = _service_from_text(row.get("question"), row.get("entity_value"), row.get("summary"))
        if service_slug is None:
            continue
        data = row.get("data") if isinstance(row.get("data"), dict) else {}
        hops = []
        for hop in data.get("hops") if isinstance(data.get("hops"), list) else []:
            if not isinstance(hop, dict):
                continue
            hops.append({**hop, "request_uid": row.get("request_uid"), "measured_at": row.get("created_at")})
        candidates.append(
            {
                "service_slug": service_slug,
                "source_kind": "learning_evidence",
                "source_ref": str(row.get("request_uid")),
                "target_host": _normalize_host(row.get("question")),
                "target_kind": "context",
                "target_hint": row.get("question"),
                "hops": hops,
                "measured_at": row.get("created_at"),
            }
        )

    for row in _iter_baseline_sources(conn=conn):
        target = _normalize_target_value(row.get("target"))
        service_slug = _service_slug_for_target_value(target) or _service_from_text(row.get("target_label"), row.get("source_label"), row.get("destination_ip"))
        if service_slug is None:
            continue
        measurement_id = row.get("measurement_id")
        if measurement_id is None:
            continue
        hops = _fetch_all(
            """
            select
              hop_number,
              hop_ip::text as hop_ip,
              responded,
              rtt_avg_ms,
              raw_line,
              ip_scope,
              is_private,
              is_public,
              hop_classification,
              classification_confidence,
              classification_owner,
              classification_provider,
              classification_notes
            from v_active_traceroute_latest_hops_with_classification
            where measurement_id = %s
            order by hop_number;
            """,
            (measurement_id,),
            conn=conn,
        )
        candidates.append(
            {
                "service_slug": service_slug,
                "source_kind": "baseline_measurement",
                "source_ref": str(row.get("baseline_uid") or row.get("traceroute_run_id")),
                "target_host": target,
                "target_kind": "ip" if target and _ip_scope(target) != "unknown" else "domain",
                "target_hint": row.get("baseline_uid") or row.get("destination_ip"),
                "hops": hops,
                "measured_at": row.get("measured_at"),
            }
        )

    return candidates


def ingest_existing_traceroutes(*, dry_run: bool = True) -> dict[str, Any]:
    with get_connection() as conn:
        service_map = _service_row_map(conn)
        target_map = _target_row_map(conn)
        candidates = _service_ingest_candidates(conn=conn)
        preview: list[dict[str, Any]] = []
        counters = Counter()
        matched_services: set[str] = set()
        total_hops = 0
        unknown_hops = 0

        for candidate in candidates:
            service_slug = candidate["service_slug"]
            if service_slug not in service_map:
                continue
            matched_services.add(service_slug)
            hops = candidate.get("hops") or []
            preview.append(
                {
                    "service": service_slug,
                    "source_kind": candidate["source_kind"],
                    "source_ref": candidate["source_ref"],
                    "target_host": candidate.get("target_host"),
                    "hop_count": len(hops),
                    "target_hint": candidate.get("target_hint"),
                }
            )
            counters["sources_seen"] += 1
            counters[f"sources_{candidate['source_kind']}"] += 1
            counters["hops_seen"] += len(hops)
            for hop in hops:
                ip_value = _extract_ip(hop.get("hop_ip"), hop.get("raw_line"))
                if ip_value is None:
                    continue
                total_hops += 1
                if not _is_public(ip_value):
                    unknown_hops += 1 if _ip_scope(ip_value) == "unknown" else 0
                if not dry_run:
                    service_id = int(service_map[service_slug]["id"])
                    target_row = None
                    target_host = candidate.get("target_host")
                    if target_host:
                        target_row = _fetch_one(
                            """
                            select id from external_route_targets where service_id = %s and lower(target_host) = lower(%s) limit 1;
                            """,
                            (service_id, target_host),
                            conn=conn,
                        )
                    hop_data = {
                        "hop_ip": ip_value,
                        "hop_classification": hop.get("hop_classification"),
                        "hop_role": hop.get("hop_role"),
                        "reverse_dns": hop.get("reverse_dns"),
                        "organization": hop.get("organization"),
                        "country": hop.get("country"),
                        "category": hop.get("category"),
                        "role": hop.get("role"),
                        "confidence": hop.get("confidence") or hop.get("classification_confidence"),
                        "confidence_rank": _confidence_rank(hop.get("confidence") or hop.get("classification_confidence")),
                        "source_priority": hop.get("source_priority") or hop.get("classification_provider") or candidate["source_kind"],
                        "evidence_sources": {
                            "source_kind": candidate["source_kind"],
                            "source_ref": candidate["source_ref"],
                            "target_hint": candidate.get("target_hint"),
                            "classification_owner": hop.get("classification_owner"),
                            "classification_provider": hop.get("classification_provider"),
                        },
                        "metadata": {
                            "target_host": target_host,
                            "target_kind": candidate.get("target_kind"),
                            "source_kind": candidate["source_kind"],
                            "source_ref": candidate["source_ref"],
                            "measurement_id": hop.get("measurement_id"),
                            "request_uid": hop.get("request_uid"),
                            "baseline_uid": candidate["source_ref"],
                            "ip_scope": hop.get("ip_scope") or _ip_scope(ip_value),
                        },
                    }
                    if _is_ix_context(
                        hop.get("hop_classification"),
                        hop.get("classification_owner"),
                        hop.get("classification_provider"),
                        hop.get("raw_line"),
                        hop.get("organization"),
                        hop.get("reverse_dns"),
                    ):
                        hop_data["category"] = "ix"
                        hop_data["role"] = "ix"
                        hop_data["confidence"] = _better_confidence(hop_data.get("confidence"), "probable")
                        hop_data["confidence_rank"] = max(hop_data["confidence_rank"], _confidence_rank("probable"))
                    if not _is_public(ip_value):
                        hop_data = {**_private_hop_enrichment(ip_value), **hop_data}
                    hop_row = _upsert_hop_row(conn, hop_data=hop_data, seen_at=candidate.get("measured_at") or _now())
                    for service_row in service_map.values():
                        if service_row["service_slug"] != service_slug and service_row["service_slug"] != "ptt":
                            continue
                        if service_row["service_slug"] == "ptt" and not _is_ix_context(
                            hop.get("hop_classification"),
                            hop.get("classification_owner"),
                            hop.get("classification_provider"),
                            hop.get("raw_line"),
                            hop.get("organization"),
                            hop.get("reverse_dns"),
                        ):
                            continue
                        source_service_slug = str(service_row["service_slug"])
                        observation_uid = _observation_source_key(
                            source_service_slug,
                            target_host,
                            candidate["source_kind"],
                            candidate["source_ref"],
                            int(hop.get("hop_number") or 0) if hop.get("hop_number") is not None else None,
                            ip_value,
                        )
                        _upsert_observation_row(
                            conn,
                            service_id=int(service_row["id"]),
                            service_slug=source_service_slug,
                            target_id=_target_id(int(service_row["id"]), target_host, conn=conn) if target_host else None,
                            target_host=target_host,
                            hop_row=hop_row,
                            source_kind=candidate["source_kind"],
                            source_ref=candidate["source_ref"],
                            source_key=observation_uid,
                            hop_number=int(hop.get("hop_number")) if hop.get("hop_number") is not None else None,
                            hop_role=str(hop_data.get("role") or "unknown"),
                            seen_at=candidate.get("measured_at") or _now(),
                            metadata={
                                "target_hint": candidate.get("target_hint"),
                                "target_kind": candidate.get("target_kind"),
                                "source_kind": candidate["source_kind"],
                                "source_ref": candidate["source_ref"],
                                "measurement_id": hop.get("measurement_id"),
                                "request_uid": hop.get("request_uid"),
                                "baseline_uid": candidate["source_ref"],
                                "ip_scope": hop_data.get("metadata", {}).get("ip_scope"),
                            },
                        )
                else:
                    unknown_hops += 1 if _ip_scope(ip_value) == "unknown" else 0

        if dry_run:
            return {
                "status": "ok",
                "dry_run": True,
                "sources_seen": int(counters["sources_seen"]),
                "hops_seen": int(counters["hops_seen"]),
                "matched_services": sorted(matched_services),
                "preview": preview[:50],
                "counters": {
                    "sources_seen": int(counters["sources_seen"]),
                    "active_traceroute_measurement_sources": int(counters.get("sources_active_traceroute_measurement", 0)),
                    "learning_evidence_sources": int(counters.get("sources_learning_evidence", 0)),
                    "baseline_measurement_sources": int(counters.get("sources_baseline_measurement", 0)),
                    "hops_seen": int(counters["hops_seen"]),
                    "unknown_hops": int(unknown_hops),
                },
            }

        _build_summary_from_observations(conn)
        conn.commit()
        service_hops = _fetch_one(
            "select count(*)::bigint as value from external_route_service_hop_summary;",
            conn=conn,
        )
        observation_count = _fetch_one(
            "select count(*)::bigint as value from external_route_observations;",
            conn=conn,
        )
        hop_count = _fetch_one(
            "select count(*)::bigint as value from external_route_hops;",
            conn=conn,
        )
        return {
            "status": "ok",
            "dry_run": False,
            "sources_seen": int(counters["sources_seen"]),
            "hops_seen": int(counters["hops_seen"]),
            "matched_services": sorted(matched_services),
            "preview": preview[:50],
            "counters": {
                "sources_seen": int(counters["sources_seen"]),
                "active_traceroute_measurement_sources": int(counters.get("sources_active_traceroute_measurement", 0)),
                "learning_evidence_sources": int(counters.get("sources_learning_evidence", 0)),
                "baseline_measurement_sources": int(counters.get("sources_baseline_measurement", 0)),
                "hops_seen": int(counters["hops_seen"]),
                "unknown_hops": int(unknown_hops),
                "observations_total": int(observation_count["value"]) if observation_count else 0,
                "hops_total": int(hop_count["value"]) if hop_count else 0,
                "service_hop_summary_rows": int(service_hops["value"]) if service_hops else 0,
            },
        }


def get_service_route_summary(service: str) -> dict[str, Any]:
    service_slug = _normalize_slug(service)
    with get_connection() as conn:
        service_row = _fetch_one(
            """
            select id, service_slug, display_name, category, description, is_ptt, enabled, created_at, updated_at
            from external_route_services
            where service_slug = %s
            limit 1;
            """,
            (service_slug,),
            conn=conn,
        )
        if service_row is None:
            return {"status": "missing", "service": service_slug, "summary": None}
        summary_rows = _service_hop_summary_rows(service_slug, conn=conn)
        edge_rows = _service_trace_edges_rows(service_slug, limit=50, conn=conn)
        latest_run = _fetch_one(
            """
            select
              run_uid,
              service_uid,
              target_uid,
              target_host,
              target_resolved_ip::text as target_resolved_ip,
              target_source,
              target_selection_reason,
              status,
              max_hops,
              hop_count,
              unknown_count,
              edge_count,
              graph_available,
              graph_url,
              observed_at,
              completed_at,
              metadata
            from external_route_traceroute_runs
            where service_uid = %s
            order by observed_at desc, completed_at desc nulls last, run_uid desc
            limit 1;
            """,
            (service_slug,),
            conn=conn,
        )
        top_asns = Counter(str(row["asn"]) for row in summary_rows if row.get("asn") is not None)
        top_roles = Counter(str(row["role"]) for row in summary_rows if row.get("role"))
        top_categories = Counter(str(row["category"]) for row in summary_rows if row.get("category"))
        unknown_hops = sum(1 for row in summary_rows if row.get("category") == "unknown" or row.get("confidence") == "unknown")
        target_hosts = _service_target_hosts(service_slug, conn=conn)
        return {
            "status": "ok",
            "service": service_row,
            "targets": target_hosts,
            "summary": {
                "service_slug": service_slug,
                "display_name": service_row.get("display_name"),
                "category": service_row.get("category"),
                "is_ptt": service_row.get("is_ptt"),
                "target_count": _service_targets_count(service_slug, conn=conn),
                "observation_count": _service_observation_count(service_slug, conn=conn),
                "hop_count": _service_hop_count(service_slug, conn=conn),
                "distinct_asn_count": _service_asn_count(service_slug, conn=conn),
                "unknown_hop_count": unknown_hops,
                "last_seen_at": summary_rows[0].get("last_seen_at") if summary_rows else None,
                "top_asns": top_asns.most_common(10),
                "top_roles": top_roles.most_common(10),
                "top_categories": top_categories.most_common(10),
            },
            "hops": summary_rows[:200],
            "edges": edge_rows,
            "edge_count": len(edge_rows),
            "latest_trace_run": latest_run,
            "graph_url": latest_run.get("graph_url") if latest_run else None,
            "service_hop_summary_rows": summary_rows,
        }


def compare_service_routes(service_a: str, service_b: str) -> dict[str, Any]:
    service_a_slug = _normalize_slug(service_a)
    service_b_slug = _normalize_slug(service_b)
    with get_connection() as conn:
        a_summary = get_service_route_summary(service_a_slug)
        b_summary = get_service_route_summary(service_b_slug)
        a_rows = a_summary.get("service_hop_summary_rows") or []
        b_rows = b_summary.get("service_hop_summary_rows") or []
        a_hops = {str(row["hop_ip"]): row for row in a_rows if row.get("hop_ip")}
        b_hops = {str(row["hop_ip"]): row for row in b_rows if row.get("hop_ip")}
        shared_hops = sorted(set(a_hops) & set(b_hops))
        shared_asns = sorted(
            {str(row["asn"]) for row in a_rows if row.get("asn") is not None}
            & {str(row["asn"]) for row in b_rows if row.get("asn") is not None}
        )
        shared_roles = sorted(
            {str(row["role"]) for row in a_rows if row.get("role")}
            & {str(row["role"]) for row in b_rows if row.get("role")}
        )
        shared_categories = sorted(
            {str(row["category"]) for row in a_rows if row.get("category")}
            & {str(row["category"]) for row in b_rows if row.get("category")}
        )
        overlap = {
            "shared_hop_count": len(shared_hops),
            "shared_asn_count": len(shared_asns),
            "shared_role_count": len(shared_roles),
            "shared_category_count": len(shared_categories),
            "shared_hop_ratio_a": round(len(shared_hops) / len(a_hops), 3) if a_hops else 0.0,
            "shared_hop_ratio_b": round(len(shared_hops) / len(b_hops), 3) if b_hops else 0.0,
        }
        shared_hop_rows = []
        for hop_ip in shared_hops[:50]:
            shared_hop_rows.append(
                {
                    "hop_ip": hop_ip,
                    "a": a_hops[hop_ip],
                    "b": b_hops[hop_ip],
                }
            )
        return {
            "status": "ok",
            "service_a": a_summary,
            "service_b": b_summary,
            "comparison": {
                "service_a": service_a_slug,
                "service_b": service_b_slug,
                "shared_hops": shared_hops[:50],
                "shared_asns": shared_asns[:50],
                "shared_roles": shared_roles,
                "shared_categories": shared_categories,
                "overlap": overlap,
                "shared_examples": shared_hop_rows,
            },
        }


def build_external_route_inventory_report() -> dict[str, Any]:
    services = list_external_services()
    service_slugs = [str(row.get("service_slug")) for row in services]
    summaries = {slug: get_service_route_summary(slug) for slug in service_slugs}
    hops = list_external_hops(limit=MAX_LIMIT)
    unknown_hops = list_external_hops(limit=MAX_LIMIT, unknown_only=True)
    compare_google_facebook = compare_service_routes("google", "facebook")
    compare_google_youtube = compare_service_routes("google", "youtube")
    return {
        "status": "ok" if any((row.get("hop_count") or 0) for row in services) else "partial",
        "generated_at": _now(),
        "services": services,
        "service_summaries": summaries,
        "hops": hops,
        "unknown_hops": unknown_hops,
        "comparisons": {
            "google_facebook": compare_google_facebook,
            "google_youtube": compare_google_youtube,
        },
    }


def write_external_route_inventory_report(report_dir: Path | str, *, timestamp: str | None = None) -> dict[str, str]:
    stamp = timestamp or _now().strftime("%Y%m%dT%H%M%SZ")
    report = build_external_route_inventory_report()
    directory = Path(report_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"routebrain_external_route_inventory_{stamp}.json"
    txt_path = directory / f"routebrain_external_route_inventory_{stamp}.txt"
    json_path.write_text(json.dumps(_safe_json(report), ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        f"status: {report['status']}",
        f"generated_at: {report['generated_at']}",
        f"services: {len(report['services'])}",
        f"hops: {len(report['hops'])}",
        f"unknown_hops: {len(report['unknown_hops'])}",
        "",
        "services:",
    ]
    for service in report["services"]:
        lines.append(
            f"- {service['service_slug']}: targets={service.get('target_count', 0)} hops={service.get('hop_count', 0)} asns={service.get('distinct_asn_count', 0)} unknown={service.get('unknown_hop_count', 0)}"
        )
    lines.extend(
        [
            "",
            "comparisons:",
            f"- google/facebook shared_hops={report['comparisons']['google_facebook']['comparison']['overlap']['shared_hop_count']}",
            f"- google/youtube shared_hops={report['comparisons']['google_youtube']['comparison']['overlap']['shared_hop_count']}",
        ]
    )
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"json_path": str(json_path), "txt_path": str(txt_path)}


def build_external_route_trace_execute_inventory_report(run_result: dict[str, Any]) -> dict[str, Any]:
    service_slug = str(run_result.get("service") or "").strip().lower()
    target = run_result.get("target") if isinstance(run_result.get("target"), dict) else {}
    trace = run_result.get("trace") if isinstance(run_result.get("trace"), dict) else {}
    hops = trace.get("hops") if isinstance(trace.get("hops"), list) else []
    edges = run_result.get("edges") if isinstance(run_result.get("edges"), list) else []
    service_summary = run_result.get("service_summary") if isinstance(run_result.get("service_summary"), dict) else {}
    sample_hops = []
    for hop in hops[:8]:
        sample_hops.append(
            {
                "hop_number": hop.get("hop_number"),
                "hop_ip": hop.get("hop_ip"),
                "responded": hop.get("responded"),
                "rtt_avg_ms": hop.get("rtt_avg_ms"),
                "ip_scope": hop.get("ip_scope"),
            }
        )
    sample_edges = []
    for edge in edges[:8]:
        sample_edges.append(
            {
                "edge_uid": edge.get("edge_uid"),
                "from_hop_ip": edge.get("from_hop_ip"),
                "to_hop_ip": edge.get("to_hop_ip"),
                "transition_type": edge.get("transition_type"),
                "confidence": edge.get("confidence"),
            }
        )
    status = str(run_result.get("status") or "failed")
    return {
        "status": "ROUTEBRAIN_EXTERNAL_ROUTE_TRACE_EXECUTE_INVENTORY_OK" if status == "ok" else "ROUTEBRAIN_EXTERNAL_ROUTE_TRACE_EXECUTE_INVENTORY_PARTIAL" if status == "partial" else "ROUTEBRAIN_EXTERNAL_ROUTE_TRACE_EXECUTE_INVENTORY_FAILED",
        "generated_at": _now(),
        "service": service_slug,
        "run_uid": run_result.get("run_uid"),
        "target": target,
        "trace": {
            "status": trace.get("status"),
            "returncode": trace.get("returncode"),
            "hop_count": len(hops),
            "hops": sample_hops,
        },
        "summary": {
            "hops_count": run_result.get("hops_count"),
            "edges_count": run_result.get("edges_count"),
            "unknown_count": run_result.get("unknown_count"),
            "graph_url": run_result.get("graph_url"),
        },
        "service_summary": service_summary,
        "edges": sample_edges,
        "hops": sample_hops,
    }


def write_external_route_trace_execute_inventory_report(
    report_dir: Path | str,
    run_result: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> dict[str, str]:
    stamp = timestamp or _now().strftime("%Y%m%dT%H%M%SZ")
    report = build_external_route_trace_execute_inventory_report(run_result)
    directory = Path(report_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"routebrain_external_route_trace_execute_inventory_{stamp}.json"
    txt_path = directory / f"routebrain_external_route_trace_execute_inventory_{stamp}.txt"
    json_path.write_text(json.dumps(_safe_json(report), ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        f"status: {report['status']}",
        f"generated_at: {report['generated_at']}",
        f"service: {report['service']}",
        f"run_uid: {report['run_uid']}",
        f"target: {report['target'].get('target_resolved_ip') or report['target'].get('target_host')}",
        f"hops_count: {report['summary']['hops_count']}",
        f"edges_count: {report['summary']['edges_count']}",
        f"unknown_count: {report['summary']['unknown_count']}",
        f"graph_url: {report['summary']['graph_url']}",
        "",
        "sample_hops:",
    ]
    for hop in report["hops"]:
        lines.append(
            f"- hop={hop.get('hop_number')} ip={hop.get('hop_ip')} scope={hop.get('ip_scope')} rtt={hop.get('rtt_avg_ms')}"
        )
    lines.extend(["", "sample_edges:"])
    for edge in report["edges"]:
        lines.append(
            f"- {edge.get('from_hop_ip')} -> {edge.get('to_hop_ip')} transition={edge.get('transition_type')} conf={edge.get('confidence')}"
        )
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"json_path": str(json_path), "txt_path": str(txt_path)}
