from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.db.connection import get_connection

DEFAULT_MEMORY_TTL = timedelta(hours=24)
EVIDENCE_TTLS: dict[str, timedelta] = {
    "dns_resolution": timedelta(hours=6),
    "bgp_prefix_lookup": timedelta(hours=12),
    "bgp_prefix_match": timedelta(hours=12),
    "bgp_prefix_not_found": timedelta(hours=12),
    "bgp_asn_lookup": timedelta(hours=12),
    "ping_measurement": timedelta(minutes=30),
    "traceroute_measurement": timedelta(minutes=30),
    "inventory_lookup": timedelta(hours=24),
    "ixbr_lookup": timedelta(hours=24),
    "reused_learning_context": timedelta(hours=24),
    "linked_prior_evidence": timedelta(hours=24),
    "active_measurement_blocked": timedelta(hours=24),
}


def _now() -> datetime:
    return datetime.now().astimezone()


def _normalize_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone()


def _humanize_age(age_seconds: int | None) -> str | None:
    if age_seconds is None:
        return None
    if age_seconds < 0:
        age_seconds = 0
    minutes, seconds = divmod(age_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def _ttl_for_evidence_type(evidence_type: str | None) -> timedelta:
    return EVIDENCE_TTLS.get(str(evidence_type or "").strip(), DEFAULT_MEMORY_TTL)


def classify_evidence_freshness(
    evidence_type: str,
    created_at: datetime | None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    created = _normalize_datetime(created_at)
    expiry = _normalize_datetime(expires_at)
    ttl = _ttl_for_evidence_type(evidence_type)
    now = _now()

    if created is None:
        return {
            "evidence_type": evidence_type,
            "status": "missing",
            "age_seconds": None,
            "age_human": None,
            "ttl_seconds": int(ttl.total_seconds()),
            "expires_at": expiry.isoformat() if expiry else None,
            "valid_until": None,
            "recommended_action": "coletar",
        }

    if expiry is None:
        expiry = created + ttl

    age_seconds = max(0, int((now - created).total_seconds()))
    freshness_window_seconds = int(ttl.total_seconds())
    stale_window = expiry + ttl

    if now <= expiry:
        status = "fresh"
        recommended_action = "reutilizar"
    elif now <= stale_window:
        status = "stale"
        recommended_action = "mostrar_com_aviso_e_considerar_refresh"
    else:
        status = "expired"
        recommended_action = "atualizar"

    return {
        "evidence_type": evidence_type,
        "status": status,
        "age_seconds": age_seconds,
        "age_human": _humanize_age(age_seconds),
        "ttl_seconds": freshness_window_seconds,
        "expires_at": expiry.isoformat() if expiry else None,
        "valid_until": expiry.isoformat() if expiry else None,
        "recommended_action": recommended_action,
    }


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


def _annotate_evidence_row(row: dict[str, Any]) -> dict[str, Any]:
    annotated = dict(row)
    freshness = classify_evidence_freshness(
        str(annotated.get("evidence_type") or ""),
        annotated.get("created_at"),
    )
    annotated["freshness"] = freshness
    return annotated


def _annotate_cache_row(row: dict[str, Any] | None, *, evidence_type: str) -> dict[str, Any] | None:
    if row is None:
        return None
    annotated = dict(row)
    freshness = classify_evidence_freshness(
        evidence_type,
        annotated.get("created_at"),
        annotated.get("expires_at"),
    )
    annotated["freshness"] = freshness
    return annotated


def get_recent_evidence(
    entity_type: str,
    entity_value: str,
    evidence_type: str | None = None,
    max_age_seconds: int | None = None,
    limit: int = 20,
    *,
    conn: psycopg.Connection | None = None,
) -> list[dict[str, Any]]:
    filters = ["e.entity_type = %s", "e.entity_value = %s"]
    params: list[Any] = [entity_type, entity_value]
    if evidence_type is not None:
        filters.append("e.evidence_type = %s")
        params.append(evidence_type)
    if max_age_seconds is not None:
        filters.append("e.created_at >= now() - (%s * interval '1 second')")
        params.append(max_age_seconds)
    params.append(limit)
    rows = _fetch_all(
        f"""
        select
          e.id,
          e.request_id,
          r.request_uid,
          r.question,
          r.intent,
          r.status as request_status,
          e.task_id,
          e.evidence_type,
          e.entity_type,
          e.entity_value,
          e.confidence,
          e.source,
          e.source_ref,
          e.summary,
          e.data,
          e.created_at
        from learning_evidence e
        join learning_requests r on r.id = e.request_id
        where {' and '.join(filters)}
        order by e.created_at desc, e.id desc
        limit %s;
        """,
        tuple(params),
        conn=conn,
    )
    return [_annotate_evidence_row(row) for row in rows]


def _fetch_latest_cache(
    cache_key: str,
    *,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any] | None:
    row = _fetch_one(
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
        limit 1;
        """,
        (cache_key,),
        conn=conn,
    )
    return row


def _fetch_related_requests(
    entity_type: str,
    entity_value: str,
    *,
    conn: psycopg.Connection | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          request_uid,
          question,
          intent,
          status,
          created_at,
          updated_at,
          started_at,
          finished_at
        from (
          select distinct on (r.id)
            r.id,
            r.request_uid,
            r.question,
            r.intent,
            r.status,
            r.created_at,
            r.updated_at,
            r.started_at,
            r.finished_at
          from learning_requests r
          join learning_entities e on e.request_id = r.id
          where e.entity_type = %s
            and e.entity_value = %s
          order by r.id, r.created_at desc
        ) related_requests
        order by created_at desc, id desc
        limit %s;
        """,
        (entity_type, entity_value, limit),
        conn=conn,
    )


def _normalize_domain(domain: str) -> str:
    return " ".join(str(domain or "").split()).strip().lower()


def _latest_evidence_by_type(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        evidence_type = str(row.get("evidence_type") or "")
        if evidence_type and evidence_type not in grouped:
            grouped[evidence_type] = row
    return grouped


def _memory_state_from_rows(rows: list[dict[str, Any]], *, evidence_types: set[str] | None = None) -> dict[str, Any]:
    latest = rows[0] if rows else None
    if latest is None:
        return {
            "status": "missing",
            "age_seconds": None,
            "age_human": None,
            "recommended_action": "coletar",
            "latest": None,
            "items": rows,
        }

    if evidence_types is not None:
        freshness_candidates = [row.get("freshness", {}) for row in rows if str(row.get("evidence_type")) in evidence_types]
        freshness = freshness_candidates[0] if freshness_candidates else latest.get("freshness", {})
    else:
        freshness = latest.get("freshness", {})
    return {
        "status": freshness.get("status", "missing"),
        "age_seconds": freshness.get("age_seconds"),
        "age_human": freshness.get("age_human"),
        "ttl_seconds": freshness.get("ttl_seconds"),
        "expires_at": freshness.get("expires_at"),
        "recommended_action": freshness.get("recommended_action"),
        "latest": latest,
        "items": rows,
    }


def _memory_summary_text(domain: str, memory: dict[str, Any]) -> str:
    dns = memory.get("dns") or {}
    ips = memory.get("ips") or []
    if not dns.get("resolved_ips"):
        return f"Nenhuma memória reutilizável para {domain} foi encontrada."

    resolved_ips = dns.get("resolved_ips") or []
    dns_status = dns.get("freshness", {}).get("status") or "missing"
    dns_age = dns.get("freshness", {}).get("age_human") or "idade desconhecida"
    fresh_ips = 0
    stale_ips = 0
    expired_ips = 0
    ping_notes: list[str] = []
    traceroute_notes: list[str] = []
    bgp_notes: list[str] = []

    for item in ips:
        ip = item.get("ip")
        bgp_state = item.get("bgp", {})
        ping_state = item.get("ping", {})
        traceroute_state = item.get("traceroute", {})
        if bgp_state.get("status") == "fresh":
            fresh_ips += 1
        elif bgp_state.get("status") == "stale":
            stale_ips += 1
        elif bgp_state.get("status") == "expired":
            expired_ips += 1
        latest_bgp = bgp_state.get("latest") or {}
        if latest_bgp:
            bgp_notes.append(
                f"{ip}:{latest_bgp.get('evidence_type')} {bgp_state.get('status')} ({bgp_state.get('age_human')})"
            )
        latest_ping = ping_state.get("latest") or {}
        if latest_ping:
            ping_data = latest_ping.get("data") or {}
            metrics = ping_data.get("metrics") or {}
            ping_notes.append(
                f"{ip} loss {metrics.get('packet_loss_percent')}% avg {metrics.get('rtt_avg_ms')} ms ({ping_state.get('status')})"
            )
        latest_traceroute = traceroute_state.get("latest") or {}
        if latest_traceroute:
            traceroute_data = latest_traceroute.get("data") or {}
            traceroute_notes.append(
                f"{ip} {traceroute_data.get('total_hops')} hop(s) ({traceroute_state.get('status')})"
            )

    parts = [
        f"Aprendizado reutilizado para {domain}: DNS {dns_status} há {dns_age}.",
        f"IPs resolvidos: {', '.join(resolved_ips)}.",
    ]
    if bgp_notes:
        parts.append(f"BGP: {', '.join(bgp_notes[:5])}.")
    if ping_notes:
        parts.append(f"Ping: {', '.join(ping_notes[:5])}.")
    if traceroute_notes:
        parts.append(f"Traceroute: {', '.join(traceroute_notes[:5])}.")
    parts.append(
        f"Resumo: {fresh_ips} evidência(s) BGP fresh, {stale_ips} stale e {expired_ips} expired."
    )
    return " ".join(parts)


def get_learning_memory_for_domain(domain: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any]:
    normalized_domain = _normalize_domain(domain)
    dns_cache_key = f"domain:{normalized_domain}:dns"
    dns_cache = _annotate_cache_row(_fetch_latest_cache(dns_cache_key, conn=conn), evidence_type="dns_resolution")
    dns_evidence = get_recent_evidence("domain", normalized_domain, "dns_resolution", limit=20, conn=conn)
    latest_dns = dns_evidence[0] if dns_evidence else None
    dns_data = {}
    if dns_cache is not None and isinstance(dns_cache.get("data"), dict):
        dns_data = dns_cache["data"]
    elif latest_dns is not None and isinstance(latest_dns.get("data"), dict):
        dns_data = latest_dns["data"]

    resolved_ips: list[str] = []
    seen_ips: set[str] = set()
    for ip_value in dns_data.get("resolved_ips") or []:
        ip_text = str(ip_value).strip()
        if ip_text and ip_text not in seen_ips:
            resolved_ips.append(ip_text)
            seen_ips.add(ip_text)
    for record in dns_data.get("resolved_records") or []:
        if not isinstance(record, dict):
            continue
        ip_value = record.get("ip")
        if not ip_value:
            continue
        ip_text = str(ip_value).strip()
        if ip_text and ip_text not in seen_ips:
            resolved_ips.append(ip_text)
            seen_ips.add(ip_text)

    ips: list[dict[str, Any]] = []
    for ip_text in resolved_ips:
        bgp_rows = get_recent_evidence("ip", ip_text, limit=20, conn=conn)
        bgp_rows = [
            row
            for row in bgp_rows
            if row.get("evidence_type") in {"bgp_prefix_match", "bgp_prefix_not_found", "bgp_prefix_lookup"}
        ]
        ping_rows = get_recent_evidence("ip", ip_text, "ping_measurement", limit=20, conn=conn)
        traceroute_rows = get_recent_evidence("ip", ip_text, "traceroute_measurement", limit=20, conn=conn)
        ips.append(
            {
                "ip": ip_text,
                "bgp": _memory_state_from_rows(bgp_rows, evidence_types={"bgp_prefix_match", "bgp_prefix_not_found", "bgp_prefix_lookup"}),
                "ping": _memory_state_from_rows(ping_rows, evidence_types={"ping_measurement"}),
                "traceroute": _memory_state_from_rows(traceroute_rows, evidence_types={"traceroute_measurement"}),
            }
        )

    related_requests = _fetch_related_requests("domain", normalized_domain, conn=conn, limit=10)
    memory = {
        "entity_type": "domain",
        "entity_value": normalized_domain,
        "dns": {
            "cache": dns_cache,
            "evidence": dns_evidence,
            "freshness": (dns_cache or latest_dns or {}).get("freshness", {"status": "missing"}),
            "resolved_ips": resolved_ips,
            "request_uid": (latest_dns or {}).get("request_uid") or (dns_cache or {}).get("source_ref"),
        },
        "ips": ips,
        "related_requests": related_requests,
    }
    memory["summary_text"] = _memory_summary_text(normalized_domain, memory)
    memory["freshness"] = {
        "dns": memory["dns"].get("freshness"),
        "ip_count": len(ips),
        "fresh_ip_count": sum(1 for item in ips if item.get("bgp", {}).get("status") == "fresh"),
        "stale_ip_count": sum(1 for item in ips if item.get("bgp", {}).get("status") == "stale"),
        "expired_ip_count": sum(1 for item in ips if item.get("bgp", {}).get("status") == "expired"),
    }
    return memory


def summarize_learning_memory(entity: dict[str, Any] | str, *, conn: psycopg.Connection | None = None) -> dict[str, Any]:
    if isinstance(entity, str):
        entity_type = "domain"
        entity_value = entity
    else:
        entity_type = str(entity.get("entity_type") or entity.get("type") or "domain")
        entity_value = str(entity.get("entity_value") or entity.get("value") or "").strip()

    if not entity_value:
        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "status": "missing",
            "summary_text": "Nenhuma memória disponível.",
            "memory": None,
        }

    if entity_type == "domain":
        memory = get_learning_memory_for_domain(entity_value, conn=conn)
    else:
        cache_row = _annotate_cache_row(
            _fetch_one(
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
                where entity_type = %s
                  and entity_value = %s
                order by updated_at desc, created_at desc, id desc
                limit 1;
                """,
                (entity_type, entity_value),
                conn=conn,
            ),
            evidence_type=str((entity_type == "ip" and "bgp_prefix_lookup") or "reused_learning_context"),
        )
        evidence_rows = get_recent_evidence(entity_type, entity_value, limit=20, conn=conn)
        related_requests = _fetch_related_requests(entity_type, entity_value, conn=conn, limit=10)
        memory = {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "cache": cache_row,
            "evidence": evidence_rows,
            "related_requests": related_requests,
            "freshness": cache_row.get("freshness") if cache_row else (evidence_rows[0].get("freshness") if evidence_rows else {"status": "missing"}),
        }
        if cache_row is not None:
            memory["summary_text"] = (
                f"Memória para {entity_type}={entity_value}: cache {cache_row.get('freshness', {}).get('status')} "
                f"há {cache_row.get('freshness', {}).get('age_human')}."
            )
        elif evidence_rows:
            latest = evidence_rows[0]
            freshness = latest.get("freshness", {})
            memory["summary_text"] = (
                f"Memória para {entity_type}={entity_value}: evidência {latest.get('evidence_type')} "
                f"{freshness.get('status')} há {freshness.get('age_human')}."
            )
        else:
            memory["summary_text"] = f"Nenhuma memória reutilizável encontrada para {entity_type}={entity_value}."

    summary_text = memory.get("summary_text") or "Nenhuma memória disponível."
    freshness = memory.get("freshness") or {}
    status = freshness.get("dns", {}).get("status") if entity_type == "domain" else freshness.get("status", "missing")
    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "status": status,
        "summary_text": summary_text,
        "memory": memory,
    }
