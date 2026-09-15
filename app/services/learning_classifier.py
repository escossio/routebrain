from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db.connection import get_connection
from app.services.external_enrichment import get_external_asn_enrichment, get_external_ip_enrichment
from app.services.inventory_queries import get_site
from app.services.ixbr_discovery_queries import get_inventory_public_context, summarize_ixbr_vs_bgp
from app.services.learning_memory import classify_evidence_freshness, get_learning_memory_for_domain, get_recent_evidence, summarize_learning_memory

DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."


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

    try:
        with get_connection() as fresh_conn:
            with fresh_conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _fetch_one(
    sql: str,
    params: tuple[Any, ...] = (),
    *,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any] | None:
    rows = _fetch_all(sql, params, conn=conn)
    return rows[0] if rows else None


def _json_value(value: Any) -> Json:
    return Json(_safe_json(value))


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(value)
    return value


def _normalize_text(value: str | None) -> str:
    return " ".join(str(value or "").split()).strip()


def _normalize_domain(value: str) -> str:
    return _normalize_text(value).lower()


def _normalize_confidence(value: str | None, fallback: str = "suggested") -> str:
    confidence = _normalize_text(value).lower()
    if confidence in {"confirmed", "probable", "suggested", "unknown"}:
        return confidence
    return fallback


def _now() -> datetime:
    return datetime.now().astimezone()


def _freshness_confidence(freshness: dict[str, Any] | None, fallback: str = "suggested") -> str:
    status = str((freshness or {}).get("status") or "missing")
    if status == "fresh":
        return "confirmed"
    if status == "stale":
        return "probable"
    if status == "expired":
        return fallback if fallback != "unknown" else "suggested"
    return "unknown"


def _classification_row(
    *,
    entity_type: str,
    entity_value: str,
    classification_type: str,
    classification_value: str,
    confidence: str = "suggested",
    source: str | None = None,
    source_ref: str | None = None,
    reason: str | None = None,
    data: dict[str, Any] | None = None,
    computed: bool = True,
) -> dict[str, Any]:
    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "classification_type": classification_type,
        "classification_value": classification_value,
        "confidence": _normalize_confidence(confidence),
        "source": source,
        "source_ref": source_ref,
        "reason": reason,
        "data": data or {},
        "computed": computed,
    }


def _network_role_from_text(*values: Any) -> tuple[str | None, str]:
    text = " ".join(str(value or "") for value in values).lower()
    if not text.strip():
        return None, "Nenhum contexto externo suficiente para inferir papel operacional."
    if any(token in text for token in ("cloudflare", "akamai", "fastly")):
        return "cdn/edge", "Contexto externo sugere CDN/edge."
    if any(token in text for token in ("baidu", "search")):
        return "content_provider/search", "Contexto externo sugere provedor de conteúdo ou busca."
    if any(token in text for token in ("aws", "amazon", "google", "microsoft", "azure", "oracle")):
        return "cloud_provider", "Contexto externo sugere provedor de nuvem."
    if "isp" in text or "internet service" in text:
        return "isp", "Contexto externo sugere ISP."
    return None, "Contexto externo não foi suficiente para inferir um papel operacional específico."


def classify_latency(rtt_avg_ms: float | int | None) -> dict[str, Any]:
    if rtt_avg_ms is None:
        return {
            "classification_type": "latency_category",
            "classification_value": "unknown",
            "confidence": "unknown",
            "reason": "RTT médio indisponível.",
        }

    value = float(rtt_avg_ms)
    if value < 30:
        category = "low_latency"
    elif value < 100:
        category = "medium_latency"
    elif value < 250:
        category = "high_latency"
    else:
        category = "very_high_latency"
    return {
        "classification_type": "latency_category",
        "classification_value": category,
        "confidence": "confirmed",
        "reason": f"RTT médio de {value:.2f} ms.",
    }


def classify_reachability(
    packet_loss_percent: float | int | None,
    rtt_avg_ms: float | int | None = None,
) -> dict[str, Any]:
    if packet_loss_percent is None:
        return {
            "classification_type": "reachability_category",
            "classification_value": "unknown",
            "confidence": "unknown",
            "reason": "Perda de pacotes indisponível.",
        }

    loss = float(packet_loss_percent)
    if loss >= 100:
        value = "unreachable_or_filtered"
    elif loss > 0:
        value = "degraded"
    else:
        if rtt_avg_ms is None:
            value = "reachable"
        else:
            latency_value = classify_latency(rtt_avg_ms)["classification_value"]
            value = f"reachable_{latency_value}"
    return {
        "classification_type": "reachability_category",
        "classification_value": value,
        "confidence": "confirmed",
        "reason": f"Perda de pacotes de {loss:.2f}%.",
    }


def classify_route_depth(hop_count: int | None, destination_reached: bool | None = None) -> dict[str, Any]:
    if hop_count is None:
        return {
            "classification_type": "route_depth",
            "classification_value": "unknown",
            "confidence": "unknown",
            "reason": "Quantidade de hops indisponível.",
        }

    hops = max(0, int(hop_count))
    if hops <= 8:
        value = "short_path"
    elif hops <= 15:
        value = "medium_path"
    else:
        value = "long_path"

    if hops >= 20 and destination_reached is False:
        value = "possibly_incomplete"

    return {
        "classification_type": "route_depth",
        "classification_value": value,
        "confidence": "confirmed",
        "reason": f"Traceroute com {hops} hop(s).",
    }


def _known_network_matches(
    *,
    entity_type: str,
    entity_value: str,
    memory_text: str = "",
    origin_asn: int | None = None,
) -> list[dict[str, Any]]:
    rows = _fetch_all(
        """
        select
          match_type,
          match_value,
          classification_type,
          classification_value,
          confidence,
          description,
          source
        from learning_known_networks
        order by match_type asc, match_value asc, classification_type asc;
        """
    )
    entity_lower = _normalize_text(entity_value).lower()
    memory_lower = memory_text.lower()
    matches: list[dict[str, Any]] = []
    for row in rows:
        match_type = str(row.get("match_type") or "")
        match_value = str(row.get("match_value") or "")
        match_lower = match_value.lower()
        matched = False
        if entity_type == "domain" and match_type == "domain_suffix":
            matched = entity_lower == match_lower or entity_lower.endswith("." + match_lower) or entity_lower.endswith(match_lower)
        elif entity_type == "domain" and match_type == "domain_contains":
            matched = match_lower in entity_lower
        elif match_type == "organization_contains":
            matched = match_lower in memory_lower or match_lower in entity_lower
        elif match_type == "participant_name_contains":
            matched = match_lower in memory_lower
        elif match_type == "asn" and origin_asn is not None:
            matched = str(origin_asn) == match_lower
        elif match_type == "ip_prefix":
            try:
                matched = ipaddress.ip_address(entity_value) in ipaddress.ip_network(match_value, strict=False)
            except ValueError:
                matched = False
        if not matched:
            continue
        matches.append(
            _classification_row(
                entity_type=entity_type,
                entity_value=entity_value,
                classification_type=str(row.get("classification_type") or ""),
                classification_value=str(row.get("classification_value") or ""),
                confidence=str(row.get("confidence") or "suggested"),
                source=str(row.get("source") or "local_seed"),
                source_ref=f"{match_type}:{match_value}",
                reason=str(row.get("description") or ""),
                data={
                    "match_type": match_type,
                    "match_value": match_value,
                    "source": row.get("source"),
                },
            )
        )
    return matches


def _domain_memory(domain: str, memory: dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(memory, dict):
        if str(memory.get("entity_type") or "").lower() == "domain":
            return memory
        if isinstance(memory.get("memory"), dict):
            inner = memory["memory"]
            if str(inner.get("entity_type") or "").lower() == "domain":
                return inner
    return get_learning_memory_for_domain(domain)


def _ip_state_from_domain_memory(ip: str, memory: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(memory, dict):
        return None
    for item in memory.get("ips") or []:
        if isinstance(item, dict) and str(item.get("ip") or "") == str(ip):
            return item
    return None


def _latest_evidence_row(entity_type: str, entity_value: str, evidence_type: str, memory: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if entity_type == "domain" and evidence_type == "dns_resolution" and isinstance(memory, dict):
        dns = memory.get("dns") or {}
        latest = (dns.get("evidence") or [None])[0]
        if isinstance(latest, dict):
            return latest
    rows = get_recent_evidence(entity_type, entity_value, evidence_type=evidence_type, limit=1)
    return rows[0] if rows else None


def _classify_ip_from_context(ip: str, ip_state: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    state = ip_state or {}
    classifications: list[dict[str, Any]] = []

    bgp_state = state.get("bgp") or {}
    bgp_freshness = bgp_state.get("freshness") or {
        "status": bgp_state.get("status"),
        "age_human": bgp_state.get("age_human"),
    }
    bgp_latest = bgp_state.get("latest") or {}
    bgp_data = bgp_latest.get("data") or {}
    if bgp_latest:
        matched_prefix = bgp_data.get("matched_prefix")
        classifications.append(
            _classification_row(
                entity_type="ip",
                entity_value=ip,
                classification_type="bgp_coverage",
                classification_value="local_match" if matched_prefix else "no_local_match",
                confidence=_freshness_confidence(bgp_freshness, fallback=str(bgp_latest.get("confidence") or "suggested")),
                source=str(bgp_latest.get("source") or "learning_evidence"),
                source_ref=str(bgp_latest.get("request_uid") or bgp_latest.get("source_ref") or ""),
                reason=str(bgp_latest.get("summary") or ""),
                data={"matched_prefix": matched_prefix, "origin_asn": bgp_data.get("origin_asn"), "origin_type": bgp_data.get("origin_type")},
            )
        )
        origin_asn = bgp_data.get("origin_asn")
        if origin_asn is not None:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="asn_context",
                    classification_value=str(origin_asn),
                    confidence=_freshness_confidence(bgp_freshness, fallback=str(bgp_latest.get("confidence") or "suggested")),
                    source=str(bgp_latest.get("source") or "learning_evidence"),
                    source_ref=str(bgp_latest.get("request_uid") or bgp_latest.get("source_ref") or ""),
                    reason=f"origin_asn {origin_asn} derivado do BGP local.",
                    data={"origin_asn": origin_asn, "origin_type": bgp_data.get("origin_type")},
                )
            )
    else:
        classifications.append(
            _classification_row(
                entity_type="ip",
                entity_value=ip,
                classification_type="bgp_coverage",
                classification_value="unknown",
                confidence="unknown",
                source="learning_memory",
                reason="Nenhuma evidência BGP encontrada para este IP.",
            )
        )

    ping_state = state.get("ping") or {}
    ping_freshness = ping_state.get("freshness") or {
        "status": ping_state.get("status"),
        "age_human": ping_state.get("age_human"),
    }
    ping_latest = ping_state.get("latest") or {}
    ping_metrics = (ping_latest.get("data") or {}).get("metrics") or {}
    if ping_latest:
        latency = classify_latency(ping_metrics.get("rtt_avg_ms"))
        reachability = classify_reachability(ping_metrics.get("packet_loss_percent"), ping_metrics.get("rtt_avg_ms"))
        classifications.append(
            _classification_row(
                entity_type="ip",
                entity_value=ip,
                classification_type=latency["classification_type"],
                classification_value=latency["classification_value"],
                confidence=_freshness_confidence(ping_freshness, fallback=str(ping_latest.get("confidence") or "suggested")),
                source=str(ping_latest.get("source") or "learning_evidence"),
                source_ref=str(ping_latest.get("request_uid") or ping_latest.get("source_ref") or ""),
                reason=latency["reason"],
                data=ping_metrics,
            )
        )
        classifications.append(
            _classification_row(
                entity_type="ip",
                entity_value=ip,
                classification_type=reachability["classification_type"],
                classification_value=reachability["classification_value"],
                confidence=_freshness_confidence(ping_freshness, fallback=str(ping_latest.get("confidence") or "suggested")),
                source=str(ping_latest.get("source") or "learning_evidence"),
                source_ref=str(ping_latest.get("request_uid") or ping_latest.get("source_ref") or ""),
                reason=reachability["reason"],
                data=ping_metrics,
            )
        )
    else:
        classifications.append(
            _classification_row(
                entity_type="ip",
                entity_value=ip,
                classification_type="reachability_category",
                classification_value="unknown",
                confidence="unknown",
                source="learning_memory",
                reason="Nenhuma evidência de ping encontrada.",
            )
        )

    traceroute_state = state.get("traceroute") or {}
    traceroute_freshness = traceroute_state.get("freshness") or {
        "status": traceroute_state.get("status"),
        "age_human": traceroute_state.get("age_human"),
    }
    traceroute_latest = traceroute_state.get("latest") or {}
    traceroute_data = traceroute_latest.get("data") or {}
    if traceroute_latest:
        hops = traceroute_data.get("total_hops")
        hops = len(traceroute_data.get("hops") or []) if hops is None else hops
        destination_reached = False
        hop_list = traceroute_data.get("hops") or []
        if hop_list:
            last_hop = hop_list[-1] if isinstance(hop_list[-1], dict) else {}
            destination_reached = str(last_hop.get("hop_ip") or "") == str(ip)
        route_depth = classify_route_depth(hops, destination_reached=destination_reached)
        classifications.append(
            _classification_row(
                entity_type="ip",
                entity_value=ip,
                classification_type=route_depth["classification_type"],
                classification_value=route_depth["classification_value"],
                confidence=_freshness_confidence(traceroute_freshness, fallback=str(traceroute_latest.get("confidence") or "suggested")),
                source=str(traceroute_latest.get("source") or "learning_evidence"),
                source_ref=str(traceroute_latest.get("request_uid") or traceroute_latest.get("source_ref") or ""),
                reason=route_depth["reason"],
                data={"total_hops": hops, "destination_reached": destination_reached, "hops": traceroute_data.get("hops") or []},
            )
        )
    else:
        classifications.append(
            _classification_row(
                entity_type="ip",
                entity_value=ip,
                classification_type="route_depth",
                classification_value="unknown",
                confidence="unknown",
                source="learning_memory",
                reason="Nenhuma evidência de traceroute encontrada.",
            )
        )

    external_ip = None
    try:
        external_ip = get_external_ip_enrichment(ip)
    except RuntimeError:
        external_ip = None
    external_asn = None
    if isinstance(external_ip, dict) and external_ip.get("asn") is not None:
        try:
            external_asn = get_external_asn_enrichment(int(external_ip.get("asn")))
        except (RuntimeError, ValueError):
            external_asn = None

    if external_ip is not None:
        source_ref = str(external_ip.get("ip") or ip)
        asn_value = external_ip.get("asn") or (external_asn or {}).get("asn")
        if asn_value is not None:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="asn_context",
                    classification_value=str(asn_value),
                    confidence=str(external_ip.get("confidence") or (external_asn or {}).get("confidence") or "suggested"),
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="ASN confirmado por enriquecimento externo cacheado.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        country = external_ip.get("country") or (external_asn or {}).get("country")
        if country:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="country_context",
                    classification_value=str(country).upper(),
                    confidence=str(external_ip.get("confidence") or (external_asn or {}).get("confidence") or "suggested"),
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="País associado ao IP por RDAP/PeeringDB cacheado.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        organization_name = external_ip.get("organization_name") or (external_asn or {}).get("organization_name")
        if organization_name:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="organization_context",
                    classification_value=str(organization_name),
                    confidence=str(external_ip.get("confidence") or (external_asn or {}).get("confidence") or "suggested"),
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Organização confirmada por enriquecimento externo cacheado.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        network_role, role_reason = _network_role_from_text(
            organization_name,
            external_ip.get("network_name"),
            (external_asn or {}).get("organization_name"),
            (external_asn or {}).get("network_name"),
            (external_asn or {}).get("info_type"),
        )
        if network_role:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="network_role",
                    classification_value=network_role,
                    confidence="probable" if network_role in {"cdn/edge", "cloud_provider"} else "suggested",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason=role_reason,
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        text_blob = " ".join(
            str(value or "")
            for value in (
                organization_name,
                external_ip.get("network_name"),
                (external_asn or {}).get("organization_name"),
                (external_asn or {}).get("network_name"),
                (external_asn or {}).get("info_type"),
            )
        ).lower()
        if "cloudflare" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="cdn_context",
                    classification_value="cloudflare",
                    confidence="confirmed" if external_ip.get("confidence") == "confirmed" else "probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o IP à Cloudflare.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif "akamai" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="cdn_context",
                    classification_value="akamai",
                    confidence="confirmed" if external_ip.get("confidence") == "confirmed" else "probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o IP à Akamai.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif "fastly" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="cdn_context",
                    classification_value="fastly",
                    confidence="probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o IP à Fastly.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif any(token in text_blob for token in ("amazon", "aws")):
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="cloud_provider_context",
                    classification_value="aws",
                    confidence="probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o IP ao contexto AWS/Amazon.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif "google" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="ip",
                    entity_value=ip,
                    classification_type="cloud_provider_context",
                    classification_value="google",
                    confidence="probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o IP ao contexto Google.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )

    return classifications


def classify_ip(ip: str, memory: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ip_text = str(ip).strip()
    ip_state = _ip_state_from_domain_memory(ip_text, memory)
    if ip_state is None:
        bgp_rows = [
            row
            for row in get_recent_evidence("ip", ip_text, limit=20)
            if row.get("evidence_type") in {"bgp_prefix_match", "bgp_prefix_not_found", "bgp_prefix_lookup"}
        ]
        ping_rows = get_recent_evidence("ip", ip_text, "ping_measurement", limit=20)
        traceroute_rows = get_recent_evidence("ip", ip_text, "traceroute_measurement", limit=20)
        ip_state = {
            "ip": ip_text,
            "bgp": {
                "latest": bgp_rows[0] if bgp_rows else None,
                "freshness": (bgp_rows[0] or {}).get("freshness") if bgp_rows else {"status": "missing"},
            },
            "ping": {
                "latest": ping_rows[0] if ping_rows else None,
                "freshness": (ping_rows[0] or {}).get("freshness") if ping_rows else {"status": "missing"},
            },
            "traceroute": {
                "latest": traceroute_rows[0] if traceroute_rows else None,
                "freshness": (traceroute_rows[0] or {}).get("freshness") if traceroute_rows else {"status": "missing"},
            },
        }
    return _classify_ip_from_context(ip_text, ip_state)


def classify_domain(domain: str, memory: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    normalized_domain = _normalize_domain(domain)
    domain_memory = _domain_memory(normalized_domain, memory)
    classifications: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    memory_text = str(domain_memory.get("summary_text") or "")
    dns = domain_memory.get("dns")
    if not isinstance(dns, dict):
        dns = {}
    dns_freshness = dns.get("freshness") or {}
    dns_cache = dns.get("cache")
    if not isinstance(dns_cache, dict):
        dns_cache = {}
    dns_request_ref = str(dns.get("request_uid") or dns_cache.get("cache_key") or "")
    resolved_ips = [str(ip).strip() for ip in dns.get("resolved_ips") or [] if str(ip).strip()]

    for item in _known_network_matches(
        entity_type="domain",
        entity_value=normalized_domain,
        memory_text=memory_text,
    ):
        key = (item["entity_type"], item["classification_type"], item["classification_value"])
        if key in seen:
            continue
        seen.add(key)
        classifications.append(item)

    if dns_cache or dns.get("evidence"):
        classifications.append(
            _classification_row(
                entity_type="domain",
                entity_value=normalized_domain,
                classification_type="dns_context",
                classification_value="cache_available" if dns_cache else "evidence_available",
                confidence=_freshness_confidence(dns_freshness, fallback="suggested"),
                source="learning_memory",
                source_ref=dns_request_ref,
                reason=f"DNS já disponível com status {dns_freshness.get('status')}.",
                data={"resolved_ips": resolved_ips, "freshness": dns_freshness},
            )
        )

    ip_classifications: list[dict[str, Any]] = []
    for ip_state in domain_memory.get("ips") or []:
        if not isinstance(ip_state, dict):
            continue
        ip_value = str(ip_state.get("ip") or "").strip()
        if not ip_value:
            continue
        ip_classifications.extend(_classify_ip_from_context(ip_value, ip_state))

    classifications.extend(ip_classifications)

    for ip_state in domain_memory.get("ips") or []:
        if not isinstance(ip_state, dict):
            continue
        ip_value = str(ip_state.get("ip") or "").strip()
        if not ip_value:
            continue
        try:
            external_ip = get_external_ip_enrichment(ip_value)
        except RuntimeError:
            external_ip = None
        if external_ip is None:
            continue
        external_asn = None
        if external_ip.get("asn") is not None:
            try:
                external_asn = get_external_asn_enrichment(int(external_ip.get("asn")))
            except (RuntimeError, ValueError):
                external_asn = None
        source_ref = str(external_ip.get("ip") or ip_value)
        organization_name = external_ip.get("organization_name") or (external_asn or {}).get("organization_name")
        country = external_ip.get("country") or (external_asn or {}).get("country")
        asn_value = external_ip.get("asn") or (external_asn or {}).get("asn")
        if asn_value is not None:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="asn_context",
                    classification_value=str(asn_value),
                    confidence=str(external_ip.get("confidence") or (external_asn or {}).get("confidence") or "suggested"),
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="ASN associado ao domínio por IP resolvido e enriquecimento externo cacheado.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        if country:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="country_context",
                    classification_value=str(country).upper(),
                    confidence=str(external_ip.get("confidence") or (external_asn or {}).get("confidence") or "suggested"),
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="País associado ao domínio por IP resolvido e enriquecimento externo cacheado.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        if organization_name:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="organization_context",
                    classification_value=str(organization_name),
                    confidence=str(external_ip.get("confidence") or (external_asn or {}).get("confidence") or "suggested"),
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Organização associada ao domínio por IP resolvido e enriquecimento externo cacheado.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        network_role, role_reason = _network_role_from_text(
            organization_name,
            external_ip.get("network_name"),
            (external_asn or {}).get("organization_name"),
            (external_asn or {}).get("network_name"),
            (external_asn or {}).get("info_type"),
        )
        if network_role:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="network_role",
                    classification_value=network_role,
                    confidence="probable" if network_role in {"cdn/edge", "cloud_provider"} else "suggested",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason=role_reason,
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        text_blob = " ".join(
            str(value or "")
            for value in (
                organization_name,
                external_ip.get("network_name"),
                (external_asn or {}).get("organization_name"),
                (external_asn or {}).get("network_name"),
                (external_asn or {}).get("info_type"),
            )
        ).lower()
        if "cloudflare" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="cdn_context",
                    classification_value="cloudflare",
                    confidence="confirmed" if external_ip.get("confidence") == "confirmed" else "probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o domínio à Cloudflare.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif "akamai" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="cdn_context",
                    classification_value="akamai",
                    confidence="confirmed" if external_ip.get("confidence") == "confirmed" else "probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o domínio à Akamai.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif "fastly" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="cdn_context",
                    classification_value="fastly",
                    confidence="probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o domínio à Fastly.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif any(token in text_blob for token in ("amazon", "aws")):
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="cloud_provider_context",
                    classification_value="aws",
                    confidence="probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o domínio ao contexto AWS/Amazon.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )
        elif "google" in text_blob:
            classifications.append(
                _classification_row(
                    entity_type="domain",
                    entity_value=normalized_domain,
                    classification_type="cloud_provider_context",
                    classification_value="google",
                    confidence="probable",
                    source="external_ip_enrichment",
                    source_ref=source_ref,
                    reason="Enriquecimento externo associou o domínio ao contexto Google.",
                    data={"external_ip_enrichment": external_ip, "external_asn_enrichment": external_asn},
                )
            )

    latency_values = [
        item["classification_value"]
        for item in ip_classifications
        if item["classification_type"] == "latency_category" and item["classification_value"] != "unknown"
    ]
    reachability_values = [
        item["classification_value"]
        for item in ip_classifications
        if item["classification_type"] == "reachability_category" and item["classification_value"] != "unknown"
    ]
    route_depth_values = [
        item["classification_value"]
        for item in ip_classifications
        if item["classification_type"] == "route_depth" and item["classification_value"] != "unknown"
    ]

    if any(item["classification_value"] == "cloudflare" for item in classifications if item["classification_type"] == "cdn_context"):
        route_category = "cdn_anycast"
    elif any(item["classification_value"] == "CN" for item in classifications if item["classification_type"] == "country_context") and any(
        value in {"high_latency", "very_high_latency"} for value in latency_values
    ):
        route_category = "international_high_latency"
    elif any(value in {"long_path", "possibly_incomplete"} for value in route_depth_values):
        route_category = "long_or_incomplete"
    elif any(value.startswith("reachable_") for value in reachability_values):
        route_category = "reachable"
    else:
        route_category = "unknown"

    route_reason = "Classificação derivada de contexto operacional."
    if route_category == "cdn_anycast":
        route_reason = "Heurística de CDN/Anycast aplicada ao domínio."
    elif route_category == "international_high_latency":
        route_reason = "Contexto de país e latência sugerem caminho internacional de alta latência."
    elif route_category == "long_or_incomplete":
        route_reason = "Traceroute longo ou incompleto observado."

    classifications.append(
        _classification_row(
            entity_type="domain",
            entity_value=normalized_domain,
            classification_type="route_category",
            classification_value=route_category,
            confidence="probable" if route_category != "unknown" else "unknown",
            source="learning_classifier",
            source_ref=dns_request_ref,
            reason=route_reason,
            data={
                "latency_values": latency_values,
                "reachability_values": reachability_values,
                "route_depth_values": route_depth_values,
            },
        )
    )

    return classifications


def classify_site(site_code: str, memory: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    normalized_site = _normalize_text(site_code).upper()
    classifications: list[dict[str, Any]] = []
    site = get_site(normalized_site)
    public_context = None
    if normalized_site == "PTT-CE":
        try:
            public_context = get_inventory_public_context(site_code=normalized_site, locality_code="CE", limit=20)
        except RuntimeError:
            public_context = None

    if site is not None:
        host_count = int(site.get("host_count") or 0)
        classifications.append(
            _classification_row(
                entity_type="site",
                entity_value=normalized_site,
                classification_type="inventory_status",
                classification_value="no_confirmed_internal_hosts" if host_count == 0 else "confirmed_internal_hosts",
                confidence="confirmed",
                source="inventory",
                source_ref=normalized_site,
                reason=(
                    f"Inventário do site {normalized_site} tem {host_count} host(s) confirmados."
                    if host_count > 0
                    else f"Inventário do site {normalized_site} ainda não confirma hosts internos."
                ),
                data={"host_count": host_count},
            )
        )

    if public_context is not None:
        classifications.append(
            _classification_row(
                entity_type="site",
                entity_value=normalized_site,
                classification_type="network_role",
                classification_value="public_ix_context",
                confidence="probable",
                source="ixbr_discovery_queries.get_inventory_public_context",
                source_ref=normalized_site,
                reason=(
                    f"Contexto público IX.br para {normalized_site} com "
                    f"{int(public_context.get('public_participants_count') or 0)} participantes."
                ),
                data=public_context,
            )
        )
        classifications.append(
            _classification_row(
                entity_type="site",
                entity_value=normalized_site,
                classification_type="route_category",
                classification_value="public_ix_context",
                confidence="probable",
                source="ixbr_discovery_queries.summarize_ixbr_vs_bgp",
                source_ref=normalized_site,
                reason="Contexto operacional orientado por IX.br público.",
                data=public_context.get("bgp_summary") or {},
            )
        )
    elif normalized_site == "PTT-CE":
        classifications.append(
            _classification_row(
                entity_type="site",
                entity_value=normalized_site,
                classification_type="network_role",
                classification_value="public_ix_context",
                confidence="suggested",
                source="learning_classifier",
                source_ref=normalized_site,
                reason="PTT-CE costuma ser tratado como contexto público de IX.br.",
                data={},
            )
        )

    return classifications


def _load_request_bundle(request_uid: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
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
        conn=conn,
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
        conn=conn,
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
        conn=conn,
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
        conn=conn,
    )
    return {
        "request": request_row,
        "entities": entities,
        "evidence": evidence,
        "classifications": classifications,
    }


def _persist_classifications(
    conn: psycopg.Connection,
    *,
    request_id: int,
    classifications: list[dict[str, Any]],
) -> None:
    if not classifications:
        return
    with conn.cursor() as cur:
        for classification in classifications:
            cur.execute(
                """
                insert into learning_classifications (
                  request_id,
                  entity_type,
                  entity_value,
                  classification_type,
                  classification_value,
                  confidence,
                  source,
                  source_ref,
                  reason,
                  data
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    request_id,
                    classification.get("entity_type"),
                    classification.get("entity_value"),
                    classification.get("classification_type"),
                    classification.get("classification_value"),
                    classification.get("confidence"),
                    classification.get("source"),
                    classification.get("source_ref"),
                    classification.get("reason"),
                    _json_value(classification.get("data") or {}),
                ),
            )


def _unique_classifications(classifications: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for classification in classifications:
        key = (
            str(classification.get("entity_type") or ""),
            str(classification.get("entity_value") or ""),
            str(classification.get("classification_type") or ""),
            str(classification.get("classification_value") or ""),
            str(classification.get("source") or ""),
            str(classification.get("source_ref") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(classification)
    return unique


def _classify_request_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    request_row = bundle["request"]
    entities = bundle["entities"]
    classifications: list[dict[str, Any]] = []
    request_memory: dict[str, Any] | None = None
    memory_summary: dict[str, Any] | None = None

    domain_entities = [entity for entity in entities if entity.get("entity_type") == "domain"]
    site_entities = [entity for entity in entities if entity.get("entity_type") == "site"]
    ip_entities = [entity for entity in entities if entity.get("entity_type") == "ip"]

    if domain_entities:
        domain_value = str(domain_entities[0].get("normalized_value") or domain_entities[0].get("entity_value") or "").strip()
        if domain_value:
            memory_summary = summarize_learning_memory({"entity_type": "domain", "entity_value": domain_value})
            request_memory = memory_summary.get("memory") if isinstance(memory_summary, dict) else None
            classifications.extend(classify_domain(domain_value, memory=request_memory))

    for entity in site_entities:
        site_value = str(entity.get("normalized_value") or entity.get("entity_value") or "").strip()
        if site_value:
            classifications.extend(classify_site(site_value))

    if request_memory is None and ip_entities:
        request_memory = None
    for entity in ip_entities:
        ip_value = str(entity.get("normalized_value") or entity.get("entity_value") or "").strip()
        if ip_value:
            classifications.extend(classify_ip(ip_value, memory=request_memory))

    classifications = _unique_classifications(classifications)
    summary_lines = [
        f"{item['entity_type']}={item['entity_value']} {item['classification_type']}={item['classification_value']} ({item['confidence']})"
        for item in classifications[:12]
    ]
    return {
        "request_uid": request_row.get("request_uid"),
        "request_id": request_row.get("id"),
        "classifications": classifications,
        "summary_text": "; ".join(summary_lines) if summary_lines else "Nenhuma classificação operacional calculada.",
        "memory": request_memory,
        "memory_summary": memory_summary,
    }


def classify_learning_request(
    request_uid: str,
    *,
    persist: bool = True,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    bundle = _load_request_bundle(request_uid, conn=conn)
    if bundle is None:
        raise ValueError("Request não encontrada.")
    result = _classify_request_bundle(bundle)
    if persist and result["classifications"]:
        request_id = int(result["request_id"])
        if conn is not None:
            _persist_classifications(conn, request_id=request_id, classifications=result["classifications"])
        else:
            with get_connection() as fresh_conn:
                _persist_classifications(fresh_conn, request_id=request_id, classifications=result["classifications"])
        result["persisted"] = True
    else:
        result["persisted"] = False
    return result


def get_request_classifications(request_uid: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
    bundle = _load_request_bundle(request_uid, conn=conn)
    if bundle is None:
        return None
    return {
        "request_uid": request_uid,
        "request": bundle["request"],
        "classifications": bundle["classifications"],
        "summary_text": (
            "; ".join(
                f"{row.get('entity_type')}={row.get('entity_value')} {row.get('classification_type')}={row.get('classification_value')} ({row.get('confidence')})"
                for row in bundle["classifications"][:12]
            )
            if bundle["classifications"]
            else "Nenhuma classificação persistida para esta request."
        ),
    }


def get_classifications_for_entity(
    entity_type: str,
    entity_value: str,
    *,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    normalized_type = _normalize_text(entity_type).lower()
    normalized_value = _normalize_text(entity_value)
    stored = _fetch_all(
        """
        select
          c.id,
          c.request_id,
          r.request_uid,
          r.question,
          r.intent,
          r.status as request_status,
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
        where c.entity_type = %s
          and c.entity_value = %s
        order by c.created_at desc, c.id desc;
        """,
        (normalized_type, normalized_value),
        conn=conn,
    )

    if stored:
        related_requests = _fetch_all(
            """
            select distinct on (r.request_uid)
              r.request_uid,
              r.question,
              r.intent,
              r.status,
              r.created_at,
              r.updated_at
            from learning_classifications c
            join learning_requests r on r.id = c.request_id
            where c.entity_type = %s
              and c.entity_value = %s
            order by r.request_uid, r.created_at desc, r.id desc;
            """,
            (normalized_type, normalized_value),
            conn=conn,
        )
        return {
            "entity_type": normalized_type,
            "entity_value": normalized_value,
            "status": "stored",
            "classifications": stored,
            "related_requests": related_requests,
            "summary_text": (
                "; ".join(
                    f"{row.get('classification_type')}={row.get('classification_value')} ({row.get('confidence')})"
                    for row in stored[:12]
                )
            ),
        }

    computed: list[dict[str, Any]] = []
    memory: dict[str, Any] | None = None
    if normalized_type == "domain":
        memory = summarize_learning_memory({"entity_type": "domain", "entity_value": normalized_value}, conn=conn)
        if isinstance(memory, dict):
            computed = classify_domain(normalized_value, memory=memory.get("memory"))
    elif normalized_type == "ip":
        memory = summarize_learning_memory({"entity_type": "ip", "entity_value": normalized_value}, conn=conn)
        if isinstance(memory, dict):
            computed = classify_ip(normalized_value, memory=memory.get("memory"))
    elif normalized_type == "site":
        computed = classify_site(normalized_value)

    related_requests = _fetch_all(
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
        limit 10;
        """,
        (normalized_type, normalized_value),
        conn=conn,
    )
    return {
        "entity_type": normalized_type,
        "entity_value": normalized_value,
        "status": "computed",
        "classifications": computed,
        "related_requests": related_requests,
        "memory": memory.get("memory") if isinstance(memory, dict) else memory,
        "summary_text": (
            "; ".join(
                f"{row.get('classification_type')}={row.get('classification_value')} ({row.get('confidence')})"
                for row in computed[:12]
            )
            if computed
            else f"Nenhuma classificação operacional disponível para {normalized_type}={normalized_value}."
        ),
    }


def list_known_networks(*, conn: psycopg.Connection | None = None) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          id,
          match_type,
          match_value,
          classification_type,
          classification_value,
          confidence,
          description,
          source,
          created_at,
          updated_at
        from learning_known_networks
        order by match_type asc, match_value asc, classification_type asc, classification_value asc;
        """,
        conn=conn,
    )
