from __future__ import annotations

import ipaddress
from collections import Counter
import json
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from psycopg.rows import dict_row

from app.db.connection import get_connection
from app.services.external_enrichment import enrich_asn, enrich_ip, get_external_asn_enrichment, get_external_ip_enrichment
from app.services.bgp_operational_queries import lookup_bgp_by_ip
from app.services.bgp_visibility import build_bgp_visibility_response


def is_public_destination(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(
        (
            addr.is_private,
            addr.is_loopback,
            addr.is_link_local,
            addr.is_multicast,
            addr.is_reserved,
            addr.is_unspecified,
            getattr(addr, "is_site_local", False),
        )
    )


def normalize_protocol(protocol: Any) -> str | None:
    if protocol is None:
        return None
    text = str(protocol).strip().lower()
    return text or None


def normalize_port(port: Any) -> int | None:
    if port in (None, ""):
        return None
    try:
        value = int(port)
    except (TypeError, ValueError):
        return None
    if 0 <= value <= 65535:
        return value
    return None


_DNS_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}


def _bgp_match_payload(bgp_row: dict[str, Any] | None) -> dict[str, Any]:
    if not bgp_row:
        return {
            "matched": False,
            "source": "bgp_current_routes",
            "confidence": "no_bgp_match",
        }
    prefix = bgp_row.get("matched_prefix") or bgp_row.get("prefix")
    origin_asn = bgp_row.get("origin_asn")
    if origin_asn is None:
        origin_asn = bgp_row.get("peer_asn")
    return {
        "matched": bool(prefix and origin_asn is not None),
        "prefix": prefix,
        "origin_asn": origin_asn,
        "route_count": bgp_row.get("match_route_count") or len(bgp_row.get("current_routes") or []),
        "peer_count": bgp_row.get("peer_count") or len(bgp_row.get("peer_counts") or []),
        "source": "bgp_current_routes",
        "confidence": "observed_bgp_match" if prefix and origin_asn is not None else "no_bgp_match",
        "origin_type": bgp_row.get("origin_type"),
    }


def resolve_observed_destination_asn_from_bgp(destination_ip: str) -> dict[str, Any]:
    try:
        normalized_ip = str(ipaddress.ip_address(destination_ip))
    except ValueError as exc:
        return {
            "matched": False,
            "source": "bgp_current_routes",
            "confidence": "invalid_ip",
            "error": str(exc),
        }
    try:
        bgp_row = lookup_bgp_by_ip(normalized_ip)
    except Exception as exc:
        return {
            "matched": False,
            "source": "bgp_current_routes",
            "confidence": "bgp_lookup_error",
            "error": str(exc),
        }
    payload = _bgp_match_payload(bgp_row)
    payload["destination_ip"] = normalized_ip
    if not payload.get("matched"):
        payload.pop("prefix", None)
        payload.pop("origin_asn", None)
        payload.pop("route_count", None)
        payload.pop("peer_count", None)
    return payload


def categorize_destination(
    asn: int | None,
    organization: str | None,
    domain_guess: str | None = None,
) -> str | None:
    org = (organization or "").lower()
    domain = (domain_guess or "").lower()
    if str(domain_guess or "").lower() in _DNS_IPS:
        return "security_dns"
    if asn in {13335} or "cloudflare" in org:
        return "cdn"
    if asn in {20940} or "akamai" in org:
        return "cdn"
    if asn in {54113} or "fastly" in org:
        return "cdn"
    if asn in {15169} and ("youtube" in domain or "googlevideo" in domain):
        return "video"
    if asn in {2906} or "netflix" in domain:
        return "video"
    if asn in {32934} or any(term in org for term in ("meta", "facebook", "instagram", "whatsapp")):
        return "social"
    if asn in {16509} or "amazon" in org or "aws" in org:
        return "cloud"
    if asn in {8075} or "microsoft" in org:
        return "software_update" if "update" in domain or "windows" in domain else "cloud"
    if asn in {15169} or "google" in org:
        if str(domain_guess or "").lower() in {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}:
            return "security_dns"
        if "youtube" in domain or "googlevideo" in domain:
            return "video"
        return "cloud"
    if asn in {36692} or "cloudflare dns" in domain or "security" in domain or "resolver" in domain or "dns" in domain:
        return "security_dns"
    if str(domain_guess or "").lower() in {"windowsupdate", "update", "apple.com"}:
        return "software_update"
    if domain_guess and any(ip in domain for ip in ("dns", "resolver")):
        return "dns"
    if asn is None and organization is None and not domain_guess:
        return "unknown"
    return "unknown"


def _row_to_dict(row: dict[str, Any] | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        key_text = str(key).lower()
        if any(token in key_text for token in ("src-address", "source-address", "payload", "query", "uri", "url")):
            continue
        clean[key] = value
    return clean


def _parse_cymru_output(output: str) -> dict[str, Any]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return {"matched": False, "source": "whois_cymru", "confidence": "no_match"}
    header = lines[0].lower()
    if "as" not in header or "ip" not in header:
        return {"matched": False, "source": "whois_cymru", "confidence": "no_match"}
    row = lines[1]
    parts = [part.strip() for part in row.split("|")]
    if len(parts) < 7:
        return {"matched": False, "source": "whois_cymru", "confidence": "no_match"}
    asn_text, ip_text, prefix_text, country, registry, allocated, as_name = parts[:7]
    try:
        asn_value = int(asn_text)
    except ValueError:
        return {"matched": False, "source": "whois_cymru", "confidence": "no_match"}
    return {
        "matched": True,
        "asn": asn_value,
        "prefix": prefix_text or None,
        "country": country or None,
        "organization": as_name or None,
        "source": "whois_cymru",
        "confidence": "external_inferred",
        "raw": {
            "ip": ip_text or None,
            "registry": registry or None,
            "allocated": allocated or None,
        },
    }


def resolve_observed_destination_asn_external(destination_ip: str, timeout_seconds: int = 6) -> dict[str, Any]:
    try:
        normalized_ip = str(ipaddress.ip_address(destination_ip))
    except ValueError as exc:
        return {
            "matched": False,
            "source": "whois_cymru",
            "confidence": "invalid_ip",
            "error": str(exc),
        }
    if shutil.which("whois") is None:
        return {
            "matched": False,
            "source": "whois_cymru",
            "confidence": "whois_unavailable",
        }
    try:
        completed = subprocess.run(
            ["whois", "-h", "whois.cymru.com", f" -v {normalized_ip}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except Exception as exc:
        return {
            "matched": False,
            "source": "whois_cymru",
            "confidence": "whois_error",
            "error": str(exc),
        }
    if completed.returncode != 0 and not completed.stdout:
        return {
            "matched": False,
            "source": "whois_cymru",
            "confidence": "whois_error",
            "error": (completed.stderr or "").strip() or "whois failed",
        }
    payload = _parse_cymru_output(completed.stdout or "")
    payload["destination_ip"] = normalized_ip
    return payload


def upsert_observed_destination(
    destination_ip: str,
    destination_port: int | None,
    protocol: str | None,
    source: str,
    run_uid: str,
    metadata: dict[str, Any] | None = None,
) -> bool:
    metadata = _sanitize_metadata(metadata)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into observed_destinations (
                    destination_ip, destination_port, protocol, source, last_run_uid,
                    observation_count, first_seen, last_seen, metadata, enrichment_status
                )
                values (
                    %s::inet, %s, %s, %s, %s,
                    1, now(), now(), %s::jsonb, 'pending'
                )
                on conflict (destination_ip, destination_port, protocol, source)
                do update set
                    last_seen = now(),
                    last_run_uid = excluded.last_run_uid,
                    observation_count = observed_destinations.observation_count + 1,
                    metadata = observed_destinations.metadata || excluded.metadata
                returning (xmax = 0) as inserted
                """,
                (destination_ip, destination_port, protocol, source, run_uid, json.dumps(metadata)),
            )
            row = cur.fetchone()
        conn.commit()
    return bool(row and row["inserted"])


def upsert_observed_destination_run_item(
    run_uid: str,
    destination_ip: str,
    destination_port: int | None,
    protocol: str | None,
    observation_count: int = 1,
    metadata: dict[str, Any] | None = None,
) -> bool:
    metadata = _sanitize_metadata(metadata)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into observed_destination_run_items (
                    run_uid, destination_ip, destination_port, protocol, observation_count, asn, asn_source,
                    bgp_confirmed, asn_confidence, organization, country, category, domain_guess,
                    enrichment_status, metadata, observed_at
                )
                select
                    %s,
                    %s::inet,
                    %s,
                    %s,
                    %s,
                    asn,
                    asn_source,
                    coalesce(bgp_confirmed, false),
                    asn_confidence,
                    organization,
                    country,
                    category,
                    domain_guess,
                    enrichment_status,
                    %s::jsonb,
                    now()
                from observed_destinations
                where destination_ip = %s::inet
                  and destination_port is not distinct from %s
                  and protocol is not distinct from %s
                order by last_seen desc
                limit 1
                on conflict (run_uid, destination_ip, destination_port, protocol)
                do update set
                    observed_at = now(),
                    observation_count = greatest(observed_destination_run_items.observation_count, excluded.observation_count),
                    metadata = observed_destination_run_items.metadata || excluded.metadata
                returning (xmax = 0) as inserted
                """,
                (
                    run_uid,
                    destination_ip,
                    destination_port,
                    protocol,
                    max(1, int(observation_count)),
                    json.dumps(metadata),
                    destination_ip,
                    destination_port,
                    protocol,
                ),
            )
            row = cur.fetchone()
        conn.commit()
    return bool(row and row["inserted"])


def upsert_observed_dns(
    domain: str,
    address: str,
    ttl: int | None,
    source: str,
    run_uid: str,
    metadata: dict[str, Any] | None = None,
) -> bool:
    metadata = metadata or {}
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into observed_destination_dns (
                    domain, address, ttl, source, last_run_uid, first_seen, last_seen, metadata
                )
                values (%s, %s::inet, %s, %s, %s, now(), now(), %s::jsonb)
                on conflict (domain, address, source)
                do update set
                    last_seen = now(),
                    last_run_uid = excluded.last_run_uid,
                    ttl = coalesce(excluded.ttl, observed_destination_dns.ttl),
                    metadata = observed_destination_dns.metadata || excluded.metadata
                returning (xmax = 0) as inserted
                """,
                (domain, address, ttl, source, run_uid, json.dumps(metadata)),
            )
            row = cur.fetchone()
        conn.commit()
    return bool(row and row["inserted"])


def list_top_observed_destinations(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select host(destination_ip) as destination_ip,
                       destination_port,
                       protocol,
                       observation_count,
                       first_seen,
                       last_seen,
                       asn,
                       asn_source,
                       bgp_confirmed,
                       asn_confidence,
                       metadata->>'bgp_prefix' as bgp_prefix,
                       (metadata->>'bgp_route_count')::bigint as bgp_route_count,
                       (metadata->>'bgp_peer_count')::bigint as bgp_peer_count,
                       metadata->>'bgp_match_confidence' as bgp_match_confidence,
                       metadata->>'external_asn' as external_asn,
                       organization,
                       country,
                       domain_guess,
                       category,
                       enrichment_status
                from observed_destinations
                order by observation_count desc, last_seen desc, destination_ip asc
                limit %s
                """,
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]


def list_top_observed_asns(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select asn,
                       coalesce(asn_source, case when asn is not null then 'bgp' end) as asn_source,
                       organization,
                       country,
                       count(*)::bigint as destination_count,
                       sum(observation_count)::bigint as total_observations,
                       count(*) filter (where bgp_confirmed)::bigint as bgp_confirmed_count,
                       count(*) filter (where asn_source = 'external')::bigint as external_inferred_count,
                       array_agg(distinct category) filter (where category is not null) as categories,
                       array_agg(distinct metadata->>'bgp_prefix') filter (where metadata ? 'bgp_prefix') as bgp_prefixes,
                       jsonb_agg(
                           jsonb_build_object(
                               'destination_ip', host(destination_ip),
                               'destination_port', destination_port,
                               'protocol', protocol,
                               'observation_count', observation_count
                           )
                           order by observation_count desc, last_seen desc
                       ) filter (where destination_ip is not null) as top_destinations
                from observed_destinations
                where asn is not null
                group by asn, asn_source, organization, country
                order by total_observations desc, destination_count desc, asn asc
                limit %s
                """,
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]


def get_observed_destination(ip: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select host(destination_ip) as destination_ip,
                       destination_port,
                       protocol,
                       first_seen,
                       last_seen,
                       observation_count,
                       source,
                       last_run_uid,
                       asn,
                       asn_source,
                       bgp_confirmed,
                       asn_confidence,
                       metadata->>'bgp_prefix' as bgp_prefix,
                       (metadata->>'bgp_route_count')::bigint as bgp_route_count,
                       (metadata->>'bgp_peer_count')::bigint as bgp_peer_count,
                       metadata->>'bgp_match_confidence' as bgp_match_confidence,
                       metadata->>'external_asn' as external_asn,
                       organization,
                       country,
                       reverse_dns,
                       domain_guess,
                       category,
                       enrichment_status,
                       metadata
                from observed_destinations
                where destination_ip = %s::inet
                order by observation_count desc, last_seen desc
                limit 1
                """,
                (ip,),
            )
            return _row_to_dict(cur.fetchone())


def list_unenriched_observed_destinations(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select host(destination_ip) as destination_ip,
                       destination_port,
                       protocol,
                       observation_count,
                       first_seen,
                       last_seen,
                       source,
                       last_run_uid,
                       asn,
                       asn_source,
                       bgp_confirmed,
                       asn_confidence,
                       metadata->>'bgp_prefix' as bgp_prefix,
                       (metadata->>'bgp_route_count')::bigint as bgp_route_count,
                       (metadata->>'bgp_peer_count')::bigint as bgp_peer_count,
                       metadata->>'bgp_match_confidence' as bgp_match_confidence,
                       metadata->>'external_asn' as external_asn,
                       organization,
                       country,
                       domain_guess,
                       category,
                       enrichment_status
                from observed_destinations
                where enrichment_status in ('pending', 'error', 'stale')
                order by last_seen desc
                limit %s
                """,
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]


def list_observed_destinations_missing_asn(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select host(destination_ip) as destination_ip,
                       destination_port,
                       protocol,
                       observation_count,
                       first_seen,
                       last_seen,
                       source,
                       last_run_uid,
                       asn,
                       asn_source,
                       bgp_confirmed,
                       asn_confidence,
                       organization,
                       country,
                       domain_guess,
                       category,
                       enrichment_status
                from observed_destinations
                where asn is null
                order by last_seen desc
                limit %s
                """,
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]


def _destination_summary_from_enrichment(ip: str, enrichment: dict[str, Any] | None) -> dict[str, Any]:
    data = enrichment or {}
    normalized = data.get("normalized") or {}
    rdap = data.get("cache", {}).get("rdap") if isinstance(data.get("cache"), dict) else None
    return {
        "asn": normalized.get("asn") or data.get("asn"),
        "organization": normalized.get("organization_name") or normalized.get("organization") or data.get("organization_name"),
        "country": normalized.get("country") or data.get("country"),
        "reverse_dns": normalized.get("reverse_dns") or data.get("reverse_dns"),
        "enrichment_status": "enriched" if data else "no_data",
        "source": "rdap+peeringdb" if normalized else (data.get("source") or "external"),
        "raw": {
            "status": data.get("status"),
            "confidence": data.get("confidence"),
            "summary": data.get("summary_text"),
            "freshness": data.get("freshness"),
            "rdap_cached": bool(rdap),
        },
    }


def enrich_observed_destination_ip(
    destination_ip: str,
    refresh: bool = False,
    resolve_bgp: bool = True,
    allow_external_asn: bool = True,
) -> dict[str, Any]:
    try:
        normalized_ip = str(ipaddress.ip_address(destination_ip))
    except ValueError as exc:
        return {"status": "error", "error": str(exc), "destination_ip": destination_ip}

    enrichment = None
    try:
        enrichment = enrich_ip(normalized_ip, force_refresh=refresh, allow_external=True)
    except Exception as exc:
        enrichment = {"status": "error", "error": str(exc)}

    summary = _destination_summary_from_enrichment(normalized_ip, enrichment)
    metadata: dict[str, Any] = {}
    asn_value = summary.get("asn")
    asn_source = "none"
    bgp_confirmed = False
    asn_confidence = "no_match"
    bgp_match: dict[str, Any] | None = None
    if resolve_bgp:
        bgp_match = resolve_observed_destination_asn_from_bgp(normalized_ip)
        metadata["bgp_match"] = {k: v for k, v in (bgp_match or {}).items() if k not in {"destination_ip", "error"}}
        if bgp_match.get("matched") and bgp_match.get("origin_asn") is not None:
            asn_value = int(bgp_match["origin_asn"])
            asn_source = "bgp"
            bgp_confirmed = True
            asn_confidence = "observed_bgp_match"
            summary["bgp_prefix"] = bgp_match.get("prefix")
            summary["bgp_route_count"] = bgp_match.get("route_count")
            summary["bgp_peer_count"] = bgp_match.get("peer_count")
            summary["bgp_match_confidence"] = bgp_match.get("confidence")
        else:
            summary["bgp_match_confidence"] = bgp_match.get("confidence") if bgp_match else None
    external_asn = None
    if asn_value is None and allow_external_asn:
        external_ip = get_external_ip_enrichment(normalized_ip)
        if external_ip and external_ip.get("asn") is not None:
            external_asn = int(external_ip["asn"])
            asn_value = external_asn
            asn_source = str(external_ip.get("source") or "external")
            asn_confidence = "external_inferred"
            bgp_confirmed = False
            metadata["external_asn"] = external_asn
            metadata["external_asn_source"] = asn_source
        elif enrichment:
            normalized = enrichment.get("normalized") or {}
            rdap_asn = normalized.get("asn")
            if rdap_asn is not None:
                external_asn = int(rdap_asn)
                asn_value = external_asn
                asn_source = "rdap"
                asn_confidence = "rdap_inferred"
                metadata["external_asn"] = external_asn
                metadata["external_asn_source"] = asn_source
    if asn_value is None and allow_external_asn:
        whois_external = resolve_observed_destination_asn_external(normalized_ip)
        if whois_external.get("matched") and whois_external.get("asn") is not None:
            external_asn = int(whois_external["asn"])
            asn_value = external_asn
            asn_source = "external"
            asn_confidence = "external_inferred"
            bgp_confirmed = False
            metadata["external_asn"] = external_asn
            metadata["external_asn_source"] = whois_external.get("source")
            metadata["external_asn_prefix"] = whois_external.get("prefix")
            if whois_external.get("raw"):
                metadata["external_asn_raw"] = whois_external.get("raw")
        elif not bgp_match or not bgp_match.get("matched"):
            metadata["external_error"] = whois_external.get("error") if isinstance(whois_external, dict) else None
    if asn_value is not None:
        try:
            asn_enrichment = get_external_asn_enrichment(int(asn_value))
            if asn_enrichment is None:
                asn_enrichment = enrich_asn(int(asn_value), allow_external=True)
            if asn_enrichment:
                summary["organization"] = summary.get("organization") or asn_enrichment.get("organization_name")
                summary["country"] = summary.get("country") or asn_enrichment.get("country")
                if not summary.get("reverse_dns"):
                    summary["reverse_dns"] = asn_enrichment.get("network_name")
                if resolve_bgp and bgp_match and bgp_match.get("matched") and bgp_match.get("origin_asn") is not None:
                    rdap_asn = asn_enrichment.get("asn")
                    if rdap_asn is not None and int(rdap_asn) != int(bgp_match["origin_asn"]):
                        metadata["asn_conflict"] = {
                            "bgp_origin_asn": int(bgp_match["origin_asn"]),
                            "external_asn": int(rdap_asn),
                            "decision": "kept_bgp_origin_asn",
                        }
                        asn_confidence = "conflict_kept_bgp"
        except Exception:
            pass
        summary["asn"] = int(asn_value)
    if asn_value is None and summary.get("organization") is None and summary.get("country") is None:
        summary["enrichment_status"] = "no_data"
    elif bgp_match and not bgp_match.get("matched") and summary.get("asn") is None:
        summary["enrichment_status"] = "no_match"
        if summary.get("organization") or summary.get("country"):
            asn_confidence = "organization_only"
    summary["asn_source"] = asn_source
    summary["bgp_confirmed"] = bgp_confirmed
    summary["asn_confidence"] = asn_confidence
    category = categorize_destination(summary.get("asn"), summary.get("organization"), summary.get("reverse_dns"))
    metadata["enrichment"] = summary.get("raw") or {}
    metadata["asn_source"] = summary.get("asn_source")
    metadata["bgp_confirmed"] = summary.get("bgp_confirmed")
    metadata["asn_confidence"] = summary.get("asn_confidence")
    metadata["category"] = category
    if summary.get("bgp_prefix") is not None:
        metadata["bgp_prefix"] = summary.get("bgp_prefix")
    if summary.get("bgp_route_count") is not None:
        metadata["bgp_route_count"] = summary.get("bgp_route_count")
    if summary.get("bgp_peer_count") is not None:
        metadata["bgp_peer_count"] = summary.get("bgp_peer_count")
    if summary.get("bgp_match_confidence") is not None:
        metadata["bgp_match_confidence"] = summary.get("bgp_match_confidence")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update observed_destinations
                set asn = %s,
                    asn_source = %s,
                    bgp_confirmed = %s,
                    asn_confidence = %s,
                    organization = %s,
                    country = %s,
                    reverse_dns = %s,
                    category = %s,
                    enrichment_status = %s,
                    metadata = coalesce(metadata, '{}'::jsonb) || %s::jsonb
                where destination_ip = %s::inet
                """,
                (
                    summary.get("asn"),
                    summary.get("asn_source"),
                    summary.get("bgp_confirmed"),
                    summary.get("asn_confidence"),
                    summary.get("organization"),
                    summary.get("country"),
                    summary.get("reverse_dns"),
                    category,
                    summary.get("enrichment_status") or ("enriched" if summary.get("asn") or summary.get("organization") or summary.get("country") else "no_data"),
                    json.dumps(_sanitize_metadata(metadata)),
                    normalized_ip,
                ),
            )
        conn.commit()
    return {"status": "ok", "destination_ip": normalized_ip, **summary, "category": category, "enrichment": enrichment, "metadata": _sanitize_metadata(metadata)}


def enrich_pending_observed_destinations(
    limit: int = 50,
    refresh: bool = False,
    resolve_bgp: bool = True,
    allow_external_asn: bool = True,
) -> dict[str, Any]:
    rows = list_observed_destinations_missing_asn(limit=limit)
    processed = enriched = no_data = errors = 0
    categories: Counter[str] = Counter()
    asns: Counter[str] = Counter()
    details: list[dict[str, Any]] = []
    for row in rows:
        processed += 1
        result = enrich_observed_destination_ip(
            row["destination_ip"],
            refresh=refresh,
            resolve_bgp=resolve_bgp,
            allow_external_asn=allow_external_asn,
        )
        if result.get("status") == "ok":
            if result.get("asn") is not None or result.get("organization") or result.get("country"):
                enriched += 1
            else:
                no_data += 1
            if result.get("category"):
                categories[str(result["category"])] += 1
            if result.get("asn") is not None:
                asns[str(result["asn"])] += 1
        else:
            errors += 1
        details.append({k: result.get(k) for k in ("destination_ip", "status", "asn", "organization", "country", "category", "error") if k in result})
    return {
        "processed": processed,
        "enriched": enriched,
        "no_data": no_data,
        "errors": errors,
        "categories_count": dict(categories),
        "asns_count": dict(asns),
        "details": details,
    }


def recategorize_observed_destinations(limit: int = 500) -> dict[str, Any]:
    rows = list_top_observed_destinations(limit=limit)
    updated = 0
    with get_connection() as conn:
        with conn.cursor() as cur:
            for row in rows:
                category = categorize_destination(row.get("asn"), row.get("organization"), row.get("domain_guess"))
                if category is None:
                    continue
                cur.execute(
                    "update observed_destinations set category = %s where destination_ip = %s::inet and destination_port is not distinct from %s and protocol is not distinct from %s",
                    (category, row["destination_ip"], row.get("destination_port"), row.get("protocol")),
                )
                updated += cur.rowcount
        conn.commit()
    return {"updated": updated}


def categories_summary(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                  coalesce(category, 'unknown') as category,
                  count(*)::bigint as destination_count,
                  sum(observation_count)::bigint as total_observations,
                  jsonb_agg(distinct asn) filter (where asn is not null) as top_asns,
                  array_agg(distinct asn) filter (where asn is not null) as asns,
                  jsonb_agg(
                      jsonb_build_object(
                        'destination_ip', host(destination_ip),
                        'destination_port', destination_port,
                        'protocol', protocol,
                        'observation_count', observation_count
                      )
                      order by observation_count desc, last_seen desc
                  ) filter (where destination_ip is not null) as top_destinations
                from observed_destinations
                group by coalesce(category, 'unknown')
                order by total_observations desc, destination_count desc
                limit %s
                """,
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]


def summarize_observed_destinations() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                  count(*)::bigint as destinations,
                  sum(observation_count)::bigint as observations,
                  count(*) filter (where asn is not null)::bigint as with_asn,
                  count(*) filter (where domain_guess is not null)::bigint as with_domain_guess
                from observed_destinations
                """
            )
            row = cur.fetchone() or {}
            return dict(row)


def summarize_observed_destinations_ui() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                  count(*)::bigint as total_destinations,
                  sum(observation_count)::bigint as total_observations,
                  count(distinct case when asn is not null then asn end)::bigint as total_asns,
                  count(distinct coalesce(category, 'unknown'))::bigint as total_categories,
                  max(last_seen) as last_seen,
                  count(*) filter (where asn_source = 'bgp')::bigint as asn_source_bgp,
                  count(*) filter (where asn_source = 'external')::bigint as asn_source_external,
                  count(*) filter (where asn is null)::bigint as asn_source_none,
                  count(*) filter (where enrichment_status = 'pending')::bigint as pending_enrichment,
                  count(*) filter (where enrichment_status = 'enriched')::bigint as enriched,
                  count(*) filter (where enrichment_status in ('error', 'no_data', 'no_match'))::bigint as unresolved
                from observed_destinations;
                """
            )
            summary = dict(cur.fetchone() or {})
            cur.execute(
                """
                select run_uid, started_at, destinations_seen, raw_seen, skipped_private, skipped_invalid, status
                from observed_destination_runs
                order by started_at desc
                limit 1
                """
            )
            last_run_row = cur.fetchone()
            last_run = dict(last_run_row) if last_run_row is not None else None
            return {
                "total_destinations": summary.get("total_destinations") or 0,
                "total_observations": summary.get("total_observations") or 0,
                "total_asns": summary.get("total_asns") or 0,
                "total_categories": summary.get("total_categories") or 0,
                "last_seen": summary.get("last_seen"),
                "last_collect_run": last_run,
                "asn_source_counts": {
                    "bgp": summary.get("asn_source_bgp") or 0,
                    "external": summary.get("asn_source_external") or 0,
                    "none": summary.get("asn_source_none") or 0,
                },
                "enrichment_status_counts": {
                    "enriched": summary.get("enriched") or 0,
                    "pending": summary.get("pending_enrichment") or 0,
                    "unresolved": summary.get("unresolved") or 0,
                },
                "privacy": {
                    "source_profiling": False,
                    "payload_collected": False,
                    "url_collected": False,
                    "query_string_collected": False,
                },
            }


def _observed_destination_ports(ip: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    destination_port,
                    protocol,
                    observation_count,
                    first_seen,
                    last_seen
                from observed_destinations
                where destination_ip = %s::inet
                order by observation_count desc, last_seen desc, destination_port asc nulls last
                """,
                (ip,),
            )
            return [dict(row) for row in cur.fetchall()]


def _fetch_latest_ping_for_target(target: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    target::text as target,
                    target_label,
                    source_label,
                    packets_sent,
                    packets_received,
                    packet_loss_percent,
                    rtt_min_ms,
                    rtt_avg_ms,
                    rtt_max_ms,
                    rtt_mdev_ms,
                    status,
                    measured_at
                from v_active_ping_latest
                where target = %s::inet
                order by measured_at desc
                limit 1
                """,
                (target,),
            )
            row = cur.fetchone()
            return dict(row) if row is not None else None


def _fetch_latest_traceroute_for_target(target: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    measurement_id,
                    target::text as target,
                    target_label,
                    source_label,
                    mode,
                    status,
                    hop_count,
                    responded_hop_count,
                    measured_at,
                    command
                from v_active_traceroute_latest
                where target = %s::inet
                order by measured_at desc, measurement_id desc
                limit 1
                """,
                (target,),
            )
            row = cur.fetchone()
            return dict(row) if row is not None else None


def _summarize_ports(ports: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for row in ports:
        port = row.get("destination_port")
        protocol = row.get("protocol")
        if port is None and not protocol:
            continue
        if port is None:
            parts.append(str(protocol))
        elif protocol:
            parts.append(f"{port}/{protocol}")
        else:
            parts.append(str(port))
    return ", ".join(parts) if parts else "sem portas observadas"


def get_observed_destination_baseline(ip: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    baseline_uid,
                    host(destination_ip) as destination_ip,
                    status,
                    source,
                    promoted_at,
                    promoted_from_observed_destination_id,
                    promoted_from_run_uid,
                    asn,
                    asn_source,
                    bgp_confirmed,
                    asn_confidence,
                    organization,
                    country,
                    category,
                    domain_guess,
                    reverse_dns,
                    observation_count,
                    first_seen,
                    last_seen,
                    observed_ports,
                    bgp_visibility,
                    baseline_snapshot,
                    notes,
                    created_at,
                    updated_at
                from observed_destination_baselines
                where destination_ip = %s::inet
                order by promoted_at desc
                limit 1
                """,
                (ip,),
            )
            row = cur.fetchone()
            return dict(row) if row is not None else None


def list_observed_destination_baselines(limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
    query = """
        select
            baseline_uid,
            host(destination_ip) as destination_ip,
            status,
            source,
            promoted_at,
            asn,
            asn_source,
            bgp_confirmed,
            asn_confidence,
            organization,
            country,
            category,
            observation_count,
            last_seen
        from observed_destination_baselines
    """
    params: list[Any] = []
    if status:
        query += " where status = %s"
        params.append(status)
    query += " order by promoted_at desc, last_seen desc nulls last, destination_ip asc limit %s"
    params.append(limit)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(query, tuple(params))
            return [dict(row) for row in cur.fetchall()]


def build_observed_destination_baseline_snapshot(destination: dict[str, Any]) -> dict[str, Any]:
    ip = str(destination.get("destination_ip"))
    ports = _observed_destination_ports(ip)
    bgp_visibility = build_bgp_visibility_response(ip)
    snapshot = {
        "destination_ip": ip,
        "asn": destination.get("asn"),
        "asn_source": destination.get("asn_source"),
        "bgp_confirmed": bool(destination.get("bgp_confirmed")),
        "asn_confidence": destination.get("asn_confidence"),
        "organization": destination.get("organization"),
        "country": destination.get("country"),
        "category": destination.get("category"),
        "domain_guess": destination.get("domain_guess"),
        "reverse_dns": destination.get("reverse_dns"),
        "observation_count": destination.get("observation_count") or 0,
        "first_seen": destination.get("first_seen"),
        "last_seen": destination.get("last_seen"),
        "observed_ports": ports,
        "bgp_visibility": bgp_visibility,
        "source": "observed_destination",
    }
    return snapshot


def promote_observed_destination_to_baseline(
    ip: str,
    confirm: bool = False,
    notes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not confirm:
        return {"status": "error", "detail": "Promover destino para baseline exige confirm=true."}
    destination = get_observed_destination(ip)
    if destination is None:
        return {"status": "error", "detail": "Destino observado não encontrado.", "code": 404}
    existing = get_observed_destination_baseline(ip)
    if existing is not None:
        return {
            "status": "ok",
            "created": False,
            "existing": True,
            "baseline_uid": existing.get("baseline_uid"),
            "destination_ip": str(existing.get("destination_ip")),
            "baseline_status": existing.get("status"),
            "baseline_snapshot": existing.get("baseline_snapshot") or {},
            "suggested_actions": get_baseline_suggested_actions(ip),
        }
    snapshot = build_observed_destination_baseline_snapshot(destination)
    baseline_uid = f"odb_{uuid4().hex}"
    observed_ports = snapshot.get("observed_ports") or []
    bgp_visibility = snapshot.get("bgp_visibility") or {}
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into observed_destination_baselines (
                    baseline_uid,
                    destination_ip,
                    status,
                    source,
                    promoted_from_observed_destination_id,
                    promoted_from_run_uid,
                    asn,
                    asn_source,
                    bgp_confirmed,
                    asn_confidence,
                    organization,
                    country,
                    category,
                    domain_guess,
                    reverse_dns,
                    observation_count,
                    first_seen,
                    last_seen,
                    observed_ports,
                    bgp_visibility,
                    baseline_snapshot,
                    notes
                )
                values (
                    %s,
                    %s::inet,
                    'monitoring',
                    'observed_destination',
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s::jsonb,
                    %s::jsonb,
                    %s::jsonb,
                    %s::jsonb
                )
                on conflict (destination_ip, source) do nothing
                returning baseline_uid
                """,
                (
                    baseline_uid,
                    ip,
                    destination.get("id"),
                    destination.get("last_run_uid"),
                    destination.get("asn"),
                    destination.get("asn_source"),
                    bool(destination.get("bgp_confirmed")),
                    destination.get("asn_confidence"),
                    destination.get("organization"),
                    destination.get("country"),
                    destination.get("category"),
                    destination.get("domain_guess"),
                    destination.get("reverse_dns"),
                    destination.get("observation_count") or 0,
                    destination.get("first_seen"),
                    destination.get("last_seen"),
                    json.dumps(observed_ports, default=str),
                    json.dumps(bgp_visibility, default=str),
                    json.dumps(snapshot, default=str),
                    json.dumps(notes or {}, default=str),
                ),
            )
            inserted = cur.fetchone()
        conn.commit()
    if inserted is None:
        existing = get_observed_destination_baseline(ip)
        return {
            "status": "ok",
            "created": False,
            "existing": True,
            "baseline_uid": existing.get("baseline_uid") if existing else None,
            "destination_ip": ip,
            "baseline_status": existing.get("status") if existing else "monitoring",
            "baseline_snapshot": existing.get("baseline_snapshot") if existing else snapshot,
            "suggested_actions": get_baseline_suggested_actions(ip),
        }
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into observed_destination_baseline_snapshots (
                    baseline_uid, destination_ip, snapshot_type, summary
                ) values (%s, %s::inet, 'baseline', %s::jsonb)
                """,
                (baseline_uid, ip, json.dumps(snapshot, default=str)),
            )
        conn.commit()
    return {
        "status": "ok",
        "created": True,
        "existing": False,
        "baseline_uid": baseline_uid,
        "destination_ip": ip,
        "baseline_status": "monitoring",
        "baseline_snapshot": snapshot,
        "suggested_actions": get_baseline_suggested_actions(ip),
    }


def refresh_observed_destination_baseline_snapshot(ip: str, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        return {"status": "error", "detail": "Refresh de snapshot exige confirm=true."}
    baseline = get_observed_destination_baseline(ip)
    if baseline is None:
        return {"status": "error", "detail": "Baseline não encontrada.", "code": 404}
    destination = get_observed_destination(ip)
    if destination is None:
        return {"status": "error", "detail": "Destino observado não encontrado.", "code": 404}
    snapshot = build_observed_destination_baseline_snapshot(destination)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update observed_destination_baselines
                set updated_at = now(),
                    last_seen = %s,
                    observation_count = %s,
                    asn = %s,
                    asn_source = %s,
                    bgp_confirmed = %s,
                    asn_confidence = %s,
                    organization = %s,
                    country = %s,
                    category = %s,
                    domain_guess = %s,
                    reverse_dns = %s,
                    observed_ports = %s::jsonb,
                    bgp_visibility = %s::jsonb,
                    baseline_snapshot = %s::jsonb
                where destination_ip = %s::inet and source = 'observed_destination'
                """,
                (
                    destination.get("last_seen"),
                    destination.get("observation_count") or 0,
                    destination.get("asn"),
                    destination.get("asn_source"),
                    bool(destination.get("bgp_confirmed")),
                    destination.get("asn_confidence"),
                    destination.get("organization"),
                    destination.get("country"),
                    destination.get("category"),
                    destination.get("domain_guess"),
                    destination.get("reverse_dns"),
                    json.dumps(snapshot.get("observed_ports") or [], default=str),
                    json.dumps(snapshot.get("bgp_visibility") or {}, default=str),
                    json.dumps(snapshot, default=str),
                    ip,
                ),
            )
            cur.execute(
                """
                insert into observed_destination_baseline_snapshots (
                    baseline_uid, destination_ip, snapshot_type, summary
                ) values (%s, %s::inet, 'baseline', %s::jsonb)
                """,
                (baseline.get("baseline_uid"), ip, json.dumps(snapshot)),
            )
        conn.commit()
    return {"status": "ok", "baseline_uid": baseline.get("baseline_uid"), "baseline_snapshot": snapshot}


def get_baseline_suggested_actions(ip: str) -> list[dict[str, Any]]:
    return [
        {"action": "trace_route", "requires_confirmation": True},
        {"action": "generate_destination_report", "requires_confirmation": False},
        {"action": "refresh_baseline_snapshot", "requires_confirmation": True},
        {"action": "bgp_visibility", "requires_confirmation": False},
    ]


def build_observed_destination_report(ip: str) -> dict[str, Any]:
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"status": "error", "detail": "IP inválido."}

    destination = get_observed_destination(normalized_ip)
    if destination is None:
        return {"status": "error", "detail": "Destino ainda não foi observado.", "code": 404}

    ports = _observed_destination_ports(normalized_ip)
    baseline = get_observed_destination_baseline(normalized_ip)
    bgp_visibility = build_bgp_visibility_response(normalized_ip, asn=destination.get("asn"))
    ping_latest = _fetch_latest_ping_for_target(normalized_ip)
    traceroute_latest = _fetch_latest_traceroute_for_target(normalized_ip)

    baseline_exists = baseline is not None
    missing_bgp_match = bool((bgp_visibility.get("bgp_visibility") or {}).get("match", {}).get("matched") is False)
    external_asn = destination.get("asn_source") == "external"
    missing_dns_name = not bool(destination.get("domain_guess") or destination.get("reverse_dns"))
    missing_baseline = not baseline_exists
    missing_traceroute = traceroute_latest is None

    gaps: list[str] = []
    if missing_bgp_match:
        gaps.append("missing_bgp_match")
    if external_asn and not destination.get("bgp_confirmed"):
        gaps.append("external_asn_not_bgp_confirmed")
    if missing_baseline:
        gaps.append("missing_baseline")
    if missing_traceroute:
        gaps.append("missing_traceroute")
    if missing_dns_name:
        gaps.append("missing_dns_name")

    recommended_actions = [
        {"action": "promote_to_baseline", "requires_confirmation": True} if missing_baseline else {"action": "refresh_baseline_snapshot", "requires_confirmation": True},
        {"action": "trace_route", "requires_confirmation": True},
        {"action": "generate_bgp_visibility_report", "requires_confirmation": False},
        {"action": "refresh_enrichment", "requires_confirmation": False},
    ]

    report_text = (
        f"Destino {normalized_ip} observado na rede local. "
        f"ASN {destination.get('asn') or '-'} {destination.get('organization') or '-'}, "
        f"fonte {destination.get('asn_source') or 'none'}, "
        f"{'confirmado' if destination.get('bgp_confirmed') else 'não confirmado'} pela BGP local. "
        f"Categoria {destination.get('category') or 'unknown'}. "
        f"Observado {(destination.get('observation_count') or 0)} vezes, nas portas { _summarize_ports(ports) }. "
        f"{'Existe baseline ativo.' if baseline_exists else 'Não existe baseline ativo.'} "
        f"{'A BGP local encontrou prefixo cobrindo o IP.' if (bgp_visibility.get('bgp_visibility') or {}).get('match', {}).get('matched') else 'A BGP local não encontrou prefixo cobrindo o IP.'} "
        f"{'Há traceroute recente salvo.' if traceroute_latest else 'Não há traceroute recente.'} "
        f"Próximas ações recomendadas: "
        f"{'promover para baseline' if missing_baseline else 'atualizar snapshot de baseline'}, "
        f"traçar rota com confirmação, gerar relatório BGP read-only e atualizar enrichment."
    )

    return {
        "status": "ok",
        "destination_ip": normalized_ip,
        "operational_report": report_text,
        "observed": {
            "destination_ip": normalized_ip,
            "ports": ports,
            "observation_count": destination.get("observation_count"),
            "first_seen": destination.get("first_seen"),
            "last_seen": destination.get("last_seen"),
            "source": destination.get("source"),
            "last_run_uid": destination.get("last_run_uid"),
        },
        "enrichment": {
            "asn": destination.get("asn"),
            "asn_source": destination.get("asn_source"),
            "bgp_confirmed": destination.get("bgp_confirmed"),
            "asn_confidence": destination.get("asn_confidence"),
            "organization": destination.get("organization"),
            "country": destination.get("country"),
            "category": destination.get("category"),
            "reverse_dns": destination.get("reverse_dns"),
            "domain_guess": destination.get("domain_guess"),
            "enrichment_status": destination.get("enrichment_status"),
        },
        "bgp_visibility": bgp_visibility,
        "baseline": {
            "baseline_exists": baseline_exists,
            "baseline_uid": baseline.get("baseline_uid") if baseline else None,
            "status": baseline.get("status") if baseline else None,
            "promoted_at": baseline.get("promoted_at") if baseline else None,
            "baseline_snapshot": baseline.get("baseline_snapshot") if baseline else {},
        },
        "measurements": {
            "ping_latest": ping_latest,
            "traceroute_latest": traceroute_latest,
            "traceroute_available": traceroute_latest is not None,
            "active_measurement_required": traceroute_latest is None,
        },
        "gaps": gaps,
        "recommended_actions": recommended_actions,
        "privacy": {
            "source_profiling": False,
            "payload_collected": False,
            "url_collected": False,
            "query_string_collected": False,
            "sensitive_metadata_collected": False,
        },
    }


def _safe_now() -> datetime:
    return datetime.now(timezone.utc)


def create_observed_destination_run(source: str, status: str, run_uid: str | None = None) -> str:
    run_uid = run_uid or f"odr_{uuid4().hex}"
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into observed_destination_runs (run_uid, source, status)
                values (%s, %s, %s)
                """,
                (run_uid, source, status),
            )
        conn.commit()
    return run_uid


def finish_observed_destination_run(
    run_uid: str,
    status: str,
    raw_seen: int = 0,
    skipped_private: int = 0,
    skipped_invalid: int = 0,
    destinations_seen: int = 0,
    destinations_inserted: int = 0,
    destinations_updated: int = 0,
    errors: list[dict[str, Any]] | None = None,
    summary: dict[str, Any] | None = None,
) -> None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update observed_destination_runs
                set status = %s,
                    finished_at = now(),
                    raw_seen = %s,
                    skipped_private = %s,
                    skipped_invalid = %s,
                    destinations_seen = %s,
                    destinations_inserted = %s,
                    destinations_updated = %s,
                    errors = %s::jsonb,
                    summary = %s::jsonb
                where run_uid = %s
                """,
                (
                    status,
                    raw_seen,
                    skipped_private,
                    skipped_invalid,
                    destinations_seen,
                    destinations_inserted,
                    destinations_updated,
                    json.dumps(errors or []),
                    json.dumps(summary or {}),
                    run_uid,
                ),
            )
        conn.commit()
